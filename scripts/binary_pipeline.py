#!/usr/bin/env python3
"""End-to-end binary-first pipeline with source as an optional overlay."""

from __future__ import annotations

import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
import gc
import hashlib
from importlib import metadata
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import sqlite3
import stat
import sys
import time
import traceback
from typing import Any, Callable, Iterable, Mapping
import zlib

try:
    import resource
except ImportError:  # pragma: no cover - Windows does not provide resource.
    resource = None

from binary_artifact_diff import ArtifactSnapshot, compare_artifact_snapshots, snapshot_archive
from binary_asm_helper import resolve_asm_jar
from binary_decision_engine import BinaryDecisionEngine, DEFAULT_RULES
from binary_fact_store import BinaryFactStore
from binary_first_contract import (
    BinaryFirstContractError,
    artifact_content_identity,
    canonical_identity,
    canonical_identity_streaming,
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
from binary_output import (
    BinaryOutputError,
    _discard_release_recapture_activation,
    _release_recapture_publication,
    activate_binary_generation,
    binary_publication_reauthorization_receipt,
    is_complete_v3_validation_result,
    prune_unreferenced_binary_generations,
    read_pending_binary_generation,
    read_binary_generation_publication_authority_binding,
    seal_active_binary_generation,
    write_binary_generation,
)
from binary_performance_identity import (
    GENERATION_SUPPORT_MANIFEST_LOGICAL_PATH,
    generation_source_identity as performance_generation_source_identity,
    harness_source_identity as performance_harness_source_identity,
    source_implementation_identity as performance_source_implementation_identity,
)
from binary_platform_image import JdkPlatformImage
from binary_runtime_reconciler import (
    RuntimeCapabilityPolicy,
    RuntimeReconciler,
    hydrate_runtime_reconciliation,
)
from binary_semantic_overlay import (
    build_binary_semantic_overlay,
    semantic_overlay_requires_runtime_selection,
)
from binary_snapshot_cache import SnapshotTemplateMemo, cached_snapshot_archive
from binary_source_overlay import build_inline_consumption_overlay, build_source_overlay
from binary_trace_engine import build_binary_traces
from binary_validation_oracle import (
    validate_generation,
    validate_oracle_tool_execution_policy,
)
from binary_validation_contract import (
    VALIDATION_POLICY_VERSION,
    oracle_support_manifest_identity,
    validator_implementation_identity,
    validator_source_identity,
)
import enhanced_source_analyzer as source_analyzer
from enhanced_source_analyzer import (
    analyze_file,
    extract_call_edges_enhanced,
    install_global_type_knowledge,
)
from path_runtime import short_temporary_directory
from jdk_preflight import JdkPreflightError, preflight_jdk_home
from process_lock import exclusive_file_lock
from process_metrics import windows_current_process_usage
from streaming_json import fsync_directory, json_file_digest_if_matches


SUPPORT_MANIFEST_PATH = Path(__file__).with_name("binary_first_support_manifest.json")
RUNTIME_REQUIREMENTS_PATH = (
    Path(__file__).resolve().parents[1] / "requirements-runtime.txt"
)
PERFORMANCE_GATE_CONTRACT_PATH = (
    "tests/fixtures/binary_first/performance_gate.json"
)
PERFORMANCE_GATE_PATH = (
    Path(__file__).resolve().parents[1] / PERFORMANCE_GATE_CONTRACT_PATH
)
RESUME_CHECKPOINT_SCHEMA = (
    "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3"
)
_RESUME_CHECKPOINT_NAME = "validation_checkpoint.json"
_RESUME_AWAITING_VALIDATION = "awaiting_independent_validation"
_RESUME_VALIDATION_FAILED = "independent_validation_failed"
_RESUME_VALIDATION_PASSED = "independent_validation_passed_pending_activation"
_VALIDATION_POLICY_VERSION = VALIDATION_POLICY_VERSION
_PIPELINE_RUN_LOCK_TIMEOUT_SECONDS = 0.0
_RESULT_GENERATION_SNAPSHOT_LAYERS = frozenset({
    "decision",
    "assessment",
    "formal_projection",
    "candidate_projection",
})
_REQUIRED_PIPELINE_GENERATION_SIDECARS = frozenset({
    "binary_decisions.json",
    "binary_projections.json",
    "binary_formal_results.json",
    "binary_candidate_results.json",
    "binary_entrypoints.json",
    "binary_coverage.json",
    "binary_summary.json",
    "binary_formal_results.csv",
    "base_binary_facts.sqlite",
    "current_binary_facts.sqlite",
    "binary_runtime_semantic_overlay.json",
    "binary_definition_verification.json",
    "binary_pairings.json",
    "binary_phase_manifest.json",
    "binary_build_identities.json",
    "binary_publication_authority.json",
})
_RESUME_RESULT_SUMMARY_FIELDS = frozenset({
    "base_runtime_reconciliation_identity",
    "current_runtime_reconciliation_identity",
    "decision_bundle_identity",
    "trace_bundle_identity",
    "decision_coverage_status",
    "trace_coverage_status",
    "authoritative_change_fact_count",
    "diagnostic_candidate_fact_count",
})
_VALIDATION_ATTACHMENT_FIELDS = frozenset({
    "schema",
    "validation_run_identity",
    "result_generation_identity",
    "oracle_support_manifest_identity",
    "truth_set_identity",
    "issue_set_identity",
    "validation_policy_version",
    "validator_implementation_identity",
    "status",
    "issue_count",
    "issues",
    "domain_summary",
    "helper_identities",
    "skipped_domains",
    "production_identity_influence",
})
_PERFORMANCE_AUTHORITY_BINDING_FIELDS = frozenset({
    "schema",
    "authority_mode",
    "support_contract_identity",
    "evidence_sha256",
    "source_implementation_identity",
    "binding_identity",
})
_PERFORMANCE_RELEASE_AUTHORITY_MODE = "release_evidence"
_PERFORMANCE_CANDIDATE_AUTHORITY_MODE = "candidate_source_measurement"
_PERFORMANCE_RECAPTURE_AUTHORITY_MODE = "release_recapture_measurement"
# A checked-in JSON file can never enable measurement bootstrap.  The
# performance harness activates this capability only in its isolated worker's
# current context while measuring candidate source.  ContextVar avoids leaking
# the exception to concurrent pipeline calls or a later resume.
_PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY = object()
_PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT: ContextVar[object | None] = (
    ContextVar("binary_performance_measurement_bootstrap", default=None)
)
_PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY = object()
_PERFORMANCE_RELEASE_RECAPTURE_CONTEXT: ContextVar[object | None] = (
    ContextVar("binary_performance_release_recapture", default=None)
)
_PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT: ContextVar[Path | None] = (
    ContextVar("binary_performance_release_recapture_root", default=None)
)
# The public CLI owns this value for one invocation.  Progress is optional
# observability shared by every writer using an output root, so a failure may
# consume it only when the file names this exact attempt.  In particular, a
# config/load failure before the recorder starts and a rejected lock contender
# must never borrow an earlier or concurrent writer's phase.
_CLI_PROGRESS_ATTEMPT_CONTEXT: ContextVar[str] = ContextVar(
    "binary_pipeline_cli_progress_attempt", default=""
)
_CLI_PROGRESS_MAX_BYTES = 4 * 1024 * 1024
_REUSABLE_DETERMINISTIC_VALIDATION_FAILURES = frozenset({
    "ORACLE_DIRECT_EDGE_MISSING",
    "ORACLE_DIRECT_EDGE_EXTRA",
    "ORACLE_DYNAMIC_HANDLE_MISSING",
    "ORACLE_DYNAMIC_HANDLE_EXTRA",
})
# Explicit, reviewable dependency closure for bytes written by
# ``write_binary_generation``.  A denylist made every newly-added Step1,
# report, gate, Oracle or benchmark module silently invalidate a multi-hour
# Step4 generation.  Keep this list at file granularity and add a source only
# when it can affect production facts, decisions, traces or immutable
# generation serialization.
_GENERATION_IMPLEMENTATION_SOURCE_PATHS = (
    "artifact_safety.py",
    "binary_artifact_diff.py",
    "binary_asm_helper.py",
    "binary_decision_engine.py",
    "binary_definition_verifier.py",
    "binary_entrypoint_discovery.py",
    "binary_fact_store.py",
    "binary_first_contract.py",
    "binary_first_model.py",
    "binary_output.py",
    "binary_pipeline.py",
    "binary_platform_image.py",
    "binary_runtime_reconciler.py",
    "binary_semantic_overlay.py",
    "binary_snapshot_cache.py",
    "binary_source_overlay.py",
    "binary_tool_execution.py",
    "binary_trace_engine.py",
    "compat.py",
    "csv_io.py",
    "enhanced_source_analyzer.py",
    "jdk_preflight.py",
    "javap_contract.py",
    "path_runtime.py",
    "safe_xml.py",
    "signature_utils.py",
    "streaming_json.py",
    "java/BinaryFactExtractor.java",
    "java/ClassDefinitionVerifier.java",
)
_GENERATION_RUNTIME_DISTRIBUTIONS = (
    ("tree-sitter", "tree_sitter"),
    ("tree-sitter-java", "tree_sitter_java"),
)


class BinaryPipelineError(BinaryFirstContractError):
    pass


def _add_cleanup_note(primary: BaseException, note: str) -> None:
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        try:
            add_note(note)
            return
        except Exception:
            pass
    try:
        notes = list(getattr(primary, "__notes__", ()) or ())
        notes.append(note)
        setattr(primary, "__notes__", notes)
    except Exception:
        pass


def _attempt_cleanups(
    actions: Iterable[tuple[str, Callable[[], None]]],
    *,
    primary: BaseException | None,
) -> None:
    errors = []
    for label, action in actions:
        try:
            action()
        except BaseException as error:
            errors.append((label, error))
    if not errors:
        return
    if primary is not None:
        for label, error in errors:
            _add_cleanup_note(
                primary,
                f"cleanup failed ({label}): {type(error).__name__}: {error}",
            )
        return
    first_label, first = errors[0]
    for label, error in errors[1:]:
        _add_cleanup_note(
            first,
            f"additional cleanup failed ({label}): {type(error).__name__}: {error}",
        )
    _add_cleanup_note(first, f"cleanup operation: {first_label}")
    raise first


def _unlink_missing_ok(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _artifact_snapshot_worker_count(configured: Any, lineage_count: int) -> int:
    """Return a bounded worker count without accepting lossy JSON coercions."""
    lineage_count = max(0, int(lineage_count))
    if configured in (None, ""):
        if lineage_count == 0:
            return 0
        return min(
            3,
            max(1, (os.cpu_count() or 1) // 3),
            lineage_count,
        )
    if isinstance(configured, bool) or isinstance(configured, float):
        raise BinaryPipelineError(
            "BINARY_ARTIFACT_WORKER_COUNT_INVALID", str(configured)
        )
    try:
        workers = int(configured)
    except (TypeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_ARTIFACT_WORKER_COUNT_INVALID", str(configured)
        ) from error
    if not 1 <= workers <= 8:
        raise BinaryPipelineError(
            "BINARY_ARTIFACT_WORKER_COUNT_INVALID", str(configured)
        )
    return min(workers, lineage_count)


def _artifact_hash_worker_count(configured: Any, file_count: int) -> int:
    """Return a bounded digest worker count for independent artifact files."""
    file_count = max(0, int(file_count))
    if configured in (None, ""):
        if file_count == 0:
            return 0
        return min(4, max(1, (os.cpu_count() or 1) // 2), file_count)
    if isinstance(configured, bool) or isinstance(configured, float):
        raise BinaryPipelineError(
            "BINARY_ARTIFACT_HASH_WORKER_COUNT_INVALID", str(configured)
        )
    try:
        workers = int(configured)
    except (TypeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_ARTIFACT_HASH_WORKER_COUNT_INVALID", str(configured)
        ) from error
    if not 1 <= workers <= 8:
        raise BinaryPipelineError(
            "BINARY_ARTIFACT_HASH_WORKER_COUNT_INVALID", str(configured)
        )
    return min(workers, file_count)


def _write_non_authoritative_json(
    path: str | Path,
    payload: Mapping[str, Any],
    *,
    durable: bool = False,
) -> bool:
    """Atomically persist optional observability without affecting authority."""
    requested = Path(path)
    try:
        if (
            requested.parent.name != "binary_observability"
            or requested.name in {"", ".", ".."}
        ):
            raise OSError(
                "observability destination is outside its physical directory"
            )
        encoded = json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ) + "\n"
        if _secure_resume_checkpoint_dirfd_supported():
            _write_bound_observability_text_posix(
                requested.parent.parent,
                requested.name,
                encoded,
                durable=durable,
            )
        elif os.name == "nt":  # pragma: no cover - native Windows CI.
            observability = _physical_observability_directory(
                requested.parent.parent,
                create=True,
            )
            _write_observability_text_windows_compat(
                observability / requested.name,
                encoded,
                durable=durable,
            )
        else:
            raise OSError(
                "secure descriptor-relative observability write is unavailable"
            )
    except (OSError, UnicodeError, TypeError, ValueError):
        return False
    return True


def _prune_unreferenced_generations_best_effort(
    output_root: Path,
    *,
    protected_generation_identities: Iterable[str] = (),
) -> dict[str, Any]:
    """Reclaim stale generation bytes without making cleanup a result gate."""

    try:
        summary = prune_unreferenced_binary_generations(
            output_root,
            protected_generation_identities=protected_generation_identities,
        )
    except (BinaryOutputError, OSError, RuntimeError) as error:
        summary = {
            "schema": "java-upgrade-analyzer.binary-generation-gc.v1",
            "removed_generation_identities": [],
            "retained_generation_identities": [],
            "skipped_entries": [],
            "failures": [{
                "generation_identity": "",
                "error_type": type(error).__name__,
                "reason_code": str(getattr(error, "reason_code", "") or ""),
                "detail": str(error),
            }],
            "removed_count": 0,
            "retained_count": 0,
            "failure_count": 1,
        }
    _write_non_authoritative_json(
        output_root / "binary_observability" / "latest_generation_gc.json",
        summary,
    )
    return summary


def _write_text_atomic_durable(path: str | Path, content: str) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
    )
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        fsync_directory(destination.parent)
        return destination
    finally:
        primary = sys.exc_info()[1]
        _attempt_cleanups(
            ((f"unlink temporary durable file {temporary}", lambda: _unlink_missing_ok(temporary)),),
            primary=primary,
        )


class _PhaseTimingRecorder(list):
    """Persist non-authoritative progress without treating attempts as success."""

    ORDER = (
        "static_preflight",
        "input_and_runtime_profile",
        "artifact_fact_build_and_local_diff",
        "target_independent_runtime_reconciliation",
        "decision_and_projection_freeze",
        "binary_trace",
        "immutable_generation_write",
        "independent_validation",
        "validated_generation_activation",
    )

    def __init__(
        self,
        output_root: Path,
        started: float,
        *,
        attempt_identity: str = "",
    ):
        super().__init__()
        self.started = started
        self.attempt_identity = (
            str(attempt_identity or "")
            or hashlib.sha256(os.urandom(32)).hexdigest()
        )
        self._previous_usage = _non_authoritative_resource_usage_snapshot()
        self.directory = output_root / "binary_observability"
        self.path = self.directory / "latest_in_progress.json"
        self.write_failure_count = 0

    def _with_resource_usage(self, item: Mapping[str, Any] | None) -> dict[str, Any]:
        item = dict(item or {})
        usage = _non_authoritative_resource_usage_snapshot()
        if usage is None:
            item.setdefault("peak_rss_bytes", 0)
            item.setdefault("completed_child_peak_rss_bytes", 0)
            item.setdefault("self_cpu_seconds", 0.0)
            item.setdefault("child_cpu_seconds", 0.0)
            item.setdefault("process_tree_cpu_seconds", 0.0)
            item.setdefault("average_cpu_cores", 0.0)
        else:
            item.setdefault("peak_rss_bytes", usage.self_peak_rss_bytes)
            item.setdefault(
                "completed_child_peak_rss_bytes",
                usage.completed_child_peak_rss_bytes,
            )
            previous = self._previous_usage
            if previous is not None:
                self_cpu = max(
                    0.0,
                    usage.self_user_seconds
                    + usage.self_system_seconds
                    - previous.self_user_seconds
                    - previous.self_system_seconds,
                )
                child_cpu = max(
                    0.0,
                    usage.child_user_seconds
                    + usage.child_system_seconds
                    - previous.child_user_seconds
                    - previous.child_system_seconds,
                )
                process_tree_cpu = self_cpu + child_cpu
                wall_seconds = float(item.get("elapsed_seconds") or 0.0)
                item.setdefault("self_cpu_seconds", round(self_cpu, 6))
                item.setdefault("child_cpu_seconds", round(child_cpu, 6))
                item.setdefault(
                    "process_tree_cpu_seconds", round(process_tree_cpu, 6)
                )
                item.setdefault(
                    "average_cpu_cores",
                    round(process_tree_cpu / wall_seconds, 6)
                    if wall_seconds > 0
                    else 0.0,
                )
            self._previous_usage = usage
        return item

    def _write_progress(
        self,
        *,
        status: str,
        last_completed_phase: str,
        current_phase: str,
        **additional: Any,
    ) -> None:
        persisted = _write_non_authoritative_json(self.path, {
            "schema": "java-upgrade-analyzer.binary-progress.v1",
            "attempt_identity": self.attempt_identity,
            "status": status,
            "last_completed_phase": last_completed_phase,
            "current_phase": current_phase,
            "elapsed_seconds": round(time.perf_counter() - self.started, 6),
            "phases": list(self),
            "non_authoritative_observability": True,
            **additional,
        })
        if not persisted:
            # Progress files are explicitly non-authoritative. Keep a bounded
            # in-memory signal for callers/tests, but never turn a valid
            # generation or activation into a pipeline failure because the
            # observability volume is unavailable.
            self.write_failure_count += 1

    def append(self, item):
        item = self._with_resource_usage(item)
        super().append(item)
        completed = str(item.get("phase") or "")
        try:
            index = self.ORDER.index(completed)
        except ValueError:
            next_phase = "unknown"
        else:
            next_phase = self.ORDER[index + 1] if index + 1 < len(self.ORDER) else ""
        self._write_progress(
            status="completed" if not next_phase else "running",
            last_completed_phase=completed,
            current_phase=next_phase,
        )

    def start(self, phase: str, **metadata: Any) -> None:
        """Record a phase transition without claiming that the phase completed."""
        last_completed = str(self[-1].get("phase") or "") if self else ""
        self._write_progress(
            status="running",
            last_completed_phase=last_completed,
            current_phase=str(phase or "unknown"),
            active_phase_metadata=dict(metadata),
        )

    def fail(self, item: Mapping[str, Any]) -> None:
        """Record a failed attempt while keeping successful phase history intact."""
        failed = self._with_resource_usage(item)
        last_completed = str(self[-1].get("phase") or "") if self else ""
        self._write_progress(
            status="failed",
            last_completed_phase=last_completed,
            current_phase=str(failed.get("phase") or "unknown"),
            failed_phase_timing=failed,
        )


SOURCE_INPUT_PURPOSE_VERSION = "source-input-purpose-v3"
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


def _generation_support_manifest_identity(
    support: Mapping[str, Any] | None = None,
) -> str:
    """Bind generation bytes only to production support policy.

    The independent Oracle owns its own content-bound validation identity.
    Including that post-generation subsection here would discard a valid,
    immutable multi-hour generation whenever only the Oracle is corrected,
    defeating the validation checkpoint that exists for exactly that case.
    """

    if support is None:
        try:
            loaded = json.loads(
                SUPPORT_MANIFEST_PATH.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise BinaryPipelineError(
                "BINARY_AUTHORITY_MANIFEST_INVALID", str(error)
            ) from error
    else:
        loaded = support
    if not isinstance(loaded, Mapping):
        raise BinaryPipelineError(
            "BINARY_AUTHORITY_MANIFEST_INVALID",
            "support manifest root must be an object",
        )
    production_support = dict(loaded)
    production_support.pop("oracle_support_manifest", None)
    # Performance evidence certifies whether a release may be activated; it
    # does not produce generation bytes.  Keeping this subsection in the
    # generation identity creates a cycle because a fresh scale run records
    # the generation produced by the very release being measured.
    production_support.pop("performance_gate", None)
    try:
        return _identity(
            "binary_generation_support_manifest_identity",
            production_support,
        )
    except (BinaryFirstContractError, TypeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_AUTHORITY_MANIFEST_INVALID", str(error)
        ) from error


_GENERATION_NONPRODUCING_LOCAL_IMPORTS = {
    # Validation and activation consume the immutable generation but cannot
    # change its bytes.  Each exception is deliberately source-specific so a
    # newly-added local import fails closed instead of expanding this boundary
    # invisibly.
    "binary_output.py": frozenset({
        "binary_validation_contract",
        "process_lock",
    }),
    "binary_pipeline.py": frozenset({
        "binary_performance_gate",
        "binary_performance_identity",
        "binary_validation_contract",
        "binary_validation_oracle",
        "process_lock",
        "process_metrics",
    }),
}


@lru_cache(maxsize=128)
def _local_python_imports_from_exact_bytes(
    source_label: str,
    content: bytes,
) -> frozenset[str]:
    """Parse one exact source version once without trusting file metadata."""

    try:
        tree = ast.parse(content, filename=source_label)
    except (UnicodeError, SyntaxError) as error:
        raise BinaryPipelineError(
            "BINARY_GENERATION_SOURCE_IMPORT_CLOSURE_INVALID",
            f"{source_label}: {error}",
        ) from error
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
    return frozenset(imported)


def _local_python_imports(source: Path) -> set[str]:
    try:
        content = source.read_bytes()
    except OSError as error:
        raise BinaryPipelineError(
            "BINARY_GENERATION_SOURCE_IMPORT_CLOSURE_INVALID",
            f"{source}: {error}",
        ) from error
    # Exact bytes, not path/mtime, are the cache authority.  A source rewrite
    # in a long-running process therefore forces a new AST parse, while the
    # repeated generation/validation identity checks in one run share it.
    return set(_local_python_imports_from_exact_bytes(str(source), content))


def _validate_generation_source_import_closure() -> None:
    scripts_dir = Path(__file__).resolve().parent
    production_modules = {
        Path(relative).stem
        for relative in _GENERATION_IMPLEMENTATION_SOURCE_PATHS
        if relative.endswith(".py")
    }
    local_modules = {path.stem for path in scripts_dir.glob("*.py")}
    for relative in _GENERATION_IMPLEMENTATION_SOURCE_PATHS:
        if not relative.endswith(".py"):
            continue
        imported = _local_python_imports(scripts_dir / relative) & local_modules
        allowed_external = _GENERATION_NONPRODUCING_LOCAL_IMPORTS.get(
            relative, frozenset()
        )
        unexpected = sorted(imported - production_modules - allowed_external)
        if unexpected:
            raise BinaryPipelineError(
                "BINARY_GENERATION_SOURCE_IMPORT_CLOSURE_INVALID",
                f"{relative}: unclassified local imports {unexpected}",
            )


def _runtime_requirement_pins(content: bytes) -> dict[str, str]:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise BinaryPipelineError(
            "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
            f"{RUNTIME_REQUIREMENTS_PATH}: {error}",
        ) from error
    pins = {}
    for line in lines:
        declaration = line.strip()
        if not declaration or declaration.startswith("#"):
            continue
        name, separator, version = declaration.partition("==")
        if (
            not separator
            or not name
            or not version
            or name in pins
            or version.strip() != version
        ):
            raise BinaryPipelineError(
                "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                f"runtime dependency must be a unique exact pin: {declaration}",
            )
        pins[name] = version
    required = {name for name, _module in _GENERATION_RUNTIME_DISTRIBUTIONS}
    if set(pins) != required:
        raise BinaryPipelineError(
            "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
            f"runtime dependency pins mismatch: expected={sorted(required)}; "
            f"actual={sorted(pins)}",
        )
    return pins


def _stable_runtime_file_record(
    path: Path,
    *,
    root: Path,
    relative: str,
) -> dict[str, Any]:
    """Hash one installed runtime file without following replacement links."""
    try:
        root_resolved = root.resolve(strict=True)
        lexical = path.absolute()
        resolved = lexical.resolve(strict=True)
        resolved.relative_to(root_resolved)
        before = lexical.lstat()
        if lexical.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise OSError("runtime dependency entry is not a bound regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lexical, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (before.st_dev, before.st_ino)
            ):
                raise OSError("runtime dependency changed before open")
            digest = hashlib.sha256()
            byte_length = 0
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                byte_length += len(block)
                digest.update(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = lexical.lstat()
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        if any(
            getattr(opened, field) != getattr(after, field)
            or getattr(after, field) != getattr(final, field)
            for field in stable_fields
        ) or byte_length != after.st_size:
            raise OSError("runtime dependency changed while hashing")
    except (OSError, RuntimeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
            f"{relative}: {error}",
        ) from error
    return {
        "path": relative,
        "sha256": digest.hexdigest(),
        "size_bytes": byte_length,
    }


def _runtime_distribution_record(
    distribution_name: str,
    module_name: str,
    required_version: str,
) -> dict[str, Any]:
    try:
        distribution = metadata.distribution(distribution_name)
        observed_version = str(distribution.version)
        files = distribution.files
        root = Path(distribution.locate_file("")).absolute()
    except (metadata.PackageNotFoundError, OSError, TypeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
            f"{distribution_name}: {error}",
        ) from error
    if observed_version != required_version or files is None:
        raise BinaryPipelineError(
            "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
            f"{distribution_name}: required={required_version}; "
            f"observed={observed_version or 'missing'}",
        )
    runtime_files = []
    for raw_relative in sorted(files, key=lambda item: str(item)):
        relative_path = Path(str(raw_relative))
        parts = relative_path.parts
        if not parts or parts[0] != module_name:
            continue
        if "__pycache__" in parts or relative_path.suffix in {".pyc", ".pyo"}:
            continue
        if ".." in parts:
            raise BinaryPipelineError(
                "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                f"{distribution_name}: unsafe installed path {raw_relative}",
            )
        runtime_files.append(_stable_runtime_file_record(
            Path(distribution.locate_file(raw_relative)),
            root=root,
            relative=relative_path.as_posix(),
        ))
    if not runtime_files:
        raise BinaryPipelineError(
            "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
            f"{distribution_name}: no runtime module files",
        )
    return {
        "distribution": distribution_name,
        "module": module_name,
        "required_version": required_version,
        "observed_version": observed_version,
        "runtime_files_identity": _identity(
            "binary_generation_runtime_distribution_files_identity",
            runtime_files,
        ),
        "runtime_files": runtime_files,
    }


def _generation_runtime_identity(required_pins: Mapping[str, str]) -> str:
    try:
        connection = sqlite3.connect(":memory:")
        try:
            sqlite_source_id = str(
                connection.execute("SELECT sqlite_source_id()").fetchone()[0]
            )
            sqlite_compile_options = sorted(
                str(row[0])
                for row in connection.execute("PRAGMA compile_options")
            )
        finally:
            connection.close()
        distributions = [
            _runtime_distribution_record(name, module, str(required_pins[name]))
            for name, module in _GENERATION_RUNTIME_DISTRIBUTIONS
        ]
        payload = {
            "python": {
                "implementation": str(sys.implementation.name),
                "cache_tag": str(sys.implementation.cache_tag or ""),
                "version": [
                    int(sys.version_info.major),
                    int(sys.version_info.minor),
                    int(sys.version_info.micro),
                    str(sys.version_info.releaselevel),
                    int(sys.version_info.serial),
                ],
                "version_text": str(sys.version),
                "abi_flags": str(getattr(sys, "abiflags", "")),
                "byteorder": str(sys.byteorder),
            },
            "platform": {
                "os_name": str(os.name),
                "sys_platform": str(sys.platform),
                "system": str(platform.system()),
                "release": str(platform.release()),
                "machine": str(platform.machine()),
            },
            "sqlite": {
                "python_module_version": str(
                    getattr(sqlite3, "version", "stdlib")
                ),
                "runtime_version": str(sqlite3.sqlite_version),
                "source_id": sqlite_source_id,
                "compile_options": sqlite_compile_options,
            },
            "zlib": {
                "compile_version": str(zlib.ZLIB_VERSION),
                "runtime_version": str(zlib.ZLIB_RUNTIME_VERSION),
            },
            "source_overlay_limits": {
                "max_tree_sitter_source_lines": int(
                    source_analyzer.MAX_TREE_SITTER_SOURCE_LINES
                ),
                "max_tree_sitter_source_bytes": int(
                    source_analyzer.MAX_TREE_SITTER_SOURCE_BYTES
                ),
            },
            "runtime_distributions": distributions,
        }
    except BinaryFirstContractError:
        raise
    except (KeyError, OSError, sqlite3.Error, TypeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE", str(error)
        ) from error
    return _identity("binary_generation_runtime_identity", payload)


def _resume_generation_source_records() -> list[dict[str, str]]:
    """Capture every disk source/policy that can produce generation bytes."""
    scripts_dir = Path(__file__).resolve().parent
    _validate_generation_source_import_closure()
    inputs = [
        *(scripts_dir / relative
          for relative in _GENERATION_IMPLEMENTATION_SOURCE_PATHS),
        SUPPORT_MANIFEST_PATH,
        RUNTIME_REQUIREMENTS_PATH,
    ]
    try:
        requirements_content = RUNTIME_REQUIREMENTS_PATH.read_bytes()
    except OSError as error:
        raise BinaryPipelineError(
            "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE", str(error)
        ) from error
    records = []
    for path in inputs:
        if not path.is_file():
            raise BinaryPipelineError(
                "BINARY_GENERATION_IMPLEMENTATION_SOURCE_MISSING", str(path)
            )
        if path == SUPPORT_MANIFEST_PATH:
            # This is a logical policy input.  Performance measurement swaps a
            # private byte-identical production-policy snapshot whose only
            # changed subsection is explicitly excluded below; its temporary
            # filesystem location must not relabel generation code.
            display_path = GENERATION_SUPPORT_MANIFEST_LOGICAL_PATH
        elif path == RUNTIME_REQUIREMENTS_PATH:
            display_path = "../requirements-runtime.txt"
        else:
            try:
                display_path = path.relative_to(scripts_dir).as_posix()
            except ValueError:
                display_path = str(path)
        records.append({
            "path": display_path,
            "sha256": (
                _generation_support_manifest_identity()
                if path == SUPPORT_MANIFEST_PATH
                else hashlib.sha256(requirements_content).hexdigest()
                if path == RUNTIME_REQUIREMENTS_PATH
                else _sha256_file(path)
            ),
        })
    # The requirements file itself is already content-bound above.  The
    # virtual record additionally binds the interpreter and native libraries
    # that actually execute the production path.
    records.append({
        "path": "@runtime/binary-generation-runtime",
        "sha256": _generation_runtime_identity(
            _runtime_requirement_pins(requirements_content)
        ),
    })
    return records


# Source fingerprints are release/performance evidence, not normal analysis
# authority.  Capture them lazily only when the dedicated measurement path
# requests that evidence; importing or running Step4 no longer hashes the
# source tree.
_CAPTURED_RESUME_GENERATION_SOURCE_RECORDS: (
    tuple[tuple[str, str], ...] | None
) = None


def _captured_resume_generation_source_records() -> list[dict[str, str]]:
    global _CAPTURED_RESUME_GENERATION_SOURCE_RECORDS
    if _CAPTURED_RESUME_GENERATION_SOURCE_RECORDS is None:
        _CAPTURED_RESUME_GENERATION_SOURCE_RECORDS = tuple(
            (record["path"], record["sha256"])
            for record in _resume_generation_source_records()
        )
    return [
        {"path": path, "sha256": sha256}
        for path, sha256 in _CAPTURED_RESUME_GENERATION_SOURCE_RECORDS
    ]


def _verify_captured_generation_sources() -> list[dict[str, str]]:
    captured = _captured_resume_generation_source_records()
    current = _resume_generation_source_records()
    if current != captured:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_IMPLEMENTATION_CHANGED_DURING_RUN",
            "generation source or support files changed after module load",
        )
    return captured


def _resume_implementation_identity(
    asm_jar: str | Path,
    *,
    source_records: Iterable[Mapping[str, str]] | None = None,
) -> str:
    scripts_dir = Path(__file__).resolve().parent
    records = [
        dict(item) for item in (
            source_records
            if source_records is not None
            else _resume_generation_source_records()
        )
    ]
    asm_path = Path(asm_jar).resolve()
    try:
        asm_display_path = asm_path.relative_to(scripts_dir).as_posix()
    except ValueError:
        asm_display_path = str(asm_path)
    records.append({
        "path": asm_display_path,
        "sha256": _sha256_file(asm_path),
    })
    return _identity(
        "binary_pipeline_resume_generation_implementation_identity",
        {
            "scope_policy": "generation-producing-explicit-closure-v3",
            "inputs": records,
        },
    )


def _resume_input_artifact_identity(
    config: Mapping[str, Any], *, digest_session: Any = None,
) -> str:
    records = []
    seen = set()
    for side_name in ("base", "current"):
        side = dict(config.get(side_name) or {})
        for artifact in side.get("artifacts") or ():
            for field in ("path", "outer_artifact_path"):
                value = str((artifact or {}).get(field) or "").strip()
                if not value:
                    continue
                path = Path(value).expanduser().resolve()
                key = str(path)
                if key in seen:
                    continue
                seen.add(key)
                if not path.is_file():
                    raise BinaryPipelineError(
                        "BINARY_RESUME_INPUT_ARTIFACT_MISSING", str(path)
                    )
                digest_record = (
                    getattr(digest_session, "_records", {}).get(path)
                    if digest_session is not None else None
                )
                if digest_record is None:
                    stat = path.stat()
                    sha256 = _sha256_file(path)
                    size_bytes = int(stat.st_size)
                else:
                    sha256 = str(digest_record.content_sha256)
                    size_bytes = int(digest_record.byte_length)
                records.append({
                    "path": key,
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                })
    return _identity("binary_pipeline_resume_input_artifact_identity", records)


def _resume_config_identity(config: Mapping[str, Any]) -> str:
    """Bind semantic config while excluding regenerated worktree root names."""
    normalized = json.loads(
        json.dumps(config, ensure_ascii=False, sort_keys=True)
    )
    overlay = dict(normalized.get("source_overlay") or {})
    normalized_sets = []
    for raw_set in overlay.get("source_sets") or ():
        source_set = dict(raw_set or {})
        root_value = str(source_set.get("source_root") or "").strip()
        root = Path(root_value).expanduser().resolve() if root_value else None
        logical_dirs = []
        for raw_dir in source_set.get("source_dirs") or ():
            source_dir = Path(str(raw_dir)).expanduser().resolve()
            if root is None:
                logical_dirs.append(str(source_dir))
                continue
            try:
                logical_dirs.append(source_dir.relative_to(root).as_posix())
            except ValueError:
                # Invalid/out-of-snapshot paths must not accidentally become
                # resumable merely because a physical prefix was removed.
                logical_dirs.append(f"outside-snapshot:{source_dir}")
        source_set["source_root"] = "<immutable-snapshot-root>" if root else ""
        source_set["source_dirs"] = logical_dirs
        normalized_sets.append(source_set)
    if overlay:
        overlay["source_sets"] = normalized_sets
        normalized["source_overlay"] = overlay
    return _identity("binary_pipeline_resume_config_identity", normalized)


def _resume_source_input_identity(config: Mapping[str, Any]) -> str:
    """Bind source bytes while allowing regenerated immutable root paths."""
    overlay = config.get("source_overlay")
    if not isinstance(overlay, Mapping):
        overlay = {}
    files = []
    source_sets = []
    for raw_set in overlay.get("source_sets") or ():
        source_set = dict(raw_set or {})
        roots = [
            Path(str(value)).expanduser().resolve()
            for value in source_set.get("source_dirs") or ()
        ]
        common_value = source_set.get("source_root") or (
            roots[0] if len(roots) == 1 else None
        )
        if common_value is None:
            raise BinaryPipelineError(
                "BINARY_RESUME_SOURCE_COMMON_ROOT_REQUIRED",
                str(source_set.get("owner_coord") or ""),
            )
        common = Path(str(common_value)).expanduser().resolve()
        set_files = []
        logical_dirs = []
        for root in roots:
            if not root.is_dir():
                raise BinaryPipelineError(
                    "BINARY_RESUME_SOURCE_ROOT_MISSING", str(root)
                )
            try:
                logical_dirs.append(root.relative_to(common).as_posix())
            except ValueError as error:
                raise BinaryPipelineError(
                    "BINARY_RESUME_SOURCE_ROOT_OUTSIDE_SNAPSHOT", str(root)
                ) from error
            for path in sorted(
                candidate for candidate in root.rglob("*")
                if candidate.is_file()
                and candidate.suffix.lower() in SOURCE_FILE_LANGUAGES
            ):
                try:
                    logical_path = path.relative_to(common).as_posix()
                except ValueError as error:
                    raise BinaryPipelineError(
                        "BINARY_RESUME_SOURCE_FILE_OUTSIDE_SNAPSHOT", str(path)
                    ) from error
                row = {
                    "owner_type": str(source_set.get("owner_type") or ""),
                    "owner_coord": str(source_set.get("owner_coord") or ""),
                    "module": str(source_set.get("module") or "root"),
                    "logical_path": logical_path,
                    "sha256": _sha256_file(path),
                }
                files.append(row)
                set_files.append(row)
        source_sets.append({
            "owner_type": str(source_set.get("owner_type") or ""),
            "owner_coord": str(source_set.get("owner_coord") or ""),
            "module": str(source_set.get("module") or "root"),
            "snapshot_revision": str(
                source_set.get("snapshot_revision") or "content-addressed-only"
            ),
            "logical_source_dirs": logical_dirs,
            "file_count": len(set_files),
        })
    return _identity(
        "binary_pipeline_resume_source_input_identity",
        {"source_sets": source_sets, "files": files},
    )


def _resume_checkpoint_path(output_root: Path) -> Path:
    return output_root / "binary_observability" / _RESUME_CHECKPOINT_NAME


def _physical_observability_directory(
    output_root: str | Path,
    *,
    create: bool,
) -> Path:
    """Return the physical observability child without following its leaf."""

    lexical_root = Path(output_root).expanduser()
    if lexical_root.name in {"", ".", ".."}:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
            f"{lexical_root}: output root must name a dedicated leaf",
        )
    root = lexical_root.parent.resolve() / lexical_root.name
    observability = root / "binary_observability"
    try:
        try:
            root_stat = os.lstat(root)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(root, 0o700)
            except FileExistsError:
                pass
            root_stat = os.lstat(root)
        if (
            stat.S_ISLNK(root_stat.st_mode)
            or not stat.S_ISDIR(root_stat.st_mode)
            or root.resolve(strict=True) != root
        ):
            raise OSError("output root is not a physical directory")
        if create:
            try:
                os.mkdir(observability, 0o700)
            except FileExistsError:
                pass
        observed = os.lstat(observability)
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or observability.resolve(strict=True) != observability
        ):
            raise OSError(
                "binary_observability is not a physical child directory"
            )
    except (OSError, RuntimeError) as error:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
            f"{observability}: {error}",
        ) from error
    return observability


def _filesystem_entry_absent(path: str | Path) -> bool:
    """Prove that one exact path has no directory entry without following links."""

    resolved = Path(path)
    try:
        os.lstat(resolved)
    except FileNotFoundError:
        return True
    except OSError as error:
        raise BinaryPipelineError(
            "BINARY_FILESYSTEM_ABSENCE_PROOF_FAILED",
            f"{resolved}: {error}",
        ) from error
    return False


def _secure_resume_checkpoint_dirfd_supported() -> bool:
    """Whether all checkpoint mutations can stay relative to one bound dirfd."""

    return bool(
        os.name != "nt"
        and int(getattr(os, "O_DIRECTORY", 0) or 0)
        and int(getattr(os, "O_NOFOLLOW", 0) or 0)
        and all(
            operation in os.supports_dir_fd
            for operation in (
                os.open,
                os.mkdir,
                os.stat,
                os.unlink,
                os.rename,
            )
        )
        and os.stat in os.supports_follow_symlinks
    )


class _CheckpointObservabilityStorageError(OSError):
    pass


def _checkpoint_directory_is_reparse_point(
    path: Path, observed: os.stat_result,
) -> bool:
    attributes = int(getattr(observed, "st_file_attributes", 0) or 0)
    reparse_attribute = int(
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0) or 0
    )
    is_junction = getattr(path, "is_junction", None)
    return bool(
        stat.S_ISLNK(observed.st_mode)
        or (reparse_attribute and attributes & reparse_attribute)
        or (callable(is_junction) and is_junction())
    )


def _validated_checkpoint_directory_stat(path: Path) -> os.stat_result:
    observed = os.lstat(path)
    if (
        not stat.S_ISDIR(observed.st_mode)
        or _checkpoint_directory_is_reparse_point(path, observed)
    ):
        raise OSError(f"checkpoint parent is not a physical directory: {path}")
    return observed


def _verify_checkpoint_directory_binding(
    path: Path,
    expected: os.stat_result,
    *,
    descriptor: int | None = None,
) -> None:
    current = _validated_checkpoint_directory_stat(path)
    if not os.path.samestat(current, expected):
        raise OSError(f"checkpoint parent changed during mutation: {path}")
    if descriptor is not None:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not os.path.samestat(opened, expected)
        ):
            raise OSError(
                f"checkpoint parent descriptor changed during mutation: {path}"
            )


def _checkpoint_directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | int(getattr(os, "O_DIRECTORY", 0) or 0)
        | int(getattr(os, "O_NOFOLLOW", 0) or 0)
        | int(getattr(os, "O_CLOEXEC", 0) or 0)
        | int(getattr(os, "O_BINARY", 0) or 0)
    )


def _open_checkpoint_directory_at(
    parent_fd: int,
    name: str,
    path: Path,
    expected: os.stat_result,
) -> int:
    descriptor = os.open(
        name, _checkpoint_directory_open_flags(), dir_fd=parent_fd
    )
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or not os.path.samestat(opened, expected)
            or not os.path.samestat(current, expected)
        ):
            raise OSError(f"checkpoint directory changed while opening: {path}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@dataclass(frozen=True, slots=True)
class _CheckpointDirectoryBinding:
    canonical_parent: Path
    output_root: Path
    observability: Path
    root_name: str
    observability_name: str
    parent_fd: int
    root_fd: int
    observability_fd: int
    parent_expected: os.stat_result
    root_expected: os.stat_result
    observability_expected: os.stat_result
    root_created: bool
    observability_created: bool


def _checkpoint_binding_close_actions(
    binding: _CheckpointDirectoryBinding,
) -> tuple[tuple[str, Callable[[], None]], ...]:
    return (
        (
            f"close checkpoint observability {binding.observability}",
            lambda: os.close(binding.observability_fd),
        ),
        (
            f"close checkpoint output root {binding.output_root}",
            lambda: os.close(binding.root_fd),
        ),
        (
            f"close checkpoint canonical parent {binding.canonical_parent}",
            lambda: os.close(binding.parent_fd),
        ),
    )


def _close_checkpoint_descriptors(
    descriptors: list[tuple[str, int]], *, primary: BaseException | None,
) -> None:
    _attempt_cleanups(
        tuple(
            (label, lambda fd=descriptor: os.close(fd))
            for label, descriptor in reversed(descriptors)
        ),
        primary=primary,
    )


def _open_bound_checkpoint_directories(
    output_root: str | Path,
    *,
    create: bool,
) -> _CheckpointDirectoryBinding | None:
    """Bind the complete owned path before any checkpoint mutation."""

    requested = Path(output_root).expanduser()
    if requested.name in {"", ".", ".."}:
        raise OSError("output root must name a dedicated leaf")
    canonical_parent = requested.parent.resolve(strict=True)
    root_name = requested.name
    output = canonical_parent / root_name
    observability_name = "binary_observability"
    observability = output / observability_name
    descriptors: list[tuple[str, int]] = []
    root_created = False
    observability_created = False
    try:
        parent_expected = _validated_checkpoint_directory_stat(
            canonical_parent
        )
        parent_fd = os.open(
            canonical_parent, _checkpoint_directory_open_flags()
        )
        descriptors.append((
            f"close checkpoint canonical parent {canonical_parent}",
            parent_fd,
        ))
        _verify_checkpoint_directory_binding(
            canonical_parent, parent_expected, descriptor=parent_fd
        )
        try:
            root_expected = os.stat(
                root_name, dir_fd=parent_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            if not create:
                closing, descriptors = descriptors, []
                _close_checkpoint_descriptors(closing, primary=None)
                return None
            os.mkdir(root_name, 0o700, dir_fd=parent_fd)
            root_created = True
            root_expected = os.stat(
                root_name, dir_fd=parent_fd, follow_symlinks=False
            )
        if (
            not stat.S_ISDIR(root_expected.st_mode)
            or _checkpoint_directory_is_reparse_point(
                output, root_expected
            )
        ):
            raise OSError("output root is not a physical directory")
        root_fd = _open_checkpoint_directory_at(
            parent_fd, root_name, output, root_expected
        )
        descriptors.append((f"close checkpoint output root {output}", root_fd))
        try:
            observability_expected = os.stat(
                observability_name,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if not create:
                closing, descriptors = descriptors, []
                _close_checkpoint_descriptors(closing, primary=None)
                return None
            os.mkdir(observability_name, 0o700, dir_fd=root_fd)
            observability_created = True
            observability_expected = os.stat(
                observability_name,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        if (
            not stat.S_ISDIR(observability_expected.st_mode)
            or _checkpoint_directory_is_reparse_point(
                observability, observability_expected
            )
        ):
            raise OSError(
                "binary_observability is not a physical child directory"
            )
        observability_fd = _open_checkpoint_directory_at(
            root_fd,
            observability_name,
            observability,
            observability_expected,
        )
        descriptors.append((
            f"close checkpoint observability {observability}",
            observability_fd,
        ))
        return _CheckpointDirectoryBinding(
            canonical_parent=canonical_parent,
            output_root=output,
            observability=observability,
            root_name=root_name,
            observability_name=observability_name,
            parent_fd=parent_fd,
            root_fd=root_fd,
            observability_fd=observability_fd,
            parent_expected=parent_expected,
            root_expected=root_expected,
            observability_expected=observability_expected,
            root_created=root_created,
            observability_created=observability_created,
        )
    except BaseException as error:
        _close_checkpoint_descriptors(
            descriptors, primary=error
        )
        if isinstance(error, _CheckpointObservabilityStorageError):
            raise
        if isinstance(error, OSError):
            raise _CheckpointObservabilityStorageError(str(error)) from error
        raise


def _verify_checkpoint_directory_tree_binding(
    binding: _CheckpointDirectoryBinding,
) -> None:
    _verify_checkpoint_directory_binding(
        binding.canonical_parent,
        binding.parent_expected,
        descriptor=binding.parent_fd,
    )
    current_root = os.stat(
        binding.root_name,
        dir_fd=binding.parent_fd,
        follow_symlinks=False,
    )
    opened_root = os.fstat(binding.root_fd)
    if (
        not stat.S_ISDIR(current_root.st_mode)
        or not os.path.samestat(current_root, binding.root_expected)
        or not os.path.samestat(opened_root, binding.root_expected)
    ):
        raise OSError("checkpoint output root binding changed")
    current_observability = os.stat(
        binding.observability_name,
        dir_fd=binding.root_fd,
        follow_symlinks=False,
    )
    opened_observability = os.fstat(binding.observability_fd)
    if (
        not stat.S_ISDIR(current_observability.st_mode)
        or not os.path.samestat(
            current_observability, binding.observability_expected
        )
        or not os.path.samestat(
            opened_observability, binding.observability_expected
        )
    ):
        raise OSError("checkpoint observability binding changed")


def _unlink_checkpoint_name_missing_ok(name: str, parent_fd: int) -> None:
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass


def _write_bound_observability_text_posix(
    output_root: str | Path,
    destination_name: str,
    content: str,
    *,
    durable: bool,
) -> Path:
    binding = _open_bound_checkpoint_directories(
        output_root, create=True
    )
    if binding is None:  # pragma: no cover - create=True is total or raises.
        raise OSError("checkpoint directory binding was not created")
    destination = binding.observability / destination_name
    parent_fd = binding.observability_fd
    temporary_name = (
        f".{destination.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
    )
    temporary_fd = -1
    temporary_exists = False
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | int(getattr(os, "O_NOFOLLOW", 0) or 0)
            | int(getattr(os, "O_CLOEXEC", 0) or 0)
            | int(getattr(os, "O_BINARY", 0) or 0)
        )
        temporary_fd = os.open(
            temporary_name, flags, 0o600, dir_fd=parent_fd
        )
        temporary_exists = True
        with os.fdopen(
            temporary_fd, "w", encoding="utf-8", newline="\n"
        ) as handle:
            temporary_fd = -1
            handle.write(content)
            handle.flush()
            if durable:
                os.fsync(handle.fileno())
            temporary_stat = os.fstat(handle.fileno())
        if not _private_regular_checkpoint_stat(temporary_stat):
            raise OSError("checkpoint temporary is not a private regular file")
        try:
            existing = os.stat(
                destination.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            if not _private_regular_checkpoint_stat(existing):
                raise OSError(
                    "checkpoint destination is not a private regular file"
                )
        _verify_checkpoint_directory_tree_binding(binding)
        os.rename(
            temporary_name,
            destination.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_exists = False
        installed = os.stat(
            destination.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not os.path.samestat(installed, temporary_stat):
            raise OSError("checkpoint destination changed during publication")
        _verify_checkpoint_directory_tree_binding(binding)
        if durable:
            os.fsync(parent_fd)
            if binding.observability_created:
                os.fsync(binding.root_fd)
            if binding.root_created:
                os.fsync(binding.parent_fd)
        _verify_checkpoint_directory_tree_binding(binding)
        return destination
    finally:
        primary = sys.exc_info()[1]
        actions: list[tuple[str, Callable[[], None]]] = []
        if temporary_fd >= 0:
            actions.append((
                f"close resume checkpoint temporary {temporary_name}",
                lambda: os.close(temporary_fd),
            ))
        if temporary_exists:
            actions.append((
                f"unlink resume checkpoint temporary {temporary_name}",
                lambda: _unlink_checkpoint_name_missing_ok(
                    temporary_name, parent_fd
                ),
            ))
        actions.extend(_checkpoint_binding_close_actions(binding))
        _attempt_cleanups(actions, primary=primary)


def _write_resume_checkpoint_posix(
    output_root: str | Path, content: str,
) -> Path:
    return _write_bound_observability_text_posix(
        output_root,
        _RESUME_CHECKPOINT_NAME,
        content,
        durable=True,
    )


def _write_observability_text_windows_compat(
    destination: Path,
    content: str,
    *,
    durable: bool,
) -> Path:
    """Path-based Windows fallback with repeated reparse/identity checks."""

    parent = destination.parent
    parent_expected = _validated_checkpoint_directory_stat(parent)
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
    )
    try:  # pragma: no cover - exercised by native Windows CI.
        _verify_checkpoint_directory_binding(parent, parent_expected)
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            if durable:
                os.fsync(handle.fileno())
        _verify_checkpoint_directory_binding(parent, parent_expected)
        try:
            existing = os.lstat(destination)
        except FileNotFoundError:
            pass
        else:
            if not _private_regular_checkpoint_stat(existing):
                raise OSError(
                    "checkpoint destination is not a private regular file"
                )
        _verify_checkpoint_directory_binding(parent, parent_expected)
        os.replace(temporary, destination)
        _verify_checkpoint_directory_binding(parent, parent_expected)
        if durable:
            fsync_directory(parent)
        _verify_checkpoint_directory_binding(parent, parent_expected)
        return destination
    finally:
        primary = sys.exc_info()[1]

        def safe_cleanup() -> None:
            _verify_checkpoint_directory_binding(parent, parent_expected)
            _unlink_missing_ok(temporary)

        _attempt_cleanups(
            ((f"unlink Windows checkpoint temporary {temporary}", safe_cleanup),),
            primary=primary,
        )


def _write_resume_checkpoint_windows_compat(
    destination: Path, content: str,
) -> Path:
    return _write_observability_text_windows_compat(
        destination, content, durable=True
    )


class _ResumeCheckpointDirectoryFsyncError(OSError):
    pass


def _delete_resume_checkpoint_posix(output_root: str | Path) -> bool:
    binding = _open_bound_checkpoint_directories(
        output_root, create=False
    )
    if binding is None:
        return False
    checkpoint = binding.observability / _RESUME_CHECKPOINT_NAME
    parent_fd = binding.observability_fd
    try:
        try:
            observed = os.stat(
                checkpoint.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            _verify_checkpoint_directory_tree_binding(binding)
            return False
        if not _private_regular_checkpoint_stat(observed):
            raise OSError("checkpoint is not a private regular file")
        os.unlink(checkpoint.name, dir_fd=parent_fd)
        try:
            os.fsync(parent_fd)
        except OSError as error:
            raise _ResumeCheckpointDirectoryFsyncError(str(error)) from error
        _verify_checkpoint_directory_tree_binding(binding)
        return True
    finally:
        primary = sys.exc_info()[1]
        _attempt_cleanups(
            _checkpoint_binding_close_actions(binding),
            primary=primary,
        )


def _delete_resume_checkpoint_windows_compat(checkpoint: Path) -> bool:
    """Path-based Windows fallback with repeated reparse/identity checks."""

    parent_expected = _validated_checkpoint_directory_stat(checkpoint.parent)
    _verify_checkpoint_directory_binding(checkpoint.parent, parent_expected)
    try:  # pragma: no cover - exercised by native Windows CI.
        observed = os.lstat(checkpoint)
    except FileNotFoundError:
        _verify_checkpoint_directory_binding(checkpoint.parent, parent_expected)
        return False
    if not _private_regular_checkpoint_stat(observed):
        raise OSError("checkpoint is not a private regular file")
    _verify_checkpoint_directory_binding(checkpoint.parent, parent_expected)
    checkpoint.unlink()
    _verify_checkpoint_directory_binding(checkpoint.parent, parent_expected)
    try:
        fsync_directory(checkpoint.parent)
    except OSError as error:
        raise _ResumeCheckpointDirectoryFsyncError(str(error)) from error
    _verify_checkpoint_directory_binding(checkpoint.parent, parent_expected)
    return True


def _is_sha256_identity(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _performance_authority_binding_is_valid(value: Any) -> bool:
    return bool(
        isinstance(value, Mapping)
        and set(value) == _PERFORMANCE_AUTHORITY_BINDING_FIELDS
        and value.get("schema")
        == "java-upgrade-analyzer.performance-authority-binding.v2"
        and value.get("authority_mode") in {
            _PERFORMANCE_RELEASE_AUTHORITY_MODE,
            _PERFORMANCE_CANDIDATE_AUTHORITY_MODE,
            _PERFORMANCE_RECAPTURE_AUTHORITY_MODE,
        }
        and all(
            _is_sha256_identity(value.get(field))
            for field in _PERFORMANCE_AUTHORITY_BINDING_FIELDS
            - {"schema", "authority_mode"}
        )
        and value.get("binding_identity")
        == _identity(
            "binary_performance_authority_binding_identity",
            {
                "support_contract_identity": value[
                    "support_contract_identity"
                ],
                "evidence_sha256": value["evidence_sha256"],
                "source_implementation_identity": value[
                    "source_implementation_identity"
                ],
                "authority_mode": value["authority_mode"],
            },
        )
    )


def _resume_checkpoint_content_identity(payload: Mapping[str, Any]) -> str:
    return _identity(
        "binary_pipeline_resume_checkpoint_content_identity",
        {
            key: value
            for key, value in payload.items()
            if key != "checkpoint_content_identity"
        },
    )


def _normalized_resume_checkpoint(payload: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    normalized["checkpoint_content_identity"] = (
        _resume_checkpoint_content_identity(normalized)
    )
    return normalized


def _write_resume_checkpoint(output_root: Path, payload: Mapping[str, Any]) -> Path:
    normalized = _normalized_resume_checkpoint(payload)
    content = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ) + "\n"
    try:
        if _secure_resume_checkpoint_dirfd_supported():
            return _write_resume_checkpoint_posix(output_root, content)
        if os.name == "nt":  # pragma: no cover - native Windows CI.
            destination = (
                _physical_observability_directory(output_root, create=True)
                / _RESUME_CHECKPOINT_NAME
            )
            return _write_resume_checkpoint_windows_compat(
                destination, content
            )
        raise OSError(
            "secure descriptor-relative checkpoint write is unavailable"
        )
    except _CheckpointObservabilityStorageError as error:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
            f"{_resume_checkpoint_path(output_root).parent}: {error}",
        ) from error
    except BinaryPipelineError:
        raise
    except OSError as error:
        destination = _resume_checkpoint_path(output_root)
        raise BinaryPipelineError(
            "BINARY_RESUME_CHECKPOINT_WRITE_FAILED",
            f"cannot durably write validation checkpoint {destination}: {error}",
        ) from error


def _write_resume_checkpoint_roundtrip(
    output_root: Path,
    payload: Mapping[str, Any],
    *,
    reason_code: str = "BINARY_RESUME_CHECKPOINT_ROUNDTRIP_FAILED",
) -> dict[str, Any]:
    """Durably write a checkpoint and prove the exact bytes are readable.

    A checkpoint is authoritative only for crash recovery.  Returning a
    silent empty mapping after a known write turns an observability glitch
    into a schema-less state transition, so the producer must fail at the
    write boundary instead.
    """

    expected = _normalized_resume_checkpoint(payload)
    _write_resume_checkpoint(output_root, expected)
    persisted = _read_resume_checkpoint(output_root)
    if persisted != expected:
        raise BinaryPipelineError(
            reason_code,
            str(_resume_checkpoint_path(output_root)),
        )
    return persisted


def _rebind_resume_checkpoint_performance_authority(
    output_root: Path,
    checkpoint: Mapping[str, Any],
    current_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Durably replace only a previously validated performance binding.

    The caller invokes this only after proving the checkpoint, immutable
    generation, implementation, config, inputs and toolchain.  Keeping the
    mutation in one narrow helper makes it impossible to accidentally bless a
    stale generation field while allowing a new benchmark/harness or Oracle
    release to reuse the expensive generation bytes.  Production callers hold
    the output-root pipeline writer lock across this compare/write/read
    sequence; the explicit comparison also detects writers that violate that
    lock protocol.
    """

    old_binding = checkpoint.get("performance_authority_gate_binding")
    if (
        not _performance_authority_binding_is_valid(old_binding)
        or not _performance_authority_binding_is_valid(current_binding)
    ):
        raise BinaryPipelineError(
            "BINARY_RESUME_PERFORMANCE_AUTHORITY_REBIND_INVALID",
            "old or current performance authority binding is invalid",
        )
    if dict(old_binding) == dict(current_binding):
        return dict(checkpoint)
    if checkpoint.get("checkpoint_content_identity") != (
        _resume_checkpoint_content_identity(checkpoint)
    ):
        raise BinaryPipelineError(
            "BINARY_RESUME_CHECKPOINT_INTEGRITY_INVALID",
            str(_resume_checkpoint_path(output_root)),
        )
    # Refuse to overwrite a checkpoint replaced after the resume decision read
    # it. Under the output-root writer lock, the durable atomic write below
    # then presents either the complete old or complete rebound checkpoint
    # after a crash.
    if _read_resume_checkpoint(output_root) != dict(checkpoint):
        raise BinaryPipelineError(
            "BINARY_RESUME_CHECKPOINT_CHANGED_DURING_REBIND",
            str(_resume_checkpoint_path(output_root)),
        )
    updated = {
        **dict(checkpoint),
        "performance_authority_gate_binding": dict(current_binding),
    }
    return _write_resume_checkpoint_roundtrip(
        output_root,
        updated,
        reason_code="BINARY_RESUME_PERFORMANCE_AUTHORITY_REBIND_FAILED",
    )


def _delete_resume_checkpoint_durable(output_root: Path) -> bool:
    """Remove a consumed checkpoint and report persistence failures.

    A missing checkpoint is already the desired state.  Once an existing
    directory entry is removed, both the unlink and the parent directory
    synchronization are part of this cleanup operation.
    """

    checkpoint = _resume_checkpoint_path(output_root)
    try:
        if _secure_resume_checkpoint_dirfd_supported():
            return _delete_resume_checkpoint_posix(output_root)
        if os.name == "nt":  # pragma: no cover - native Windows CI.
            observability = output_root / "binary_observability"
            try:
                os.lstat(observability)
            except FileNotFoundError:
                return False
            checkpoint = (
                _physical_observability_directory(
                    output_root, create=False
                )
                / _RESUME_CHECKPOINT_NAME
            )
            return _delete_resume_checkpoint_windows_compat(checkpoint)
        raise OSError(
            "secure descriptor-relative checkpoint deletion is unavailable"
        )
    except _CheckpointObservabilityStorageError as error:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
            f"{checkpoint.parent}: {error}",
        ) from error
    except _ResumeCheckpointDirectoryFsyncError as error:
        raise BinaryPipelineError(
            "BINARY_RESUME_CHECKPOINT_DIRECTORY_FSYNC_FAILED",
            f"cannot durably remove consumed validation checkpoint {checkpoint}: {error}",
        ) from error
    except OSError as error:
        raise BinaryPipelineError(
            "BINARY_RESUME_CHECKPOINT_UNLINK_FAILED",
            f"cannot remove consumed validation checkpoint {checkpoint}: {error}",
        ) from error


def _cleanup_consumed_resume_checkpoint(
    output_root: Path,
    performance_authority_gate_binding: Mapping[str, Any] | None,
) -> bool:
    """Best-effort cleanup for a completed normal analysis activation.

    Benchmark and release-recapture runs keep strict cleanup because their
    private measurement state must not become reusable production state.
    Normal analysis is already authoritative once the validated generation is
    sealed; a leftover restart checkpoint can be removed on the next startup.
    """

    try:
        return _delete_resume_checkpoint_durable(output_root)
    except BinaryPipelineError:
        if performance_authority_gate_binding is not None:
            raise
        return False


def _read_optional_json_object(path: str | Path) -> dict[str, Any]:
    """Read an optional JSON object without applying config-error semantics."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


_MAX_RESUME_CHECKPOINT_BYTES = 16 * 1024 * 1024


def _strict_json_object_from_bytes(content: bytes) -> dict[str, Any]:
    """Decode strict UTF-8 JSON while rejecting non-finite and duplicate data."""

    if type(content) is not bytes:
        raise ValueError("JSON content must be exact bytes")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key: {key}")
            value[key] = item
        return value

    value = json.loads(
        content.decode("utf-8"),
        object_pairs_hook=object_pairs,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number: {token}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def _checkpoint_stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_nlink),
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000))),
    )


def _private_regular_checkpoint_stat(value: os.stat_result) -> bool:
    return bool(stat.S_ISREG(value.st_mode) and value.st_nlink == 1)


def _read_resume_checkpoint_bytes(
    path: Path,
    *,
    parent_fd: int | None = None,
) -> bytes | None:
    """Read one stable private file, optionally relative to a bound parent."""

    entry: str | Path = path.name if parent_fd is not None else path

    def entry_stat() -> os.stat_result:
        if parent_fd is None:
            return os.lstat(entry)
        return os.stat(entry, dir_fd=parent_fd, follow_symlinks=False)

    try:
        path_before = entry_stat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        return None
    if (
        not _private_regular_checkpoint_stat(path_before)
        or path_before.st_size > _MAX_RESUME_CHECKPOINT_BYTES
    ):
        return None

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = -1
    try:
        if parent_fd is None:
            descriptor = os.open(entry, flags)
        else:
            descriptor = os.open(entry, flags, dir_fd=parent_fd)
        descriptor_before = os.fstat(descriptor)
        if (
            not _private_regular_checkpoint_stat(descriptor_before)
            or descriptor_before.st_size > _MAX_RESUME_CHECKPOINT_BYTES
            or _checkpoint_stat_identity(path_before)
            != _checkpoint_stat_identity(descriptor_before)
        ):
            return None
        chunks: list[bytes] = []
        remaining = _MAX_RESUME_CHECKPOINT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        descriptor_after = os.fstat(descriptor)
        if (
            len(content) > _MAX_RESUME_CHECKPOINT_BYTES
            or len(content) != descriptor_after.st_size
            or not _private_regular_checkpoint_stat(descriptor_after)
            or _checkpoint_stat_identity(descriptor_before)
            != _checkpoint_stat_identity(descriptor_after)
        ):
            return None
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        path_after = entry_stat()
    except (FileNotFoundError, NotADirectoryError, OSError):
        return None
    if (
        not _private_regular_checkpoint_stat(path_after)
        or _checkpoint_stat_identity(descriptor_after)
        != _checkpoint_stat_identity(path_after)
    ):
        return None
    return content


def _read_resume_checkpoint(output_root: Path) -> dict[str, Any]:
    """Read a bounded checkpoint through a physically bound directory tree."""

    path = _resume_checkpoint_path(output_root)
    binding: _CheckpointDirectoryBinding | None = None
    try:
        if _secure_resume_checkpoint_dirfd_supported():
            try:
                binding = _open_bound_checkpoint_directories(
                    output_root, create=False
                )
            except OSError:
                return {}
            if binding is None:
                return {}
            content = _read_resume_checkpoint_bytes(
                path, parent_fd=binding.observability_fd
            )
            if content is None:
                return {}
            try:
                _verify_checkpoint_directory_tree_binding(binding)
            except OSError:
                return {}
        elif os.name == "nt":  # pragma: no cover - native Windows CI.
            try:
                observability = _physical_observability_directory(
                    output_root, create=False
                )
            except (BinaryPipelineError, OSError):
                return {}
            content = _read_resume_checkpoint_bytes(
                observability / _RESUME_CHECKPOINT_NAME
            )
            if content is None:
                return {}
        else:
            return {}
    finally:
        if binding is not None:
            for descriptor in (
                binding.observability_fd,
                binding.root_fd,
                binding.parent_fd,
            ):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    try:
        return _strict_json_object_from_bytes(content)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        return {}


def _validation_checkpoint_result_receipt(
    output_root: Path,
    manifest: Mapping[str, Any],
    activation_record: Mapping[str, Any],
    performance_authority_gate_binding: Mapping[str, Any] | None,
    *,
    retain_requested: bool,
    candidate_discarded: bool,
) -> dict[str, Any]:
    """Return the retained handoff receipt needed by the workflow parent."""

    checkpoint_path = _resume_checkpoint_path(output_root)
    if not retain_requested or candidate_discarded:
        return {}
    try:
        checkpoint_stat = os.lstat(checkpoint_path)
    except FileNotFoundError:
        checkpoint_stat = None
    except OSError as error:
        raise BinaryPipelineError(
            "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
            f"{checkpoint_path}: {error}",
        ) from error
    if (
        checkpoint_stat is None
        or stat.S_ISLNK(checkpoint_stat.st_mode)
        or not stat.S_ISREG(checkpoint_stat.st_mode)
        or checkpoint_stat.st_nlink != 1
    ):
        raise BinaryPipelineError(
            "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
            f"retained checkpoint is not a private regular file: {checkpoint_path}",
        )
    checkpoint = _read_resume_checkpoint(output_root)
    generation_identity = str(
        manifest.get("result_generation_identity") or ""
    )
    activation_identity = str(
        activation_record.get("activation_identity") or ""
    )
    pending = read_pending_binary_generation(output_root, missing_ok=True)
    if (
        not checkpoint
        or checkpoint.get("status") != _RESUME_VALIDATION_PASSED
        or checkpoint.get("result_generation_identity") != generation_identity
        or checkpoint.get("activation_identity") != activation_identity
        or checkpoint.get("performance_authority_gate_binding")
        != (
            dict(performance_authority_gate_binding)
            if performance_authority_gate_binding is not None
            else None
        )
        or pending is None
        or pending.get("result_generation_identity") != generation_identity
        or pending.get("activation_identity") != activation_identity
        or pending.get("activation_state") != "pending"
    ):
        raise BinaryPipelineError(
            "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
            "retained checkpoint, pending descriptor, and result do not match",
        )
    return {
        "validation_checkpoint_retained": True,
        "validation_checkpoint_path": str(checkpoint_path),
    }


def _resume_generation_integrity_valid(
    generation: Path, manifest: Mapping[str, Any]
) -> bool:
    """Cheaply prove an immutable checkpoint generation before revalidation."""
    snapshots = manifest.get("active_snapshot_identities")
    sidecars = manifest.get("sidecar_content_identities")
    policies = manifest.get("policy_identities")
    if (
        manifest.get("schema")
        != "java-upgrade-analyzer.binary-result-generation.v1"
        or manifest.get("authority") != "binary_first"
        or not isinstance(snapshots, Mapping)
        or set(snapshots) != _RESULT_GENERATION_SNAPSHOT_LAYERS
        or not all(_is_sha256_identity(value) for value in snapshots.values())
        or not isinstance(sidecars, Mapping)
        or not _REQUIRED_PIPELINE_GENERATION_SIDECARS.issubset(sidecars)
        or not isinstance(policies, Mapping)
        or not all(
            _is_sha256_identity(policies.get(field))
            for field in (
                "base_jdk_preflight_identity",
                "current_jdk_preflight_identity",
            )
        )
        or not isinstance(manifest.get("analysis_context_identity"), str)
        or not manifest.get("analysis_context_identity")
        or not isinstance(manifest.get("trace_result_set_digest"), str)
        or not manifest.get("trace_result_set_digest")
    ):
        return False
    expected_identity = _identity("result_generation_identity", {
        "analysis_context_identity": manifest["analysis_context_identity"],
        "authority": "binary_first",
        "snapshot_identities": dict(snapshots),
        "trace_result_set_digest": manifest["trace_result_set_digest"],
        "sidecar_content_identities": dict(sidecars),
        "policy_identities": dict(policies),
    })
    if (
        manifest.get("result_generation_identity") != expected_identity
        or generation.name != expected_identity
    ):
        return False
    for name, expected_sha256 in sidecars.items():
        if (
            not isinstance(name, str)
            or name in {"", ".", ".."}
            or "/" in name
            or "\\" in name
            or "\x00" in name
            or not re.fullmatch(r"[0-9a-f]{64}", str(expected_sha256))
        ):
            return False
        sidecar = generation / name
        if (
            sidecar.is_symlink()
            or not sidecar.is_file()
            or _sha256_file(sidecar) != expected_sha256
        ):
            return False
    return True


def _resume_checkpoint_metadata(
    checkpoint: Mapping[str, Any],
    manifest: Mapping[str, Any],
    config: Mapping[str, Any],
    source_inputs: Mapping[str, Any],
    toolchain_preflight: Mapping[str, Any],
    performance_authority_gate_binding: Mapping[str, Any] | None,
) -> tuple[str, dict[str, Any]]:
    """Validate every checkpoint field that can affect control flow or output."""
    declared_checkpoint_identity = checkpoint.get(
        "checkpoint_content_identity"
    )
    try:
        expected_checkpoint_identity = _resume_checkpoint_content_identity(
            checkpoint
        )
    except (BinaryFirstContractError, TypeError, ValueError):
        expected_checkpoint_identity = ""
    if (
        not _is_sha256_identity(declared_checkpoint_identity)
        or declared_checkpoint_identity != expected_checkpoint_identity
    ):
        return "BINARY_RESUME_CHECKPOINT_INTEGRITY_INVALID", {}

    required_fields = {
        "schema",
        "status",
        "created_at",
        "config_identity",
        "implementation_identity",
        "input_artifact_identity",
        "source_input_identity",
        "result_generation_identity",
        "runtime_comparison_identity",
        "analysis_scope_identity",
        "analysis_context_identity",
        "base_jdk_preflight_identity",
        "current_jdk_preflight_identity",
        "result_summary",
        "source_inputs",
        "artifact_safety_policy",
        "cache_metrics",
        "phase_timings_before_validation",
        "performance_authority_gate_binding",
        "checkpoint_content_identity",
    }
    if not required_fields.issubset(checkpoint):
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}
    if not isinstance(checkpoint.get("created_at"), str) or not str(
        checkpoint.get("created_at") or ""
    ).strip():
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}
    identity_fields = (
        "config_identity",
        "implementation_identity",
        "input_artifact_identity",
        "source_input_identity",
        "result_generation_identity",
        "runtime_comparison_identity",
        "analysis_scope_identity",
        "analysis_context_identity",
        "base_jdk_preflight_identity",
        "current_jdk_preflight_identity",
    )
    if not all(
        _is_sha256_identity(checkpoint.get(field)) for field in identity_fields
    ):
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}

    status = checkpoint.get("status")
    if status not in {
        _RESUME_AWAITING_VALIDATION,
        _RESUME_VALIDATION_FAILED,
        _RESUME_VALIDATION_PASSED,
    }:
        return "BINARY_RESUME_VALIDATION_STATE_INVALID", {}
    expected_fields = set(required_fields)
    if status != _RESUME_AWAITING_VALIDATION:
        expected_fields.update({
            "validation_run_identity", "validation_result_sha256"
        })
    if status == _RESUME_VALIDATION_PASSED:
        expected_fields.add("activation_identity")
    if set(checkpoint) != expected_fields:
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}
    if status != _RESUME_AWAITING_VALIDATION and (
        not _is_sha256_identity(checkpoint.get("validation_run_identity"))
        or not _is_sha256_identity(checkpoint.get("validation_result_sha256"))
    ):
        return "BINARY_RESUME_VALIDATION_STATE_INVALID", {}
    if status == _RESUME_VALIDATION_PASSED and not _is_sha256_identity(
        checkpoint.get("activation_identity")
    ):
        return "BINARY_RESUME_VALIDATION_STATE_INVALID", {}

    policies = manifest.get("policy_identities")
    actual_jdk_identities = {}
    for side in ("base", "current"):
        observed = toolchain_preflight.get(side)
        if not isinstance(observed, Mapping):
            return "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH", {}
        actual_jdk_identities[f"{side}_jdk_preflight_identity"] = str(
            observed.get("jdk_preflight_identity") or ""
        )
    if not isinstance(policies, Mapping) or (
        checkpoint.get("analysis_context_identity")
        != manifest.get("analysis_context_identity")
        or checkpoint.get("analysis_scope_identity")
        != policies.get("analysis_scope")
        or checkpoint.get("runtime_comparison_identity")
        != policies.get("runtime_comparison")
        or any(
            checkpoint.get(field) != policies.get(field)
            for field in (
                "base_jdk_preflight_identity",
                "current_jdk_preflight_identity",
            )
        )
        or any(
            checkpoint.get(field) != identity
            for field, identity in actual_jdk_identities.items()
        )
    ):
        return "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH", {}

    result_summary = checkpoint.get("result_summary")
    if (
        not isinstance(result_summary, Mapping)
        or set(result_summary) != _RESUME_RESULT_SUMMARY_FIELDS
    ):
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}
    summary_identity_fields = (
        "base_runtime_reconciliation_identity",
        "current_runtime_reconciliation_identity",
        "decision_bundle_identity",
        "trace_bundle_identity",
    )
    if not all(
        _is_sha256_identity(result_summary.get(field))
        for field in summary_identity_fields
    ):
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}
    if not all(
        isinstance(result_summary.get(field), str)
        and bool(result_summary.get(field))
        for field in ("decision_coverage_status", "trace_coverage_status")
    ):
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}
    if not all(
        type(result_summary.get(field)) is int
        and result_summary[field] >= 0
        for field in (
            "authoritative_change_fact_count",
            "diagnostic_candidate_fact_count",
        )
    ):
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}

    checkpoint_source_inputs = checkpoint.get("source_inputs")
    checkpoint_safety_policy = checkpoint.get("artifact_safety_policy")
    checkpoint_performance_binding = checkpoint.get(
        "performance_authority_gate_binding"
    )
    performance_binding_shape_valid = (
        checkpoint_performance_binding is None
        and performance_authority_gate_binding is None
    ) or (
        _performance_authority_binding_is_valid(
            checkpoint_performance_binding
        )
        and _performance_authority_binding_is_valid(
            performance_authority_gate_binding
        )
    )
    if (
        not isinstance(checkpoint_source_inputs, Mapping)
        or not isinstance(checkpoint_safety_policy, Mapping)
        or not performance_binding_shape_valid
        or not isinstance(checkpoint.get("cache_metrics"), Mapping)
        or not isinstance(checkpoint.get("phase_timings_before_validation"), list)
    ):
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}
    try:
        source_binding_matches = _identity(
            "binary_resume_source_inputs", dict(checkpoint_source_inputs)
        ) == _identity("binary_resume_source_inputs", dict(source_inputs))
        source_content_binding_matches = (
            checkpoint.get("source_input_identity")
            == _resume_source_input_identity(config)
        )
        support = _load_support_manifest_snapshot()
        expected_safety_policy = _artifact_safety_policy(config, support)
        safety_binding_matches = _identity(
            "binary_resume_artifact_safety_policy",
            dict(checkpoint_safety_policy),
        ) == _identity(
            "binary_resume_artifact_safety_policy", expected_safety_policy
        )
        performance_binding_matches = (
            checkpoint_performance_binding
            == performance_authority_gate_binding
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        BinaryFirstContractError,
        TypeError,
        ValueError,
    ):
        return "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH", {}
    if (
        not source_binding_matches
        or not source_content_binding_matches
        or not safety_binding_matches
    ):
        return "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH", {}
    if not _restorable_prevalidation_phase_timings(checkpoint):
        return "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID", {}
    return "", {
        "result_summary": {
            key: result_summary[key]
            for key in _RESUME_RESULT_SUMMARY_FIELDS
        },
        "artifact_safety_policy": expected_safety_policy,
        "source_inputs": dict(source_inputs),
        "cache_metrics": dict(checkpoint["cache_metrics"]),
        "performance_authority_gate_binding": (
            dict(performance_authority_gate_binding)
            if performance_authority_gate_binding is not None
            else None
        ),
        "performance_authority_rebind_required": (
            performance_authority_gate_binding is not None
            and not performance_binding_matches
        ),
    }


def _canonical_json_bytes(value: Any) -> bytes:
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


def _current_oracle_support_manifest_identity() -> str:
    return oracle_support_manifest_identity()


def _current_validator_implementation_identity() -> str:
    return validator_implementation_identity()


def _failed_validation_attachment_is_bound(
    validation: Mapping[str, Any], manifest: Mapping[str, Any]
) -> bool:
    """Validate a cached failure strongly enough to reuse only as fail-closed."""
    issues = validation.get("issues")
    helper_identities = validation.get("helper_identities")
    skipped_domains = validation.get("skipped_domains")
    if (
        set(validation) != _VALIDATION_ATTACHMENT_FIELDS
        or validation.get("schema")
        != "java-upgrade-analyzer.binary-validation-result.v1"
        or validation.get("status") != "failed"
        or validation.get("result_generation_identity")
        != manifest.get("result_generation_identity")
        or type(validation.get("issue_count")) is not int
        or validation.get("issue_count", 0) <= 0
        or not isinstance(issues, list)
        or len(issues) != validation.get("issue_count")
        or not isinstance(validation.get("domain_summary"), Mapping)
        or not isinstance(skipped_domains, list)
        or not isinstance(helper_identities, Mapping)
        or not set(helper_identities).issubset({"base", "current"})
        or validation.get("validation_policy_version")
        != _VALIDATION_POLICY_VERSION
        or validation.get("production_identity_influence")
        != "none_validation_attachment_only"
    ):
        return False
    domain_counts: dict[str, dict[str, int]] = {}
    for issue in issues:
        if not isinstance(issue, Mapping):
            return False
        domain = issue.get("domain")
        if not isinstance(domain, str) or not domain:
            return False
        domain_counts.setdefault(domain, {"issues": 0})["issues"] += 1
    if dict(validation["domain_summary"]) != domain_counts:
        return False
    normalized_skipped_domains = []
    for item in skipped_domains:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"domain", "reason_code"}
            or not isinstance(item.get("domain"), str)
            or not item.get("domain")
            or not isinstance(item.get("reason_code"), str)
            or not item.get("reason_code")
        ):
            return False
        normalized_skipped_domains.append({
            "domain": item["domain"],
            "reason_code": item["reason_code"],
        })
    if (
        normalized_skipped_domains
        != sorted(
            normalized_skipped_domains,
            key=lambda item: (item["domain"], item["reason_code"]),
        )
        or len({
            (item["domain"], item["reason_code"])
            for item in normalized_skipped_domains
        }) != len(normalized_skipped_domains)
    ):
        return False
    identity_fields = (
        "validation_run_identity",
        "oracle_support_manifest_identity",
        "truth_set_identity",
        "issue_set_identity",
        "validator_implementation_identity",
    )
    if not all(
        _is_sha256_identity(validation.get(field)) for field in identity_fields
    ) or not all(
        _is_sha256_identity(value) for value in helper_identities.values()
    ):
        return False
    try:
        issue_set_identity = canonical_identity_streaming(
            "binary_validation_issue_set_identity", issues, schema_version="1"
        )
        validation_run_identity = _identity(
            "binary_validation_run_identity",
            {
                "result_generation_identity": manifest[
                    "result_generation_identity"
                ],
                "active_snapshot_identities": dict(
                    manifest["active_snapshot_identities"]
                ),
                "oracle_support_manifest_identity": validation[
                    "oracle_support_manifest_identity"
                ],
                "truth_set_identity": validation["truth_set_identity"],
                "issue_set_identity": validation["issue_set_identity"],
                "validation_policy_version": validation[
                    "validation_policy_version"
                ],
                "validator_implementation_identity": validation[
                    "validator_implementation_identity"
                ],
                "helper_identities": dict(helper_identities),
            },
        )
        expected_oracle_support_identity = (
            _current_oracle_support_manifest_identity()
        )
        expected_validator_identity = (
            _current_validator_implementation_identity()
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        BinaryFirstContractError,
        KeyError,
        TypeError,
        ValueError,
    ):
        return False
    return bool(
        validation["issue_set_identity"] == issue_set_identity
        and validation["validation_run_identity"] == validation_run_identity
        and validation["oracle_support_manifest_identity"]
        == expected_oracle_support_identity
        and validation["validator_implementation_identity"]
        == expected_validator_identity
    )


def _checkpoint_validation_attachment(
    generation: Path,
    manifest: Mapping[str, Any],
    *,
    validation_run_identity: str,
    validation_result_sha256: str,
    expected_status: str,
) -> dict[str, Any]:
    validation_dir = generation / "validation"
    path = validation_dir / f"{validation_run_identity}.json"
    try:
        validation_dir_resolved = validation_dir.resolve(strict=True)
        path_resolved = path.resolve(strict=True)
        if (
            validation_dir_resolved != validation_dir
            or path_resolved != path
            or not path.is_file()
        ):
            raise OSError("validation attachment is not a bound regular file")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != validation_result_sha256:
            raise OSError("validation attachment digest mismatch")
        validation = json.loads(content.decode("utf-8"))
    except (OSError, RuntimeError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryPipelineError(
            "BINARY_RESUME_VALIDATION_ATTACHMENT_INVALID", f"{path}: {error}"
        ) from error
    if (
        not isinstance(validation, Mapping)
        or set(validation) != _VALIDATION_ATTACHMENT_FIELDS
        or content != _canonical_json_bytes(validation)
        or validation.get("validation_run_identity")
        != validation_run_identity
        or validation.get("status") != expected_status
        or (
            expected_status == "passed"
            and not is_complete_v3_validation_result(validation, manifest)
        )
        or (
            expected_status == "failed"
            and not _failed_validation_attachment_is_bound(validation, manifest)
        )
    ):
        raise BinaryPipelineError(
            "BINARY_RESUME_VALIDATION_ATTACHMENT_INVALID", str(path)
        )
    return {**dict(validation), "validation_result_path": str(path)}


def _checkpoint_validator_attachment_is_stale(
    generation: Path,
    checkpoint: Mapping[str, Any],
    *,
    expected_status: str,
) -> bool:
    """Detect a safely discardable attachment from an older validator.

    A validator-only implementation change must not force regeneration of an
    already-bound immutable generation.  We still require the old attachment
    path, digest, canonical bytes and generation/status bindings to match the
    checkpoint before using it as a signal.  Its findings are never reused;
    current validation reconstructs truth from the generation again.
    """
    validation_identity = str(
        checkpoint.get("validation_run_identity") or ""
    )
    validation_sha256 = str(
        checkpoint.get("validation_result_sha256") or ""
    )
    if not (
        _is_sha256_identity(validation_identity)
        and _is_sha256_identity(validation_sha256)
    ):
        return False
    validation_dir = generation / "validation"
    path = validation_dir / f"{validation_identity}.json"
    try:
        validation_dir_resolved = validation_dir.resolve(strict=True)
        path_resolved = path.resolve(strict=True)
        if (
            validation_dir_resolved != validation_dir
            or path_resolved != path
            or not path.is_file()
        ):
            return False
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != validation_sha256:
            return False
        validation = json.loads(content.decode("utf-8"))
        if (
            not isinstance(validation, Mapping)
            or set(validation) != _VALIDATION_ATTACHMENT_FIELDS
            or content != _canonical_json_bytes(validation)
            or validation.get("validation_run_identity")
            != validation_identity
            or validation.get("result_generation_identity")
            != generation.name
            or validation.get("status") != expected_status
        ):
            return False
        current_validator = _current_validator_implementation_identity()
        current_oracle_support = _current_oracle_support_manifest_identity()
    except (
        OSError,
        RuntimeError,
        UnicodeError,
        json.JSONDecodeError,
        BinaryFirstContractError,
        TypeError,
        ValueError,
    ):
        return False
    declared_validator = validation.get("validator_implementation_identity")
    declared_oracle_support = validation.get(
        "oracle_support_manifest_identity"
    )
    return bool(
        _is_sha256_identity(declared_validator)
        and _is_sha256_identity(declared_oracle_support)
        and (
            declared_validator != current_validator
            or declared_oracle_support != current_oracle_support
        )
    )


def _discover_current_validation_attachment(
    generation: Path,
    manifest: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Recover validation completed just before checkpoint persistence.

    The validator atomically writes its content-addressed attachment before
    the pipeline advances the checkpoint.  A process crash in that tiny
    window must not discard hours of independent validation work.
    """
    validation_dir = generation / "validation"
    try:
        if (
            validation_dir.is_symlink()
            or not validation_dir.is_dir()
            or validation_dir.resolve(strict=True) != validation_dir
        ):
            return None
        paths = sorted(validation_dir.iterdir(), key=lambda path: path.name)
    except OSError:
        return None
    candidates = []
    for path in paths:
        match = re.fullmatch(r"([0-9a-f]{64})\.json", path.name)
        if match is None:
            continue
        try:
            resolved = path.resolve(strict=True)
            if (
                resolved != path
                or not path.is_file()
            ):
                continue
            content = path.read_bytes()
            validation = json.loads(content.decode("utf-8"))
        except (OSError, RuntimeError, UnicodeError, json.JSONDecodeError):
            continue
        if (
            not isinstance(validation, Mapping)
            or set(validation) != _VALIDATION_ATTACHMENT_FIELDS
            or content != _canonical_json_bytes(validation)
            or validation.get("validation_run_identity") != match.group(1)
            or validation.get("result_generation_identity")
            != manifest.get("result_generation_identity")
        ):
            continue
        status = validation.get("status")
        if status == "passed":
            valid = is_complete_v3_validation_result(validation, manifest)
        elif status == "failed":
            valid = (
                _failed_validation_attachment_is_bound(validation, manifest)
                and _failed_validation_attachment_is_reusable(validation)
            )
        else:
            valid = False
        if valid:
            candidates.append({
                **dict(validation),
                "validation_result_path": str(path),
            })
    if len(candidates) > 1:
        raise BinaryPipelineError(
            "BINARY_RESUME_VALIDATION_ATTACHMENT_AMBIGUOUS",
            ",".join(
                str(item["validation_run_identity"]) for item in candidates
            ),
        )
    return candidates[0] if candidates else None


def _persist_validation_checkpoint(
    output_root: Path,
    generation: Path,
    manifest: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    validation: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        checkpoint.get("schema") != RESUME_CHECKPOINT_SCHEMA
        or checkpoint.get("status") not in {
            _RESUME_AWAITING_VALIDATION,
            _RESUME_VALIDATION_FAILED,
            _RESUME_VALIDATION_PASSED,
        }
        or checkpoint.get("result_generation_identity")
        != manifest.get("result_generation_identity")
        or checkpoint.get("checkpoint_content_identity")
        != _resume_checkpoint_content_identity(checkpoint)
    ):
        raise BinaryPipelineError(
            "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
            str(_resume_checkpoint_path(output_root)),
        )
    status = str(validation.get("status") or "")
    if status not in {"passed", "failed"}:
        raise BinaryPipelineError(
            "BINARY_VALIDATION_RESULT_STATUS_INVALID", status
        )
    validation_run_identity = str(
        validation.get("validation_run_identity") or ""
    )
    declared_path = validation.get("validation_result_path")
    expected_path = generation / "validation" / (
        f"{validation_run_identity}.json"
    )
    try:
        declared_path_resolved = Path(str(declared_path)).resolve(strict=True)
    except (OSError, RuntimeError):
        declared_path_resolved = None
    if (
        not _is_sha256_identity(validation_run_identity)
        or declared_path_resolved != expected_path
    ):
        raise BinaryPipelineError(
            "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
            str(declared_path or expected_path),
        )
    expected_payload = {
        key: value for key, value in validation.items()
        if key != "validation_result_path"
    }
    try:
        validation_result_sha256 = json_file_digest_if_matches(
            expected_path,
            expected_payload,
        )
    except OSError as error:
        raise BinaryPipelineError(
            "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
            f"{expected_path}: {error}",
        ) from error
    if validation_result_sha256 is None:
        raise BinaryPipelineError(
            "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
            str(expected_path),
        )
    if (
        status == "passed"
        and not is_complete_v3_validation_result(expected_payload, manifest)
    ) or (
        status == "failed"
        and not _failed_validation_attachment_is_bound(
            expected_payload, manifest
        )
    ):
        raise BinaryPipelineError(
            "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
            str(expected_path),
        )
    updated = dict(checkpoint)
    updated.update({
        "status": (
            _RESUME_VALIDATION_PASSED
            if status == "passed"
            else _RESUME_VALIDATION_FAILED
        ),
        "validation_run_identity": validation_run_identity,
        "validation_result_sha256": validation_result_sha256,
    })
    if status == "passed":
        activation_identity = str(updated.get("activation_identity") or "")
        if not _is_sha256_identity(activation_identity):
            activation_identity = hashlib.sha256(os.urandom(32)).hexdigest()
        updated["activation_identity"] = activation_identity
    else:
        updated.pop("activation_identity", None)
    return _write_resume_checkpoint_roundtrip(
        output_root,
        updated,
        reason_code="BINARY_VALIDATION_CHECKPOINT_ROUNDTRIP_FAILED",
    )


def _quarantine_resume_generation(
    output_root: Path, generation: Path, generation_identity: str
) -> Path:
    """Atomically preserve a corrupt immutable generation before rebuilding."""
    quarantine_root = output_root / "binary_generation_quarantine"
    quarantine_root.mkdir(parents=True, exist_ok=True)
    destination = quarantine_root / (
        f"{generation_identity}.{os.getpid()}.{time.monotonic_ns()}"
    )
    os.replace(generation, destination)
    return destination


def _restorable_prevalidation_phase_timings(
    checkpoint: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Return a complete, sanitized historical phase prefix when available.

    Checkpoint timing data is never authoritative and is restored only after
    the checkpoint's config, input and generation bindings have been verified
    by the caller. Only the ordered phase name and a finite duration are
    retained so unbound metadata cannot influence or masquerade as an
    authoritative result field.
    """
    raw_timings = checkpoint.get("phase_timings_before_validation")
    validation_index = _PhaseTimingRecorder.ORDER.index(
        "independent_validation"
    )
    expected_phases = _PhaseTimingRecorder.ORDER[:validation_index]
    if not isinstance(raw_timings, list) or len(raw_timings) != len(
        expected_phases
    ):
        return []
    restored = []
    for expected_phase, raw_item in zip(expected_phases, raw_timings):
        if not isinstance(raw_item, dict):
            return []
        if str(raw_item.get("phase") or "") != expected_phase:
            return []
        elapsed = raw_item.get("elapsed_seconds")
        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
            return []
        try:
            elapsed_seconds = float(elapsed)
        except (TypeError, ValueError, OverflowError):
            return []
        if not math.isfinite(elapsed_seconds) or elapsed_seconds < 0:
            return []
        restored.append({
            "phase": expected_phase,
            "elapsed_seconds": elapsed_seconds,
            "restored_from_generation_checkpoint": True,
            "authority": "non_authoritative_checkpoint_observability",
        })
    return restored


def _record_resume_decision(
    output_root: Path, *, status: str, reason_code: str, checkpoint: Mapping[str, Any],
) -> None:
    destination = output_root / "binary_observability" / "latest_resume_decision.json"
    payload = {
        "schema": "java-upgrade-analyzer.binary-resume-decision.v1",
        "status": status,
        "reason_code": reason_code,
        "result_generation_identity": str(
            checkpoint.get("result_generation_identity") or ""
        ),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "non_authoritative_observability": True,
    }
    _write_non_authoritative_json(destination, payload)


def _validation_failure_detail(validation: Mapping[str, Any]) -> dict[str, Any]:
    """Keep failure output bounded while pointing at the complete persisted truth."""
    issues = validation.get("issues")
    if not isinstance(issues, list):
        issues = []
    try:
        issue_count = int(validation.get("issue_count", len(issues)))
    except (TypeError, ValueError):
        issue_count = len(issues)
    issue_count = max(issue_count, len(issues))
    preview_limit = 20
    preview = []
    preview_indices: set[int] = set()
    represented_groups: set[tuple[str, str]] = set()
    reason_code_counts: dict[str, int] = {}
    for index, issue in enumerate(issues):
        if isinstance(issue, Mapping):
            domain = str(issue.get("domain") or "")
            reason_code = str(issue.get("reason_code") or "")
        else:
            domain = ""
            reason_code = ""
        reason_code_counts[reason_code] = reason_code_counts.get(reason_code, 0) + 1
        group = (domain, reason_code)
        if group not in represented_groups and len(preview) < preview_limit:
            represented_groups.add(group)
            preview_indices.add(index)
            preview.append(issue)
    if len(preview) < preview_limit:
        for index, issue in enumerate(issues):
            if index in preview_indices:
                continue
            preview.append(issue)
            if len(preview) >= preview_limit:
                break
    return {
        "validation_run_identity": str(
            validation.get("validation_run_identity") or ""
        ),
        "validation_result_path": str(
            validation.get("validation_result_path") or ""
        ),
        "issue_count": issue_count,
        "domain_summary": dict(validation.get("domain_summary") or {}),
        "reason_code_counts": dict(sorted(reason_code_counts.items())),
        "issues_preview": preview,
        "issues_preview_count": len(preview),
        "issues_truncated": issue_count > len(preview),
    }


def _failed_validation_attachment_is_reusable(
    validation: Mapping[str, Any],
) -> bool:
    """Reuse only failures whose truth cannot improve on a later attempt."""
    issues = validation.get("issues")
    if (
        not isinstance(issues, list)
        or not issues
        or not all(isinstance(issue, Mapping) for issue in issues)
    ):
        return False
    reason_codes = {
        str(issue.get("reason_code") or "")
        for issue in issues
    }
    return bool(
        "" not in reason_codes
        and reason_codes.issubset(
            _REUSABLE_DETERMINISTIC_VALIDATION_FAILURES
        )
    )


def _validate_or_reuse_checkpoint_attachment(
    config: Mapping[str, Any],
    *,
    output_root: Path,
    generation: Path,
    manifest: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    phase_timings: _PhaseTimingRecorder,
    resumed: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    checkpoint_status = str(checkpoint.get("status") or "")
    reuse_status = {
        _RESUME_VALIDATION_FAILED: "failed",
        _RESUME_VALIDATION_PASSED: "passed",
    }.get(checkpoint_status)
    phase_metadata = {}
    if resumed:
        phase_metadata["resumed_from_generation_checkpoint"] = True
    attached_validation = None
    if checkpoint_status == _RESUME_AWAITING_VALIDATION:
        attached_validation = _discover_current_validation_attachment(
            generation, manifest
        )
        if attached_validation is not None:
            updated_checkpoint = _persist_validation_checkpoint(
                output_root,
                generation,
                manifest,
                checkpoint,
                attached_validation,
            )
            checkpoint = updated_checkpoint
            reuse_status = str(attached_validation["status"])
            phase_metadata[
                "recovered_orphan_validation_attachment"
            ] = True
    if reuse_status:
        if attached_validation is not None:
            phase_metadata["reused_validation_attachment"] = True
        elif _checkpoint_validator_attachment_is_stale(
            generation, checkpoint, expected_status=reuse_status
        ):
            reuse_status = None
            phase_metadata[
                "revalidated_stale_validator_attachment"
            ] = True
        else:
            attached_validation = _checkpoint_validation_attachment(
                generation,
                manifest,
                validation_run_identity=str(
                    checkpoint.get("validation_run_identity") or ""
                ),
                validation_result_sha256=str(
                    checkpoint.get("validation_result_sha256") or ""
                ),
                expected_status=reuse_status,
            )
            if (
                reuse_status == "failed"
                and not _failed_validation_attachment_is_reusable(
                    attached_validation
                )
            ):
                reuse_status = None
                phase_metadata[
                    "revalidated_non_deterministic_failure"
                ] = True
            else:
                phase_metadata["reused_validation_attachment"] = True
    phase_timings.start("independent_validation", **phase_metadata)
    validation_started = time.perf_counter()
    if reuse_status:
        validation = attached_validation
        updated_checkpoint = dict(checkpoint)
    else:
        validation = validate_generation(config, generation)
        updated_checkpoint = _persist_validation_checkpoint(
            output_root,
            generation,
            manifest,
            checkpoint,
            validation,
        )
    validation_timing = {
        "phase": "independent_validation",
        "elapsed_seconds": round(time.perf_counter() - validation_started, 6),
        "issue_count": int(validation.get("issue_count") or 0),
        **phase_metadata,
    }
    if validation["status"] != "passed":
        phase_timings.fail(validation_timing)
        raise BinaryPipelineError(
            "BINARY_INDEPENDENT_VALIDATION_FAILED",
            json.dumps(
                _validation_failure_detail(validation),
                ensure_ascii=False,
                sort_keys=True,
            ),
        )
    phase_timings.append(validation_timing)
    return dict(validation), updated_checkpoint


def _resume_generation_validation(
    config: Mapping[str, Any],
    *,
    output_root: Path,
    source_inputs: Mapping[str, Any],
    toolchain_preflight: Mapping[str, Any],
    asm_jar: str | Path,
    phase_timings: _PhaseTimingRecorder,
    pipeline_started: float,
    retain_checkpoint: bool = False,
    generation_implementation_identity: str = "",
    performance_authority_gate_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    checkpoint = _read_resume_checkpoint(output_root)
    if not checkpoint:
        return None
    expected_config_identity = _resume_config_identity(config)
    checks = [
        (
            checkpoint.get("schema") == RESUME_CHECKPOINT_SCHEMA,
            "BINARY_RESUME_CHECKPOINT_SCHEMA_MISMATCH",
        ),
        (
            checkpoint.get("config_identity") == expected_config_identity,
            "BINARY_RESUME_CONFIG_CHANGED",
        ),
    ]
    if performance_authority_gate_binding is not None:
        resume_implementation_identity = (
            generation_implementation_identity
            or _resume_implementation_identity(asm_jar)
        )
        checks.append((
            checkpoint.get("implementation_identity")
            == resume_implementation_identity,
            "BINARY_RESUME_IMPLEMENTATION_CHANGED",
        ))
    for accepted, reason_code in checks:
        if not accepted:
            _record_resume_decision(
                output_root,
                status="rejected",
                reason_code=reason_code,
                checkpoint=checkpoint,
            )
            return None
    try:
        current_input_identity = _resume_input_artifact_identity(config)
    except BinaryFirstContractError:
        _record_resume_decision(
            output_root,
            status="rejected",
            reason_code="BINARY_RESUME_INPUT_ARTIFACT_UNAVAILABLE",
            checkpoint=checkpoint,
        )
        return None
    if checkpoint.get("input_artifact_identity") != current_input_identity:
        _record_resume_decision(
            output_root,
            status="rejected",
            reason_code="BINARY_RESUME_INPUT_ARTIFACT_CHANGED",
            checkpoint=checkpoint,
        )
        return None
    generation_identity = str(
        checkpoint.get("result_generation_identity") or ""
    )
    if not re.fullmatch(r"[0-9a-f]{64}", generation_identity):
        _record_resume_decision(
            output_root,
            status="rejected",
            reason_code="BINARY_RESUME_GENERATION_IDENTITY_INVALID",
            checkpoint=checkpoint,
        )
        return None
    generation = (
        output_root / "binary_generations" / generation_identity
    ).resolve()
    expected_generation = (
        output_root.resolve() / "binary_generations" / generation_identity
    )
    manifest_path = generation / "result_generation.json"
    if (
        generation != expected_generation
        or not generation.is_dir()
    ):
        _record_resume_decision(
            output_root,
            status="rejected",
            reason_code="BINARY_RESUME_GENERATION_MISSING",
            checkpoint=checkpoint,
        )
        return None

    def reject_corrupt_generation(reason_code: str) -> None:
        try:
            _quarantine_resume_generation(
                output_root, generation, generation_identity
            )
        except OSError as error:
            raise BinaryPipelineError(
                "BINARY_RESUME_GENERATION_QUARANTINE_FAILED",
                f"{generation}: {error}",
            ) from error
        _record_resume_decision(
            output_root,
            status="rejected",
            reason_code=reason_code,
            checkpoint=checkpoint,
        )

    if manifest_path.is_symlink() or not manifest_path.is_file():
        reject_corrupt_generation("BINARY_RESUME_GENERATION_MANIFEST_INVALID")
        return None
    manifest = _read_optional_json_object(manifest_path)
    if not manifest:
        reject_corrupt_generation("BINARY_RESUME_GENERATION_MANIFEST_INVALID")
        return None
    if manifest.get("result_generation_identity") != generation_identity:
        reject_corrupt_generation("BINARY_RESUME_GENERATION_IDENTITY_MISMATCH")
        return None
    if not _resume_generation_integrity_valid(generation, manifest):
        reject_corrupt_generation("BINARY_RESUME_GENERATION_INTEGRITY_INVALID")
        return None
    metadata_reason, resume_metadata = _resume_checkpoint_metadata(
        checkpoint,
        manifest,
        config,
        source_inputs,
        toolchain_preflight,
        performance_authority_gate_binding,
    )
    if metadata_reason:
        _record_resume_decision(
            output_root,
            status="rejected",
            reason_code=metadata_reason,
            checkpoint=checkpoint,
        )
        return None
    if resume_metadata.pop("performance_authority_rebind_required", False):
        checkpoint = _rebind_resume_checkpoint_performance_authority(
            output_root,
            checkpoint,
            performance_authority_gate_binding,
        )
    restored_timings = _restorable_prevalidation_phase_timings(checkpoint)
    phase_timings[:] = restored_timings
    _record_resume_decision(
        output_root,
        status="accepted",
        reason_code=(
            "BINARY_RESUME_VALIDATION_ATTACHMENT"
            if checkpoint.get("status") != _RESUME_AWAITING_VALIDATION
            else "BINARY_RESUME_VALIDATION_ONLY"
        ),
        checkpoint=checkpoint,
    )
    validation, checkpoint = _validate_or_reuse_checkpoint_attachment(
        config,
        output_root=output_root,
        generation=generation,
        manifest=manifest,
        checkpoint=checkpoint,
        phase_timings=phase_timings,
        resumed=True,
    )
    if (
        performance_authority_gate_binding is not None
        and checkpoint.get("implementation_identity")
        != _resume_implementation_identity(asm_jar)
    ):
        # This source fingerprint is release-measurement evidence only.  Normal
        # Step4 runs do not hash implementation files or fail on their metadata.
        raise BinaryPipelineError(
            "BINARY_PIPELINE_IMPLEMENTATION_CHANGED_DURING_RUN",
            "generation implementation changed during resumed validation",
        )
    manifest["generation_directory"] = str(generation)
    activation_started = time.perf_counter()
    activation_record: dict[str, Any] = {}
    manifest["active_generation_descriptor"] = (
        _activate_validated_generation_with_authority_binding(
            output_root,
            manifest,
            validation,
            activation_identity=str(
                checkpoint.get("activation_identity") or ""
            ),
            activation_record=activation_record,
            defer_publication=retain_checkpoint,
            performance_authority_gate_binding=(
                performance_authority_gate_binding
            ),
        )
    )
    # Keep the durable resume checkpoint until the activation transition and
    # authoritative result assembly have completed. Resource measurements are
    # best-effort and cannot affect this lifecycle.
    pre_finalize_peak_rss_bytes = _peak_rss_bytes()
    candidate_discarded = _discard_measurement_candidate_activation(
        output_root,
        manifest,
        activation_record,
        performance_authority_gate_binding,
    )
    if candidate_discarded:
        manifest["active_generation_descriptor"] = ""
    if not retain_checkpoint:
        if _seal_and_finalize_measured_activation(
            output_root,
            manifest,
            validation,
            activation_record,
            performance_authority_gate_binding,
        ):
            manifest["active_generation_descriptor"] = ""
        _cleanup_consumed_resume_checkpoint(
            output_root, performance_authority_gate_binding
        )
    checkpoint_receipt = _validation_checkpoint_result_receipt(
        output_root,
        manifest,
        activation_record,
        performance_authority_gate_binding,
        retain_requested=retain_checkpoint,
        candidate_discarded=candidate_discarded,
    )
    # Activation includes candidate/recapture discard, publication sealing and
    # durable checkpoint cleanup.  Preserve the earlier peak while also
    # sampling after those lifecycle operations have completed.
    peak_rss_bytes = max(pre_finalize_peak_rss_bytes, _peak_rss_bytes())
    phase_timings.append({
        "phase": "validated_generation_activation",
        "elapsed_seconds": round(time.perf_counter() - activation_started, 6),
        "resumed_from_generation_checkpoint": True,
        "publication_deferred": bool(checkpoint_receipt),
        "checkpoint_retained": bool(checkpoint_receipt),
        "activation_candidate_discarded": bool(candidate_discarded),
        "activation_authority_mode": (
            performance_authority_gate_binding.get("authority_mode")
            if performance_authority_gate_binding is not None
            else "analysis_result"
        ),
    })
    observability = output_root / "binary_observability"
    cache_metrics = dict(resume_metadata["cache_metrics"])
    cache_metrics["resumed_generation_checkpoint_count"] = 1
    cache_metrics_path = observability / "latest_cache_metrics.json"
    cache_metrics_persisted = _write_non_authoritative_json(
        cache_metrics_path,
        {
            **cache_metrics,
            "schema": "java-upgrade-analyzer.binary-cache-metrics.v1",
            "result_generation_identity": generation_identity,
        },
    )
    total_elapsed_seconds = round(time.perf_counter() - pipeline_started, 6)
    phase_timings_path = observability / "latest_phase_timings.json"
    phase_timings_persisted = _write_non_authoritative_json(
        phase_timings_path,
        {
            "schema": "java-upgrade-analyzer.binary-phase-timings.v1",
            "result_generation_identity": generation_identity,
            "total_elapsed_seconds": total_elapsed_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "peak_rss_scope": "current_process",
            "total_elapsed_scope": "current_pipeline_attempt",
            "phase_timings_scope": (
                "restored_prevalidation_history_plus_current_attempt"
            ),
            "phases": list(phase_timings),
            "resumed_from_generation_checkpoint": True,
            "non_authoritative_observability": True,
        },
    )
    result = {
        **manifest,
        "schema": "java-upgrade-analyzer.binary-pipeline-result.v1",
        "runtime_comparison_identity": manifest["policy_identities"][
            "runtime_comparison"
        ],
        "analysis_scope_identity": manifest["policy_identities"][
            "analysis_scope"
        ],
        "analysis_context_identity": manifest["analysis_context_identity"],
        **resume_metadata["result_summary"],
        "source_inputs": resume_metadata["source_inputs"],
        "artifact_safety_policy": resume_metadata[
            "artifact_safety_policy"
        ],
        "validation_run_identity": validation["validation_run_identity"],
        "validation_status": validation["status"],
        "validation_result_path": validation["validation_result_path"],
        "definition_verification_path": str(
            generation / "binary_definition_verification.json"
        ),
        "cache_metrics": cache_metrics,
        "cache_metrics_path": str(cache_metrics_path),
        "cache_metrics_persisted": cache_metrics_persisted,
        "phase_timings": list(phase_timings),
        "phase_timings_path": str(phase_timings_path),
        "phase_timings_persisted": phase_timings_persisted,
        "total_elapsed_seconds": total_elapsed_seconds,
        "peak_rss_bytes": peak_rss_bytes,
        "peak_rss_scope": "current_process",
        "total_elapsed_scope": "current_pipeline_attempt",
        "phase_timings_scope": (
            "restored_prevalidation_history_plus_current_attempt"
        ),
        "resumed_from_generation_checkpoint": True,
        "performance_authority_gate_binding": (
            dict(performance_authority_gate_binding)
            if performance_authority_gate_binding is not None
            else None
        ),
        **activation_record,
        **checkpoint_receipt,
    }
    return result


@dataclass(frozen=True)
class _ArtifactDigestRecord:
    content_sha256: str
    byte_length: int
    file_identity: tuple[int, int, int, int]


class _ArtifactDigestSession:
    """Reuse hashes only while a file's stable OS identity is unchanged.

    Runtime materialization can expose hundreds of nested artifacts backed by
    one executable Spring Boot JAR.  Hashing that outer container once per
    nested entry adds no evidence: every call observes the same path.  This
    session hashes each unique file once, checks its stat identity on every
    reuse, and performs a second full hash for outer containers after all
    ArtifactInstances have been constructed.  A changed file therefore fails
    closed while the common case performs two reads per outer JAR, not one read
    per nested dependency.
    """

    def __init__(self):
        self._records: dict[Path, _ArtifactDigestRecord] = {}
        self._revalidate: set[Path] = set()
        self.hash_request_count = 0
        self.hash_execution_count = 0
        self.hash_reuse_count = 0
        self.hash_bytes = 0
        self.final_verification_hash_count = 0
        self.hash_worker_count = 0
        self.parallel_hash_file_count = 0

    @staticmethod
    def _file_identity(stat_result) -> tuple[int, int, int, int]:
        return (
            int(stat_result.st_dev),
            int(stat_result.st_ino),
            int(stat_result.st_size),
            int(getattr(stat_result, "st_mtime_ns", stat_result.st_mtime * 1e9)),
        )

    @staticmethod
    def _expected_sha256(value: Any, *, path: Path) -> str:
        expected = str(value or "").strip().lower()
        if expected and (
            len(expected) != 64
            or any(character not in "0123456789abcdef" for character in expected)
        ):
            raise BinaryPipelineError(
                "BINARY_PIPELINE_ARTIFACT_SHA256_INVALID",
                f"{path}: {expected}",
            )
        return expected

    @classmethod
    def _hash_stable_record(cls, path: Path) -> _ArtifactDigestRecord:
        try:
            before = path.stat()
            if not path.is_file():
                raise OSError("not a regular file")
            content_sha256 = _sha256_file(path)
            after = path.stat()
        except OSError as error:
            raise BinaryPipelineError(
                "BINARY_PIPELINE_ARTIFACT_MISSING", f"{path}: {error}"
            ) from error
        before_identity = cls._file_identity(before)
        after_identity = cls._file_identity(after)
        if before_identity != after_identity:
            raise BinaryPipelineError(
                "BINARY_PIPELINE_ARTIFACT_CHANGED_DURING_HASH", str(path)
            )
        return _ArtifactDigestRecord(
            content_sha256=content_sha256,
            byte_length=int(after.st_size),
            file_identity=after_identity,
        )

    def _record_hash_execution(
        self, record: _ArtifactDigestRecord
    ) -> _ArtifactDigestRecord:
        self.hash_execution_count += 1
        self.hash_bytes += record.byte_length
        return record

    def _hash_stable(self, path: Path) -> _ArtifactDigestRecord:
        return self._record_hash_execution(self._hash_stable_record(path))

    def prime(
        self,
        requests: Iterable[tuple[str | Path, Any]],
        *,
        configured_workers: Any = None,
    ) -> None:
        """Hash independent files concurrently, then publish results in order.

        Every ordinary ``digest`` call still performs its stable stat check and
        validates its declared SHA-256.  Priming only moves the unavoidable
        full-file reads ahead of those calls and overlaps them; it does not
        allow a timestamp, size, cache entry, or caller-supplied digest to stand
        in for observed content bytes.
        """
        expected_by_path: dict[Path, list[str]] = {}
        for raw_path, raw_expected in requests:
            path = Path(raw_path).expanduser().resolve()
            expected = self._expected_sha256(raw_expected, path=path)
            expected_by_path.setdefault(path, []).append(expected)
        paths = sorted(expected_by_path, key=str)
        workers = _artifact_hash_worker_count(configured_workers, len(paths))
        self.hash_worker_count = max(self.hash_worker_count, workers)
        if not paths:
            return

        if workers == 1:
            observed = [(path, self._hash_stable_record(path)) for path in paths]
        else:
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="binary-artifact-digest",
            ) as executor:
                futures = {
                    path: executor.submit(self._hash_stable_record, path)
                    for path in paths
                }
                # Resolve futures in canonical path order. This keeps failure
                # selection deterministic even though the reads run in parallel.
                observed = [(path, futures[path].result()) for path in paths]
            self.parallel_hash_file_count += len(paths)

        for path, record in observed:
            previous = self._records.get(path)
            if previous is not None and (
                previous.content_sha256 != record.content_sha256
            ):
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_ARTIFACT_CHANGED_DURING_PROFILE",
                    str(path),
                )
            self._records[path] = self._record_hash_execution(record)
            for expected in expected_by_path[path]:
                if expected and record.content_sha256 != expected:
                    raise BinaryPipelineError(
                        "BINARY_PIPELINE_ARTIFACT_SHA256_MISMATCH",
                        (
                            f"{path}: expected={expected}; "
                            f"actual={record.content_sha256}"
                        ),
                    )

    def digest(
        self,
        path: str | Path,
        *,
        expected_sha256: Any = "",
        revalidate_at_end: bool = False,
    ) -> _ArtifactDigestRecord:
        resolved = Path(path).expanduser().resolve()
        expected = self._expected_sha256(expected_sha256, path=resolved)
        self.hash_request_count += 1
        try:
            current_identity = self._file_identity(resolved.stat())
        except OSError as error:
            raise BinaryPipelineError(
                "BINARY_PIPELINE_ARTIFACT_MISSING", f"{resolved}: {error}"
            ) from error
        record = self._records.get(resolved)
        if record is not None and record.file_identity == current_identity:
            self.hash_reuse_count += 1
        else:
            observed = self._hash_stable(resolved)
            if record is not None and (
                record.content_sha256 != observed.content_sha256
            ):
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_ARTIFACT_CHANGED_DURING_PROFILE",
                    str(resolved),
                )
            record = observed
            self._records[resolved] = record
        if expected and record.content_sha256 != expected:
            raise BinaryPipelineError(
                "BINARY_PIPELINE_ARTIFACT_SHA256_MISMATCH",
                f"{resolved}: expected={expected}; actual={record.content_sha256}",
            )
        if revalidate_at_end:
            self._revalidate.add(resolved)
        return record

    def revalidate_marked(self) -> None:
        for path in sorted(self._revalidate, key=str):
            expected = self._records[path]
            observed = self._hash_stable(path)
            self.final_verification_hash_count += 1
            if observed.content_sha256 != expected.content_sha256:
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_OUTER_ARTIFACT_CHANGED_DURING_PROFILE",
                    str(path),
                )
            self._records[path] = observed

    def metrics(self) -> dict[str, int]:
        return {
            "artifact_hash_request_count": self.hash_request_count,
            "artifact_hash_execution_count": self.hash_execution_count,
            "artifact_hash_reuse_count": self.hash_reuse_count,
            "artifact_hash_bytes": self.hash_bytes,
            "outer_artifact_unique_count": len(self._revalidate),
            "outer_artifact_final_verification_hash_count": (
                self.final_verification_hash_count
            ),
            "artifact_hash_workers": self.hash_worker_count,
            "artifact_parallel_hash_file_count": self.parallel_hash_file_count,
        }


@dataclass(frozen=True)
class _ResourceUsageSnapshot:
    self_user_seconds: float
    self_system_seconds: float
    child_user_seconds: float
    child_system_seconds: float
    self_peak_rss_bytes: int
    completed_child_peak_rss_bytes: int


def _rss_bytes_from_rusage(value: int | float) -> int:
    raw = int(value or 0)
    return raw if sys.platform == "darwin" else raw * 1024


def _resource_usage_snapshot() -> _ResourceUsageSnapshot | None:
    if resource is None:
        try:
            windows_usage = windows_current_process_usage()
        except OSError:
            return None
        if windows_usage is None:
            return None
        return _ResourceUsageSnapshot(
            self_user_seconds=windows_usage.user_seconds,
            self_system_seconds=windows_usage.system_seconds,
            child_user_seconds=0.0,
            child_system_seconds=0.0,
            self_peak_rss_bytes=windows_usage.peak_rss_bytes,
            completed_child_peak_rss_bytes=0,
        )
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return _ResourceUsageSnapshot(
        self_user_seconds=float(own.ru_utime or 0.0),
        self_system_seconds=float(own.ru_stime or 0.0),
        child_user_seconds=float(children.ru_utime or 0.0),
        child_system_seconds=float(children.ru_stime or 0.0),
        self_peak_rss_bytes=_rss_bytes_from_rusage(own.ru_maxrss),
        completed_child_peak_rss_bytes=_rss_bytes_from_rusage(children.ru_maxrss),
    )


def _non_authoritative_resource_usage_snapshot() -> (
    _ResourceUsageSnapshot | None
):
    """Return metrics when available; observability must never block analysis."""

    try:
        return _resource_usage_snapshot()
    except Exception:
        return None


def _peak_rss_bytes() -> int:
    """Return this analyzer process' peak resident set size."""
    usage = _non_authoritative_resource_usage_snapshot()
    if usage is None:
        return 0
    return usage.self_peak_rss_bytes


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
    raw_source_inputs = config.get("source_inputs")
    if raw_source_inputs is not None and not isinstance(
        raw_source_inputs, Mapping
    ):
        raise BinaryPipelineError(
            "BINARY_SOURCE_INPUTS_INVALID", "source_inputs must be an object"
        )
    raw = dict(raw_source_inputs or {})
    declared_purpose_version = str(raw.get("purpose_version") or "").strip()
    if (
        declared_purpose_version
        and declared_purpose_version != SOURCE_INPUT_PURPOSE_VERSION
    ):
        raise BinaryPipelineError(
            "BINARY_SOURCE_INPUT_PURPOSE_VERSION_MISMATCH",
            f"expected={SOURCE_INPUT_PURPOSE_VERSION}; "
            f"actual={declared_purpose_version}",
        )
    for field in ("business", "dependencies"):
        value = raw.get(field)
        if value is not None and not isinstance(value, Mapping):
            raise BinaryPipelineError(
                "BINARY_SOURCE_INPUTS_INVALID",
                f"source_inputs.{field} must be an object",
            )
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


def _load_support_manifest_snapshot() -> dict[str, Any]:
    """Read the release support manifest exactly once into private bytes."""
    try:
        content = SUPPORT_MANIFEST_PATH.read_bytes()
        value = _strict_json_object_from_bytes(content)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_AUTHORITY_MANIFEST_INVALID", str(error)
        ) from error
    return value


def _performance_authority_gate_binding(
    support: Mapping[str, Any],
    *,
    generation_source_records: Iterable[Mapping[str, str]] | None = None,
    asm_jar: str | Path | None = None,
    reuse_verified_generation_records_for_runtime: bool = False,
) -> dict[str, str]:
    """Capture one mutually-consistent support/evidence byte snapshot.

    The support contract names the exact SHA-256 of the evidence file.  The
    evidence is parsed from the same private bytes that are hashed, so a
    replacement between a JSON read and a later digest read cannot be
    accepted.  Reading the two files cannot be filesystem-atomic, but any
    crossed pair fails the content binding unless it is itself the declared,
    valid pair.
    """
    if type(reuse_verified_generation_records_for_runtime) is not bool:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_AUTHORITY_BINDING_INVALID",
            "runtime source-record reuse must be an exact boolean",
        )
    raw_performance_contract = support.get("performance_gate")
    if not isinstance(raw_performance_contract, Mapping):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_AUTHORITY_GATE_BLOCKED",
            "performance_gate support contract is missing",
        )
    performance_contract = dict(raw_performance_contract)
    try:
        evidence_content = PERFORMANCE_GATE_PATH.read_bytes()
        evidence = _strict_json_object_from_bytes(evidence_content)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_GATE_UNAVAILABLE", str(error)
        ) from error
    evidence_sha256 = hashlib.sha256(evidence_content).hexdigest()
    expected_relative_path = PERFORMANCE_GATE_CONTRACT_PATH
    recorded = evidence.get("recorded_measurements")
    invariants = evidence.get("accuracy_invariants")
    protocol = evidence.get("measurement_protocol")
    implementation = (
        protocol.get("implementation")
        if isinstance(protocol, Mapping)
        else None
    )
    bootstrap_marker_present = "measurement_bootstrap" in evidence
    bootstrap_marker = evidence.get("measurement_bootstrap")
    provisional_marker_present = "measurement_provisional" in evidence
    provisional_marker = evidence.get("measurement_provisional")
    try:
        source_records = (
            [dict(item) for item in generation_source_records]
            if generation_source_records is not None
            else _verify_captured_generation_sources()
        )
        current_implementation = {
            "generation_source_identity": (
                performance_generation_source_identity(source_records)
            ),
            "validator_source_identity": validator_source_identity(),
            "oracle_support_manifest_identity": (
                oracle_support_manifest_identity()
            ),
            "harness_source_identity": performance_harness_source_identity(
                Path(__file__).resolve().parent
            ),
        }
        current_implementation["source_implementation_identity"] = (
            performance_source_implementation_identity(
                current_implementation
            )
        )
    except (OSError, BinaryFirstContractError, TypeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_IMPLEMENTATION_IDENTITY_UNAVAILABLE",
            str(error),
        ) from error
    source_identity_fields = (
        "generation_source_identity",
        "validator_source_identity",
        "oracle_support_manifest_identity",
        "harness_source_identity",
        "source_implementation_identity",
    )
    implementation_matches = (
        isinstance(implementation, Mapping)
        and all(
            _is_sha256_identity(implementation.get(field))
            and implementation.get(field) == current_implementation[field]
            for field in source_identity_fields
        )
        and isinstance(protocol, Mapping)
        and protocol.get("source_implementation_identity")
        == current_implementation["source_implementation_identity"]
        and performance_contract.get("source_implementation_identity")
        == current_implementation["source_implementation_identity"]
    )
    if (
        performance_contract.get("status") != "passed"
        or performance_contract.get("blocks_binary_authority_switch") is not False
        or performance_contract.get("path") != expected_relative_path
        or performance_contract.get("sha256") != evidence_sha256
        or type(performance_contract.get("warm_parser_invocations")) is not int
        or performance_contract.get("warm_parser_invocations") != 0
        or evidence.get("schema")
        != "java-upgrade-analyzer.binary-first-performance-gate.v1"
        or evidence.get("status") != "passed"
        or evidence.get("blocks_binary_authority_switch") is not False
        or not isinstance(recorded, Mapping)
        or type(recorded.get("warm_parser_invocations")) is not int
        or recorded.get("warm_parser_invocations") != 0
        or not isinstance(invariants, Mapping)
        or type(invariants.get("warm_parser_invocations")) is not int
        or invariants.get("warm_parser_invocations") != 0
    ):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_AUTHORITY_GATE_BLOCKED",
            str(PERFORMANCE_GATE_PATH),
        )
    if not implementation_matches:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
            json.dumps(
                {
                    "expected": current_implementation,
                    "recorded": (
                        dict(implementation)
                        if isinstance(implementation, Mapping)
                        else {"actual_type": type(implementation).__name__}
                    ),
                    "protocol_source_implementation_identity": (
                        protocol.get("source_implementation_identity")
                        if isinstance(protocol, Mapping)
                        else None
                    ),
                    "support_source_implementation_identity": (
                        performance_contract.get(
                            "source_implementation_identity"
                        )
                    ),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
        )
    bootstrap_enabled = (
        _PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.get()
        is _PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY
    )
    expected_bootstrap_marker = {
        "mode": "candidate_source_measurement",
        "source_implementation_identity": current_implementation[
            "source_implementation_identity"
        ],
        "not_release_evidence": True,
    }
    if bootstrap_marker_present and provisional_marker_present:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_MEASUREMENT_BOOTSTRAP_FORBIDDEN",
            "candidate and provisional markers are mutually exclusive",
        )
    if bootstrap_marker_present:
        if (
            not bootstrap_enabled
            or not isinstance(bootstrap_marker, Mapping)
            or set(bootstrap_marker) != set(expected_bootstrap_marker)
            or bootstrap_marker.get("mode")
            != expected_bootstrap_marker["mode"]
            or bootstrap_marker.get("source_implementation_identity")
            != expected_bootstrap_marker[
                "source_implementation_identity"
            ]
            or bootstrap_marker.get("not_release_evidence") is not True
        ):
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_MEASUREMENT_BOOTSTRAP_FORBIDDEN",
                "persisted candidate measurement evidence cannot authorize production",
            )
    elif provisional_marker_present:
        recapture_enabled = (
            _PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.get()
            is _PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
        )
        if not recapture_enabled or not isinstance(
            provisional_marker, Mapping
        ):
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_PROVISIONAL_RECAPTURE_FORBIDDEN",
                "provisional evidence is benchmark-only",
            )
        try:
            from binary_performance_gate import (
                _performance_implementation_protocol,
                evaluate_provisional_gate,
            )

            live_runtime_implementation = (
                _performance_implementation_protocol(
                    resolve_asm_jar(asm_jar),
                    _verified_generation_source_records=(
                        source_records
                        if reuse_verified_generation_records_for_runtime
                        else None
                    ),
                )
            )
            snapshot_mismatches = {
                field: {
                    "pipeline_source_snapshot": current_implementation.get(
                        field
                    ),
                    "independent_runtime_snapshot": (
                        live_runtime_implementation.get(field)
                    ),
                }
                for field in source_identity_fields
                if live_runtime_implementation.get(field)
                != current_implementation.get(field)
            }
            if snapshot_mismatches:
                raise BinaryPipelineError(
                    "BINARY_PERFORMANCE_IMPLEMENTATION_IDENTITY_UNAVAILABLE",
                    json.dumps(
                        {
                            "detail": (
                                "independent source and runtime implementation "
                                "snapshots differ"
                            ),
                            "mismatches": snapshot_mismatches,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                )

            recorded_verification = evaluate_provisional_gate(
                evidence,
                _current_source_implementation=live_runtime_implementation,
            )
        except BinaryPipelineError:
            raise
        except Exception as error:
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_PROVISIONAL_VERIFICATION_UNAVAILABLE",
                f"{type(error).__name__}: {error}",
            ) from error
        if recorded_verification.get("status") != "passed":
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID",
                json.dumps(
                    recorded_verification.get("issues") or (),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
    else:
        try:
            from binary_performance_gate import evaluate_recorded_gate

            recorded_verification = evaluate_recorded_gate(
                evidence,
                _current_source_implementation=current_implementation,
            )
        except Exception as error:
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_RECORDED_VERIFICATION_UNAVAILABLE",
                f"{type(error).__name__}: {error}",
            ) from error
        if recorded_verification.get("status") != "passed":
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_RECORDED_EVIDENCE_INVALID",
                json.dumps(
                    recorded_verification.get("issues") or (),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
    authority_mode = (
        _PERFORMANCE_CANDIDATE_AUTHORITY_MODE
        if bootstrap_marker_present
        else _PERFORMANCE_RECAPTURE_AUTHORITY_MODE
        if provisional_marker_present
        else _PERFORMANCE_RELEASE_AUTHORITY_MODE
    )
    contract_identity = _identity(
        "binary_performance_authority_support_contract_identity",
        dict(performance_contract),
    )
    return {
        "schema": "java-upgrade-analyzer.performance-authority-binding.v2",
        "authority_mode": authority_mode,
        "support_contract_identity": contract_identity,
        "evidence_sha256": evidence_sha256,
        "source_implementation_identity": current_implementation[
            "source_implementation_identity"
        ],
        "binding_identity": _identity(
            "binary_performance_authority_binding_identity",
            {
                "support_contract_identity": contract_identity,
                "evidence_sha256": evidence_sha256,
                "source_implementation_identity": current_implementation[
                    "source_implementation_identity"
                ],
                "authority_mode": authority_mode,
            },
        ),
    }


def _verify_performance_authority_gate_binding(
    captured: Mapping[str, Any],
) -> dict[str, str]:
    """Fail closed if performance authority changed before activation."""
    try:
        current_support = _load_support_manifest_snapshot()
        current = _performance_authority_gate_binding(
            current_support,
            reuse_verified_generation_records_for_runtime=True,
        )
    except BinaryFirstContractError as error:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_AUTHORITY_GATE_CHANGED_DURING_RUN",
            f"{error.reason_code}: {error}",
        ) from error
    if dict(captured) != current:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_AUTHORITY_GATE_CHANGED_DURING_RUN",
            json.dumps(
                {"captured": dict(captured), "current": current},
                sort_keys=True,
            ),
        )
    return current


def _activation_publication_guard_value(
    output_root: str | Path,
    manifest: Mapping[str, Any],
    validation: Mapping[str, Any],
    *,
    activation_identity: str,
    captured_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the captured binding in the shape the output guard expects.

    ``binary_output._run_publication_guard`` independently re-derives the
    current performance authority after this callback returns.  Repeating the
    same source/evidence hashing here would not add an independent trust
    boundary; it only multiplies the cost of both direct activation and seal.
    The callback therefore constructs the exact binding/receipt while the
    output layer remains the single live verifier at the descriptor commit.
    """

    if not _performance_authority_binding_is_valid(captured_binding):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_AUTHORITY_BINDING_INVALID",
            "publication guard requires a valid captured binding",
        )
    current = dict(captured_binding)
    if current.get("authority_mode") != _PERFORMANCE_RELEASE_AUTHORITY_MODE:
        return dict(current)
    generation_identity = str(
        manifest.get("result_generation_identity") or ""
    )
    validation_identity = str(validation.get("validation_run_identity") or "")
    expected_validation = {
        key: value
        for key, value in validation.items()
        if key != "validation_result_path"
    }
    validation_sha256 = hashlib.sha256(
        _canonical_json_bytes(expected_validation)
    ).hexdigest()
    generation_binding = (
        read_binary_generation_publication_authority_binding(
            output_root, generation_identity
        )
    )
    if generation_binding == dict(current):
        return dict(current)
    return binary_publication_reauthorization_receipt(
        generation_performance_authority_binding=generation_binding,
        current_performance_authority_binding=current,
        result_generation_identity=generation_identity,
        validation_run_identity=validation_identity,
        validation_result_sha256=validation_sha256,
        activation_identity=activation_identity,
    )


def _activate_validated_generation_with_authority_binding(
    output_root: Path,
    manifest: Mapping[str, Any],
    validation: Mapping[str, Any],
    *,
    activation_identity: str,
    activation_record: dict[str, Any],
    defer_publication: bool,
    performance_authority_gate_binding: Mapping[str, Any] | None,
) -> str:
    """Activate a validated result; performance bindings are benchmark-only."""
    if performance_authority_gate_binding is None:
        return activate_binary_generation(
            output_root,
            manifest,
            validation_result=validation,
            activation_identity=activation_identity,
            activation_record=activation_record,
            defer_publication=defer_publication,
        )
    if not _performance_authority_binding_is_valid(
        performance_authority_gate_binding
    ):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_AUTHORITY_BINDING_INVALID",
            "activation requires a valid performance authority binding",
        )
    candidate_measurement = (
        performance_authority_gate_binding.get("authority_mode")
        == _PERFORMANCE_CANDIDATE_AUTHORITY_MODE
    )
    recapture_measurement = (
        performance_authority_gate_binding.get("authority_mode")
        == _PERFORMANCE_RECAPTURE_AUTHORITY_MODE
    )
    if candidate_measurement and not defer_publication:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_FORBIDDEN",
            "candidate measurement authority cannot publish an active generation",
        )
    if recapture_measurement and defer_publication:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
            "release recapture must exercise direct activation and sealing",
        )
    if recapture_measurement and (
        _PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.get()
        is not _PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
        or _PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.get()
        != Path(output_root).resolve()
    ):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
            "release recapture is restricted to its private benchmark root",
        )
    if candidate_measurement:
        # Exercise the same generation/validation integrity and durability
        # boundary without ever entering the public descriptor protocol.  The
        # immutable publication-authority sidecar also makes later raw direct
        # or deferred activation of this candidate fail at binary_output.
        return activate_binary_generation(
            output_root,
            manifest,
            validation_result=validation,
            activation_identity=activation_identity,
            activation_record=activation_record,
            defer_publication=True,
            publication_guard=lambda: (
                _activation_publication_guard_value(
                    output_root,
                    manifest,
                    validation,
                    activation_identity=activation_identity,
                    captured_binding=performance_authority_gate_binding,
                )
            ),
            publication_dry_run=True,
        )
    if recapture_measurement:
        with _release_recapture_publication(output_root):
            return activate_binary_generation(
                output_root,
                manifest,
                validation_result=validation,
                activation_identity=activation_identity,
                activation_record=activation_record,
                defer_publication=False,
                publication_guard=lambda: (
                    _activation_publication_guard_value(
                        output_root,
                        manifest,
                        validation,
                        activation_identity=activation_identity,
                        captured_binding=performance_authority_gate_binding,
                    )
                ),
            )
    return activate_binary_generation(
        output_root,
        manifest,
        validation_result=validation,
        activation_identity=activation_identity,
        activation_record=activation_record,
        defer_publication=defer_publication,
        publication_guard=lambda: (
            _activation_publication_guard_value(
                output_root,
                manifest,
                validation,
                activation_identity=activation_identity,
                captured_binding=performance_authority_gate_binding,
            )
        ),
    )


def _discard_measurement_candidate_activation(
    output_root: Path,
    manifest: Mapping[str, Any],
    activation_record: dict[str, Any],
    performance_authority_gate_binding: Mapping[str, Any] | None,
) -> bool:
    """Remove every durable benchmark-only publication artefact.

    Candidate authority may exercise validation and the private activation
    transaction, but it must never leave a publishable pointer or checkpoint
    for a later production process to consume.
    """

    if performance_authority_gate_binding is None or (
        performance_authority_gate_binding.get("authority_mode")
        != _PERFORMANCE_CANDIDATE_AUTHORITY_MODE
    ):
        return False
    activation_identity = str(activation_record.get("activation_identity") or "")
    pending = read_pending_binary_generation(output_root, missing_ok=True)
    checkpoint = _read_resume_checkpoint(output_root)
    if (
        not _is_sha256_identity(activation_identity)
        or not activation_record.get("activation_candidate_private")
        or not activation_record.get("activation_candidate_nonpublishable")
        or pending is not None
        or not checkpoint
        or checkpoint.get("result_generation_identity")
        != manifest.get("result_generation_identity")
        or checkpoint.get("activation_identity") != activation_identity
        or checkpoint.get("performance_authority_gate_binding")
        != dict(performance_authority_gate_binding)
    ):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_DISCARD_FAILED",
            activation_identity,
        )
    activation_record["activation_candidate_discarded"] = True
    _delete_resume_checkpoint_durable(output_root)
    return True


def _seal_and_finalize_measured_activation(
    output_root: Path,
    manifest: Mapping[str, Any],
    validation: Mapping[str, Any],
    activation_record: dict[str, Any],
    performance_authority_gate_binding: Mapping[str, Any] | None,
) -> bool:
    """Seal production or recapture activation and remove recapture authority."""

    if not activation_record:
        return False
    generation_identity = str(manifest.get("result_generation_identity") or "")
    activation_identity = str(activation_record.get("activation_identity") or "")
    recapture = bool(
        performance_authority_gate_binding is not None
        and
        performance_authority_gate_binding.get("authority_mode")
        == _PERFORMANCE_RECAPTURE_AUTHORITY_MODE
    )
    if recapture:
        if (
            _PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.get()
            is not _PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
            or _PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.get()
            != output_root.resolve()
            or activation_record.get("activation_predecessor") is not None
        ):
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
                "release recapture root was not private and empty",
            )
        with _release_recapture_publication(output_root):
            sealed = seal_active_binary_generation(
                output_root,
                expected_current_identity=generation_identity,
                expected_activation_identity=activation_identity,
                publication_guard=lambda: (
                    _activation_publication_guard_value(
                        output_root,
                        manifest,
                        validation,
                        activation_identity=activation_identity,
                        captured_binding=(
                            performance_authority_gate_binding
                        ),
                    )
                ),
            )
            discarded = bool(
                sealed
                and _discard_release_recapture_activation(
                    output_root,
                    expected_current_identity=generation_identity,
                    expected_activation_identity=activation_identity,
                    previous_active=None,
                )
            )
        if not sealed:
            raise BinaryPipelineError(
                "BINARY_GENERATION_ACTIVATION_SEAL_FAILED",
                generation_identity,
            )
        if not discarded:
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                generation_identity,
            )
        activation_record["activation_recapture_discarded"] = True
        return True
    publication_guard = None
    if performance_authority_gate_binding is not None:
        publication_guard = lambda: _activation_publication_guard_value(
            output_root,
            manifest,
            validation,
            activation_identity=activation_identity,
            captured_binding=performance_authority_gate_binding,
        )
    if not seal_active_binary_generation(
        output_root,
        expected_current_identity=generation_identity,
        expected_activation_identity=activation_identity,
        publication_guard=publication_guard,
    ):
        raise BinaryPipelineError(
            "BINARY_GENERATION_ACTIVATION_SEAL_FAILED", generation_identity
        )
    return False


def _cleanup_performance_measurement_state(output_root: Path) -> None:
    """Best-effort entry point with fail-closed semantics for probe cleanup.

    The performance harness calls this from its candidate context ``finally``
    block.  It recovers an activation record from the exact private pending
    descriptor, if one was written before a failure, and removes the exact
    validation checkpoint path.  It never touches a public generation unless
    that pending descriptor proves the predecessor relationship.
    """

    if (
        _PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.get()
        is not _PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY
    ):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_MEASUREMENT_CLEANUP_FORBIDDEN",
            "candidate measurement capability is not active",
        )
    root = Path(output_root).resolve()
    if not root.exists():
        return
    pending = read_pending_binary_generation(root, missing_ok=True)
    if pending is not None:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_DISCARD_FAILED",
            "candidate measurement unexpectedly encountered a public pending "
            "descriptor; it was left untouched",
        )
    checkpoint = _read_resume_checkpoint(root)
    checkpoint_binding = (
        checkpoint.get("performance_authority_gate_binding")
        if checkpoint else None
    )
    if (
        checkpoint
        and _performance_authority_binding_is_valid(checkpoint_binding)
        and checkpoint_binding.get("authority_mode")
        == _PERFORMANCE_CANDIDATE_AUTHORITY_MODE
    ):
        _delete_resume_checkpoint_durable(root)
    if not _filesystem_entry_absent(_resume_checkpoint_path(root)):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_DISCARD_FAILED",
            "candidate validation checkpoint entry remains after cleanup",
        )


def _cleanup_performance_recapture_state(output_root: Path) -> None:
    """Recover only an exact benchmark recapture, then prove no pointer remains."""

    root = Path(output_root).resolve()
    if (
        _PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.get()
        is not _PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
        or _PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.get() != root
    ):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_RECAPTURE_CLEANUP_FORBIDDEN", str(root)
        )
    if not root.exists():
        return
    pending = read_pending_binary_generation(root, missing_ok=True)
    if pending is not None:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
            "release recapture unexpectedly created a pending descriptor",
        )
    checkpoint = _read_resume_checkpoint(root)
    if checkpoint:
        binding = checkpoint.get("performance_authority_gate_binding")
        generation_identity = str(
            checkpoint.get("result_generation_identity") or ""
        )
        activation_identity = str(checkpoint.get("activation_identity") or "")
        if (
            not _performance_authority_binding_is_valid(binding)
            or binding.get("authority_mode")
            != _PERFORMANCE_RECAPTURE_AUTHORITY_MODE
            or not _is_sha256_identity(generation_identity)
            or not _is_sha256_identity(activation_identity)
        ):
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                "recapture checkpoint identity is invalid",
            )
        active_path = root / "active_binary_generation.json"
        if active_path.exists() or active_path.is_symlink():
            with _release_recapture_publication(root):
                discarded = _discard_release_recapture_activation(
                    root,
                    expected_current_identity=generation_identity,
                    expected_activation_identity=activation_identity,
                    previous_active=None,
                )
            if not discarded:
                raise BinaryPipelineError(
                    "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                    generation_identity,
                )
        _delete_resume_checkpoint_durable(root)
    if (
        (root / "active_binary_generation.json").exists()
        or (root / "active_binary_generation.json").is_symlink()
        or read_pending_binary_generation(root, missing_ok=True) is not None
        or not _filesystem_entry_absent(_resume_checkpoint_path(root))
    ):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
            "release recapture state remains after cleanup",
        )


def _performance_measurement_binding(
    support: Mapping[str, Any],
    *,
    generation_source_records: Iterable[Mapping[str, str]] | None = None,
    asm_jar: str | Path | None = None,
) -> dict[str, str] | None:
    """Return strict performance evidence only inside the benchmark harness.

    Performance evidence and release metadata do not change analysis facts.
    Normal Step4 runs therefore never read or validate them.  The dedicated
    performance harness keeps its existing binding so measurements remain
    reproducible without making that release concern a user-facing gate.
    """
    measurement_active = (
        _PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.get()
        is _PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY
        or _PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.get()
        is _PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
    )
    if not measurement_active:
        return None
    return _performance_authority_gate_binding(
        support,
        generation_source_records=generation_source_records,
        asm_jar=asm_jar,
    )


def _artifact_safety_policy(
    config: Mapping[str, Any], support: Mapping[str, Any]
) -> dict[str, Any]:
    """Resolve only caller-requested limits stricter than the release policy."""
    defaults = dict(
        support["artifact_diff_support_manifest"]["artifact_safety_policy"]
    )
    raw_limits = config.get("artifact_safety_limits")
    if raw_limits is not None and not isinstance(raw_limits, Mapping):
        raise BinaryPipelineError(
            "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
            "artifact_safety_limits must be an object",
        )
    raw = dict(raw_limits or {})
    allowed = {
        "max_archive_entries",
        "max_total_uncompressed_bytes",
        "max_expansion_ratio",
        "max_nested_depth",
        "max_nested_archive_bytes",
        "max_class_bytes",
        "max_protocol_frame_bytes",
        "max_fact_records",
        "helper_timeout_seconds",
        "helper_max_heap",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise BinaryPipelineError(
            "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
            f"unknown fields: {unknown}",
        )
    effective = dict(defaults)
    integer_fields = allowed - {
        "max_expansion_ratio", "helper_timeout_seconds", "helper_max_heap"
    }
    for key in integer_fields:
        if key not in raw:
            continue
        value = raw[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < (0 if key == "max_nested_depth" else 1)
            or value > int(defaults[key])
        ):
            raise BinaryPipelineError(
                "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID", key
            )
        effective[key] = value
    for key in ("max_expansion_ratio", "helper_timeout_seconds"):
        if key not in raw:
            continue
        value = raw[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BinaryPipelineError(
                "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID", key
            )
        minimum = 1.0 if key == "max_expansion_ratio" else 0.01
        if not minimum <= float(value) <= float(defaults[key]):
            raise BinaryPipelineError(
                "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID", key
            )
        effective[key] = float(value)
    if "helper_max_heap" in raw:
        value = str(raw["helper_max_heap"] or "")
        match = re.fullmatch(r"([1-9][0-9]*)m", value)
        default_match = re.fullmatch(
            r"([1-9][0-9]*)m", str(defaults["helper_max_heap"])
        )
        if (
            not match
            or not default_match
            or not 16 <= int(match.group(1)) <= int(default_match.group(1))
        ):
            raise BinaryPipelineError(
                "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID", "helper_max_heap"
            )
        effective["helper_max_heap"] = value
    return effective


def _positive_pipeline_limit(
    config: Mapping[str, Any], field: str, default: int,
) -> int:
    """Parse a generation limit without truncation or boolean coercion."""
    value = config.get(field)
    if value in (None, ""):
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_TRACE_LIMIT_INVALID", f"{field}={value!r}"
        )
    return value


def _validate_static_source_overlay(config: Mapping[str, Any]) -> None:
    overlay = config.get("source_overlay")
    if overlay in (None, {}):
        return
    if not isinstance(overlay, Mapping):
        raise BinaryPipelineError(
            "BINARY_SOURCE_OVERLAY_INVALID", "source_overlay must be an object"
        )
    source_sets = overlay.get("source_sets")
    if not isinstance(source_sets, list) or not source_sets:
        raise BinaryPipelineError(
            "BINARY_SOURCE_SETS_REQUIRED",
            "source_overlay.source_sets must be a non-empty list",
        )
    for raw_set in source_sets:
        if not isinstance(raw_set, Mapping):
            raise BinaryPipelineError(
                "BINARY_SOURCE_SET_INVALID", "source set must be an object"
            )
        roots_value = raw_set.get("source_dirs")
        if not isinstance(roots_value, list) or not roots_value:
            raise BinaryPipelineError(
                "BINARY_SOURCE_ROOT_MISSING", "source_dirs must be non-empty"
            )
        roots = [Path(str(value)).expanduser().resolve() for value in roots_value]
        common_value = raw_set.get("source_root") or (
            roots[0] if len(roots) == 1 else None
        )
        if common_value is None:
            raise BinaryPipelineError(
                "BINARY_SOURCE_COMMON_ROOT_REQUIRED",
                "multiple source_dirs require source_root",
            )
        common = Path(str(common_value)).expanduser().resolve()
        if not common.is_dir():
            raise BinaryPipelineError("BINARY_SOURCE_ROOT_MISSING", str(common))
        owner_type = str(raw_set.get("owner_type") or "").strip()
        owner_coord = str(raw_set.get("owner_coord") or "").strip()
        if owner_type not in {"business", "dependency"} or not owner_coord:
            raise BinaryPipelineError(
                "BINARY_SOURCE_OWNER_REQUIRED",
                "every source set requires owner_type and owner_coord",
            )
        for root in roots:
            if not root.is_dir():
                raise BinaryPipelineError("BINARY_SOURCE_ROOT_MISSING", str(root))
            try:
                root.relative_to(common)
            except ValueError as error:
                raise BinaryPipelineError(
                    "BINARY_SOURCE_ROOT_OUTSIDE_SNAPSHOT", str(root)
                ) from error


def _validate_static_artifact_inputs(config: Mapping[str, Any]) -> None:
    """Reject deterministic artifact-shape errors before hashing JDK images."""
    allowed_path_kinds = {
        "business_classes", "classpath", "module_path", "nested_runtime",
    }
    for side_name in ("base", "current"):
        side = config.get(side_name)
        if not isinstance(side, Mapping):
            raise BinaryPipelineError(
                "BINARY_PIPELINE_SIDE_CONFIG_INVALID", side_name
            )
        artifacts = side.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise BinaryPipelineError(
                "BINARY_PIPELINE_ARTIFACTS_REQUIRED", side_name
            )
        slots: set[tuple[str, int]] = set()
        lineages: set[str] = set()
        logical_locations: set[str] = set()
        for index, raw in enumerate(artifacts):
            if not isinstance(raw, Mapping):
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_ARTIFACT_CONFIG_INVALID",
                    f"{side_name}[{index}] must be an object",
                )
            raw_path = str(raw.get("path") or "").strip()
            if not raw_path:
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_ARTIFACT_MISSING",
                    f"{side_name}[{index}] path is empty",
                )
            path = Path(raw_path).expanduser().resolve()
            if not path.is_file():
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_ARTIFACT_MISSING", str(path)
                )
            raw_outer = str(raw.get("outer_artifact_path") or "").strip()
            outer = (
                Path(raw_outer).expanduser().resolve() if raw_outer else path
            )
            if not outer.is_file():
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_ARTIFACT_MISSING", str(outer)
                )
            for digest_field in ("content_sha256", "outer_artifact_sha256"):
                digest = str(raw.get(digest_field) or "").strip().lower()
                if digest and re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                    raise BinaryPipelineError(
                        "BINARY_PIPELINE_ARTIFACT_SHA256_INVALID",
                        f"{side_name}[{index}].{digest_field}={digest}",
                    )
            slot = raw.get("slot")
            if isinstance(slot, bool) or not isinstance(slot, int) or slot < 0:
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_RUNTIME_SLOT_INVALID",
                    f"{side_name}[{index}]={slot!r}",
                )
            loader = str(raw.get("loader_realm") or "").strip()
            logical = str(raw.get("logical_location") or "").strip()
            if not loader or not logical:
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_ARTIFACT_CONFIG_INVALID",
                    f"{side_name}[{index}] loader/logical location is required",
                )
            if logical in logical_locations:
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_LOGICAL_LOCATION_AMBIGUOUS",
                    f"{side_name}:{logical}",
                )
            logical_locations.add(logical)
            if logical.startswith(("/", "~")) or ":\\" in logical:
                raise BinaryPipelineError(
                    "RUNTIME_PROFILE_PATH_NOT_REPRODUCIBLE", logical
                )
            slot_key = (loader, slot)
            if slot_key in slots:
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_RUNTIME_SLOT_INVALID",
                    f"duplicate {side_name}:{loader}:{slot}",
                )
            slots.add(slot_key)
            path_kind = str(raw.get("path_kind") or "classpath")
            if path_kind not in allowed_path_kinds:
                raise BinaryPipelineError(
                    "ARTIFACT_INSTANCE_PATH_KIND_INVALID", path_kind
                )
            if not str(
                raw.get("runtime_code_source_origin_identity") or ""
            ).strip():
                raise BinaryPipelineError(
                    "ARTIFACT_INSTANCE_FIELD_MISSING",
                    "runtime_code_source_origin_identity is required",
                )
            lineage = str(
                raw.get("lineage") or raw.get("coord") or logical
            ).strip()
            # logical_location is already required and is the final fallback,
            # so an empty lineage is impossible after the checks above.
            if lineage in lineages:
                raise BinaryPipelineError(
                    "BINARY_ARTIFACT_LINEAGE_AMBIGUOUS", lineage
                )
            lineages.add(lineage)


def _validate_static_runtime_profile_inputs(config: Mapping[str, Any]) -> None:
    """Validate profile containers used much later by semantic/trace phases."""
    sequence_fields = (
        "active_profile_identities",
        "external_config_snapshot_identities",
        "agent_transformer_plugin_profile_identities",
        "runtime_configuration_coverage_gaps",
        "entrypoint_discovery_coverage_gaps",
    )
    argument_fields = (
        "runtime_jvm_arguments",
        "jvm_arguments",
        "known_jvm_arguments",
        "jvm_args",
        "java_tool_options",
        "jdk_java_options",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
    )
    for side_name in ("base", "current"):
        side = config.get(side_name)
        if not isinstance(side, Mapping):
            # The artifact-shape validator reports this stable reason first.
            continue
        raw_profile = side.get("runtime_profile")
        if raw_profile is not None and not isinstance(raw_profile, Mapping):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID", side_name
            )
        profile = dict(raw_profile or {})
        mapping_fields = (
            "target_jvm",
            "loader_topology",
            "business_entrypoint_profile",
            "resolved_configuration_properties",
            "field_coverage",
        )
        for field in mapping_fields:
            value = profile.get(field)
            if value is not None and not isinstance(value, Mapping):
                raise BinaryPipelineError(
                    "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                    f"{side_name}.{field} must be an object",
                )
        for field in sequence_fields:
            value = profile.get(field)
            if value is not None and not isinstance(value, (list, tuple)):
                raise BinaryPipelineError(
                    "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                    f"{side_name}.{field} must be a list",
                )
        business = profile.get("business_entrypoint_profile") or {}
        for field in (
            "methods",
            "activated_frameworks",
            "activated_classes",
            "activated_entity_classes",
            "activated_resource_names",
            "activated_component_scan_packages",
            "coverage_gaps",
        ):
            value = business.get(field)
            if value is not None and not isinstance(value, (list, tuple)):
                raise BinaryPipelineError(
                    "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                    f"{side_name}.business_entrypoint_profile.{field} "
                    "must be a list",
                )
        methods = business.get("methods") or ()
        if not all(isinstance(item, Mapping) for item in methods):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                f"{side_name}.business_entrypoint_profile.methods invalid",
            )
        topology = profile.get("loader_topology") or {}
        realms = topology.get("realms")
        if realms is not None and not isinstance(realms, list):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                f"{side_name}.loader_topology.realms must be a list",
            )
        if isinstance(realms, list) and not all(
            isinstance(item, Mapping) for item in realms
        ):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                f"{side_name}.loader_topology.realms invalid",
            )
        entrypoint_realms = topology.get("entrypoint_realms")
        if entrypoint_realms is not None and not isinstance(
            entrypoint_realms, (list, tuple)
        ):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                f"{side_name}.loader_topology.entrypoint_realms must be a list",
            )
        for source_name, source in (("side", side), ("runtime_profile", profile)):
            for field in argument_fields:
                _pipeline_jvm_argument_tokens(
                    source.get(field),
                    source=f"{side_name}.{source_name}.{field}",
                )


def _validate_static_build_identity_inputs(config: Mapping[str, Any]) -> None:
    for side_name in ("base", "current"):
        side = config.get(side_name)
        if not isinstance(side, Mapping):
            continue
        raw_identity = side.get("build_identity")
        if raw_identity is not None and not isinstance(raw_identity, Mapping):
            raise BinaryPipelineError(
                "BINARY_BUILD_IDENTITY_CONFIG_INVALID", side_name
            )
        raw_identity = dict(raw_identity or {})
        for field in (
            "build_environment",
            "build_input_manifest",
            "artifact_build_provenance",
        ):
            value = raw_identity.get(field)
            if value is not None and not isinstance(value, Mapping):
                raise BinaryPipelineError(
                    "BINARY_BUILD_IDENTITY_CONFIG_INVALID",
                    f"{side_name}.{field} must be an object",
                )
        provenance = raw_identity.get("artifact_build_provenance")
        if provenance:
            # This explicit portion is independent of artifact hashes. The
            # default provenance is built later from observed content.
            try:
                BuildIdentityBundle(
                    dict(raw_identity.get("build_environment") or {}),
                    dict(raw_identity.get("build_input_manifest") or {}),
                    dict(provenance),
                )
            except BinaryFirstContractError as error:
                raise BinaryPipelineError(
                    error.reason_code, str(error)
                ) from error


def _preflight_output_root(output_root: Path) -> None:
    """Prove generation storage is writable before starting expensive work."""
    probe = output_root / (
        f".binary-output-probe.{os.getpid()}.{time.monotonic_ns()}"
    )

    def remove_probe() -> None:
        try:
            _unlink_missing_ok(probe)
        except OSError as error:
            raise BinaryPipelineError(
                "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
                f"{output_root}: cannot remove output storage probe: {error}",
            ) from error

    try:
        output_root.mkdir(parents=True, exist_ok=True)
        if not output_root.is_dir():
            raise OSError("output root is not a directory")
        _write_text_atomic_durable(probe, "binary-output-preflight\n")
        if probe.read_bytes() != b"binary-output-preflight\n":
            raise OSError("output probe content mismatch")
        _physical_observability_directory(output_root, create=True)
    except (OSError, UnicodeError) as error:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
            f"{output_root}: {error}",
        ) from error
    finally:
        _attempt_cleanups(
            ((f"remove output storage probe {probe}", remove_probe),),
            primary=sys.exc_info()[1],
        )


def _canonical_output_root_preserving_leaf(output_root: str | Path) -> Path:
    """Canonicalize ancestors while refusing to follow the owned leaf."""

    lexical = Path(output_root).expanduser()
    if lexical.name in {"", ".", ".."}:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
            f"{lexical}: output root must name a dedicated directory leaf",
        )
    canonical = lexical.parent.resolve() / lexical.name
    try:
        entry = os.lstat(canonical)
    except FileNotFoundError:
        return canonical
    except OSError as error:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
            f"{canonical}: cannot inspect output root: {error}",
        ) from error
    if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
        raise BinaryPipelineError(
            "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
            f"{canonical}: output root must be a physical directory",
        )
    return canonical


_RUNTIME_CAPABILITY_LIST_FIELDS = {
    "supported_loader_policy_versions": "container_loader_policy_versions",
    "supported_delegation_modes": "delegation_for_binary_authority",
    "supported_security_policy_identities": "security_policy_identities",
    "supported_module_modes": "module_modes",
    "supported_transformer_profile_identities": "transformer_profile_identities",
}
_RUNTIME_CAPABILITY_BOOLEAN_FIELDS = (
    "signed_artifacts_supported",
    "sealed_packages_supported",
    "closed_world_dispatch",
)


def _runtime_capability_policy(
    config: Mapping[str, Any], support: Mapping[str, Any]
) -> RuntimeCapabilityPolicy:
    """Resolve a caller policy that can only restrict release capabilities.

    The support manifest is release-owned evidence.  Treating caller input as
    the capability source would let a request self-certify loader/security
    behavior that this engine release has never validated.
    """
    raw_value = config.get("runtime_capability_policy")
    if raw_value is not None and not isinstance(raw_value, Mapping):
        raise BinaryPipelineError(
            "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            "runtime_capability_policy must be an object",
        )
    raw = dict(raw_value or {})
    allowed = set(_RUNTIME_CAPABILITY_LIST_FIELDS) | set(
        _RUNTIME_CAPABILITY_BOOLEAN_FIELDS
    )
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise BinaryPipelineError(
            "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            f"unknown fields: {unknown}",
        )

    loader_manifest = support.get("runtime_loader_support_manifest")
    if not isinstance(loader_manifest, Mapping):
        raise BinaryPipelineError(
            "BINARY_AUTHORITY_MANIFEST_INVALID",
            "runtime_loader_support_manifest must be an object",
        )
    supported = loader_manifest.get("supported")
    if not isinstance(supported, Mapping):
        raise BinaryPipelineError(
            "BINARY_AUTHORITY_MANIFEST_INVALID",
            "runtime_loader_support_manifest.supported must be an object",
        )
    release_values: dict[str, Any] = {}
    for policy_field, manifest_field in _RUNTIME_CAPABILITY_LIST_FIELDS.items():
        manifest_value = supported.get(manifest_field)
        if not isinstance(manifest_value, list):
            raise BinaryPipelineError(
                "BINARY_AUTHORITY_MANIFEST_INVALID",
                f"runtime loader support {manifest_field} must be a list",
            )
        normalized_manifest = tuple(manifest_value)
        if (
            any(not isinstance(item, str) or not item for item in normalized_manifest)
            or len(set(normalized_manifest)) != len(normalized_manifest)
        ):
            raise BinaryPipelineError(
                "BINARY_AUTHORITY_MANIFEST_INVALID",
                f"runtime loader support {manifest_field} is not canonical",
            )
        requested = raw.get(policy_field, normalized_manifest)
        if not isinstance(requested, (list, tuple)):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
                f"runtime_capability_policy.{policy_field} must be a list",
            )
        requested = tuple(requested)
        if (
            any(not isinstance(item, str) or not item for item in requested)
            or len(set(requested)) != len(requested)
            or not set(requested) <= set(normalized_manifest)
        ):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
                f"runtime_capability_policy.{policy_field} exceeds release support",
            )
        release_values[policy_field] = requested

    for field in _RUNTIME_CAPABILITY_BOOLEAN_FIELDS:
        release_value = supported.get(field)
        if not isinstance(release_value, bool):
            raise BinaryPipelineError(
                "BINARY_AUTHORITY_MANIFEST_INVALID",
                f"runtime loader support {field} must be boolean",
            )
        requested = raw.get(field, release_value)
        if not isinstance(requested, bool) or (requested and not release_value):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
                f"runtime_capability_policy.{field} exceeds release support",
            )
        release_values[field] = requested

    policy_version = loader_manifest.get("policy_version")
    if not isinstance(policy_version, str) or not policy_version:
        raise BinaryPipelineError(
            "BINARY_AUTHORITY_MANIFEST_INVALID",
            "runtime loader support policy_version is required",
        )
    try:
        return RuntimeCapabilityPolicy(
            **release_values,
            policy_version=policy_version,
        )
    except (TypeError, ValueError) as error:
        raise BinaryPipelineError(
            "BINARY_AUTHORITY_MANIFEST_INVALID", str(error)
        ) from error


def _static_pipeline_preflight(
    config: Mapping[str, Any],
    *,
    generation_source_records: Iterable[Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """Validate all JDK-independent controls before multi-hour generation."""
    validate_oracle_tool_execution_policy(config)
    _artifact_snapshot_worker_count(config.get("artifact_snapshot_workers"), 1)
    _artifact_hash_worker_count(config.get("artifact_hash_workers"), 1)
    max_trace_nodes = _positive_pipeline_limit(
        config, "max_trace_nodes", 1_000_000
    )
    max_paths_per_target = _positive_pipeline_limit(
        config, "max_paths_per_target", 20
    )
    _validate_static_source_overlay(config)
    _validate_static_artifact_inputs(config)
    _validate_static_runtime_profile_inputs(config)
    _validate_static_build_identity_inputs(config)
    comparison = config.get("runtime_comparison")
    if comparison is not None and not isinstance(comparison, Mapping):
        raise BinaryPipelineError(
            "BINARY_RUNTIME_COMPARISON_CONFIG_INVALID",
            "runtime_comparison must be an object",
        )
    intent = str(
        (comparison or {}).get("comparison_intent")
        or "same_deployment_profile"
    )
    if intent not in {"same_deployment_profile", "release_snapshot"}:
        raise BinaryPipelineError("RUNTIME_COMPARISON_INTENT_INVALID", intent)
    for field in (
        "controlled_profile_fields",
        "declared_upgrade_payload_scope",
        "changed_or_unknown_profile_fields",
    ):
        value = (comparison or {}).get(field)
        if value is not None and not isinstance(value, (list, tuple)):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_COMPARISON_CONFIG_INVALID",
                f"runtime_comparison.{field} must be a list",
            )
    support = _load_support_manifest_snapshot()
    performance_authority_gate_binding = _performance_measurement_binding(
        support,
        generation_source_records=generation_source_records,
        asm_jar=config.get("asm_jar") or None,
    )
    capability = _runtime_capability_policy(config, support)
    return {
        "support": support,
        "performance_authority_gate_binding": (
            performance_authority_gate_binding
        ),
        "artifact_safety_policy": _artifact_safety_policy(config, support),
        "runtime_capability_policy": capability,
        "max_trace_nodes": max_trace_nodes,
        "max_paths_per_target": max_paths_per_target,
    }


def _definition_verification_summary(
    reconciliation: Any,
    platform: JdkPlatformImage,
    store: BinaryFactStore | None = None,
) -> dict[str, Any]:
    """Build a bounded public summary of target-JVM definition evidence."""
    status_counts: dict[str, int] = {}
    target_status_counts: dict[str, int] = {}
    platform_class_names = set()
    target_verified_contexts = []
    verifier_identities = set()
    failures = []
    records = reconciliation.class_definitions
    if not records:
        if store is None:
            records = ()
        else:
            records = store.reconciliation_payloads("class_definition")
    class_definition_count = 0
    for record in records:
        class_definition_count += 1
        status = str(record.get("class_definition_status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        evidence = dict(record.get("evidence") or {})
        name = str(record.get("class_name") or "")
        if evidence.get("verification") == "target_platform_image":
            platform_class_names.add(name)
        verification = dict(evidence.get("target_jvm_verification") or {})
        if verification:
            target_verified_contexts.append(
                f"{record.get('initiating_loader_realm_identity') or ''}:{name}"
            )
            target_status = str(verification.get("status") or "unknown")
            target_status_counts[target_status] = (
                target_status_counts.get(target_status, 0) + 1
            )
            verifier_identity = str(
                verification.get("class_definition_verifier_identity") or ""
            )
            if verifier_identity:
                verifier_identities.add(verifier_identity)
        if status != "definition_ready" and len(failures) < 20:
            failures.append({
                "class_name": name,
                "status": status,
                "reason": str(evidence.get("reason") or ""),
                "parse_failure_kind": str(
                    evidence.get("parse_failure_kind") or ""
                ),
            })
    platform_class_names = sorted(platform_class_names)
    target_verified_contexts.sort()
    return {
        "runtime_profile_identity": reconciliation.runtime_profile_identity,
        "runtime_reconciliation_identity": reconciliation.identity,
        "coverage_status": reconciliation.coverage_status,
        "coverage_gaps": list(reconciliation.coverage_gaps),
        "class_definition_count": class_definition_count,
        "definition_status_counts": dict(sorted(status_counts.items())),
        "target_jvm_verified_class_count": len(target_verified_contexts),
        "target_jvm_status_counts": dict(sorted(target_status_counts.items())),
        "target_jvm_verified_context_set_identity": _identity(
            "target_jvm_verified_class_context_set_identity",
            target_verified_contexts,
        ),
        "class_definition_verifier_identities": sorted(verifier_identities),
        "platform_definition_ready_count": len(platform_class_names),
        "platform_class_names": platform_class_names,
        "failure_count": sum(
            count for status, count in status_counts.items()
            if status != "definition_ready"
        ),
        "failure_samples": failures,
        "runtime_platform_image": platform.manifest(),
    }


def _artifact_descriptors(
    raw_artifacts: list[Mapping[str, Any]],
    *,
    digest_session: _ArtifactDigestSession | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    digest_session = digest_session or _ArtifactDigestSession()
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
        digest = digest_session.digest(
            path,
            expected_sha256=raw.get("content_sha256"),
        )
        sha = digest.content_sha256
        item = {
            **dict(raw), "path": str(path), "content_sha256": sha,
            "byte_length": digest.byte_length, "slot": slot,
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


_MR_JVM_PROPERTY_NAMES = frozenset({
    "jdk.util.jar.enableMultiRelease",
    "jdk.util.jar.version",
})


def _pipeline_jvm_argument_tokens(raw: Any, *, source: str) -> list[str]:
    if isinstance(raw, str):
        try:
            return shlex.split(raw)
        except ValueError as error:
            raise BinaryPipelineError(
                "BINARY_PIPELINE_JVM_ARGUMENTS_INVALID",
                f"{source}:{error}",
            ) from error
    if isinstance(raw, (list, tuple)):
        return [str(item) for item in raw]
    return []


def _validate_multi_release_runtime_contract(
    side_config: Mapping[str, Any],
    runtime_profile: Mapping[str, Any],
    target_jvm_major: int,
) -> None:
    """Reject direct inputs whose JarFile switches the engine cannot model."""

    properties: dict[str, str] = {}
    for source_name, source in (
        ("side", side_config),
        ("runtime_profile", runtime_profile),
    ):
        for key in ("runtime_system_properties", "jvm_system_properties"):
            raw = source.get(key)
            if isinstance(raw, Mapping):
                for name, value in raw.items():
                    if str(name) in _MR_JVM_PROPERTY_NAMES:
                        properties[str(name)] = str(value).strip()
        for key in (
            "runtime_jvm_arguments",
            "jvm_arguments",
            "known_jvm_arguments",
            "jvm_args",
            "java_tool_options",
            "jdk_java_options",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
        ):
            for argument in _pipeline_jvm_argument_tokens(
                source.get(key), source=f"{source_name}.{key}"
            ):
                if not argument.startswith("-D"):
                    continue
                name, separator, value = argument[2:].partition("=")
                if name in _MR_JVM_PROPERTY_NAMES:
                    properties[name] = value.strip() if separator else ""
    unsupported_properties = {
        name: value
        for name, value in properties.items()
        if name == "jdk.util.jar.version"
        or (
            name == "jdk.util.jar.enableMultiRelease"
            and value != "true"
        )
    }
    if unsupported_properties:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_MULTI_RELEASE_JVM_PROPERTY_UNSUPPORTED",
            ",".join(
                f"{name}={value}"
                for name, value in sorted(unsupported_properties.items())
            ),
        )

    loader_topology = runtime_profile.get("loader_topology")
    nested_policy = (
        loader_topology.get("multi_release_jar_runtime_policy")
        if isinstance(loader_topology, Mapping)
        else None
    )
    declared_policies = [
        value for value in (
            side_config.get("multi_release_jar_runtime_policy"),
            runtime_profile.get("multi_release_jar_runtime_policy"),
            nested_policy,
        )
        if value is not None
    ]
    expected_policy = {
        "policy_identity": "openjdk-jarfile-default-properties-v1",
        "target_runtime_feature": int(target_jvm_major),
        "jdk.util.jar.enableMultiRelease": "true",
        "jdk.util.jar.version": "target-runtime-feature",
        "non_default_behavior": "fail_closed",
    }
    if any(
        not isinstance(policy, Mapping)
        or dict(policy) != expected_policy
        for policy in declared_policies
    ):
        raise BinaryPipelineError(
            "BINARY_PIPELINE_MULTI_RELEASE_POLICY_UNSUPPORTED",
            "direct config must use openjdk-jarfile-default-properties-v1",
        )


def _runtime_profile(
    side_config: Mapping[str, Any],
    platform: JdkPlatformImage,
    path_descriptors: list[dict[str, Any]],
) -> RuntimeProfile:
    raw = dict(side_config.get("runtime_profile") or {})
    _validate_multi_release_runtime_contract(
        side_config, raw, platform.java_major
    )
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
    target_jvm = raw["target_jvm"]
    if (
        not isinstance(target_jvm, Mapping)
        or int(target_jvm.get("major") or 0) != platform.java_major
    ):
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
    artifacts: list[dict[str, Any]],
    profile: RuntimeProfile,
    *,
    digest_session: _ArtifactDigestSession | None = None,
) -> list[tuple[dict[str, Any], ArtifactInstance]]:
    owns_digest_session = digest_session is None
    digest_session = digest_session or _ArtifactDigestSession()
    result = []
    for raw in artifacts:
        artifact_path = Path(str(raw["path"])).expanduser().resolve()
        outer_path = Path(
            str(raw.get("outer_artifact_path") or artifact_path)
        ).expanduser().resolve()
        outer_digest = digest_session.digest(
            outer_path,
            expected_sha256=raw.get("outer_artifact_sha256"),
            # A distinct outer container is not read by snapshot parsing later,
            # so verify it a second time after all shared references are built.
            revalidate_at_end=outer_path != artifact_path,
        )
        outer_sha = outer_digest.content_sha256
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
    if owns_digest_session:
        digest_session.revalidate_marked()
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
    methods = install_global_type_knowledge(methods)
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
    mapped_by_symbol = {}
    for row in source_overlay.rows:
        if not isinstance(row, Mapping) or row.get("mapping_status") != "mapped":
            continue
        raw_location = row.get("source_location")
        if not isinstance(raw_location, Mapping):
            continue
        source_symbol_id = str(raw_location.get("source_symbol_id") or "")
        if not source_symbol_id:
            continue
        mapped_by_symbol[source_symbol_id] = (row, dict(raw_location))
    declarations = []
    candidates = []
    for method in methods:
        mapped = mapped_by_symbol.get(
            str(getattr(method, "symbol_id", "") or "")
        )
        if mapped is None:
            continue
        overlay, location = mapped
        raw_member = overlay.get("binary_member")
        member = dict(raw_member) if isinstance(raw_member, Mapping) else {}
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


def _source_mapping_status_counts(
    rows: Iterable[Mapping[str, Any]],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("mapping_status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _nonempty_first_column(rows: Iterable[Sequence[Any]]) -> set[Any]:
    return {row[0] for row in rows if row[0]}


def _single_parser_identity(parser_identities: Iterable[str]) -> str:
    observed = sorted(set(parser_identities))
    if len(observed) != 1:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_PARSER_IDENTITY_SET_INVALID",
            str(observed),
        )
    return observed[0]


def _should_prune_generation_after_result(
    *,
    performance_measurement_run: bool,
    checkpoint_receipt: Mapping[str, Any],
    candidate_discarded: bool,
) -> bool:
    return bool(
        not performance_measurement_run
        and (not checkpoint_receipt or candidate_discarded)
    )


def _run_pipeline_under_lock(
    config: Mapping[str, Any],
    *,
    output_root: str | Path,
    retain_validation_checkpoint: bool = False,
) -> dict[str, Any]:
    pipeline_started = time.perf_counter()
    preflight_started = pipeline_started
    if config.get("schema") != "java-upgrade-analyzer.binary-pipeline-input.v1":
        raise BinaryPipelineError("BINARY_PIPELINE_CONFIG_SCHEMA_INVALID", str(config.get("schema")))
    performance_measurement_run = (
        _PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.get()
        is _PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY
        or _PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.get()
        is _PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
    )
    captured_generation_source_records = (
        _verify_captured_generation_sources()
        if performance_measurement_run
        else None
    )
    asm_jar = config.get("asm_jar") or None
    output_root = Path(output_root)
    recapture_context_enabled = (
        _PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.get()
        is _PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
    )
    if recapture_context_enabled:
        expected_recapture_root = (
            _PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.get()
        )
        existing_names = (
            {item.name for item in output_root.iterdir()}
            if output_root.exists() else set()
        )
        if (
            expected_recapture_root != output_root
            or existing_names - {".binary-pipeline-run.lock"}
        ):
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_RECAPTURE_ROOT_NOT_PRIVATE",
                json.dumps({
                    "expected_root": str(expected_recapture_root or ""),
                    "actual_root": str(output_root),
                    "existing_entries": sorted(existing_names),
                }, sort_keys=True),
            )
    _preflight_output_root(output_root)
    phase_timings: list[dict[str, Any]] = _PhaseTimingRecorder(
        output_root,
        pipeline_started,
        attempt_identity=_CLI_PROGRESS_ATTEMPT_CONTEXT.get(),
    )
    phase_timings.start("static_preflight")
    static_preflight = _static_pipeline_preflight(
        config,
        generation_source_records=captured_generation_source_records,
    )
    performance_binding = static_preflight[
        "performance_authority_gate_binding"
    ]
    performance_authority_mode = (
        performance_binding.get("authority_mode")
        if performance_binding is not None
        else "analysis_result"
    )
    if (
        performance_authority_mode
        == _PERFORMANCE_CANDIDATE_AUTHORITY_MODE
        and not retain_validation_checkpoint
    ):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_FORBIDDEN",
            "candidate measurement authority requires a retained, "
            "non-publishable validation checkpoint",
        )
    if performance_authority_mode == _PERFORMANCE_RECAPTURE_AUTHORITY_MODE:
        if not recapture_context_enabled or retain_validation_checkpoint:
            raise BinaryPipelineError(
                "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
                "release recapture requires its private benchmark context "
                "and a complete direct activation transaction",
            )
    source_inputs = _source_inputs_contract(config)
    cache_root = Path(
        str(config.get("cache_root") or (output_root / "binary_cache"))
    ).expanduser().resolve()
    base_config = dict(config.get("base") or {})
    current_config = dict(config.get("current") or {})
    toolchain_preflight = {}
    preflight_by_home = {}
    for side_name, side_config in (
        ("base", base_config), ("current", current_config),
    ):
        home = str(Path(str(side_config.get("jdk_home") or "")).expanduser().resolve())
        try:
            observed = preflight_by_home.get(home)
            if observed is None:
                observed = preflight_jdk_home(home)
                preflight_by_home[home] = observed
        except JdkPreflightError as error:
            raise BinaryPipelineError(
                "BINARY_JDK_PREFLIGHT_FAILED",
                json.dumps({
                    "side": side_name,
                    "jdk_home": home,
                    "reason_code": error.reason_code,
                    "detail": str(error),
                    "diagnostic": error.diagnostic,
                }, ensure_ascii=False, sort_keys=True),
            ) from error
        expected = str(side_config.get("jdk_preflight_identity") or "")
        if expected and expected != observed["jdk_preflight_identity"]:
            raise BinaryPipelineError(
                "BINARY_JDK_CHANGED_SINCE_STEP0",
                json.dumps({
                    "side": side_name,
                    "jdk_home": home,
                    "expected_jdk_preflight_identity": expected,
                    "actual_jdk_preflight_identity": observed[
                        "jdk_preflight_identity"
                    ],
                }, ensure_ascii=False, sort_keys=True),
            )
        toolchain_preflight[side_name] = observed
        runtime_profile = side_config.get("runtime_profile")
        if runtime_profile is not None and not isinstance(
            runtime_profile, Mapping
        ):
            raise BinaryPipelineError(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID", side_name
            )
        _validate_multi_release_runtime_contract(
            side_config,
            dict(runtime_profile or {}),
            int(observed["java_major"]),
        )
        target_jvm = (runtime_profile or {}).get("target_jvm")
        if target_jvm is not None:
            if not isinstance(target_jvm, Mapping):
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_TARGET_JVM_MISMATCH",
                    f"{side_name}:{target_jvm}",
                )
            try:
                declared_major = int(target_jvm.get("major") or 0)
            except (TypeError, ValueError) as error:
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_TARGET_JVM_MISMATCH",
                    f"{side_name}:{target_jvm}",
                ) from error
            if declared_major != int(observed["java_major"]):
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_TARGET_JVM_MISMATCH",
                    f"{side_name}:{target_jvm}",
                )
    # Resolve and digest-check the parser dependency before opening large fact
    # stores or reading application artifacts.
    asm_jar = str(resolve_asm_jar(asm_jar))
    run_implementation_identity = (
        _resume_implementation_identity(
            asm_jar, source_records=captured_generation_source_records
        )
        if performance_measurement_run
        else _identity(
            "binary_pipeline_generation_protocol_metadata",
            {
                "checkpoint_schema": RESUME_CHECKPOINT_SCHEMA,
                "validation_policy": VALIDATION_POLICY_VERSION,
            },
        )
    )
    phase_timings.append({
        "phase": "static_preflight",
        "elapsed_seconds": round(time.perf_counter() - preflight_started, 6),
        "base_jdk_preflight_identity": toolchain_preflight["base"][
            "jdk_preflight_identity"
        ],
        "current_jdk_preflight_identity": toolchain_preflight["current"][
            "jdk_preflight_identity"
        ],
    })
    resumed_result = _resume_generation_validation(
        config,
        output_root=output_root,
        source_inputs=source_inputs,
        toolchain_preflight=toolchain_preflight,
        asm_jar=asm_jar,
        phase_timings=phase_timings,
        pipeline_started=pipeline_started,
        retain_checkpoint=retain_validation_checkpoint,
        generation_implementation_identity=run_implementation_identity,
        performance_authority_gate_binding=static_preflight[
            "performance_authority_gate_binding"
        ],
    )
    if resumed_result is not None:
        if (
            not retain_validation_checkpoint
            or resumed_result.get("activation_candidate_discarded") is True
        ):
            _prune_unreferenced_generations_best_effort(output_root)
        return resumed_result
    # A checkpoint that reached this point was either absent or explicitly
    # rejected by the resume decision above.  Remove its stale reference before
    # reclaiming generations so a failed old attempt cannot consume another
    # full generation's worth of disk during this rerun.
    _delete_resume_checkpoint_durable(output_root)
    _prune_unreferenced_generations_best_effort(output_root)
    input_profile_started = time.perf_counter()
    platform_started = input_profile_started
    base_jdk_home = Path(
        str(base_config.get("jdk_home") or "")
    ).expanduser().resolve()
    current_jdk_home = Path(
        str(current_config.get("jdk_home") or "")
    ).expanduser().resolve()
    base_platform = JdkPlatformImage(base_jdk_home, asm_jar=asm_jar)
    if current_jdk_home == base_jdk_home:
        # One canonical JDK path denotes one target platform snapshot. Avoid
        # rehashing its module image, launcher and release file for the second
        # side; validation independently rechecks the same bound toolchain.
        current_platform = base_platform
    else:
        current_platform = JdkPlatformImage(current_jdk_home, asm_jar=asm_jar)
        if current_platform.identity == base_platform.identity:
            # Distinct paths can still be byte-identical immutable images.
            current_platform = base_platform
    platform_seconds = time.perf_counter() - platform_started
    digest_session = _ArtifactDigestSession()
    artifact_digest_requests = []
    for raw in (
        *(base_config.get("artifacts") or ()),
        *(current_config.get("artifacts") or ()),
    ):
        artifact_path = Path(str(raw.get("path") or "")).expanduser().resolve()
        artifact_digest_requests.append((
            artifact_path,
            raw.get("content_sha256"),
        ))
        artifact_digest_requests.append((
            Path(
                str(raw.get("outer_artifact_path") or artifact_path)
            ).expanduser().resolve(),
            raw.get("outer_artifact_sha256"),
        ))
    digest_prime_started = time.perf_counter()
    digest_session.prime(
        artifact_digest_requests,
        configured_workers=config.get("artifact_hash_workers"),
    )
    digest_prime_seconds = time.perf_counter() - digest_prime_started
    del artifact_digest_requests
    profile_build_started = time.perf_counter()
    base_artifacts, base_paths = _artifact_descriptors(
        list(base_config.get("artifacts") or ()),
        digest_session=digest_session,
    )
    current_artifacts, current_paths = _artifact_descriptors(
        list(current_config.get("artifacts") or ()),
        digest_session=digest_session,
    )
    base_config["artifacts"] = base_artifacts
    current_config["artifacts"] = current_artifacts
    base_profile = _runtime_profile(base_config, base_platform, base_paths)
    current_profile = _runtime_profile(current_config, current_platform, current_paths)
    base_build = _build_identity_bundle(base_config, base_artifacts)
    current_build = _build_identity_bundle(current_config, current_artifacts)
    base_instances = _artifact_instances(
        base_artifacts, base_profile, digest_session=digest_session
    )
    current_instances = _artifact_instances(
        current_artifacts, current_profile, digest_session=digest_session
    )
    digest_session.revalidate_marked()
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
    capability = static_preflight["runtime_capability_policy"]
    support = static_preflight["support"]
    artifact_safety_policy = static_preflight["artifact_safety_policy"]
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
        "elapsed_seconds": round(time.perf_counter() - input_profile_started, 6),
        "pipeline_elapsed_seconds": round(
            time.perf_counter() - pipeline_started, 6
        ),
        "platform_image_seconds": round(platform_seconds, 6),
        "artifact_digest_prime_seconds": round(digest_prime_seconds, 6),
        "runtime_profile_build_seconds": round(
            time.perf_counter() - profile_build_started, 6
        ),
        "artifact_count": len(base_artifacts) + len(current_artifacts),
        **digest_session.metrics(),
    })
    with short_temporary_directory(prefix="binary-pipeline") as temp_text:
        temp = Path(temp_text)
        base_store = BinaryFactStore(
            temp / "base.sqlite",
            defer_secondary_indexes=True,
            bulk_load_transaction=True,
        )
        base_store_open = True
        current_store_open = False
        try:
            # Enter cleanup protection for the first store before opening the
            # second.  A current-side SQLite setup failure must not leak the
            # already-open base-side database for the remainder of a worker.
            current_store = BinaryFactStore(
                temp / "current.sqlite",
                defer_secondary_indexes=True,
                bulk_load_transaction=True,
            )
            current_store_open = True
            artifact_phase_started = time.perf_counter()
            cache_metrics = {
                "artifact_snapshot_hits": 0,
                "artifact_snapshot_disk_hits": 0,
                "artifact_snapshot_memory_hits": 0,
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
            diffs = []
            pairings = []
            lineages = sorted(set(base_by_lineage) | set(current_by_lineage))
            # Each task drives a bounded Java helper and performs ZIP/I/O work.
            # Three tasks keep a 12-core workstation busy without multiplying
            # the helper's 512 MiB hard ceiling excessively.
            artifact_snapshot_workers = _artifact_snapshot_worker_count(
                config.get("artifact_snapshot_workers"), len(lineages)
            )

            def build_lineage_snapshot(lineage):
                # A pair-local one-entry memo preserves the base/current
                # content hit while making concurrent tasks independent.
                snapshot_template_memo = SnapshotTemplateMemo()

                def load_snapshot(raw, instance, target_jvm_major):
                    return cached_snapshot_archive(
                        raw["path"],
                        artifact_instance_identity=instance.identity,
                        expected_sha256=instance.content_sha256,
                        asm_jar=asm_jar,
                        jdk_home=current_platform.jdk_home,
                        cache_root=cache_root,
                        target_jvm_major=target_jvm_major,
                        template_memo=snapshot_template_memo,
                        safety_policy=artifact_safety_policy,
                    )

                base_pair = base_by_lineage.get(lineage)
                current_pair = current_by_lineage.get(lineage)
                base_outcome = None
                current_outcome = None
                if base_pair and current_pair:
                    status = "exact"
                    base_raw, base_instance = base_pair
                    current_raw, current_instance = current_pair
                    base_outcome = load_snapshot(
                        base_raw, base_instance, base_platform.java_major,
                    )
                    base_snapshot = base_outcome.snapshot
                    if runtime_sides_identical:
                        # The ArtifactInstance (including content, slot, realm,
                        # origin and runtime profile) is byte-for-byte equal.
                        # Compare the immutable snapshot with itself and clone
                        # the completed evidence store once after reconciliation
                        # instead of parsing/decompressing and inserting every
                        # unchanged class a second time.
                        current_snapshot = base_snapshot
                    else:
                        current_outcome = load_snapshot(
                            current_raw, current_instance,
                            current_platform.java_major,
                        )
                        current_snapshot = current_outcome.snapshot
                elif base_pair:
                    status = "base_only"
                    base_raw, base_instance = base_pair
                    base_outcome = load_snapshot(
                        base_raw, base_instance, base_platform.java_major,
                    )
                    base_snapshot = base_outcome.snapshot
                    current_instance = None
                    current_snapshot = _absent_snapshot(
                        f"ABSENT:current:{lineage}", base_snapshot.parser_identity
                    )
                else:
                    status = "current_only"
                    current_raw, current_instance = current_pair
                    current_outcome = load_snapshot(
                        current_raw, current_instance,
                        current_platform.java_major,
                    )
                    current_snapshot = current_outcome.snapshot
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
                artifact_diff = compare_artifact_snapshots(
                    base_snapshot,
                    current_snapshot,
                    comparison_or_runtime_scope={
                        "runtime_comparison_identity": runtime_comparison.identity,
                        "cross_version_artifact_pairing_identity": pairing.identity,
                    },
                )
                artifact_diff["logical_dependency_lineage"] = lineage
                snapshot_template_memo.clear()
                return (
                    pairing, artifact_diff,
                    base_instance, base_outcome,
                    current_instance, current_outcome,
                )

            def record_lineage_snapshot(result):
                (
                    pairing, artifact_diff,
                    base_instance, base_outcome,
                    current_instance, current_outcome,
                ) = result
                outcomes = (
                    (base_outcome, base_instance, base_store),
                    (current_outcome, current_instance, current_store),
                )
                for outcome, instance, store in outcomes:
                    if outcome is None:
                        continue
                    cache_metrics[
                        "artifact_snapshot_hits"
                        if outcome.cache_status == "hit"
                        else "artifact_snapshot_misses"
                    ] += 1
                    if outcome.cache_status == "corrupt_rebuilt":
                        cache_metrics[
                            "artifact_snapshot_corrupt_rebuilt"
                        ] += 1
                    if outcome.cache_tier == "disk":
                        cache_metrics["artifact_snapshot_disk_hits"] += 1
                    elif outcome.cache_tier == "memory":
                        cache_metrics["artifact_snapshot_memory_hits"] += 1
                    cache_metrics["classfile_parser_invocations"] += (
                        outcome.parser_invocation_count
                    )
                    parser_identities.add(outcome.snapshot.parser_identity)
                    store.add_artifact_snapshot(instance, outcome.snapshot)
                pairings.append(pairing)
                diffs.append(artifact_diff)

            if lineages:
                # Warm helper compilation and its LRU contract on one lineage
                # before worker threads start, avoiding duplicate javac races.
                record_lineage_snapshot(build_lineage_snapshot(lineages[0]))
                remaining = iter(lineages[1:])
                if artifact_snapshot_workers == 1:
                    for lineage in remaining:
                        record_lineage_snapshot(build_lineage_snapshot(lineage))
                else:
                    # Submit only a bounded rolling window. Completed snapshots
                    # can be much larger than their JARs; retaining a Future for
                    # every dependency would defeat the phase's memory bound.
                    with ThreadPoolExecutor(
                        max_workers=artifact_snapshot_workers,
                        thread_name_prefix="binary-artifact-snapshot",
                    ) as executor:
                        active = []
                        for _ in range(artifact_snapshot_workers):
                            try:
                                lineage = next(remaining)
                            except StopIteration:
                                break
                            active.append(executor.submit(
                                build_lineage_snapshot, lineage
                            ))
                        while active:
                            future = active.pop(0)
                            record_lineage_snapshot(future.result())
                            try:
                                lineage = next(remaining)
                            except StopIteration:
                                continue
                            active.append(executor.submit(
                                build_lineage_snapshot, lineage
                            ))
            del build_lineage_snapshot, record_lineage_snapshot
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
                "artifact_snapshot_workers": artifact_snapshot_workers,
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
                    _nonempty_first_column(store.connection.execute(
                        "SELECT DISTINCT class_name FROM classes"
                    ))
                )
                common_runtime_classes.update(
                    _nonempty_first_column(store.connection.execute(
                        """
                        SELECT DISTINCT symbolic_owner FROM direct_edges
                        WHERE symbolic_owner<>''
                        """
                    ))
                )
            base_retained_kinds = {
                "resource_selection",
            }
            current_retained_kinds = {
                "resource_selection",
            }
            base_runtime = RuntimeReconciler(
                base_store, base_profile, base_platform,
                analysis_context_identity=context.identity,
                capability_policy=capability,
                additional_initial_classes=common_runtime_classes,
            ).reconcile(retain_record_kinds=base_retained_kinds)
            shared_runtime_evidence = False
            if runtime_sides_identical:
                # Reconciliation is a deterministic function of the complete
                # runtime side identity. SQLite backup preserves the full
                # independently-validatable evidence without constructing a
                # second million-record Python graph.
                base_store.connection.commit()
                base_store.connection.backup(current_store.connection)
                current_store.connection.commit()
                current_store.adopt_runtime_trigger_summary_from_exact_backup(
                    base_store
                )
                current_runtime = base_runtime
                shared_runtime_evidence = True
            else:
                current_runtime = RuntimeReconciler(
                    current_store, current_profile, current_platform,
                    analysis_context_identity=context.identity,
                    capability_policy=capability,
                    additional_initial_classes=common_runtime_classes,
                ).reconcile(retain_record_kinds=current_retained_kinds)
            del common_runtime_classes
            base_runtime_identity = base_runtime.identity
            current_runtime_identity = current_runtime.identity
            definition_verification = {
                "schema": (
                    "java-upgrade-analyzer.binary-definition-verification.v1"
                ),
                "authority": "target_jvm_execution_and_bound_platform_image",
                "base": _definition_verification_summary(
                    base_runtime, base_platform, base_store
                ),
                "current": _definition_verification_summary(
                    current_runtime, current_platform, current_store
                ),
            }
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
                mapping_status_counts = _source_mapping_status_counts(
                    source_overlay.rows
                )
                source_attestation["mapping_status_counts"] = (
                    mapping_status_counts
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
                shared_runtime_evidence=shared_runtime_evidence,
            ).build()
            # Provider and definition evidence was deliberately not retained
            # during the reconciliation/decision peaks. Restore it only when
            # a downstream semantic consumer is actually present; empty
            # semantic and entrypoint fast paths use only persisted summaries.
            semantic_runtime_selection_required = (
                semantic_overlay_requires_runtime_selection(
                    current_store, decisions
                )
            )
            if (
                source_overlay is not None
                or semantic_runtime_selection_required
            ):
                current_runtime = hydrate_runtime_reconciliation(
                    current_store,
                    current_runtime,
                    ("provider_binding", "class_definition"),
                )
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
                runtime_selection_required=(
                    semantic_runtime_selection_required
                ),
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
                max_visited_nodes=static_preflight["max_trace_nodes"],
                max_paths_per_target=static_preflight["max_paths_per_target"],
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
            parser_identity = _single_parser_identity(parser_identities)
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
                "binary_definition_verification.json": (
                    json.dumps(
                        definition_verification,
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
            publication_binding = static_preflight[
                "performance_authority_gate_binding"
            ]
            if publication_binding is not None:
                publication_binding = dict(publication_binding)
                publication_authority = {
                    "schema": (
                        "java-upgrade-analyzer."
                        "binary-publication-authority.v1"
                    ),
                    "authority_mode": publication_binding["authority_mode"],
                    "binding_identity": publication_binding[
                        "binding_identity"
                    ],
                    "public_activation_allowed": (
                        publication_binding["authority_mode"]
                        == _PERFORMANCE_RELEASE_AUTHORITY_MODE
                    ),
                    "performance_authority_gate_binding": publication_binding,
                }
                additional["binary_publication_authority.json"] = (
                    json.dumps(
                        publication_authority,
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
                    "support_manifest": (
                        _generation_support_manifest_identity(support)
                    ),
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
                    "base_jdk_preflight_identity": toolchain_preflight["base"][
                        "jdk_preflight_identity"
                    ],
                    "current_jdk_preflight_identity": toolchain_preflight[
                        "current"
                    ]["jdk_preflight_identity"],
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
            validation_checkpoint = {
                "schema": RESUME_CHECKPOINT_SCHEMA,
                "status": _RESUME_AWAITING_VALIDATION,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "config_identity": _resume_config_identity(config),
                "implementation_identity": run_implementation_identity,
                "input_artifact_identity": _resume_input_artifact_identity(
                    config, digest_session=digest_session,
                ),
                "source_input_identity": _resume_source_input_identity(config),
                "result_generation_identity": manifest[
                    "result_generation_identity"
                ],
                "runtime_comparison_identity": runtime_comparison.identity,
                "analysis_scope_identity": analysis_scope.identity,
                "analysis_context_identity": context.identity,
                "base_jdk_preflight_identity": toolchain_preflight["base"][
                    "jdk_preflight_identity"
                ],
                "current_jdk_preflight_identity": toolchain_preflight["current"][
                    "jdk_preflight_identity"
                ],
                "result_summary": result_summary,
                "source_inputs": source_inputs,
                "artifact_safety_policy": artifact_safety_policy,
                "cache_metrics": cache_metrics,
                "phase_timings_before_validation": list(phase_timings),
                "performance_authority_gate_binding": (
                    dict(static_preflight[
                        "performance_authority_gate_binding"
                    ])
                    if static_preflight[
                        "performance_authority_gate_binding"
                    ] is not None
                    else None
                ),
            }
            validation_checkpoint = _write_resume_checkpoint_roundtrip(
                output_root, validation_checkpoint
            )
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
            store_cleanup_actions = []
            # Reaching immutable generation validation proves both stores were
            # constructed successfully and neither flag has been cleared yet.
            base_store_open = False
            current_store_open = False
            store_cleanup_actions.extend((
                (
                    "close base binary fact store before validation",
                    base_store.close,
                ),
                (
                    "close current binary fact store before validation",
                    current_store.close,
                ),
            ))
            _attempt_cleanups(store_cleanup_actions, primary=None)
            gc.collect()
            validation, validation_checkpoint = (
                _validate_or_reuse_checkpoint_attachment(
                    config,
                    output_root=output_root,
                    generation=Path(manifest["generation_directory"]),
                    manifest=manifest,
                    checkpoint=validation_checkpoint,
                    phase_timings=phase_timings,
                    resumed=False,
                )
            )
            activation_started = time.perf_counter()
            activation_record: dict[str, Any] = {}
            manifest["active_generation_descriptor"] = (
                _activate_validated_generation_with_authority_binding(
                    output_root,
                    manifest,
                    validation,
                    activation_identity=str(
                        validation_checkpoint["activation_identity"]
                    ),
                    activation_record=activation_record,
                    defer_publication=retain_validation_checkpoint,
                    performance_authority_gate_binding=static_preflight[
                        "performance_authority_gate_binding"
                    ],
                )
            )
            # Preserve the restart checkpoint until activation and
            # authoritative result assembly complete; metrics are best-effort.
            pre_finalize_peak_rss_bytes = _peak_rss_bytes()
            candidate_discarded = _discard_measurement_candidate_activation(
                output_root,
                manifest,
                activation_record,
                static_preflight["performance_authority_gate_binding"],
            )
            if candidate_discarded:
                manifest["active_generation_descriptor"] = ""
            if not retain_validation_checkpoint:
                if _seal_and_finalize_measured_activation(
                    output_root,
                    manifest,
                    validation,
                    activation_record,
                    static_preflight["performance_authority_gate_binding"],
                ):
                    manifest["active_generation_descriptor"] = ""
                _cleanup_consumed_resume_checkpoint(
                    output_root,
                    static_preflight["performance_authority_gate_binding"],
                )
            checkpoint_receipt = _validation_checkpoint_result_receipt(
                output_root,
                manifest,
                activation_record,
                static_preflight["performance_authority_gate_binding"],
                retain_requested=retain_validation_checkpoint,
                candidate_discarded=candidate_discarded,
            )
            # Cover the complete activation lifecycle, including discard,
            # sealing and durable checkpoint deletion/retention verification.
            peak_rss_bytes = max(
                pre_finalize_peak_rss_bytes,
                _peak_rss_bytes(),
            )
            phase_timings.append({
                "phase": "validated_generation_activation",
                "elapsed_seconds": round(time.perf_counter() - activation_started, 6),
                "publication_deferred": bool(checkpoint_receipt),
                "checkpoint_retained": bool(checkpoint_receipt),
                "activation_candidate_discarded": bool(candidate_discarded),
                "activation_authority_mode": performance_authority_mode,
            })
            observability = output_root / "binary_observability"
            cache_metrics_path = observability / "latest_cache_metrics.json"
            cache_metrics_persisted = _write_non_authoritative_json(
                cache_metrics_path,
                {
                    **cache_metrics,
                    "schema": "java-upgrade-analyzer.binary-cache-metrics.v1",
                    "result_generation_identity": manifest["result_generation_identity"],
                },
            )
            total_elapsed_seconds = round(time.perf_counter() - pipeline_started, 6)
            phase_timings_path = observability / "latest_phase_timings.json"
            phase_timings_persisted = _write_non_authoritative_json(
                phase_timings_path,
                {
                    "schema": "java-upgrade-analyzer.binary-phase-timings.v1",
                    "result_generation_identity": manifest[
                        "result_generation_identity"
                    ],
                    "total_elapsed_seconds": total_elapsed_seconds,
                    "peak_rss_bytes": peak_rss_bytes,
                    "peak_rss_scope": "current_process",
                    "total_elapsed_scope": "current_pipeline_attempt",
                    "phase_timings_scope": "current_pipeline_attempt",
                    "phases": phase_timings,
                    "non_authoritative_observability": True,
                },
            )
            result = {
                **manifest,
                "schema": "java-upgrade-analyzer.binary-pipeline-result.v1",
                "runtime_comparison_identity": runtime_comparison.identity,
                "analysis_scope_identity": analysis_scope.identity,
                "analysis_context_identity": context.identity,
                **result_summary,
                "source_inputs": source_inputs,
                "artifact_safety_policy": artifact_safety_policy,
                "validation_run_identity": validation["validation_run_identity"],
                "validation_status": validation["status"],
                "validation_result_path": validation["validation_result_path"],
                "definition_verification_path": str(
                    Path(manifest["generation_directory"])
                    / "binary_definition_verification.json"
                ),
                "cache_metrics": cache_metrics,
                "cache_metrics_path": str(cache_metrics_path),
                "cache_metrics_persisted": cache_metrics_persisted,
                "phase_timings": phase_timings,
                "phase_timings_path": str(phase_timings_path),
                "phase_timings_persisted": phase_timings_persisted,
                "total_elapsed_seconds": total_elapsed_seconds,
                "peak_rss_bytes": peak_rss_bytes,
                "peak_rss_scope": "current_process",
                "total_elapsed_scope": "current_pipeline_attempt",
                "phase_timings_scope": "current_pipeline_attempt",
                "performance_authority_gate_binding": (
                    dict(static_preflight[
                        "performance_authority_gate_binding"
                    ])
                    if static_preflight[
                        "performance_authority_gate_binding"
                    ] is not None
                    else None
                ),
                **activation_record,
                **checkpoint_receipt,
            }
            # The isolated performance worker still has to read the immutable
            # validation attachment and generation metrics after this call
            # returns. Its private root is removed as a whole by the harness,
            # so generation GC here would both race that read and save no
            # persistent disk space.
            if _should_prune_generation_after_result(
                performance_measurement_run=performance_measurement_run,
                checkpoint_receipt=checkpoint_receipt,
                candidate_discarded=candidate_discarded,
            ):
                _prune_unreferenced_generations_best_effort(output_root)
            return result
        finally:
            primary = sys.exc_info()[1]
            store_cleanup_actions = []
            if base_store_open:
                base_store_open = False
                store_cleanup_actions.append((
                    "close base binary fact store",
                    base_store.close,
                ))
            if current_store_open:
                current_store_open = False
                store_cleanup_actions.append((
                    "close current binary fact store",
                    current_store.close,
                ))
            _attempt_cleanups(store_cleanup_actions, primary=primary)


@contextmanager
def _pipeline_output_run_lock(output_root: Path):
    """Acquire the writer lock without relabeling failures from its body."""

    lock_path = output_root / ".binary-pipeline-run.lock"
    manager = exclusive_file_lock(
        lock_path,
        timeout_seconds=_PIPELINE_RUN_LOCK_TIMEOUT_SECONDS,
    )
    try:
        acquired_path = manager.__enter__()
    except TimeoutError as error:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_RUN_ALREADY_ACTIVE",
            str(lock_path),
        ) from error
    except OSError as error:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_RUN_LOCK_UNAVAILABLE",
            f"{lock_path}: {error}",
        ) from error
    try:
        yield acquired_path
    finally:
        manager.__exit__(*sys.exc_info())


def run_pipeline(
    config: Mapping[str, Any],
    *,
    output_root: str | Path,
    retain_validation_checkpoint: bool = False,
) -> dict[str, Any]:
    """Run one complete generation transaction as the output root's writer.

    Checkpoint reuse, rebinding, generation writes, validation and activation
    form one read-modify-write transaction.  Serializing only the workflow
    parent is insufficient because this module also has a standalone CLI; the
    lock therefore belongs to the pipeline output itself and is always taken,
    independent of environment flags or the caller used to reach this API.
    """

    resolved_output_root = _canonical_output_root_preserving_leaf(output_root)
    with _pipeline_output_run_lock(resolved_output_root):
        return _run_pipeline_under_lock(
            config,
            output_root=resolved_output_root,
            retain_validation_checkpoint=retain_validation_checkpoint,
        )


def _cli_attempt_progress(
    diagnostic_root: Path | None,
    attempt_identity: str,
) -> dict[str, Any]:
    """Return progress only when it was emitted by this CLI invocation."""

    if diagnostic_root is None:
        return {}
    progress_path = (
        diagnostic_root / "binary_observability" / "latest_in_progress.json"
    )
    try:
        with progress_path.open("rb") as handle:
            content = handle.read(_CLI_PROGRESS_MAX_BYTES + 1)
        if len(content) > _CLI_PROGRESS_MAX_BYTES:
            return {}
        candidate = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, TypeError, ValueError, RecursionError, MemoryError):
        # Progress is optional, untrusted observability.  A malformed numeric
        # value or excessive nesting must not break the failure reporter that
        # is trying to explain the primary pipeline error.
        return {}
    if (
        not isinstance(candidate, dict)
        or candidate.get("attempt_identity") != attempt_identity
    ):
        return {}
    bounded = _cli_bounded_json_value(
        candidate,
        max_depth=4,
        max_items=16,
        max_nodes=32,
        max_text_chars=1024,
    )
    return bounded if isinstance(bounded, dict) else {}


def _cli_type_name(value: Any) -> str:
    try:
        name = type(value).__name__
    except BaseException:
        name = "unknown"
    return str(name or "unknown")[:128]


def _cli_safe_error_text(error: Any, *, limit: int = 16000) -> str:
    try:
        detail = str(error)
    except BaseException as formatting_error:
        detail = (
            f"<{_cli_type_name(error)} detail unavailable: "
            f"{_cli_type_name(formatting_error)}>"
        )
    if len(detail) <= limit:
        return detail
    return detail[: max(limit - 14, 0)] + "...[truncated]"


def _cli_bounded_json_value(
    value: Any,
    *,
    max_depth: int = 6,
    max_items: int = 64,
    max_nodes: int = 512,
    max_text_chars: int = 16000,
) -> Any:
    """Return a bounded value that the standard JSON encoder always accepts."""

    remaining = [max(1, int(max_nodes))]

    def bounded_text(text: str) -> str:
        if len(text) <= max_text_chars:
            return text
        return text[: max(max_text_chars - 14, 0)] + "...[truncated]"

    def visit(item: Any, depth: int) -> Any:
        if remaining[0] <= 0:
            return {"value_status": "node_limit_exceeded"}
        remaining[0] -= 1
        if item is None or type(item) is bool:
            return item
        if type(item) is str:
            return bounded_text(item)
        if type(item) is int:
            if item.bit_length() <= 63:
                return item
            return {
                "value_status": "integer_out_of_range",
                "bit_length": min(item.bit_length(), 1_000_000_000),
            }
        if type(item) is float:
            if math.isfinite(item):
                return item
            return {"value_status": "non_finite_float"}
        if depth >= max_depth:
            return {
                "value_status": "depth_limit_exceeded",
                "value_type": _cli_type_name(item),
            }
        if type(item) is list or type(item) is tuple:
            values = [
                visit(child, depth + 1)
                for child in item[:max_items]
            ]
            if len(item) > max_items:
                values.append({
                    "value_status": "item_limit_exceeded",
                    "omitted_count": len(item) - max_items,
                })
            return values
        if type(item) is dict:
            result: dict[str, Any] = {}
            for index, (key, child) in enumerate(item.items()):
                if index >= max_items:
                    result["__truncated__"] = {
                        "value_status": "item_limit_exceeded",
                        "omitted_count": len(item) - max_items,
                    }
                    break
                if type(key) is not str:
                    normalized_key = f"__non_string_key_{index}__"
                else:
                    normalized_key = bounded_text(key)
                if normalized_key in result:
                    normalized_key = f"__duplicate_key_{index}__"
                result[normalized_key] = visit(child, depth + 1)
            return result
        if isinstance(item, os.PathLike):
            try:
                path_value = os.fspath(item)
            except BaseException:
                path_value = None
            if type(path_value) is str:
                return bounded_text(path_value)
        return {
            "value_status": "non_json_value_omitted",
            "value_type": _cli_type_name(item),
        }

    return visit(value, 0)


def _cli_core_result_receipt(result: Mapping[str, Any]) -> dict[str, Any]:
    """Expose a bounded receipt when result delivery fails after core success."""

    fields = (
        "schema",
        "result_generation_identity",
        "validation_run_identity",
        "validation_status",
        "active_generation_descriptor",
        "validation_checkpoint_retained",
        "validation_checkpoint_path",
        "activation_candidate_private",
        "activation_candidate_discarded",
        "activation_recapture_discarded",
        "activation_identity",
    )
    receipt: dict[str, Any] = {}
    for field in fields:
        try:
            present = field in result
            value = result[field] if present else None
        except BaseException as access_error:
            receipt[field] = {
                "value_status": "receipt_field_unavailable",
                "failure_type": _cli_type_name(access_error),
            }
            continue
        if present:
            receipt[field] = _cli_bounded_json_value(
                value,
                max_depth=2,
                max_items=8,
                max_nodes=16,
                max_text_chars=4096,
            )
    if receipt.get("activation_candidate_private") is True:
        disposition = "private_candidate_pending_parent_commit"
    elif receipt.get("activation_candidate_discarded") is True:
        disposition = "candidate_measurement_discarded"
    elif receipt.get("activation_recapture_discarded") is True:
        disposition = "release_recapture_discarded"
    elif (
        type(receipt.get("active_generation_descriptor")) is str
        and bool(receipt["active_generation_descriptor"])
    ):
        disposition = "active_generation_committed"
    else:
        disposition = "core_completed_without_active_descriptor_receipt"
    receipt["activation_disposition"] = disposition
    return receipt


def _cli_failure_payload(
    error: BaseException,
    *,
    diagnostic_root: Path | None,
    attempt_identity: str,
    core_result: Mapping[str, Any] | None = None,
    failure_stage: str = "core_transaction",
) -> dict[str, Any]:
    detail = _cli_safe_error_text(error)
    cause: Any = None
    try:
        parsed = json.loads(detail)
    except (TypeError, ValueError, RecursionError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        cause = _cli_bounded_json_value(
            parsed,
            max_depth=4,
            max_items=16,
            max_nodes=32,
            max_text_chars=2048,
        )
    progress = _cli_attempt_progress(diagnostic_root, attempt_identity)
    core_succeeded = core_result is not None
    if core_succeeded:
        reason_code = (
            "BINARY_PIPELINE_RESULT_SERIALIZATION_FAILED"
            if failure_stage == "result_serialization"
            else "BINARY_PIPELINE_RESULT_PERSIST_FAILED"
        )
        cause = {
            "failure_stage": failure_stage,
            "failure_type": _cli_type_name(error),
            "detail": detail,
        }
    elif isinstance(error, BinaryFirstContractError):
        reason_code = _cli_safe_error_text(error.reason_code, limit=256)
    elif isinstance(error, MemoryError):
        reason_code = "BINARY_PIPELINE_MEMORY_EXHAUSTED"
    else:
        reason_code = "BINARY_PIPELINE_UNHANDLED_FAILURE"
    return {
        "schema": "java-upgrade-analyzer.binary-pipeline-failure.v1",
        "status": "failed",
        "reason_code": reason_code,
        "failure_type": _cli_type_name(error),
        "detail": detail,
        "cause": cause,
        "failed_phase": (
            "result_delivery"
            if core_succeeded
            else str(progress.get("current_phase") or "")
        ),
        "last_progress": progress,
        "attempt_identity": attempt_identity,
        "progress_bound_to_attempt": bool(progress),
        "core_transaction_status": "succeeded" if core_succeeded else "failed",
        "core_transaction_succeeded": core_succeeded,
        "core_result_receipt": (
            _cli_core_result_receipt(core_result)
            if core_result is not None else None
        ),
        "traceback": _cli_safe_traceback(),
        "fail_closed": True,
    }


def _cli_safe_traceback() -> str:
    try:
        value = traceback.format_exc()
    except BaseException:
        return ""
    return value[-32000:]


def _emit_cli_failure(
    failure: Mapping[str, Any],
    *,
    diagnostic_root: Path | None,
    result_json: str,
    prior_result_sink_error: BaseException | None = None,
) -> int:
    """Best-effort persistence that never hides the primary public failure."""

    sanitized = _cli_bounded_json_value(dict(failure))
    detailed_failure = sanitized if isinstance(sanitized, dict) else {
        "schema": "java-upgrade-analyzer.binary-pipeline-failure.v1",
        "status": "failed",
        "reason_code": "BINARY_PIPELINE_FAILURE_REPORT_INVALID",
        "fail_closed": True,
    }
    public_failure = {
        key: value
        for key, value in detailed_failure.items()
        if key != "traceback"
    }
    if result_json:
        if prior_result_sink_error is None:
            detailed_failure["result_json_persisted"] = True
            public_failure["result_json_persisted"] = True
            encoded = json.dumps(
                public_failure,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
            try:
                _write_text_atomic_durable(result_json, encoded)
            except Exception as persist_error:
                prior_result_sink_error = persist_error
        if prior_result_sink_error is not None:
            persist_failure = {
                "failure_type": _cli_type_name(prior_result_sink_error),
                "detail": _cli_safe_error_text(prior_result_sink_error),
            }
            detailed_failure["result_json_persisted"] = False
            detailed_failure["result_json_persist_error"] = persist_failure
            public_failure["result_json_persisted"] = False
            public_failure["result_json_persist_error"] = persist_failure
    public_encoded = json.dumps(
        public_failure,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    diagnostic_path = (
        diagnostic_root / "binary_observability" / "latest_failure.json"
        if diagnostic_root is not None else None
    )
    if diagnostic_path is not None:
        # Internal diagnostics are non-authoritative and must obey the same
        # physical-directory boundary as progress.  In particular, never
        # follow a replaced/symlinked observability leaf while reporting the
        # storage failure that rejected it.
        try:
            _write_non_authoritative_json(diagnostic_path, detailed_failure)
        except Exception:
            # stderr remains the mandatory public failure channel.
            pass
    print(public_encoded, end="", file=sys.stderr)
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the binary-first analysis generation")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--result-json", default="")
    parser.add_argument(
        "--retain-validation-checkpoint",
        action="store_true",
        help=(
            "leave the validated activation checkpoint pending so the "
            "workflow parent can gate and commit the bound Step4 reports"
        ),
    )
    args = parser.parse_args(argv)
    attempt_identity = hashlib.sha256(os.urandom(32)).hexdigest()
    attempt_token = _CLI_PROGRESS_ATTEMPT_CONTEXT.set(attempt_identity)
    try:
        try:
            diagnostic_root: Path | None = (
                _canonical_output_root_preserving_leaf(args.output_root)
            )
        except (BinaryPipelineError, OSError, RuntimeError, ValueError):
            # An unsafe output-root leaf must not be resolved and reused by the
            # failure reporter. stderr and an explicit result JSON remain usable.
            diagnostic_root = None
        try:
            retain_checkpoint = bool(args.retain_validation_checkpoint)
            result = run_pipeline(
                _load_json(args.config),
                output_root=args.output_root,
                retain_validation_checkpoint=retain_checkpoint,
            )
        except Exception as error:
            return _emit_cli_failure(
                _cli_failure_payload(
                    error,
                    diagnostic_root=diagnostic_root,
                    attempt_identity=attempt_identity,
                ),
                diagnostic_root=diagnostic_root,
                result_json=args.result_json,
            )
        try:
            encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        except Exception as error:
            return _emit_cli_failure(
                _cli_failure_payload(
                    error,
                    diagnostic_root=diagnostic_root,
                    attempt_identity=attempt_identity,
                    core_result=result,
                    failure_stage="result_serialization",
                ),
                diagnostic_root=diagnostic_root,
                result_json=args.result_json,
            )
        if args.result_json:
            try:
                _write_text_atomic_durable(args.result_json, encoded)
            except Exception as error:
                return _emit_cli_failure(
                    _cli_failure_payload(
                        error,
                        diagnostic_root=diagnostic_root,
                        attempt_identity=attempt_identity,
                        core_result=result,
                        failure_stage="result_persistence",
                    ),
                    diagnostic_root=diagnostic_root,
                    result_json=args.result_json,
                    prior_result_sink_error=error,
                )
        print(encoded, end="")
        return 0
    finally:
        _CLI_PROGRESS_ATTEMPT_CONTEXT.reset(attempt_token)


if __name__ == "__main__":
    raise SystemExit(main())
