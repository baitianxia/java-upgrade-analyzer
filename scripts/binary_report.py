#!/usr/bin/env python3
"""Publish native Step4/5/6 reports from one validated binary generation.

Published files are terminal views for users and gates.  They never become
inputs to the binary graph and preserve the four independent result axes.
"""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import threading
import uuid
from typing import Any, Callable, Iterable, Mapping

from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_output import (
    BinaryOutputError,
    is_complete_v3_validation_result,
    read_active_binary_generation,
    read_pending_binary_generation,
)
from analysis_contract import derive_coverage_report
from csv_io import open_csv_read, open_csv_write
from path_runtime import short_temporary_directory
from process_lock import exclusive_file_lock
from s4_contract import ALL_CHANGED_APIS_FIELDS, DEFAULT_SEVERITY, make_per_dependency_dirname
import s6_report
from signature_utils import jvm_method_parameter_signature
from streaming_json import fsync_directory as _fsync_directory_durable
BINARY_OUTPUT_RELATIVE_PATH = Path(".runtime/binary_authority")
ACTIVE_GENERATION_SCHEMA = "java-upgrade-analyzer.active-binary-generation.v1"
RESULT_GENERATION_SCHEMA = "java-upgrade-analyzer.binary-result-generation.v1"
VALIDATION_RESULT_SCHEMA = "java-upgrade-analyzer.binary-validation-result.v1"
_RESULT_GENERATION_SNAPSHOT_LAYERS = frozenset({
    "decision",
    "assessment",
    "formal_projection",
    "candidate_projection",
})
_REQUIRED_CORE_GENERATION_SIDECARS = frozenset({
    "binary_decisions.json",
    "binary_projections.json",
    "binary_formal_results.json",
    "binary_candidate_results.json",
    "binary_entrypoints.json",
    "binary_coverage.json",
    "binary_summary.json",
    "binary_formal_results.csv",
})
_REPORT_PUBLICATION_TRANSACTION_SCHEMA = (
    "java-upgrade-analyzer.binary-report-publication-transaction.v3"
)
_LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA = (
    "java-upgrade-analyzer.binary-report-publication-transaction.v2"
)
_REPORT_PUBLICATION_SEALED_CONTEXT_BINDING_FIELDS = frozenset({
    "result_generation_identity",
    "validation_run_identity",
    "validation_result_sha256",
})
_REPORT_PUBLICATION_CONTEXT_BINDING_FIELDS = frozenset({
    *_REPORT_PUBLICATION_SEALED_CONTEXT_BINDING_FIELDS,
    "activation_identity",
})
_REPORT_PUBLICATION_SEALED_DOWNSTREAM_CONTEXT_BINDING_FIELDS = frozenset({
    *_REPORT_PUBLICATION_SEALED_CONTEXT_BINDING_FIELDS,
    "upstream_publication_receipt_identity",
    "publication_input_identity",
})
_REPORT_PUBLICATION_DOWNSTREAM_CONTEXT_BINDING_FIELDS = frozenset({
    *_REPORT_PUBLICATION_CONTEXT_BINDING_FIELDS,
    "upstream_publication_receipt_identity",
    "publication_input_identity",
})
_REPORT_IMPLEMENTATION_IDENTITY_FIELD = "report_implementation_identity"
_REPORT_GATE_RECEIPT_SCHEMA = (
    "java-upgrade-analyzer.binary-report-gate-receipt.v1"
)
_FORMAL_PUBLICATION_GATES = {
    "step4": "binary_generation",
    "step5": "binary_report",
    "step6": "binary_final_report",
}


class _ReportPrepareCapability:
    """One in-process, single-use authority for a private report prepare.

    The workflow orchestrator already owns the report mutation lock in its
    parent process.  Re-entering that lock from a report subprocess deadlocks,
    while exposing the prepare-only CLI lets an unrelated process bypass the
    lock.  A context-local capability keeps the mutation in the lock-owning
    process and binds it to one exact report root and phase.
    """

    __slots__ = (
        "authority",
        "report_root",
        "phase",
        "process_id",
        "thread_id",
        "consumed",
    )

    def __init__(self, report_root: Path, phase: str) -> None:
        self.authority = _REPORT_PREPARE_CAPABILITY_AUTHORITY
        self.report_root = report_root
        self.phase = phase
        self.process_id = os.getpid()
        self.thread_id = threading.get_ident()
        self.consumed = False


_REPORT_PREPARE_CAPABILITY_AUTHORITY = object()
_REPORT_PREPARE_CAPABILITY_CONTEXT: ContextVar[
    _ReportPrepareCapability | None
] = ContextVar("binary_report_prepare_capability", default=None)
_REPORT_COMMITTED_RECEIPT_SCHEMA = (
    "java-upgrade-analyzer.binary-report-committed-receipt.v1"
)
_GLOBAL_RELEASE_SCHEMA = "java-upgrade-analyzer.global-report-release.v1"
_REPORT_PUBLICATION_PROTOCOL_MARKER_SCHEMA = (
    "java-upgrade-analyzer.report-publication-protocol.v1"
)
_GLOBAL_RELEASE_STAGE_FIELDS = frozenset({
    "status",
    "transaction_id",
    "committed_receipt_identity",
    "published_content_identity",
    "publication_input_identity",
    "upstream_publication_receipt_identity",
})
_REPORT_PUBLICATION_BINDING_FIELDS = frozenset({
    *_REPORT_PUBLICATION_CONTEXT_BINDING_FIELDS,
    _REPORT_IMPLEMENTATION_IDENTITY_FIELD,
})
_REPORT_PUBLICATION_SEALED_BINDING_FIELDS = frozenset({
    *_REPORT_PUBLICATION_SEALED_CONTEXT_BINDING_FIELDS,
    _REPORT_IMPLEMENTATION_IDENTITY_FIELD,
})
_REPORT_PUBLICATION_SEALED_DOWNSTREAM_BINDING_FIELDS = frozenset({
    *_REPORT_PUBLICATION_SEALED_DOWNSTREAM_CONTEXT_BINDING_FIELDS,
    _REPORT_IMPLEMENTATION_IDENTITY_FIELD,
})
_REPORT_PUBLICATION_DOWNSTREAM_BINDING_FIELDS = frozenset({
    *_REPORT_PUBLICATION_DOWNSTREAM_CONTEXT_BINDING_FIELDS,
    _REPORT_IMPLEMENTATION_IDENTITY_FIELD,
})
_REPORT_PUBLICATION_PROTOCOL_POLICY_VERSION = (
    "binary-step4-report-publication-protocol-v1"
)


class BinaryReportError(BinaryFirstContractError):
    pass


def _require_formal_publication_gate(stage: str, gate_name: str) -> str:
    expected = _FORMAL_PUBLICATION_GATES.get(str(stage or ""))
    if expected is None or str(gate_name or "") != expected:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_GATE_POLICY_INVALID",
            f"{stage}:{gate_name}",
        )
    return expected


def _require_pending_publication_candidate(
    stage: str, result: Mapping[str, Any]
) -> Mapping[str, Any]:
    transaction = dict((result or {}).get("publication_transaction") or {})
    if (
        (result or {}).get("phase") != stage
        or transaction.get("state") != "pending_gate"
        or transaction.get("gate_receipt") is not None
        or (result or {}).get("publication_receipt") is not None
        or (result or {}).get("global_release") is not None
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_PREPARE_CONTRACT_INVALID",
            str(stage),
        )
    return result


@contextmanager
def _report_publication_prepare_capability(
    report_dir: str | Path,
    phase: str,
):
    """Authorize exactly one prepare call in this process and thread.

    This is deliberately a private Python boundary, not a CLI/environment
    protocol.  ``run_step`` enters it only after proving that its workflow
    mutation lock is held; standalone publishers enter it only inside their
    own workflow-lock context.  The prepare function consumes the capability
    before reading or mutating publication state.
    """

    normalized_phase = str(phase or "").strip()
    if normalized_phase not in _FORMAL_PUBLICATION_GATES:
        raise BinaryReportError(
            "BINARY_REPORT_PREPARE_CAPABILITY_PHASE_INVALID",
            normalized_phase,
        )
    if _REPORT_PREPARE_CAPABILITY_CONTEXT.get() is not None:
        raise BinaryReportError(
            "BINARY_REPORT_PREPARE_CAPABILITY_NESTED",
            normalized_phase,
        )
    capability = _ReportPrepareCapability(
        Path(report_dir).resolve(), normalized_phase
    )
    token = _REPORT_PREPARE_CAPABILITY_CONTEXT.set(capability)
    try:
        yield
    finally:
        _REPORT_PREPARE_CAPABILITY_CONTEXT.reset(token)


def _consume_report_publication_prepare_capability(
    report_dir: str | Path,
    phase: str,
) -> None:
    """Consume and validate the current prepare authority before mutation."""

    capability = _REPORT_PREPARE_CAPABILITY_CONTEXT.get()
    if not isinstance(capability, _ReportPrepareCapability) or (
        capability.authority is not _REPORT_PREPARE_CAPABILITY_AUTHORITY
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PREPARE_CAPABILITY_REQUIRED",
            str(phase or ""),
        )
    if capability.consumed:
        raise BinaryReportError(
            "BINARY_REPORT_PREPARE_CAPABILITY_REPLAYED",
            str(phase or ""),
        )

    # An attempted use consumes the grant even when its binding is wrong.  A
    # caller cannot probe one root/phase and then reuse the same authority for
    # a different mutation.
    capability.consumed = True
    expected_root = Path(report_dir).resolve()
    normalized_phase = str(phase or "").strip()
    if (
        capability.report_root != expected_root
        or capability.phase != normalized_phase
        or capability.process_id != os.getpid()
        or capability.thread_id != threading.get_ident()
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PREPARE_CAPABILITY_BINDING_MISMATCH",
            json.dumps(
                {
                    "expected_report_root": str(capability.report_root),
                    "actual_report_root": str(expected_root),
                    "expected_phase": capability.phase,
                    "actual_phase": normalized_phase,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
        )


@contextmanager
def _classified_report_lock(lock_path: Path, timeout_reason_code: str):
    """Translate only lock-acquisition timeout, never a body failure."""

    manager = exclusive_file_lock(lock_path, timeout_seconds=5.0)
    try:
        acquired = manager.__enter__()
    except TimeoutError as error:
        raise BinaryReportError(
            timeout_reason_code, str(lock_path)
        ) from error
    try:
        yield acquired
    finally:
        manager.__exit__(*sys.exc_info())


@contextmanager
def _standalone_report_workflow_lock(report_dir: str | Path):
    """Serialize supported direct publishers with the workflow orchestrator."""

    lock_path = _report_workflow_lock_path(report_dir)
    with _classified_report_lock(
        lock_path, "BINARY_REPORT_WORKFLOW_MUTATION_ALREADY_ACTIVE"
    ):
        yield


def _report_workflow_lock_path(report_dir: str | Path) -> Path:
    return (
        Path(report_dir).resolve()
        / ".runtime"
        / "state"
        / ".workflow-mutation.lock"
    )


@contextmanager
def _active_generation_publication_lock(report_dir: str | Path):
    """Prevent active-generation CAS changes during a report commit window."""

    lock_path = (
        Path(report_dir).resolve()
        / BINARY_OUTPUT_RELATIVE_PATH
        / ".active-generation.lock"
    )
    with _classified_report_lock(
        lock_path, "BINARY_ACTIVE_GENERATION_LOCK_TIMEOUT"
    ):
        yield


@contextmanager
def _report_workflow_read_lock(report_dir: str | Path):
    """Hold the workflow lock for a public read/verification transaction."""

    lock_path = _report_workflow_lock_path(report_dir)
    with _classified_report_lock(
        lock_path, "BINARY_REPORT_WORKFLOW_MUTATION_ALREADY_ACTIVE"
    ):
        yield


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


def _report_runtime_identity() -> dict[str, Any]:
    return {
        "implementation": str(sys.implementation.name),
        "cache_tag": str(sys.implementation.cache_tag or ""),
        "version": [
            int(sys.version_info.major),
            int(sys.version_info.minor),
            int(sys.version_info.micro),
        ],
        "platform": str(sys.platform),
    }


_CAPTURED_REPORT_RUNTIME_IDENTITY = _report_runtime_identity()
_CAPTURED_REPORT_IMPLEMENTATION_IDENTITY = canonical_identity(
    "binary_report_protocol_metadata_identity",
    {
        "policy_version": _REPORT_PUBLICATION_PROTOCOL_POLICY_VERSION,
        "python_runtime": _CAPTURED_REPORT_RUNTIME_IDENTITY,
    },
    schema_version="1",
)


def report_implementation_identity() -> str:
    """Return diagnostic provenance captured when this process started.

    Report correctness is established by the published content digest and its
    generation/validation binding.  Re-hashing source files here added a
    second, unrelated runtime gate: an editor or deployment replacing source
    files could invalidate an already-rendered, content-bound transaction.
    Keep the identity as provenance only.
    """

    return _CAPTURED_REPORT_IMPLEMENTATION_IDENTITY


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


def _unlink_missing_ok(path: str | Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryReportError(
            "BINARY_REPORT_JSON_INVALID", f"{path}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise BinaryReportError(
            "BINARY_REPORT_JSON_INVALID", f"{path}: root must be an object"
        )
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_sha256_identity(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _result_generation_identity_from_manifest(
    manifest: Mapping[str, Any],
) -> str:
    snapshots = manifest.get("active_snapshot_identities")
    sidecars = manifest.get("sidecar_content_identities")
    policies = manifest.get("policy_identities")
    if (
        manifest.get("authority") != "binary_first"
        or not isinstance(manifest.get("analysis_context_identity"), str)
        or not manifest.get("analysis_context_identity")
        or not isinstance(manifest.get("trace_result_set_digest"), str)
        or not manifest.get("trace_result_set_digest")
        or not isinstance(snapshots, Mapping)
        or set(snapshots) != _RESULT_GENERATION_SNAPSHOT_LAYERS
        or not all(
            isinstance(value, str) and value for value in snapshots.values()
        )
        or not isinstance(sidecars, Mapping)
        or not _REQUIRED_CORE_GENERATION_SIDECARS.issubset(sidecars)
        or not isinstance(policies, Mapping)
    ):
        return ""
    return canonical_identity(
        "result_generation_identity",
        {
            "analysis_context_identity": manifest["analysis_context_identity"],
            "authority": "binary_first",
            "snapshot_identities": dict(snapshots),
            "trace_result_set_digest": manifest["trace_result_set_digest"],
            "sidecar_content_identities": dict(sidecars),
            "policy_identities": dict(policies),
        },
        schema_version="1",
    )


def _safe_sidecar_name(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
        and Path(value).name == value
    )


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        primary = sys.exc_info()[1]
        actions = []
        if os.path.exists(temporary):
            actions.append((
                f"unlink temporary report JSON {temporary}",
                lambda: _unlink_missing_ok(temporary),
            ))
        _attempt_cleanups(actions, primary=primary)


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        primary = sys.exc_info()[1]
        actions = []
        if os.path.exists(temporary):
            actions.append((
                f"unlink temporary report text {temporary}",
                lambda: _unlink_missing_ok(temporary),
            ))
        _attempt_cleanups(actions, primary=primary)


def _fsync_directory(path: Path) -> bool:
    return _fsync_directory_durable(path)


def _generation_within_root(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise BinaryReportError(
            "BINARY_ACTIVE_GENERATION_PATH_ESCAPE", str(candidate)
        ) from error
    return candidate


def load_validated_generation(
    report_dir: str | Path,
    *,
    candidate_activation_identity: str = "",
) -> dict[str, Any]:
    report = Path(report_dir).resolve()
    root = report / BINARY_OUTPUT_RELATIVE_PATH
    try:
        if candidate_activation_identity:
            active = read_pending_binary_generation(
                root,
                expected_activation_identity=candidate_activation_identity,
            )
        else:
            active = read_active_binary_generation(root)
    except BinaryOutputError as error:
        source_reason = str(getattr(error, "reason_code", "") or "")
        if source_reason == "BINARY_GENERATION_MANIFEST_INVALID":
            reason_code = "BINARY_GENERATION_MANIFEST_MISMATCH"
        elif source_reason in {
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID",
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_FORBIDDEN",
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_REQUIRED",
        }:
            # These failures belong to the immutable generation's release
            # authority, not to the active descriptor that merely references
            # it.  Preserve their taxonomy for actionable diagnostics.
            reason_code = source_reason
        else:
            reason_code = "BINARY_ACTIVE_GENERATION_INVALID"
        raise BinaryReportError(
            reason_code, str(error)
        ) from error
    if active.get("schema") != ACTIVE_GENERATION_SCHEMA:
        raise BinaryReportError(
            "BINARY_ACTIVE_GENERATION_INVALID", str(active.get("schema") or "")
        )
    generation_identity = str(active.get("result_generation_identity") or "")
    generation = _generation_within_root(root, str(active.get("generation_directory") or ""))
    expected_generation = root / "binary_generations" / generation_identity
    try:
        generations_root = (root / "binary_generations").resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BinaryReportError(
            "BINARY_ACTIVE_GENERATION_INVALID", str(generation)
        ) from error
    if (
        not _is_sha256_identity(generation_identity)
        or generations_root != root / "binary_generations"
        or generation != expected_generation
        or generation.name != generation_identity
        or generation.is_symlink()
        or not generation.is_dir()
    ):
        raise BinaryReportError(
            "BINARY_ACTIVE_GENERATION_INVALID", str(generation)
        )
    manifest = _load_json(generation / "result_generation.json")
    if (
        manifest.get("schema") != RESULT_GENERATION_SCHEMA
        or manifest.get("result_generation_identity") != generation_identity
        or manifest.get("authority") != "binary_first"
        or _result_generation_identity_from_manifest(manifest)
        != generation_identity
    ):
        raise BinaryReportError(
            "BINARY_GENERATION_MANIFEST_MISMATCH", generation_identity
        )
    sidecar_identities = manifest.get("sidecar_content_identities")
    if not isinstance(sidecar_identities, Mapping):
        raise BinaryReportError(
            "BINARY_GENERATION_MANIFEST_MISMATCH", generation_identity
        )
    for name, expected in sidecar_identities.items():
        if not _safe_sidecar_name(name) or not _is_sha256_identity(expected):
            raise BinaryReportError(
                "BINARY_GENERATION_SIDECAR_NAME_INVALID", str(name)
            )
        path = generation / str(name)
        if path.is_symlink() or not path.is_file() or _sha256(path) != expected:
            raise BinaryReportError(
                "BINARY_GENERATION_SIDECAR_INTEGRITY_FAILED", str(path)
            )
    validation_identity = active.get("validation_run_identity")
    validation_sha256 = active.get("validation_result_sha256")
    if (
        not _is_sha256_identity(validation_identity)
        or not _is_sha256_identity(validation_sha256)
    ):
        raise BinaryReportError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
            str(validation_identity or ""),
        )
    validation_dir = generation / "validation"
    validation_path = validation_dir / f"{validation_identity}.json"
    try:
        validation_dir_resolved = validation_dir.resolve(strict=True)
        validation_path_resolved = validation_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BinaryReportError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID", str(validation_path)
        ) from error
    if (
        validation_dir_resolved != validation_dir
        or validation_path_resolved != validation_path
        or validation_path_resolved.parent != validation_dir_resolved
        or validation_path.is_symlink()
        or not validation_path.is_file()
    ):
        raise BinaryReportError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID", str(validation_path)
        )
    if _sha256(validation_path) != validation_sha256:
        raise BinaryReportError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INTEGRITY_FAILED",
            str(validation_path),
        )
    validation = _load_json(validation_path)
    if (
        validation.get("validation_run_identity") != validation_identity
        or not is_complete_v3_validation_result(validation, manifest)
    ):
        raise BinaryReportError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID", str(validation_path)
        )
    source_explanations_path = generation / "binary_source_explanations.json"
    source_attestation_path = generation / "binary_source_attestation.json"

    def optional_bound_sidecar(
        name: str, default: Mapping[str, Any],
    ) -> dict[str, Any]:
        path = generation / name
        if name in sidecar_identities:
            return _load_json(path)
        if path.is_symlink() or path.exists():
            raise BinaryReportError(
                "BINARY_GENERATION_UNDECLARED_SIDECAR", str(path)
            )
        return dict(default)

    return {
        "report_dir": report,
        "active": active,
        "manifest": manifest,
        "validation": validation,
        "generation": generation,
        "summary": _load_json(generation / "binary_summary.json"),
        "decisions": _load_json(generation / "binary_decisions.json"),
        "projections": _load_json(generation / "binary_projections.json"),
        "formal": _load_json(generation / "binary_formal_results.json"),
        "candidate": _load_json(generation / "binary_candidate_results.json"),
        "coverage": _load_json(generation / "binary_coverage.json"),
        "source_explanations": optional_bound_sidecar(
            source_explanations_path.name,
            {
                "authority": "not_provided",
                "declarations": [],
                "candidate_relationships": [],
            },
        ),
        "source_attestation": optional_bound_sidecar(
            source_attestation_path.name,
            {"coverage_gaps": [], "language_file_counts": {}},
        ),
    }


def _stage_directory(
    destination: Path,
    writer,
    *,
    trusted_root: Path | None = None,
) -> None:
    _stage_directory_group((
        (Path(destination), lambda stage, _prepared: writer(stage)),
    ), trusted_root=trusted_root)


def _publication_path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _remove_publication_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _report_file_sha256(path: Path, *, make_durable: bool = False) -> str:
    """Hash a private regular report file without following a raced link/FIFO."""

    try:
        initial_stat = os.lstat(path)
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", f"{path}: {error}"
        ) from error
    if (
        stat.S_ISLNK(initial_stat.st_mode)
        or not stat.S_ISREG(initial_stat.st_mode)
        or initial_stat.st_nlink != 1
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
            f"report entry is not a private regular file: {path}",
        )
    expected_identity = (int(initial_stat.st_dev), int(initial_stat.st_ino))
    descriptor = None
    try:
        descriptor = os.open(
            path,
            (
                os.O_RDWR
                if os.name == "nt" and make_durable
                else os.O_RDONLY
            )
            | int(getattr(os, "O_NOFOLLOW", 0) or 0)
            | int(getattr(os, "O_NONBLOCK", 0) or 0)
            | int(getattr(os, "O_BINARY", 0) or 0),
        )
        opened_stat = os.fstat(descriptor)
        current_stat = os.lstat(path)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or opened_stat.st_nlink != 1
            or current_stat.st_nlink != 1
            or (int(opened_stat.st_dev), int(opened_stat.st_ino))
            != expected_identity
            or (int(current_stat.st_dev), int(current_stat.st_ino))
            != expected_identity
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                f"report entry changed while opening: {path}",
            )
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
            if make_durable:
                os.fsync(handle.fileno())
            final_opened_stat = os.fstat(handle.fileno())
            final_path_stat = os.lstat(path)
            if (
                (int(final_opened_stat.st_dev), int(final_opened_stat.st_ino))
                != expected_identity
                or (int(final_path_stat.st_dev), int(final_path_stat.st_ino))
                != expected_identity
                or final_opened_stat.st_nlink != 1
                or final_path_stat.st_nlink != 1
                or final_opened_stat.st_size != opened_stat.st_size
                or final_opened_stat.st_mtime_ns != opened_stat.st_mtime_ns
                or (
                    os.name != "nt"
                    and final_opened_stat.st_ctime_ns
                    != opened_stat.st_ctime_ns
                )
            ):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    f"report entry changed while hashing: {path}",
                )
        return digest.hexdigest()
    except BinaryReportError:
        raise
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", f"{path}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            _attempt_cleanups(
                ((f"close report file descriptor for {path}", lambda: os.close(descriptor)),),
                primary=sys.exc_info()[1],
            )


def _directory_content_identity(
    root: Path,
    *,
    make_durable: bool = False,
) -> str:
    """Return a deterministic identity for every path, mode and file byte."""

    try:
        root_stat = os.lstat(root)
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", f"{root}: {error}"
        ) from error
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
            f"report root is not a directory: {root}",
        )

    entries: list[dict[str, Any]] = []

    def visit(directory: Path, relative: Path) -> None:
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
        except OSError as error:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                f"{directory}: {error}",
            ) from error
        for child in children:
            child_path = directory / child.name
            child_relative = relative / child.name
            try:
                child_stat = child.stat(follow_symlinks=False)
            except OSError as error:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    f"{child_path}: {error}",
                ) from error
            if stat.S_ISLNK(child_stat.st_mode):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    f"report tree contains a symlink: {child_path}",
                )
            relative_text = child_relative.as_posix()
            if stat.S_ISDIR(child_stat.st_mode):
                entries.append({
                    "path": relative_text,
                    "type": "directory",
                    "mode": stat.S_IMODE(child_stat.st_mode),
                })
                visit(child_path, child_relative)
            elif stat.S_ISREG(child_stat.st_mode):
                entries.append({
                    "path": relative_text,
                    "type": "file",
                    "mode": stat.S_IMODE(child_stat.st_mode),
                    "sha256": _report_file_sha256(
                        child_path, make_durable=make_durable
                    ),
                })
            else:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    f"report tree contains a non-regular entry: {child_path}",
                )
        if make_durable:
            _fsync_directory(directory)

    visit(root, Path())
    payload = json.dumps(
        entries,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _copy_report_file_secure(source: Path, destination: Path) -> None:
    """Copy one publication file without following a raced link or FIFO."""

    try:
        initial_stat = os.lstat(source)
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", f"{source}: {error}"
        ) from error
    if not stat.S_ISREG(initial_stat.st_mode) or initial_stat.st_nlink != 1:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
            f"report entry is not a private regular file: {source}",
        )
    identity = (int(initial_stat.st_dev), int(initial_stat.st_ino))
    source_descriptor = None
    destination_descriptor = None
    try:
        source_descriptor = os.open(
            source,
            os.O_RDONLY
            | int(getattr(os, "O_NOFOLLOW", 0) or 0)
            | int(getattr(os, "O_NONBLOCK", 0) or 0)
            | int(getattr(os, "O_BINARY", 0) or 0),
        )
        opened_stat = os.fstat(source_descriptor)
        current_stat = os.lstat(source)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or opened_stat.st_nlink != 1
            or current_stat.st_nlink != 1
            or (int(opened_stat.st_dev), int(opened_stat.st_ino)) != identity
            or (int(current_stat.st_dev), int(current_stat.st_ino)) != identity
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                f"report entry changed while opening: {source}",
            )
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | int(getattr(os, "O_BINARY", 0) or 0),
            0o600,
        )
        while True:
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            offset = 0
            while offset < len(block):
                offset += os.write(destination_descriptor, block[offset:])
        os.fchmod(destination_descriptor, stat.S_IMODE(opened_stat.st_mode))
        os.fsync(destination_descriptor)
        final_opened_stat = os.fstat(source_descriptor)
        final_path_stat = os.lstat(source)
        if (
            (int(final_opened_stat.st_dev), int(final_opened_stat.st_ino))
            != identity
            or (int(final_path_stat.st_dev), int(final_path_stat.st_ino))
            != identity
            or final_opened_stat.st_nlink != 1
            or final_path_stat.st_nlink != 1
            or final_opened_stat.st_size != opened_stat.st_size
            or final_opened_stat.st_mtime_ns != opened_stat.st_mtime_ns
            or (
                os.name != "nt"
                and final_opened_stat.st_ctime_ns != opened_stat.st_ctime_ns
            )
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                f"report entry changed while copying: {source}",
            )
    except BinaryReportError:
        raise
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", f"{source}: {error}"
        ) from error
    finally:
        primary = sys.exc_info()[1]
        cleanups = []
        if destination_descriptor is not None:
            cleanups.append((
                f"close snapshot destination {destination}",
                lambda: os.close(destination_descriptor),
            ))
        if source_descriptor is not None:
            cleanups.append((
                f"close snapshot source {source}",
                lambda: os.close(source_descriptor),
            ))
        _attempt_cleanups(tuple(cleanups), primary=primary)


def _copy_report_directory_secure(
    source: Path,
    destination: Path,
    *,
    destination_exists: bool = False,
) -> None:
    """Materialize an immutable reader snapshot of a publication directory."""

    try:
        initial_stat = os.lstat(source)
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", f"{source}: {error}"
        ) from error
    if stat.S_ISLNK(initial_stat.st_mode) or not stat.S_ISDIR(
        initial_stat.st_mode
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
            f"report root is not a directory: {source}",
        )
    identity = (int(initial_stat.st_dev), int(initial_stat.st_ino))
    try:
        if destination_exists:
            destination_stat = os.lstat(destination)
            if (
                stat.S_ISLNK(destination_stat.st_mode)
                or not stat.S_ISDIR(destination_stat.st_mode)
                or any(destination.iterdir())
            ):
                raise OSError("snapshot destination is not an empty directory")
        else:
            destination.mkdir(mode=0o700)
        with os.scandir(source) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            child_source = source / child.name
            child_destination = destination / child.name
            child_stat = child.stat(follow_symlinks=False)
            if stat.S_ISLNK(child_stat.st_mode):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    f"report tree contains a symlink: {child_source}",
                )
            if stat.S_ISDIR(child_stat.st_mode):
                _copy_report_directory_secure(
                    child_source, child_destination
                )
                os.chmod(
                    child_destination, stat.S_IMODE(child_stat.st_mode)
                )
            elif stat.S_ISREG(child_stat.st_mode):
                _copy_report_file_secure(child_source, child_destination)
            else:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    f"report tree contains a non-regular entry: {child_source}",
                )
        _fsync_directory(destination)
        final_stat = os.lstat(source)
        if (
            (int(final_stat.st_dev), int(final_stat.st_ino)) != identity
            or final_stat.st_mtime_ns != initial_stat.st_mtime_ns
            or (
                os.name != "nt"
                and final_stat.st_ctime_ns != initial_stat.st_ctime_ns
            )
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                f"report directory changed while copying: {source}",
            )
    except BinaryReportError:
        raise
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", f"{source}: {error}"
        ) from error


def _new_publication_binding(
    value: Mapping[str, Any] | None,
) -> dict[str, str]:
    """Bind every new transaction to this loaded report implementation."""

    if value is None:
        raw: dict[str, Any] = {}
    elif isinstance(value, Mapping):
        raw = dict(value)
    else:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            "transaction binding must be an object",
        )
    current_identity = report_implementation_identity()
    # A caller-provided implementation identity is diagnostic metadata, not
    # publication authority.  Record the renderer actually loaded here.
    raw.pop(_REPORT_IMPLEMENTATION_IDENTITY_FIELD, None)
    if raw and set(raw) not in {
        _REPORT_PUBLICATION_SEALED_CONTEXT_BINDING_FIELDS,
        _REPORT_PUBLICATION_CONTEXT_BINDING_FIELDS,
        _REPORT_PUBLICATION_SEALED_DOWNSTREAM_CONTEXT_BINDING_FIELDS,
        _REPORT_PUBLICATION_DOWNSTREAM_CONTEXT_BINDING_FIELDS,
    }:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            "transaction binding must contain one complete context identity set",
        )
    if not all(_is_sha256_identity(raw.get(field)) for field in raw):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            "transaction context binding must contain SHA-256 identities",
        )
    return {
        **{field: str(raw[field]) for field in sorted(raw)},
        _REPORT_IMPLEMENTATION_IDENTITY_FIELD: current_identity,
    }


def _stored_publication_binding(
    value: Any,
    *,
    schema: str,
) -> dict[str, str]:
    """Strictly normalize current or legacy on-disk transaction bindings."""

    if not isinstance(value, Mapping):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            "transaction binding must be an object",
        )
    fields = set(value)
    if schema == _REPORT_PUBLICATION_TRANSACTION_SCHEMA:
        if fields not in (
            {_REPORT_IMPLEMENTATION_IDENTITY_FIELD},
            set(_REPORT_PUBLICATION_SEALED_BINDING_FIELDS),
            set(_REPORT_PUBLICATION_BINDING_FIELDS),
            set(_REPORT_PUBLICATION_SEALED_DOWNSTREAM_BINDING_FIELDS),
            set(_REPORT_PUBLICATION_DOWNSTREAM_BINDING_FIELDS),
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
                "v3 transaction binding has an invalid field set",
            )
    elif schema == _LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA:
        if fields not in (
            set(), set(_REPORT_PUBLICATION_CONTEXT_BINDING_FIELDS)
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
                "legacy transaction binding has an invalid field set",
            )
    else:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            f"unsupported transaction schema: {schema}",
        )
    if not all(_is_sha256_identity(value.get(field)) for field in fields):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            "transaction binding contains a non-SHA-256 identity",
        )
    return {field: str(value[field]) for field in sorted(fields)}


def _publication_implementation_status(
    schema: str,
    binding: Mapping[str, str],
) -> str:
    if schema == _LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA:
        return "legacy"
    return (
        "current"
        if binding.get(_REPORT_IMPLEMENTATION_IDENTITY_FIELD)
        == report_implementation_identity()
        else "mismatch"
    )


def _report_gate_receipt_identity(value: Mapping[str, Any]) -> str:
    return canonical_identity(
        "binary_report_gate_receipt_identity",
        {
            "schema": value.get("schema"),
            "transaction_id": value.get("transaction_id"),
            "transaction_binding_identity": value.get(
                "transaction_binding_identity"
            ),
            "published_content_identity": value.get(
                "published_content_identity"
            ),
            "gate_name": value.get("gate_name"),
            "strict_risk_gate": value.get("strict_risk_gate"),
            "gate_implementation_identity": value.get(
                "gate_implementation_identity"
            ),
        },
        schema_version="1",
    )


def _new_report_gate_receipt(
    payload: Mapping[str, Any],
    *,
    gate_name: str,
    strict_risk_gate: bool,
) -> dict[str, Any]:
    normalized_gate = str(gate_name or "").strip()
    if not normalized_gate or type(strict_risk_gate) is not bool:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_GATE_POLICY_INVALID",
            normalized_gate,
        )
    binding = dict(payload.get("binding") or {})
    receipt = {
        "schema": _REPORT_GATE_RECEIPT_SCHEMA,
        "transaction_id": payload.get("transaction_id"),
        "transaction_binding_identity": canonical_identity(
            "binary_report_transaction_binding_identity",
            binding,
            schema_version="1",
        ),
        "published_content_identity": payload.get(
            "published_content_identity"
        ),
        "gate_name": normalized_gate,
        "strict_risk_gate": strict_risk_gate,
        "gate_implementation_identity": binding.get(
            _REPORT_IMPLEMENTATION_IDENTITY_FIELD
        ),
    }
    receipt["gate_receipt_identity"] = _report_gate_receipt_identity(
        receipt
    )
    return receipt


def _validate_report_gate_receipt(
    value: Any,
    *,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "gate receipt is not an object",
        )
    receipt = dict(value)
    binding = dict(payload.get("binding") or {})
    if (
        set(receipt)
        != {
            "schema",
            "transaction_id",
            "transaction_binding_identity",
            "published_content_identity",
            "gate_name",
            "strict_risk_gate",
            "gate_implementation_identity",
            "gate_receipt_identity",
        }
        or receipt.get("schema") != _REPORT_GATE_RECEIPT_SCHEMA
        or receipt.get("transaction_id") != payload.get("transaction_id")
        or receipt.get("transaction_binding_identity")
        != canonical_identity(
            "binary_report_transaction_binding_identity",
            binding,
            schema_version="1",
        )
        or receipt.get("published_content_identity")
        != payload.get("published_content_identity")
        or not isinstance(receipt.get("gate_name"), str)
        or not receipt.get("gate_name")
        or type(receipt.get("strict_risk_gate")) is not bool
        or receipt.get("gate_implementation_identity")
        != binding.get(_REPORT_IMPLEMENTATION_IDENTITY_FIELD)
        or receipt.get("gate_receipt_identity")
        != _report_gate_receipt_identity(receipt)
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "gate receipt is not content-bound to the transaction",
        )
    return receipt


def _committed_publication_receipt_path(transaction_path: Path) -> Path:
    suffix = ".transaction.json"
    if not transaction_path.name.endswith(suffix):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            str(transaction_path),
        )
    return transaction_path.with_name(
        transaction_path.name[: -len(suffix)] + ".committed.json"
    )


def _committed_publication_receipt_identity(
    value: Mapping[str, Any],
) -> str:
    return canonical_identity(
        "binary_report_committed_publication_receipt_identity",
        {
            key: item
            for key, item in value.items()
            if key != "committed_receipt_identity"
        },
        schema_version="1",
    )


def _new_committed_publication_receipt(
    payload: Mapping[str, Any], records
) -> dict[str, Any]:
    receipt = {
        "schema": _REPORT_COMMITTED_RECEIPT_SCHEMA,
        "transaction_id": payload.get("transaction_id"),
        "binding": dict(payload.get("binding") or {}),
        "gate_receipt": dict(payload.get("gate_receipt") or {}),
        "published_content_identity": payload.get(
            "published_content_identity"
        ),
        "destinations": [
            {
                "destination": str(record["destination"]),
                "content_sha256": str(record["content_sha256"]),
            }
            for record in records
        ],
    }
    receipt["committed_receipt_identity"] = (
        _committed_publication_receipt_identity(receipt)
    )
    return receipt


def _read_private_publication_json(path: Path) -> dict[str, Any] | None:
    try:
        initial_stat = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID", f"{path}: {error}"
        ) from error
    if (
        stat.S_ISLNK(initial_stat.st_mode)
        or not stat.S_ISREG(initial_stat.st_mode)
        or initial_stat.st_nlink != 1
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            f"publication receipt is not a private regular file: {path}",
        )
    descriptor = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | int(getattr(os, "O_NOFOLLOW", 0) or 0)
            | int(getattr(os, "O_NONBLOCK", 0) or 0)
            | int(getattr(os, "O_BINARY", 0) or 0),
        )
        opened_stat = os.fstat(descriptor)
        current_stat = os.lstat(path)
        identity = (int(initial_stat.st_dev), int(initial_stat.st_ino))
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or opened_stat.st_nlink != 1
            or current_stat.st_nlink != 1
            or (int(opened_stat.st_dev), int(opened_stat.st_ino)) != identity
            or (int(current_stat.st_dev), int(current_stat.st_ino)) != identity
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                f"publication receipt changed while opening: {path}",
            )
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = None
            value = json.load(handle)
            final_opened_stat = os.fstat(handle.fileno())
            final_path_stat = os.lstat(path)
            if (
                (int(final_opened_stat.st_dev), int(final_opened_stat.st_ino))
                != identity
                or (int(final_path_stat.st_dev), int(final_path_stat.st_ino))
                != identity
                or final_opened_stat.st_nlink != 1
                or final_path_stat.st_nlink != 1
                or final_opened_stat.st_size != opened_stat.st_size
                or final_opened_stat.st_mtime_ns != opened_stat.st_mtime_ns
                or (
                    os.name != "nt"
                    and final_opened_stat.st_ctime_ns
                    != opened_stat.st_ctime_ns
                )
            ):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    f"publication receipt changed while reading: {path}",
                )
    except BinaryReportError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID", f"{path}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            _attempt_cleanups(
                ((f"close committed publication receipt {path}", lambda: os.close(descriptor)),),
                primary=sys.exc_info()[1],
            )
    if not isinstance(value, Mapping):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            f"publication receipt root is not an object: {path}",
        )
    return dict(value)


def _validate_committed_publication_receipt(
    value: Mapping[str, Any],
    *,
    destinations,
    verify_content: bool,
) -> tuple[dict[str, Any], str]:
    receipt = dict(value)
    if set(receipt) != {
        "schema",
        "transaction_id",
        "binding",
        "gate_receipt",
        "published_content_identity",
        "destinations",
        "committed_receipt_identity",
    } or receipt.get("schema") != _REPORT_COMMITTED_RECEIPT_SCHEMA:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "invalid committed publication receipt header",
        )
    transaction_id = receipt.get("transaction_id")
    if (
        not isinstance(transaction_id, str)
        or len(transaction_id) != 32
        or any(character not in "0123456789abcdef" for character in transaction_id)
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "invalid committed publication transaction id",
        )
    binding = _stored_publication_binding(
        receipt.get("binding"), schema=_REPORT_PUBLICATION_TRANSACTION_SCHEMA
    )
    raw_records = receipt.get("destinations")
    if not isinstance(raw_records, list) or len(raw_records) != len(destinations):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "invalid committed publication destination set",
        )
    expected = set(destinations)
    records = []
    seen = set()
    for raw in raw_records:
        if not isinstance(raw, Mapping) or set(raw) != {
            "destination", "content_sha256"
        }:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                "invalid committed publication destination record",
            )
        destination = Path(str(raw.get("destination") or ""))
        digest = raw.get("content_sha256")
        if destination not in expected or destination in seen or not _is_sha256_identity(digest):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                "unbound committed publication destination record",
            )
        seen.add(destination)
        records.append({
            "destination": destination,
            "content_sha256": str(digest),
        })
    if (
        seen != expected
        or receipt.get("published_content_identity")
        != _transaction_content_identity(records)
        or receipt.get("committed_receipt_identity")
        != _committed_publication_receipt_identity(receipt)
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "committed publication receipt identity mismatch",
        )
    _validate_report_gate_receipt(
        receipt.get("gate_receipt"),
        payload={
            "transaction_id": transaction_id,
            "binding": binding,
            "published_content_identity": receipt[
                "published_content_identity"
            ],
        },
    )
    if verify_content:
        for record in records:
            if _directory_content_identity(record["destination"]) != record[
                "content_sha256"
            ]:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                    str(record["destination"]),
                )
    receipt["binding"] = binding
    return receipt, _publication_implementation_status(
        _REPORT_PUBLICATION_TRANSACTION_SCHEMA, binding
    )


def _transaction_content_identity(records) -> str:
    payload = [
        {
            "destination": str(record["destination"]),
            "content_sha256": str(record["content_sha256"]),
        }
        for record in records
    ]
    return hashlib.sha256(json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _verify_published_transaction_content(
    payload: Mapping[str, Any], records
) -> None:
    use_private_candidate = bool(
        payload.get("schema") == _REPORT_PUBLICATION_TRANSACTION_SCHEMA
        and payload.get("state") in {"prepared", "pending_gate", "gate_passed"}
    )
    for record in records:
        content_path = (
            record["stage"] if use_private_candidate else record["destination"]
        )
        actual = _directory_content_identity(content_path)
        if actual != record["content_sha256"]:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                str(content_path),
            )
    if _transaction_content_identity(records) != payload.get(
        "published_content_identity"
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
            "transaction content identity mismatch",
        )


def _publication_group_token(destinations) -> str:
    payload = json.dumps(
        sorted(str(destination) for destination in destinations),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:20]


def _publication_transaction_path(destinations) -> tuple[Path, str]:
    group_token = _publication_group_token(destinations)
    coordinator = sorted(destinations, key=lambda item: str(item))[0].parent
    return (
        coordinator / f".jua-br-{group_token}.transaction.json",
        group_token,
    )


def _validate_publication_transaction(
    payload: Mapping[str, Any],
    *,
    destinations,
    group_token: str,
) -> tuple[list[dict[str, Any]], dict[str, str], str]:
    transaction_id = payload.get("transaction_id")
    records = payload.get("destinations")
    state = payload.get("state")
    schema = str(payload.get("schema") or "")
    expected_payload_fields = {
        "schema",
        "transaction_id",
        "state",
        "binding",
        "published_content_identity",
        "destinations",
    }
    if schema == _REPORT_PUBLICATION_TRANSACTION_SCHEMA:
        expected_payload_fields.add("gate_receipt")
    try:
        binding = _stored_publication_binding(
            payload.get("binding"), schema=schema
        )
    except BinaryReportError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID", str(error)
        ) from error
    if (
        set(payload) != expected_payload_fields
        or schema not in {
            _REPORT_PUBLICATION_TRANSACTION_SCHEMA,
            _LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA,
        }
        or state not in {
            "staging", "prepared", "pending_gate", "gate_passed",
            "published", "committed",
        }
        or (
            state == "published"
            and schema != _REPORT_PUBLICATION_TRANSACTION_SCHEMA
        )
        or not isinstance(transaction_id, str)
        or len(transaction_id) != 32
        or any(character not in "0123456789abcdef" for character in transaction_id)
        or not isinstance(records, list)
        or len(records) != len(destinations)
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "invalid transaction header",
        )
    published_content_identity = payload.get("published_content_identity")
    if state == "staging":
        if published_content_identity != "":
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                "staging transaction unexpectedly has a content identity",
            )
    elif not _is_sha256_identity(published_content_identity):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "transaction content identity is missing",
        )
    if dict(payload.get("binding") or {}) != binding:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "transaction binding is not canonical",
        )
    expected_destinations = set(destinations)
    seen_destinations = set()
    validated = []
    for index, raw_record in enumerate(records):
        if not isinstance(raw_record, Mapping):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                f"invalid destination record {index}",
            )
        expected_destination = Path(str(raw_record.get("destination") or ""))
        if (
            expected_destination not in expected_destinations
            or expected_destination in seen_destinations
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                f"unbound destination record {index}",
            )
        seen_destinations.add(expected_destination)
        expected_stage = expected_destination.parent / (
            f".jua-br-{group_token}-{transaction_id}-{index}.stage"
        )
        expected_backup = expected_destination.parent / (
            f".jua-br-{group_token}-{transaction_id}-{index}.backup"
        )
        if (
            set(raw_record)
            != {
                "destination",
                "stage",
                "backup",
                "had_destination",
                "content_sha256",
            }
            or Path(str(raw_record.get("stage") or "")) != expected_stage
            or Path(str(raw_record.get("backup") or "")) != expected_backup
            or type(raw_record.get("had_destination")) is not bool
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                f"unbound destination record {index}",
            )
        content_sha256 = raw_record.get("content_sha256")
        if (
            (state == "staging" and content_sha256 != "")
            or (state != "staging" and not _is_sha256_identity(content_sha256))
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                f"invalid destination content identity {index}",
            )
        for candidate in (expected_destination, expected_stage, expected_backup):
            if _publication_path_exists(candidate) and (
                candidate.is_symlink() or not candidate.is_dir()
            ):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    f"non-directory transaction path: {candidate}",
                )
        validated.append({
            "destination": expected_destination,
            "stage": expected_stage,
            "backup": expected_backup,
            "had_destination": raw_record["had_destination"],
            "content_sha256": str(content_sha256),
        })
    if seen_destinations != expected_destinations:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "transaction destination set is incomplete",
        )
    if state != "staging" and _transaction_content_identity(validated) != (
        published_content_identity
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            "transaction content identities are inconsistent",
        )
    if schema == _REPORT_PUBLICATION_TRANSACTION_SCHEMA:
        gate_receipt = payload.get("gate_receipt")
        if state in {"staging", "prepared", "pending_gate"}:
            if gate_receipt is not None:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    "pre-gate transaction unexpectedly has a gate receipt",
                )
        else:
            _validate_report_gate_receipt(
                gate_receipt,
                payload=payload,
            )
    return (
        validated,
        binding,
        _publication_implementation_status(schema, binding),
    )


def _finish_committed_publication(
    transaction_path: Path,
    payload: Mapping[str, Any],
    records,
    *,
    suppress_errors: bool,
) -> bool:
    # The committed receipt is authoritative downstream input and must be
    # durable.  Everything after it is recoverable housekeeping and must not
    # turn a successfully published report into an analysis failure.
    if payload.get("schema") == _REPORT_PUBLICATION_TRANSACTION_SCHEMA:
        committed_receipt = _new_committed_publication_receipt(
            payload, records
        )
        _atomic_json(
            _committed_publication_receipt_path(transaction_path),
            committed_receipt,
        )
    try:
        touched_parents = set()
        for record in records:
            for key in ("backup", "stage"):
                path = record[key]
                if _publication_path_exists(path):
                    _remove_publication_path(path)
                    touched_parents.add(path.parent)
        for parent in touched_parents:
            _fsync_directory(parent)
        transaction_path.unlink()
        _fsync_directory(transaction_path.parent)
        return True
    except OSError:
        if suppress_errors:
            return False
        raise


def _publish_transaction_record(record: Mapping[str, Any]) -> None:
    """Forward one gate-approved directory rename without overwriting backup.

    The transaction marker can still say ``gate_passed`` after either rename
    reached durable storage.  Infer only the layouts produced by those exact
    steps; every other combination is ambiguous and therefore fails closed.
    """

    destination = Path(record["destination"])
    stage = Path(record["stage"])
    backup = Path(record["backup"])
    had_destination = bool(record["had_destination"])
    destination_exists = _publication_path_exists(destination)
    stage_exists = _publication_path_exists(stage)
    backup_exists = _publication_path_exists(backup)

    if not stage_exists:
        if (
            not destination_exists
            or (had_destination and not backup_exists)
            or (not had_destination and backup_exists)
            or _directory_content_identity(destination)
            != record["content_sha256"]
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                f"ambiguous completed publish layout: {destination}",
            )
        return

    if _directory_content_identity(stage) != record["content_sha256"]:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH", str(stage)
        )

    if had_destination:
        if backup_exists:
            if destination_exists:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    f"ambiguous post-backup publish layout: {destination}",
                )
        else:
            if not destination_exists:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    f"missing predecessor before publish: {destination}",
                )
            os.replace(destination, backup)
            _fsync_directory(destination.parent)
    elif backup_exists or destination_exists:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            f"ambiguous new-destination publish layout: {destination}",
        )

    os.replace(stage, destination)
    _fsync_directory(destination.parent)
    if _directory_content_identity(destination) != record["content_sha256"]:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH", str(destination)
        )


def _load_publication_transaction(
    transaction_path: Path,
    *,
    destinations,
    group_token: str,
) -> tuple[
    dict[str, Any], list[dict[str, Any]], str
] | None:
    try:
        marker_stat = os.lstat(transaction_path)
    except FileNotFoundError:
        return None
    if (
        stat.S_ISLNK(marker_stat.st_mode)
        or not stat.S_ISREG(marker_stat.st_mode)
        or marker_stat.st_nlink != 1
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            f"transaction marker is not a private regular file: {transaction_path}",
        )
    descriptor = None
    try:
        descriptor = os.open(
            transaction_path,
            os.O_RDONLY
            | int(getattr(os, "O_NOFOLLOW", 0) or 0)
            | int(getattr(os, "O_NONBLOCK", 0) or 0)
            | int(getattr(os, "O_BINARY", 0) or 0),
        )
        opened_stat = os.fstat(descriptor)
        current_stat = os.lstat(transaction_path)
        if (
            opened_stat.st_dev != current_stat.st_dev
            or opened_stat.st_ino != current_stat.st_ino
            or not stat.S_ISREG(opened_stat.st_mode)
            or opened_stat.st_nlink != 1
            or current_stat.st_nlink != 1
            or opened_stat.st_size != marker_stat.st_size
            or opened_stat.st_mtime_ns != marker_stat.st_mtime_ns
            or (
                os.name != "nt"
                and opened_stat.st_ctime_ns != marker_stat.st_ctime_ns
            )
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                f"transaction marker changed while opening: {transaction_path}",
            )
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = None
            payload = json.load(handle)
            final_opened_stat = os.fstat(handle.fileno())
            final_path_stat = os.lstat(transaction_path)
            if (
                opened_stat.st_dev != final_opened_stat.st_dev
                or opened_stat.st_ino != final_opened_stat.st_ino
                or opened_stat.st_dev != final_path_stat.st_dev
                or opened_stat.st_ino != final_path_stat.st_ino
                or final_opened_stat.st_nlink != 1
                or final_path_stat.st_nlink != 1
                or final_opened_stat.st_size != opened_stat.st_size
                or final_opened_stat.st_mtime_ns != opened_stat.st_mtime_ns
                or (
                    os.name != "nt"
                    and final_opened_stat.st_ctime_ns
                    != opened_stat.st_ctime_ns
                )
            ):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    f"transaction marker changed while reading: {transaction_path}",
                )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            f"{transaction_path}: {error}",
        ) from error
    finally:
        if descriptor is not None:
            _attempt_cleanups(
                ((
                    f"close publication transaction descriptor {transaction_path}",
                    lambda: os.close(descriptor),
                ),),
                primary=sys.exc_info()[1],
            )
    if not isinstance(payload, Mapping):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            f"transaction root is not an object: {transaction_path}",
        )
    normalized_payload = dict(payload)
    records, binding, implementation_status = _validate_publication_transaction(
        payload,
        destinations=destinations,
        group_token=group_token,
    )
    normalized_payload["binding"] = binding
    return normalized_payload, records, implementation_status


def _recover_publication_transaction(
    transaction_path: Path,
    *,
    destinations,
    group_token: str,
    expected_transaction_id: str | None = None,
    expected_binding: Mapping[str, Any] | None = None,
) -> bool:
    loaded = _load_publication_transaction(
        transaction_path,
        destinations=destinations,
        group_token=group_token,
    )
    if loaded is None:
        if expected_transaction_id is not None:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
                expected_transaction_id,
            )
        return False
    payload, records, _implementation_status = loaded
    if (
        expected_transaction_id is not None
        and payload.get("transaction_id") != expected_transaction_id
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
            expected_transaction_id,
        )
    if (
        expected_binding is not None
        and dict(payload.get("binding") or {}) != dict(expected_binding)
    ):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TRANSACTION_BINDING_MISMATCH",
            str(expected_transaction_id or ""),
        )
    state = payload["state"]
    try:
        if state == "committed":
            if any(
                not _publication_path_exists(record["destination"])
                for record in records
            ):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    "committed transaction is missing a destination",
                )
            _verify_published_transaction_content(payload, records)
            _finish_committed_publication(
                transaction_path, payload, records, suppress_errors=False
            )
            return True

        if state == "staging":
            for record in records:
                destination_exists = _publication_path_exists(
                    record["destination"]
                )
                if (
                    _publication_path_exists(record["backup"])
                    or destination_exists != record["had_destination"]
                ):
                    raise BinaryReportError(
                        "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                        "staging transaction changed a destination",
                    )
        else:
            for record in reversed(records):
                destination = record["destination"]
                stage = record["stage"]
                backup = record["backup"]
                destination_exists = _publication_path_exists(destination)
                stage_exists = _publication_path_exists(stage)
                backup_exists = _publication_path_exists(backup)
                if record["had_destination"]:
                    if backup_exists:
                        if destination_exists:
                            _remove_publication_path(destination)
                        os.replace(backup, destination)
                        _fsync_directory(destination.parent)
                    elif not destination_exists:
                        raise BinaryReportError(
                            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                            f"prior destination cannot be restored: {destination}",
                        )
                else:
                    if backup_exists:
                        raise BinaryReportError(
                            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                            f"unexpected backup: {backup}",
                        )
                    if stage_exists and destination_exists:
                        raise BinaryReportError(
                            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                            f"ambiguous new destination: {destination}",
                        )
                    if not stage_exists and destination_exists:
                        _remove_publication_path(destination)
                        _fsync_directory(destination.parent)

        for record in records:
            stage = record["stage"]
            if _publication_path_exists(stage):
                _remove_publication_path(stage)
                _fsync_directory(stage.parent)
        transaction_path.unlink()
        _fsync_directory(transaction_path.parent)
        return True
    except BinaryReportError:
        raise
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_ROLLBACK_FAILED",
            str(transaction_path),
        ) from error


def _prepare_physical_publication_parent(
    parent: Path,
    *,
    trusted_root: Path | None = None,
) -> Path:
    """Create a publication parent without first traversing an ancestor link."""

    absolute_parent = Path(os.path.abspath(parent))
    if trusted_root is None:
        anchor = Path(absolute_parent.anchor)
    else:
        requested_root = Path(trusted_root).expanduser()
        if requested_root.name in {"", ".", ".."}:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                str(requested_root),
            )
        anchor = requested_root.parent.resolve() / requested_root.name
        try:
            root_stat = os.lstat(anchor)
        except OSError as error:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                f"{anchor}: {error}",
            ) from error
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(
            root_stat.st_mode
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                f"trusted report root is not a physical directory: {anchor}",
            )
    current = anchor
    try:
        relative_parts = absolute_parent.relative_to(anchor).parts
    except ValueError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
            str(absolute_parent),
        ) from error
    try:
        for part in relative_parts:
            current = current / part
            try:
                observed = os.lstat(current)
            except FileNotFoundError:
                try:
                    os.mkdir(current)
                except FileExistsError:
                    pass
                observed = os.lstat(current)
            if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(
                observed.st_mode
            ):
                raise OSError(
                    f"publication parent component is not a physical "
                    f"directory: {current}"
                )
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
            f"{absolute_parent}: {error}",
        ) from error
    return absolute_parent


def _normalize_publication_destination(
    raw_destination,
    *,
    trusted_root: Path | None = None,
) -> Path:
    lexical_destination = Path(
        os.path.abspath(str(Path(raw_destination)))
    )
    normalized_trusted_root = None
    if trusted_root is not None:
        requested_root = Path(
            os.path.abspath(str(Path(trusted_root).expanduser()))
        )
        try:
            relative_destination = lexical_destination.relative_to(
                requested_root
            )
        except ValueError as error:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                f"destination is outside trusted report root: {lexical_destination}",
            ) from error
        if requested_root.name in {"", ".", ".."}:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                str(requested_root),
            )
        normalized_trusted_root = (
            requested_root.parent.resolve() / requested_root.name
        )
        lexical_destination = (
            normalized_trusted_root / relative_destination
        )
    if lexical_destination.is_symlink():
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
            str(lexical_destination),
        )
    _prepare_physical_publication_parent(
        lexical_destination.parent,
        trusted_root=normalized_trusted_root,
    )
    try:
        resolved_parent = lexical_destination.parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
            str(lexical_destination),
        ) from error
    if resolved_parent != lexical_destination.parent:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
            f"symlinked parent is not allowed: {lexical_destination.parent}",
        )
    destination = resolved_parent / lexical_destination.name
    if destination.is_symlink():
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_INVALID", str(destination)
        )
    return destination


def _stage_directory_group(
    entries,
    *,
    retain_transaction: bool = False,
    transaction_binding: Mapping[str, Any] | None = None,
    trusted_root: Path | None = None,
):
    """Durably publish all report views, recovering any interrupted predecessor."""

    normalized = [
        (
            _normalize_publication_destination(
                destination,
                trusted_root=trusted_root,
            ),
            writer,
        )
        for destination, writer in entries
    ]
    if not normalized:
        return
    if len({destination for destination, _writer in normalized}) != len(normalized):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_DUPLICATE", "duplicate destination"
        )
    destinations = [destination for destination, _writer in normalized]
    binding = _new_publication_binding(transaction_binding)
    transaction_path, group_token = _publication_transaction_path(destinations)
    locks = ExitStack()
    try:
        for destination in sorted(
            (item[0] for item in normalized), key=lambda item: str(item)
        ):
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                locks.enter_context(exclusive_file_lock(
                    destination.parent
                    / f".{destination.name}.binary-publish.lock",
                    timeout_seconds=5.0,
                ))
            except TimeoutError as error:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_LOCK_TIMEOUT", str(destination)
                ) from error
        predecessor = _load_publication_transaction(
            transaction_path,
            destinations=destinations,
            group_token=group_token,
        )
        if (
            predecessor is not None
            and predecessor[0]["state"] in {"pending_gate", "gate_passed"}
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_IN_PROGRESS",
                str(predecessor[0]["transaction_id"]),
            )
        if predecessor is not None:
            # Locks are still held from the validated predecessor snapshot.
            # Staging/prepared can only survive a dead writer; committed needs
            # idempotent cleanup.  Retained gate states require their owner or
            # startup recovery to present the exact CAS token.
            _recover_publication_transaction(
                transaction_path,
                destinations=destinations,
                group_token=group_token,
            )

        transaction_id = uuid.uuid4().hex
        stages: dict[Path, Path] = {}
        records = []
        for index, (destination, _writer) in enumerate(normalized):
            if _publication_path_exists(destination) and (
                destination.is_symlink() or not destination.is_dir()
            ):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_TARGET_INVALID", str(destination)
                )
            stage = destination.parent / (
                f".jua-br-{group_token}-{transaction_id}-{index}.stage"
            )
            backup = destination.parent / (
                f".jua-br-{group_token}-{transaction_id}-{index}.backup"
            )
            if _publication_path_exists(stage) or _publication_path_exists(backup):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_TRANSACTION_COLLISION",
                    str(destination),
                )
            stage.mkdir(mode=0o700)
            _fsync_directory(stage.parent)
            stages[destination] = stage
            records.append({
                "destination": str(destination),
                "stage": str(stage),
                "backup": str(backup),
                "had_destination": _publication_path_exists(destination),
                "content_sha256": "",
            })
        transaction = {
            "schema": _REPORT_PUBLICATION_TRANSACTION_SCHEMA,
            "transaction_id": transaction_id,
            "state": "staging",
            "binding": binding,
            "gate_receipt": None,
            "published_content_identity": "",
            "destinations": records,
        }
        _atomic_json(transaction_path, transaction)
        try:
            for destination, writer in normalized:
                writer(stages[destination], stages)
            for record in records:
                record["content_sha256"] = _directory_content_identity(
                    Path(record["stage"]), make_durable=True
                )
            transaction["published_content_identity"] = (
                _transaction_content_identity(records)
            )
            transaction["state"] = "prepared"
            _atomic_json(transaction_path, transaction)
            if not retain_transaction:
                for record in records:
                    destination = Path(record["destination"])
                    stage = Path(record["stage"])
                    backup = Path(record["backup"])
                    if record["had_destination"]:
                        os.replace(destination, backup)
                        _fsync_directory(destination.parent)
                    os.replace(stage, destination)
                    _fsync_directory(destination.parent)
            transaction["state"] = (
                "pending_gate" if retain_transaction else "committed"
            )
            if not retain_transaction:
                transaction["gate_receipt"] = _new_report_gate_receipt(
                    transaction,
                    gate_name="immediate_publication_no_gate",
                    strict_risk_gate=False,
                )
            _atomic_json(transaction_path, transaction)
        except BaseException as error:
            try:
                _recover_publication_transaction(
                    transaction_path,
                    destinations=destinations,
                    group_token=group_token,
                )
            except Exception as rollback_error:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_ROLLBACK_FAILED",
                    ",".join(str(item) for item in destinations),
                ) from rollback_error
            raise error
        validated_records, _validated_binding, _implementation_status = (
            _validate_publication_transaction(
            transaction,
            destinations=destinations,
            group_token=group_token,
            )
        )
        if retain_transaction:
            return {
                "schema": _REPORT_PUBLICATION_TRANSACTION_SCHEMA,
                "transaction_id": transaction_id,
                "state": "pending_gate",
                "transaction_path": str(transaction_path),
                "destinations": [str(item) for item in destinations],
                "candidate_destinations": [
                    str(record["stage"]) for record in records
                ],
                "binding": dict(binding),
                "gate_receipt": None,
                "published_content_identity": transaction[
                    "published_content_identity"
                ],
            }
        _verify_published_transaction_content(transaction, validated_records)
        _finish_committed_publication(
            transaction_path,
            transaction,
            validated_records,
            suppress_errors=True,
        )
        return None
    finally:
        primary = sys.exc_info()[1]
        if primary is None:
            close_action = locks.close
        else:
            close_action = lambda: locks.__exit__(
                type(primary), primary, primary.__traceback__
            )
        _attempt_cleanups(
            (("close report publication locks", close_action),),
            primary=primary,
        )


def _publication_transaction_action(
    raw_destinations,
    action: str,
    *,
    expected_transaction_id: str | None = None,
    expected_binding: Mapping[str, Any] | None = None,
    gate_name: str | None = None,
    strict_risk_gate: bool | None = None,
    expected_published_content_identity: str | None = None,
    candidate_snapshot_root: str | Path | None = None,
):
    destinations = [
        _normalize_publication_destination(item) for item in raw_destinations
    ]
    if not destinations or len(set(destinations)) != len(destinations):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_DUPLICATE",
            "empty or duplicate destination set",
        )
    transaction_path, group_token = _publication_transaction_path(destinations)
    with ExitStack() as locks:
        for destination in sorted(destinations, key=lambda item: str(item)):
            try:
                locks.enter_context(exclusive_file_lock(
                    destination.parent
                    / f".{destination.name}.binary-publish.lock",
                    timeout_seconds=5.0,
                ))
            except TimeoutError as error:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_LOCK_TIMEOUT", str(destination)
                ) from error
        loaded = _load_publication_transaction(
            transaction_path,
            destinations=destinations,
            group_token=group_token,
        )
        if expected_transaction_id is not None and (
            not isinstance(expected_transaction_id, str)
            or len(expected_transaction_id) != 32
            or any(
                character not in "0123456789abcdef"
                for character in expected_transaction_id
            )
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_INVALID",
                str(expected_transaction_id),
            )
        mutating_actions = {
            "rollback", "gate_candidate", "gate_passed", "publish",
            "commit", "finalize_irreversible", "recover",
        }
        if action in mutating_actions and (
            expected_transaction_id is None or expected_binding is None
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_CAS_REQUIRED",
                action,
            )
        if expected_binding is not None and not isinstance(
            expected_binding, Mapping
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
                "expected transaction binding must be an object",
            )
        if expected_binding is not None and expected_transaction_id is None:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_CAS_REQUIRED",
                action,
            )
        if expected_transaction_id is not None:
            if (
                loaded is None
                or loaded[0].get("transaction_id")
                != expected_transaction_id
            ):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
                    expected_transaction_id,
                )
            if (
                expected_binding is not None
                and dict(loaded[0].get("binding") or {})
                != dict(expected_binding)
            ):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_TRANSACTION_BINDING_MISMATCH",
                    expected_transaction_id,
                )
        if action == "state":
            return "absent" if loaded is None else loaded[0]["state"]
        if action == "recovery_metadata":
            if loaded is None:
                return {
                    "transaction_id": "",
                    "state": "absent",
                    "implementation_status": "absent",
                    "binding": {},
                    "gate_receipt": None,
                }
            payload, _records, implementation_status = loaded
            return {
                "schema": payload["schema"],
                "transaction_id": payload["transaction_id"],
                "state": payload["state"],
                "implementation_status": implementation_status,
                # This is rollback-only metadata.  It is deliberately not a
                # publication receipt and cannot authorize gate/commit.
                "binding": dict(payload["binding"]),
                "gate_receipt": (
                    dict(payload["gate_receipt"])
                    if isinstance(payload.get("gate_receipt"), Mapping)
                    else None
                ),
            }
        if action == "gate_candidate":
            if loaded is None:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
                    str(expected_transaction_id or ""),
                )
            payload, records, _implementation_status = loaded
            if payload["state"] != "pending_gate":
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_STATE_INVALID",
                    payload["state"],
                )
            if (
                not _is_sha256_identity(expected_published_content_identity)
                or payload["published_content_identity"]
                != expected_published_content_identity
            ):
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                    str(expected_published_content_identity or ""),
                )
            if candidate_snapshot_root is None:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_GATE_SNAPSHOT_INVALID",
                    "snapshot root is required",
                )
            snapshot_root = Path(candidate_snapshot_root)
            try:
                snapshot_stat = os.lstat(snapshot_root)
                resolved_snapshot = snapshot_root.resolve(strict=True)
                if (
                    stat.S_ISLNK(snapshot_stat.st_mode)
                    or not stat.S_ISDIR(snapshot_stat.st_mode)
                    or resolved_snapshot != snapshot_root.absolute()
                    or any(snapshot_root.iterdir())
                ):
                    raise OSError("snapshot root is not an empty private directory")
            except OSError as error:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_GATE_SNAPSHOT_INVALID",
                    f"{snapshot_root}: {error}",
                ) from error
            _verify_published_transaction_content(payload, records)
            snapshot_paths = []
            for index, record in enumerate(records):
                snapshot = snapshot_root / str(index)
                try:
                    _copy_report_directory_secure(
                        Path(record["stage"]), snapshot
                    )
                except (OSError, BinaryReportError) as error:
                    raise BinaryReportError(
                        "BINARY_REPORT_PUBLICATION_GATE_SNAPSHOT_INVALID",
                        f"{record['stage']}: {error}",
                    ) from error
                if (
                    _directory_content_identity(snapshot)
                    != record["content_sha256"]
                ):
                    raise BinaryReportError(
                        "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                        str(snapshot),
                    )
                snapshot_paths.append(str(snapshot))
            _verify_published_transaction_content(payload, records)
            return {
                "transaction_id": payload["transaction_id"],
                "binding": dict(payload["binding"]),
                "published_content_identity": payload[
                    "published_content_identity"
                ],
                "candidate_destinations": snapshot_paths,
            }
        if action == "receipt":
            if loaded is None:
                return {}
            payload, records, _implementation_status = loaded
            if payload["state"] not in {
                "prepared", "pending_gate", "gate_passed", "published",
                "committed",
            }:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_STATE_INVALID",
                    payload["state"],
                )
            _verify_published_transaction_content(payload, records)
            return {
                "schema": payload["schema"],
                "transaction_id": payload["transaction_id"],
                "state": payload["state"],
                "binding": dict(payload["binding"]),
                "gate_receipt": (
                    dict(payload["gate_receipt"])
                    if isinstance(payload.get("gate_receipt"), Mapping)
                    else None
                ),
                "published_content_identity": payload[
                    "published_content_identity"
                ],
                "destinations": [str(record["destination"]) for record in records],
                "candidate_destinations": [
                    str(record["stage"])
                    for record in records
                    if payload["state"] in {
                        "prepared", "pending_gate", "gate_passed"
                    }
                ],
            }
        if loaded is None:
            return False
        payload, records, _implementation_status = loaded
        state = payload["state"]
        if action == "rollback":
            if state == "committed":
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_ALREADY_COMMITTED", state
                )
            return _recover_publication_transaction(
                transaction_path,
                destinations=destinations,
                group_token=group_token,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
            )
        if action == "gate_passed":
            if state != "pending_gate":
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_STATE_INVALID", state
                )
            _verify_published_transaction_content(payload, records)
            payload["gate_receipt"] = _new_report_gate_receipt(
                payload,
                gate_name=str(gate_name or ""),
                strict_risk_gate=strict_risk_gate,
            )
            payload["state"] = "gate_passed"
            _atomic_json(transaction_path, payload)
            return dict(payload["gate_receipt"])
        if action == "publish":
            if state not in {"gate_passed", "published"}:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_STATE_INVALID", state
                )
            if state == "gate_passed":
                try:
                    for record in records:
                        _publish_transaction_record(record)
                except OSError as error:
                    raise BinaryReportError(
                        "BINARY_REPORT_PUBLICATION_PUBLISH_FAILED",
                        str(transaction_path),
                    ) from error
                payload["state"] = "published"
                _atomic_json(transaction_path, payload)
            _verify_published_transaction_content(payload, records)
            return True
        if action == "commit":
            if state not in {"published", "committed"}:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_STATE_INVALID", state
                )
            _verify_published_transaction_content(payload, records)
            if state != "committed":
                payload["state"] = "committed"
                _atomic_json(transaction_path, payload)
            return _finish_committed_publication(
                transaction_path, payload, records, suppress_errors=True
            )
        if action == "finalize_irreversible":
            # Recovery-only transition for the crash window after the bound
            # active generation receipt was committed.  At that point report
            # rollback would create a cross-generation public state.  A valid
            # persisted gate receipt plus exact CAS binding permits only
            # finishing this already-published release after a process restart.
            if state not in {"published", "committed"}:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_STATE_INVALID", state
                )
            _verify_published_transaction_content(payload, records)
            if state != "committed":
                payload["state"] = "committed"
                _atomic_json(transaction_path, payload)
            return _finish_committed_publication(
                transaction_path, payload, records, suppress_errors=True
            )
        if action == "recover":
            return _recover_publication_transaction(
                transaction_path,
                destinations=destinations,
                group_token=group_token,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
            )
        raise ValueError(f"unknown publication transaction action: {action}")


def report_publication_transaction_state(destinations) -> str:
    return str(_publication_transaction_action(destinations, "state"))


def report_publication_transaction_receipt(
    destinations,
    *,
    expected_transaction_id: str | None = None,
    expected_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    value = _publication_transaction_action(
        destinations,
        "receipt",
        expected_transaction_id=expected_transaction_id,
        expected_binding=expected_binding,
    )
    return dict(value) if isinstance(value, Mapping) else {}


def report_publication_transaction_recovery_metadata(
    destinations,
) -> dict[str, Any]:
    value = _publication_transaction_action(destinations, "recovery_metadata")
    return dict(value) if isinstance(value, Mapping) else {}


def materialize_report_publication_gate_candidate(
    destinations,
    snapshot_root,
    *,
    expected_transaction_id: str,
    expected_binding: Mapping[str, Any],
    expected_published_content_identity: str,
) -> dict[str, Any]:
    value = _publication_transaction_action(
        destinations,
        "gate_candidate",
        expected_transaction_id=expected_transaction_id,
        expected_binding=expected_binding,
        expected_published_content_identity=(
            expected_published_content_identity
        ),
        candidate_snapshot_root=snapshot_root,
    )
    return dict(value) if isinstance(value, Mapping) else {}


def mark_report_publication_gate_passed(
    destinations,
    *,
    expected_transaction_id: str,
    expected_binding: Mapping[str, Any],
    gate_name: str,
    strict_risk_gate: bool,
) -> dict[str, Any]:
    value = _publication_transaction_action(
        destinations,
        "gate_passed",
        expected_transaction_id=expected_transaction_id,
        expected_binding=expected_binding,
        gate_name=gate_name,
        strict_risk_gate=strict_risk_gate,
    )
    return dict(value) if isinstance(value, Mapping) else {}


def commit_report_publication(
    destinations,
    *,
    expected_transaction_id: str,
    expected_binding: Mapping[str, Any],
) -> bool:
    return bool(_publication_transaction_action(
        destinations,
        "commit",
        expected_transaction_id=expected_transaction_id,
        expected_binding=expected_binding,
    ))


def publish_report_publication(
    destinations,
    *,
    expected_transaction_id: str,
    expected_binding: Mapping[str, Any],
) -> bool:
    return bool(_publication_transaction_action(
        destinations,
        "publish",
        expected_transaction_id=expected_transaction_id,
        expected_binding=expected_binding,
    ))


def rollback_report_publication(
    destinations,
    *,
    expected_transaction_id: str,
    expected_binding: Mapping[str, Any],
) -> bool:
    return bool(_publication_transaction_action(
        destinations,
        "rollback",
        expected_transaction_id=expected_transaction_id,
        expected_binding=expected_binding,
    ))


def recover_report_publication(
    destinations,
    *,
    expected_transaction_id: str,
    expected_binding: Mapping[str, Any],
) -> bool:
    return bool(_publication_transaction_action(
        destinations,
        "recover",
        expected_transaction_id=expected_transaction_id,
        expected_binding=expected_binding,
    ))


def finalize_irreversible_report_publication(
    destinations,
    *,
    expected_transaction_id: str,
    expected_binding: Mapping[str, Any],
) -> bool:
    return bool(_publication_transaction_action(
        destinations,
        "finalize_irreversible",
        expected_transaction_id=expected_transaction_id,
        expected_binding=expected_binding,
    ))


def report_publication_committed_receipt(
    raw_destinations,
    *,
    expected_transaction_id: str | None = None,
    expected_binding: Mapping[str, Any] | None = None,
    verify_content: bool = True,
) -> dict[str, Any]:
    """Read the durable gate/content receipt for the current public group."""

    if expected_binding is not None and expected_transaction_id is None:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CAS_REQUIRED", "committed_receipt"
        )
    destinations = [
        _normalize_publication_destination(item) for item in raw_destinations
    ]
    if not destinations or len(set(destinations)) != len(destinations):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_DUPLICATE",
            "empty or duplicate destination set",
        )
    transaction_path, _group_token = _publication_transaction_path(
        destinations
    )
    with ExitStack() as locks:
        for destination in sorted(destinations, key=lambda item: str(item)):
            try:
                locks.enter_context(exclusive_file_lock(
                    destination.parent
                    / f".{destination.name}.binary-publish.lock",
                    timeout_seconds=5.0,
                ))
            except TimeoutError as error:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_LOCK_TIMEOUT", str(destination)
                ) from error
        raw = _read_private_publication_json(
            _committed_publication_receipt_path(transaction_path)
        )
        if raw is None:
            if expected_transaction_id is not None:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
                    str(expected_transaction_id),
                )
            if expected_binding is not None:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_CAS_REQUIRED",
                    "committed_receipt",
                )
            return {}
        receipt, _implementation_status = (
            _validate_committed_publication_receipt(
                raw,
                destinations=destinations,
                verify_content=bool(verify_content),
            )
        )
        if (
            expected_transaction_id is not None
            and receipt.get("transaction_id") != expected_transaction_id
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
                str(expected_transaction_id),
            )
        if (
            expected_binding is not None
            and dict(receipt.get("binding") or {})
            != dict(expected_binding)
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_BINDING_MISMATCH",
                str(expected_transaction_id or ""),
            )
        return {**receipt, "state": "committed"}


def materialize_report_publication_committed_snapshot(
    raw_destinations,
    snapshot_root,
    *,
    expected_transaction_id: str | None = None,
    expected_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Copy one content-bound committed group while every destination is locked.

    A receipt read followed by ordinary path reads has a TOCTOU window: another
    valid publication can replace the fixed paths in between.  Downstream steps
    must consume the returned private paths, never the fixed destinations they
    supplied to this function.
    """

    if expected_binding is not None and expected_transaction_id is None:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CAS_REQUIRED", "committed_snapshot"
        )
    destinations = [
        _normalize_publication_destination(item) for item in raw_destinations
    ]
    if not destinations or len(set(destinations)) != len(destinations):
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_TARGET_DUPLICATE",
            "empty or duplicate destination set",
        )
    snapshot_root = Path(snapshot_root)
    try:
        snapshot_stat = os.lstat(snapshot_root)
        resolved_snapshot = snapshot_root.resolve(strict=True)
        if (
            stat.S_ISLNK(snapshot_stat.st_mode)
            or not stat.S_ISDIR(snapshot_stat.st_mode)
            or resolved_snapshot != snapshot_root.absolute()
            or any(snapshot_root.iterdir())
        ):
            raise OSError("snapshot root is not an empty private directory")
    except OSError as error:
        raise BinaryReportError(
            "BINARY_REPORT_PUBLICATION_READER_SNAPSHOT_INVALID",
            f"{snapshot_root}: {error}",
        ) from error
    transaction_path, _group_token = _publication_transaction_path(
        destinations
    )
    receipt_path = _committed_publication_receipt_path(transaction_path)
    with ExitStack() as locks:
        for destination in sorted(destinations, key=lambda item: str(item)):
            try:
                locks.enter_context(exclusive_file_lock(
                    destination.parent
                    / f".{destination.name}.binary-publish.lock",
                    timeout_seconds=5.0,
                ))
            except TimeoutError as error:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_LOCK_TIMEOUT", str(destination)
                ) from error
        raw = _read_private_publication_json(receipt_path)
        if raw is None:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_COMMITTED_RECEIPT_MISSING",
                str(receipt_path),
            )
        receipt, _implementation_status = (
            _validate_committed_publication_receipt(
                raw,
                destinations=destinations,
                verify_content=True,
            )
        )
        if (
            expected_transaction_id is not None
            and receipt.get("transaction_id") != expected_transaction_id
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
                str(expected_transaction_id),
            )
        if (
            expected_binding is not None
            and dict(receipt.get("binding") or {}) != dict(expected_binding)
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_BINDING_MISMATCH",
                str(expected_transaction_id or ""),
            )
        digest_by_destination = {
            Path(record["destination"]): str(record["content_sha256"])
            for record in receipt["destinations"]
        }
        snapshot_paths = []
        try:
            for index, destination in enumerate(destinations):
                snapshot = snapshot_root / str(index)
                snapshot_paths.append(str(snapshot))
                _copy_report_directory_secure(destination, snapshot)
                if (
                    _directory_content_identity(snapshot)
                    != digest_by_destination[destination]
                ):
                    raise BinaryReportError(
                        "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                        str(snapshot),
                    )
            # Detect a writer that ignored the publication locks, and ensure
            # the durable receipt was not replaced while the snapshot copied.
            for destination in destinations:
                if (
                    _directory_content_identity(destination)
                    != digest_by_destination[destination]
                ):
                    raise BinaryReportError(
                        "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                        str(destination),
                    )
            final_raw = _read_private_publication_json(receipt_path)
            if final_raw != raw:
                raise BinaryReportError(
                    "BINARY_REPORT_PUBLICATION_READER_SNAPSHOT_INVALID",
                    "committed receipt changed while copying",
                )
        except BaseException:
            for snapshot in snapshot_paths:
                snapshot_path = Path(snapshot)
                if _publication_path_exists(snapshot_path):
                    _remove_publication_path(snapshot_path)
            raise
        return {
            **receipt,
            "state": "committed",
            "snapshot_destinations": snapshot_paths,
        }


def _global_release_path(report_dir: str | Path) -> Path:
    return (
        Path(report_dir).resolve()
        / ".runtime"
        / "releases"
        / "current_release.json"
    )


def _publication_protocol_marker_path(report_dir: str | Path) -> Path:
    return (
        Path(report_dir).resolve()
        / ".runtime"
        / "releases"
        / "publication_protocol.json"
    )


def _ensure_publication_protocol_marker(report_dir: str | Path) -> None:
    """Durably make the protocol/legacy boundary monotonic for this report."""

    marker = _publication_protocol_marker_path(report_dir)
    expected = {
        "schema": _REPORT_PUBLICATION_PROTOCOL_MARKER_SCHEMA,
        "protocol_version": 1,
    }
    if _publication_path_exists(marker):
        raw = _read_private_publication_json(marker)
        if raw != expected:
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_PROTOCOL_MARKER_INVALID",
                str(marker),
            )
        return
    _atomic_json(marker, expected)


def ensure_report_publication_protocol(report_dir: str | Path) -> None:
    """Public orchestration hook used before any protocol-owned Step4 write."""

    _ensure_publication_protocol_marker(report_dir)


def report_uses_release_protocol(report_dir: str | Path) -> bool:
    """Return whether any durable or published protocol-era evidence exists.

    Legacy fallback is intentionally allowed only when protocol evidence is
    completely absent.  Existence checks include malformed and symlinked
    markers so corruption can never turn a protocol report back into legacy.
    """

    report = Path(report_dir).resolve()
    direct_evidence = (
        _publication_protocol_marker_path(report),
        _global_release_path(report),
    )
    if any(_publication_path_exists(path) for path in direct_evidence):
        return True
    for destinations in (
        _step4_report_publication_destinations(report),
        _step5_report_publication_destinations(report),
        _step6_report_publication_destinations(report),
    ):
        transaction_path, _token = _publication_transaction_path(
            destinations
        )
        if (
            _publication_path_exists(transaction_path)
            or _publication_path_exists(
                _committed_publication_receipt_path(transaction_path)
            )
        ):
            return True

    structured_evidence = (
        (
            report / ".runtime" / "indexes" / "s5_query_index.json",
            {
                "step4_publication_receipt_identity",
                "step5_publication_input_identity",
            },
        ),
        (
            report / "evidence" / "call_chain" / "summary.json",
            {
                "step4_publication_receipt_identity",
                "step5_publication_input_identity",
            },
        ),
        (
            report / ".runtime" / "findings" / "s6_findings.json",
            {
                "step4_publication_receipt_identity",
                "step5_publication_receipt_identity",
                "step6_publication_input_identity",
            },
        ),
    )
    for path, identity_fields in structured_evidence:
        if not _publication_path_exists(path):
            continue
        try:
            payload = _read_private_publication_json(path)
        except BinaryReportError:
            # An unreadable artifact at a protocol-owned location is not
            # evidence that the report is safely legacy.
            return True
        if payload is not None and all(
            _is_sha256_identity(payload.get(field))
            for field in identity_fields
        ):
            return True
    return False


def _stale_release_stage() -> dict[str, str]:
    return {
        "status": "stale",
        "transaction_id": "",
        "committed_receipt_identity": "",
        "published_content_identity": "",
        "publication_input_identity": "",
        "upstream_publication_receipt_identity": "",
    }


def _release_stage_from_receipt(
    stage: str, receipt: Mapping[str, Any]
) -> dict[str, str]:
    binding = dict(receipt.get("binding") or {})
    publication_input_identity = str(
        binding.get("publication_input_identity")
        or canonical_identity(
            "binary_report_transaction_binding_identity",
            binding,
            schema_version="1",
        )
    )
    value = {
        "status": "current",
        "transaction_id": str(receipt.get("transaction_id") or ""),
        "committed_receipt_identity": str(
            receipt.get("committed_receipt_identity") or ""
        ),
        "published_content_identity": str(
            receipt.get("published_content_identity") or ""
        ),
        "publication_input_identity": publication_input_identity,
        "upstream_publication_receipt_identity": str(
            binding.get("upstream_publication_receipt_identity") or ""
        ),
    }
    if (
        len(value["transaction_id"]) != 32
        or any(
            character not in "0123456789abcdef"
            for character in value["transaction_id"]
        )
        or not all(
            _is_sha256_identity(value[field])
            for field in (
                "committed_receipt_identity",
                "published_content_identity",
                "publication_input_identity",
            )
        )
        or (
            stage != "step4"
            and not _is_sha256_identity(
                value["upstream_publication_receipt_identity"]
            )
        )
        or (
            stage == "step4"
            and value["upstream_publication_receipt_identity"]
        )
    ):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_RECEIPT_INVALID", stage
        )
    return value


def _global_release_identity(value: Mapping[str, Any]) -> str:
    return canonical_identity(
        "global_report_release_identity",
        {
            key: item
            for key, item in value.items()
            if key != "release_identity"
        },
        schema_version="1",
    )


def _validate_global_release(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_INVALID", "release root is not an object"
        )
    release = dict(value)
    if set(release) != {
        "schema",
        "release_sequence",
        "active_core",
        "step4",
        "step5",
        "step6",
        "previous_complete",
        "release_identity",
    } or release.get("schema") != _GLOBAL_RELEASE_SCHEMA:
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_INVALID", "invalid release header"
        )
    if (
        type(release.get("release_sequence")) is not int
        or release["release_sequence"] < 1
        or not isinstance(release.get("active_core"), Mapping)
        or set(release["active_core"])
        != _REPORT_PUBLICATION_SEALED_CONTEXT_BINDING_FIELDS
        or not all(
            _is_sha256_identity(item)
            for item in release["active_core"].values()
        )
    ):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_INVALID", "invalid active core"
        )
    for stage in ("step4", "step5", "step6"):
        item = release.get(stage)
        if not isinstance(item, Mapping) or set(item) != set(
            _GLOBAL_RELEASE_STAGE_FIELDS
        ):
            raise BinaryReportError(
                "BINARY_GLOBAL_RELEASE_INVALID", f"invalid {stage} entry"
            )
        if item.get("status") == "stale":
            if dict(item) != _stale_release_stage():
                raise BinaryReportError(
                    "BINARY_GLOBAL_RELEASE_INVALID",
                    f"non-canonical stale {stage} entry",
                )
        elif item.get("status") == "current":
            _release_stage_from_receipt(stage, {
                "transaction_id": item.get("transaction_id"),
                "committed_receipt_identity": item.get(
                    "committed_receipt_identity"
                ),
                "published_content_identity": item.get(
                    "published_content_identity"
                ),
                "binding": {
                    "publication_input_identity": item.get(
                        "publication_input_identity"
                    ),
                    "upstream_publication_receipt_identity": item.get(
                        "upstream_publication_receipt_identity"
                    ),
                },
            })
        else:
            raise BinaryReportError(
                "BINARY_GLOBAL_RELEASE_INVALID", f"invalid {stage} status"
            )
    previous = release.get("previous_complete")
    if previous is not None and (
        not isinstance(previous, Mapping)
        or set(previous) != {
            "active_core", "step4", "step5", "step6", "release_identity"
        }
        or not _is_sha256_identity(previous.get("release_identity"))
    ):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_INVALID", "invalid previous release"
        )
    if release.get("release_identity") != _global_release_identity(release):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_INVALID", "release identity mismatch"
        )
    release["active_core"] = dict(release["active_core"])
    for stage in ("step4", "step5", "step6"):
        release[stage] = dict(release[stage])
    return release


def _active_release_core(loaded: Mapping[str, Any]) -> dict[str, str]:
    core = {
        "result_generation_identity": loaded["manifest"].get(
            "result_generation_identity"
        ),
        "validation_run_identity": loaded["active"].get(
            "validation_run_identity"
        ),
        "validation_result_sha256": loaded["active"].get(
            "validation_result_sha256"
        ),
    }
    if not all(_is_sha256_identity(item) for item in core.values()):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_ACTIVE_INVALID", str(core)
        )
    return {key: str(value) for key, value in core.items()}


def _receipt_matches_release_core(
    receipt: Mapping[str, Any], core: Mapping[str, str]
) -> bool:
    binding = dict(receipt.get("binding") or {})
    return all(binding.get(key) == value for key, value in core.items())


def _receipt_has_formal_gate(
    receipt: Mapping[str, Any] | None,
    expected_gate_name: str,
) -> bool:
    gate_receipt = dict((receipt or {}).get("gate_receipt") or {})
    return gate_receipt.get("gate_name") == expected_gate_name


def _complete_release_snapshot(value: Mapping[str, Any]) -> dict[str, Any] | None:
    if not all(
        (value.get(stage) or {}).get("status") == "current"
        for stage in ("step4", "step5", "step6")
    ):
        return None
    return {
        "active_core": dict(value["active_core"]),
        "step4": dict(value["step4"]),
        "step5": dict(value["step5"]),
        "step6": dict(value["step6"]),
        "release_identity": str(value["release_identity"]),
    }


def reconcile_current_release(
    report_dir: str | Path,
    *,
    workflow_lock_held: bool = False,
    active_lock_held: bool = False,
) -> dict[str, Any]:
    if not workflow_lock_held:
        with _standalone_report_workflow_lock(report_dir):
            return reconcile_current_release(
                report_dir,
                workflow_lock_held=True,
                active_lock_held=active_lock_held,
            )
    if not active_lock_held:
        with _active_generation_publication_lock(report_dir):
            return _reconcile_current_release_with_workflow_lock(report_dir)
    return _reconcile_current_release_with_workflow_lock(report_dir)


def _reconcile_current_release_with_workflow_lock(
    report_dir: str | Path,
) -> dict[str, Any]:
    """Reconcile the CAS descriptor from independently durable stage receipts."""

    report = Path(report_dir).resolve()
    loaded = load_validated_generation(report)
    core = _active_release_core(loaded)
    step4_receipt = report_publication_committed_receipt(
        _step4_report_publication_destinations(report)
    )
    if (
        not step4_receipt
        or not _receipt_has_formal_gate(
            step4_receipt, "binary_generation"
        )
        or not _step4_publication_binding_matches_loaded(
            step4_receipt.get("binding") or {}, loaded
        )
    ):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_STEP4_NOT_CURRENT", str(report)
        )
    step4 = _release_stage_from_receipt("step4", step4_receipt)
    step5_receipt = report_publication_committed_receipt(
        _step5_report_publication_destinations(report),
    )
    step5_gate_policy_valid = _receipt_has_formal_gate(
        step5_receipt, "binary_report"
    )
    step5_current = bool(
        step5_receipt
        and step5_gate_policy_valid
        and _receipt_matches_release_core(step5_receipt, core)
        and (step5_receipt.get("binding") or {}).get(
            "upstream_publication_receipt_identity"
        ) == step4_receipt.get("committed_receipt_identity")
    )
    step5 = (
        _release_stage_from_receipt("step5", step5_receipt)
        if step5_current
        else _stale_release_stage()
    )
    step6_receipt = report_publication_committed_receipt(
        _step6_report_publication_destinations(report),
    )
    step6_gate_policy_valid = _receipt_has_formal_gate(
        step6_receipt, "binary_final_report"
    )
    expected_step6_input_identity = ""
    if step5_current and step6_receipt:
        expected_step6_input_identity = _step6_publication_input_identity(
            loaded,
            step4_receipt,
            step5_receipt,
            _step6_upstream_evidence_state(
                report, require_complete=False
            ),
        )
    step6_current = bool(
        step5_current
        and step6_receipt
        and step6_gate_policy_valid
        and _receipt_matches_release_core(step6_receipt, core)
        and (step6_receipt.get("binding") or {}).get(
            "upstream_publication_receipt_identity"
        ) == step5_receipt.get("committed_receipt_identity")
        and (step6_receipt.get("binding") or {}).get(
            "publication_input_identity"
        ) == expected_step6_input_identity
    )
    step6_upstream_input_changed = bool(
        step5_current
        and step6_receipt
        and _receipt_matches_release_core(step6_receipt, core)
        and (step6_receipt.get("binding") or {}).get(
            "upstream_publication_receipt_identity"
        ) == step5_receipt.get("committed_receipt_identity")
        and (step6_receipt.get("binding") or {}).get(
            "publication_input_identity"
        ) != expected_step6_input_identity
    )
    step6 = (
        _release_stage_from_receipt("step6", step6_receipt)
        if step6_current
        else _stale_release_stage()
    )
    release_path = _global_release_path(report)
    lock_path = release_path.with_name(".current-release.lock")
    with exclusive_file_lock(lock_path, timeout_seconds=5.0):
        raw = _read_private_publication_json(release_path)
        previous = _validate_global_release(raw) if raw is not None else None
        expected_stages = (step4, step5, step6)
        if previous is not None and (
            previous.get("active_core") == core
            and tuple(previous.get(stage) for stage in (
                "step4", "step5", "step6"
            )) == expected_stages
        ):
            return previous
        if previous is not None:
            for stage, actual in zip(
                ("step4", "step5", "step6"), expected_stages
            ):
                declared = previous[stage]
                if (
                    declared.get("status") == "current"
                    and actual.get("status") == "stale"
                    and previous.get("active_core") == core
                    and previous.get("step4") == step4
                ):
                    downstream_advanced = bool(
                        (stage == "step5" and not step5_gate_policy_valid)
                        or (stage == "step6" and (
                            not step6_gate_policy_valid
                            or step6_upstream_input_changed
                            or (
                                step5.get("status") == "current"
                                and previous["step5"].get("status")
                                == "current"
                                and step5.get(
                                    "committed_receipt_identity"
                                )
                                != previous["step5"].get(
                                    "committed_receipt_identity"
                                )
                            )
                        ))
                    )
                    if downstream_advanced:
                        # A newer, valid Step5 commit makes the old Step6
                        # receipt stale by construction.  Crashing between
                        # that durable commit and descriptor reconciliation is
                        # a normal forward-progress window, not evidence that
                        # the descriptor is ahead of storage.
                        continue
                    raise BinaryReportError(
                        "BINARY_GLOBAL_RELEASE_DESCRIPTOR_AHEAD",
                        stage,
                    )
        previous_complete = (
            _complete_release_snapshot(previous)
            if previous is not None
            else None
        ) or (
            previous.get("previous_complete")
            if previous is not None else None
        )
        release = {
            "schema": _GLOBAL_RELEASE_SCHEMA,
            "release_sequence": int(
                (previous or {}).get("release_sequence") or 0
            ) + 1,
            "active_core": core,
            "step4": step4,
            "step5": step5,
            "step6": step6,
            "previous_complete": previous_complete,
        }
        release["release_identity"] = _global_release_identity(release)
        _atomic_json(release_path, release)
        return _validate_global_release(release)


def require_current_release_stage(
    report_dir: str | Path,
    stage: str,
    *,
    workflow_lock_held: bool = False,
    active_lock_held: bool = False,
) -> dict[str, Any]:
    if stage not in {"step4", "step5", "step6"}:
        raise ValueError(f"unsupported release stage: {stage}")
    release = reconcile_current_release(
        report_dir,
        workflow_lock_held=workflow_lock_held,
        active_lock_held=active_lock_held,
    )
    required = ("step4", "step5", "step6")[:
        ("step4", "step5", "step6").index(stage) + 1
    ]
    stale = [
        item for item in required
        if release[item].get("status") != "current"
    ]
    if stale:
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_STAGE_STALE", ",".join(stale)
        )
    return release


def load_consistent_step5_query_inputs(
    report_dir: str | Path,
) -> dict[str, Any]:
    """Load index and alerts from one immutable Step5 release snapshot."""

    report = Path(report_dir).resolve()
    public_path = (
        report / ".runtime" / "indexes" / "s5_query_index.json"
    )
    with (
        _report_workflow_read_lock(report),
        _active_generation_publication_lock(report),
    ):
        destinations = _step5_report_publication_destinations(report)
        receipt = report_publication_committed_receipt(
            destinations,
        )
        if not receipt and not report_uses_release_protocol(report):
            return {
                "index": _load_json(public_path),
                "alerts": tuple(_read_csv_rows(
                    report / "evidence" / "call_chain" / "alerts.csv"
                )),
                "index_path": public_path,
                "committed_receipt_identity": "",
            }

        release = require_current_release_stage(
            report,
            "step5",
            workflow_lock_held=True,
            active_lock_held=True,
        )
        with short_temporary_directory(
            prefix="binary-step5-query-snapshot"
        ) as snapshot_text:
            snapshot = materialize_report_publication_committed_snapshot(
                destinations,
                Path(snapshot_text).resolve(),
            )
            snapshot_destinations = tuple(
                Path(item)
                for item in snapshot.get("snapshot_destinations") or ()
            )
            binding = dict(snapshot.get("binding") or {})
            if (
                len(snapshot_destinations) != 3
                or snapshot.get("committed_receipt_identity")
                != release["step5"].get("committed_receipt_identity")
                or binding.get("upstream_publication_receipt_identity")
                != release["step4"].get("committed_receipt_identity")
                or binding.get("publication_input_identity")
                != release["step5"].get("publication_input_identity")
            ):
                raise BinaryReportError(
                    "BINARY_STEP5_QUERY_INDEX_RELEASE_MISMATCH",
                    str(public_path),
                )
            snapshot_path = (
                snapshot_destinations[2] / "s5_query_index.json"
            )
            data = _load_json(snapshot_path)
            if (
                data.get("result_generation_identity")
                != release["active_core"].get(
                    "result_generation_identity"
                )
                or data.get("step4_publication_receipt_identity")
                != binding.get(
                    "upstream_publication_receipt_identity"
                )
                or data.get("step5_publication_input_identity")
                != binding.get("publication_input_identity")
            ):
                raise BinaryReportError(
                    "BINARY_STEP5_QUERY_INDEX_BINDING_MISMATCH",
                    str(public_path),
                )
            return {
                "index": data,
                "alerts": tuple(_read_csv_rows(
                    snapshot_destinations[0] / "alerts.csv"
                )),
                "index_path": public_path,
                "committed_receipt_identity": str(
                    snapshot.get("committed_receipt_identity") or ""
                ),
            }


def load_consistent_step5_query_index(
    report_dir: str | Path,
) -> tuple[dict[str, Any], Path]:
    """Backward-compatible index-only view of the atomic Step5 bundle."""

    bundle = load_consistent_step5_query_inputs(report_dir)
    return dict(bundle["index"]), Path(bundle["index_path"])


def load_consistent_step6_publication(
    report_dir: str | Path,
) -> dict[str, Any]:
    """Read Step6 findings and artifact names from one committed snapshot."""

    report = Path(report_dir).resolve()
    with (
        _report_workflow_read_lock(report),
        _active_generation_publication_lock(report),
    ):
        release = require_current_release_stage(
            report,
            "step6",
            workflow_lock_held=True,
            active_lock_held=True,
        )
        with short_temporary_directory(
            prefix="binary-step6-reader-snapshot"
        ) as snapshot_text:
            snapshot = materialize_report_publication_committed_snapshot(
                _step6_report_publication_destinations(report),
                Path(snapshot_text).resolve(),
            )
            destinations = tuple(
                Path(item)
                for item in snapshot.get("snapshot_destinations") or ()
            )
            binding = dict(snapshot.get("binding") or {})
            if (
                len(destinations) != 2
                or snapshot.get("committed_receipt_identity")
                != release["step6"].get("committed_receipt_identity")
                or binding.get("upstream_publication_receipt_identity")
                != release["step5"].get("committed_receipt_identity")
                or binding.get("publication_input_identity")
                != release["step6"].get("publication_input_identity")
            ):
                raise BinaryReportError(
                    "BINARY_STEP6_READER_RELEASE_MISMATCH", str(report)
                )
            findings = _load_json(destinations[1] / "s6_findings.json")
            if (
                findings.get("schema")
                != "java-upgrade-analyzer.binary-findings.v2"
                or findings.get("result_generation_identity")
                != release["active_core"].get("result_generation_identity")
                or findings.get("step5_publication_receipt_identity")
                != binding.get("upstream_publication_receipt_identity")
                or findings.get("step6_publication_input_identity")
                != binding.get("publication_input_identity")
            ):
                raise BinaryReportError(
                    "BINARY_STEP6_READER_BINDING_MISMATCH", str(report)
                )
            deliverable_names = tuple(sorted(
                path.relative_to(destinations[0]).as_posix()
                for path in destinations[0].rglob("*")
                if path.is_file() and not path.is_symlink()
            ))
            return {
                "findings": findings,
                "deliverable_names": deliverable_names,
                "committed_receipt_identity": str(
                    snapshot.get("committed_receipt_identity") or ""
                ),
                "release_identity": str(release.get("release_identity") or ""),
            }


def verify_current_step4_release(
    report_dir: str | Path,
    *,
    expected_gate_name: str | None = None,
    expected_strict_risk_gate: bool | None = None,
    workflow_lock_held: bool = False,
    active_lock_held: bool = False,
) -> dict[str, Any]:
    """Verify the committed Step4 views against the sealed active generation."""

    if not workflow_lock_held:
        with _standalone_report_workflow_lock(report_dir):
            return verify_current_step4_release(
                report_dir,
                expected_gate_name=expected_gate_name,
                expected_strict_risk_gate=expected_strict_risk_gate,
                workflow_lock_held=True,
                active_lock_held=active_lock_held,
            )
    report = Path(report_dir).resolve()
    if not active_lock_held:
        with _active_generation_publication_lock(report):
            return verify_current_step4_release(
                report,
                expected_gate_name=expected_gate_name,
                expected_strict_risk_gate=expected_strict_risk_gate,
                workflow_lock_held=True,
                active_lock_held=True,
            )
    loaded = load_validated_generation(report)
    with short_temporary_directory(
        prefix="binary-step4-release-verification"
    ) as snapshot_text:
        snapshot = materialize_report_publication_committed_snapshot(
            _step4_report_publication_destinations(report),
            Path(snapshot_text).resolve(),
        )
        if not _step4_publication_binding_matches_loaded(
            snapshot.get("binding") or {}, loaded
        ):
            raise BinaryReportError(
                "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
                str(snapshot.get("transaction_id") or ""),
            )
        gate_receipt = dict(snapshot.get("gate_receipt") or {})
        if (
            expected_gate_name is not None
            and gate_receipt.get("gate_name") != expected_gate_name
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_GATE_POLICY_MISMATCH",
                str(gate_receipt.get("gate_name") or ""),
            )
        if (
            expected_strict_risk_gate is not None
            and gate_receipt.get("strict_risk_gate")
            is not bool(expected_strict_risk_gate)
        ):
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_GATE_POLICY_MISMATCH",
                str(gate_receipt.get("strict_risk_gate")),
            )
        snapshot_destinations = [
            Path(item)
            for item in snapshot.get("snapshot_destinations") or ()
        ]
        if len(snapshot_destinations) != 2:
            raise BinaryReportError(
                "BINARY_STEP4_PUBLICATION_SNAPSHOT_INVALID",
                str(snapshot_text),
            )
        summary = _load_json(snapshot_destinations[0] / "summary.json")
        if (
            summary.get("schema")
            != "java-upgrade-analyzer.binary-step4-summary.v1"
            or summary.get("authority") != "binary_first"
            or summary.get("result_generation_identity")
            != loaded["manifest"].get("result_generation_identity")
            or summary.get("analysis_context_identity")
            != loaded["manifest"].get("analysis_context_identity")
        ):
            raise BinaryReportError(
                "BINARY_STEP4_PUBLICATION_SUMMARY_MISMATCH",
                str(snapshot_destinations[0] / "summary.json"),
            )
    release = require_current_release_stage(
        report,
        "step4",
        workflow_lock_held=True,
        active_lock_held=True,
    )
    if release["step4"].get("committed_receipt_identity") != snapshot.get(
        "committed_receipt_identity"
    ):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_STEP4_RECEIPT_MISMATCH",
            str(snapshot.get("transaction_id") or ""),
        )
    return {
        key: value
        for key, value in snapshot.items()
        if key != "snapshot_destinations"
    }


def _api_display(scope: Mapping[str, Any]) -> tuple[str, str, str]:
    owner = str(scope.get("class_name") or "").replace("/", ".")
    member = str(scope.get("member_name") or "")
    descriptor = str(scope.get("descriptor") or "")
    api_name = owner if not member or member == "<class>" else f"{owner}.{member}"
    return api_name, member or owner.rsplit(".", 1)[-1], descriptor


_CHANGE_LABELS = {
    "added": "新增",
    "removed": "删除",
    "descriptor_changed": "签名变化",
    "access_changed": "访问权限变化",
    "constant_value_changed": "常量值变化",
    "implementation_changed": "实现变化",
    "contract_changed": "二进制契约变化",
    "class_provider": "类提供者变化",
    "class_definition": "类定义结果变化",
}


def _dependency_view(record: Mapping[str, Any]) -> dict[str, str]:
    artifacts = list(record.get("dependency_artifacts") or ())
    lineages = sorted({
        str(item.get("logical_dependency_lineage") or "")
        for item in artifacts if item.get("logical_dependency_lineage")
    })
    base = sorted({
        str(item.get("coord") or item.get("runtime_code_source_origin_identity") or "")
        for item in artifacts if item.get("side") == "base"
    } - {""})
    current = sorted({
        str(item.get("coord") or item.get("runtime_code_source_origin_identity") or "")
        for item in artifacts if item.get("side") == "current"
    } - {""})
    fallback = sorted({
        str(item.get("coord") or item.get("runtime_code_source_origin_identity") or "")
        for item in artifacts
    } - {""})
    normalized_coord, _base_version, _current_version = _artifact_coord_parts(record)
    normalized_fallback = (
        [normalized_coord]
        if normalized_coord and normalized_coord != "UNBOUND_RUNTIME_ARTIFACT"
        else fallback
    )
    dependency = (
        "、".join(lineages or normalized_fallback)
        or "未绑定制品（需查看裁决证据）"
    )
    return {
        "dependency": dependency,
        "dependency_lineage": "|".join(lineages),
        "base_dependency": "|".join(base) or "-",
        "current_dependency": "|".join(current) or "-",
    }


def _change_object(record: Mapping[str, Any]) -> str:
    scope = record.get("fact_scope") or {}
    api_name, _simple, descriptor = _api_display(scope)
    if api_name:
        return f"{api_name}{descriptor}"
    return str(
        scope.get("resource_name")
        or scope.get("entry_name")
        or scope.get("mechanism")
        or record.get("fact_kind")
        or "未知对象"
    )


def _source_inputs_view(loaded: Mapping[str, Any]) -> dict[str, Any]:
    coverage = dict(loaded.get("coverage") or {})
    inputs = dict(coverage.get("source_inputs") or {})
    overlay = dict(coverage.get("source_overlay") or {})
    attestation = dict(loaded.get("source_attestation") or {})
    business = dict(inputs.get("business") or {})
    dependencies = dict(inputs.get("dependencies") or {})
    business_available = business.get("status") == "available"
    dependency_available = dependencies.get("status") == "available"
    business_label = (
        "构建输入已具备并直接使用"
        if business_available and business.get("origin") == "checkout_build"
        else ("已提供并直接使用" if business_available else "未提供")
    )
    dependency_label = "已提供并直接使用" if dependency_available else "未提供"
    label = f"业务源码：{business_label}；依赖源码：{dependency_label}"
    effect = (
        "可用源码用于补充文件/行号、声明与语义解释；正式变化、运行时解析和精确可执行边"
        "仍由最终二进制制品决定。未提供的源码类别会单独保留解释覆盖缺口。"
    )
    return {
        "purpose_version": str(inputs.get("purpose_version") or "missing"),
        "business": business,
        "dependencies": dependencies,
        "label": label,
        "effect": effect,
        "coverage_status": str(overlay.get("coverage_status") or "not_provided"),
        "mapped_count": int(overlay.get("mapped_count") or 0),
        "ambiguous_count": int(overlay.get("ambiguous_count") or 0),
        "conflict_count": int(overlay.get("conflict_count") or 0),
        "language_file_counts": dict(
            attestation.get("language_file_counts") or {}
        ),
        "coverage_gaps": list(attestation.get("coverage_gaps") or ()),
    }


def _source_review_rows(loaded: Mapping[str, Any]) -> list[dict[str, str]]:
    overlay = dict((loaded.get("coverage") or {}).get("source_overlay") or {})
    declarations = {
        str(item.get("overlay_identity") or ""): dict(item)
        for item in (loaded.get("source_explanations") or {}).get("declarations") or []
    }
    rows = []
    for item in overlay.get("rows") or []:
        if str(item.get("mapping_status") or "") != "mapped":
            continue
        location = dict(item.get("source_location") or {})
        member = dict(item.get("binary_member") or {})
        descriptor = str(member.get("descriptor") or "")
        signature = (
            jvm_method_parameter_signature(descriptor)
            if descriptor.startswith("(") else descriptor
        )
        class_name = str(member.get("class_name") or "").replace("/", ".")
        member_name = str(member.get("member_name") or "")
        declaration = declarations.get(str(item.get("overlay_identity") or ""), {})
        line = int(location.get("line") or 0)
        end_line = int(location.get("end_line") or 0)
        line_text = str(line) if not end_line or end_line == line else f"{line}-{end_line}"
        rows.append({
            "源码归属": str(location.get("owner_coord") or "未标识"),
            "归属类型": str(location.get("owner_type") or "unknown"),
            "二进制制品": str(member.get("artifact_coord") or "未标识"),
            "二进制方法": f"{class_name}.{member_name}{signature}",
            "源码位置": (
                f"{location.get('logical_path') or '未知'}:{line_text}"
                if line_text else str(location.get("logical_path") or "未知")
            ),
            "模块": str(location.get("module") or ""),
            "语言": str(location.get("language") or ""),
            "源码声明": str(declaration.get("declared_signature") or ""),
            "注解": "、".join(map(str, declaration.get("annotations") or [])),
            "修饰符": " ".join(map(str, declaration.get("modifiers") or [])),
        })
    return sorted(rows, key=lambda item: (
        item["源码归属"], item["二进制制品"], item["二进制方法"], item["源码位置"]
    ))


def _source_candidate_review_rows(loaded: Mapping[str, Any]) -> list[dict[str, str]]:
    rows = []
    for item in (
        (loaded.get("source_explanations") or {}).get("candidate_relationships") or []
    ):
        descriptor = str(item.get("caller_binary_descriptor") or "")
        signature = (
            jvm_method_parameter_signature(descriptor)
            if descriptor.startswith("(") else descriptor
        )
        caller_class = str(item.get("caller_binary_class_name") or "").replace("/", ".")
        caller_member = str(item.get("caller_binary_member_name") or "")
        rows.append({
            "源码归属": str(item.get("source_owner_coord") or "未标识"),
            "二进制制品": str(item.get("binary_artifact_coord") or "未标识"),
            "调用方": f"{caller_class}.{caller_member}{signature}",
            "源码位置": f"{item.get('caller_logical_path') or '未知'}:{item.get('source_line') or 0}",
            "候选目标": str(item.get("callee_key") or ""),
            "证据类型": str(item.get("evidence_type") or ""),
            "置信度": str(item.get("confidence") or ""),
            "权威边界": "源码候选关系，不是可执行调用边",
        })
    return rows


def _change_label(record: Mapping[str, Any]) -> str:
    scope = record.get("fact_scope") or {}
    value = str(
        scope.get("member_change_kind")
        or scope.get("mechanism")
        or record.get("fact_kind")
        or "changed"
    )
    return _CHANGE_LABELS.get(value, value)


def _review_row(
    record: Mapping[str, Any],
    assessment: Mapping[str, Any] | None,
    *,
    conclusion: str,
) -> dict[str, str]:
    dependency = _dependency_view(record)
    evidence = record.get("evidence") or {}
    coverage_gaps = list(record.get("coverage_gaps") or ())
    return {
        "依赖包": dependency["dependency"],
        "升级前制品": dependency["base_dependency"],
        "升级后制品": dependency["current_dependency"],
        "变化对象": _change_object(record),
        "变化类型": _change_label(record),
        "裁决结论": conclusion,
        "裁决原因": str(record.get("reason_code") or ""),
        "投影状态": str((assessment or {}).get("analysis_projection_status") or "未投影"),
        "覆盖状态": (
            str((assessment or {}).get("projection_coverage_status") or "")
            or ("不完整" if coverage_gaps else "完整")
        ),
        "需人工复核": "是" if conclusion != "正式变化" or coverage_gaps else "否",
        "升级前证据": json.dumps(
            evidence.get("base_contract") or evidence.get("base_member_fingerprint") or {},
            ensure_ascii=False, sort_keys=True,
        ),
        "升级后证据": json.dumps(
            evidence.get("current_contract") or evidence.get("current_member_fingerprint") or {},
            ensure_ascii=False, sort_keys=True,
        ),
        "证据缺口": "|".join(str(item) for item in coverage_gaps) or "-",
        "decision_identity": str(record.get("decision_identity") or ""),
    }


_PRODUCT_CHANGE_TYPES = {
    "removed": "REMOVED",
    "descriptor_changed": "SIGNATURE_CHANGED",
    "access_changed": "ACCESS_REDUCED",
    "constant_value_changed": "CONSTANT_VALUE_CHANGED",
    "added": "METHOD_ADDED",
    "implementation_changed": "BEHAVIOR_CHANGED",
    "contract_changed": "BEHAVIOR_CHANGED",
}


def _visibility_rank(access: Any) -> int:
    value = int(access or 0)
    if value & 0x0001:  # public
        return 3
    if value & 0x0004:  # protected
        return 2
    if value & 0x0002:  # private
        return 0
    return 1


def _product_change_type(decision: Mapping[str, Any]) -> str:
    scope = decision.get("fact_scope") or {}
    evidence = decision.get("evidence") or {}
    fact_kind = str(decision.get("fact_kind") or "")
    change_kind = str(scope.get("member_change_kind") or "implementation_changed")
    base_contract = evidence.get("base_contract")
    current_contract = evidence.get("current_contract")

    if fact_kind == "member_resolution":
        return "MEMBER_RESOLUTION_CHANGED"

    if fact_kind == "provider_topology":
        base_status = str((evidence.get("base_provider") or {}).get("class_provider_status") or "missing")
        current_status = str((evidence.get("current_provider") or {}).get("class_provider_status") or "missing")
        if base_status == "resolved" and current_status == "missing":
            return "CLASS_REMOVED"
        if base_status == "missing" and current_status == "resolved":
            return "CLASS_ADDED"
        return "BEHAVIOR_CHANGED"
    if change_kind == "added" and fact_kind == "class":
        return "CLASS_ADDED"
    if change_kind == "added" and fact_kind == "field":
        return "DATA_FIELD_ADDED"
    if change_kind == "removed" and fact_kind == "field":
        return "DATA_FIELD_REMOVED"
    if change_kind == "contract_changed" and isinstance(base_contract, Mapping) and isinstance(current_contract, Mapping):
        if _visibility_rank(current_contract.get("access")) < _visibility_rank(base_contract.get("access")):
            return "ACCESS_REDUCED"
        if (
            fact_kind == "field"
            and base_contract.get("descriptor") != current_contract.get("descriptor")
        ):
            return "DATA_FIELD_TYPE_CHANGED"
        if (
            fact_kind == "field"
            and base_contract.get("constant") != current_contract.get("constant")
        ):
            return "CONSTANT_VALUE_CHANGED"
        if base_contract.get("descriptor") != current_contract.get("descriptor"):
            return "SIGNATURE_CHANGED"
        return "CONTRACT_CHANGED"
    return _PRODUCT_CHANGE_TYPES.get(change_kind, "BEHAVIOR_CHANGED")


def _artifact_coord_parts(record: Mapping[str, Any]) -> tuple[str, str, str]:
    artifacts = list(record.get("dependency_artifacts") or ())
    lineages = [
        str(item.get("logical_dependency_lineage") or "").strip()
        for item in artifacts if item.get("logical_dependency_lineage")
    ]
    base_coords = [
        str(item.get("coord") or "").strip()
        for item in artifacts if item.get("side") == "base" and item.get("coord")
    ]
    current_coords = [
        str(item.get("coord") or "").strip()
        for item in artifacts if item.get("side") == "current" and item.get("coord")
    ]
    fallback = next((
        str(item.get("runtime_code_source_origin_identity") or "").strip()
        for item in artifacts if item.get("runtime_code_source_origin_identity")
    ), "")
    coord = next((item for item in lineages if item), "")
    if not coord:
        candidate = next(iter(current_coords or base_coords), "")
        parts = candidate.split(":")
        coord = ":".join(parts[:-1]) if len(parts) >= 3 else candidate
    coord = coord or fallback or "UNBOUND_RUNTIME_ARTIFACT"

    def version(values: list[str]) -> str:
        if not values:
            return "-"
        parts = values[0].split(":")
        return parts[-1] if len(parts) >= 3 else values[0]

    return coord, version(base_coords), version(current_coords)


def _resource_activation_item(result: Mapping[str, Any]) -> dict[str, Any]:
    coord, old_version, new_version = _artifact_coord_parts(result)
    callers = []
    for caller in result.get("activation_callers") or ():
        if caller.get("path_certainty") not in {"exact", "possible"}:
            continue
        owner = str(caller.get("caller_class_name") or "").replace("/", ".")
        name = str(caller.get("caller_member_name") or "")
        descriptor = str(caller.get("caller_descriptor") or "")
        signature = (
            jvm_method_parameter_signature(descriptor)
            if descriptor.startswith("(") else "()"
        )
        callers.append({
            **dict(caller),
            "display_caller": f"{owner}.{name}{signature}",
        })
    return {
        **dict(result),
        "coord": coord,
        "old_version": old_version,
        "new_version": new_version,
        "activation_callers": callers,
        "business_entries": sorted({
            item["display_caller"] for item in callers
            if item.get("display_caller")
        }),
    }


def _product_change_row(
    decision: Mapping[str, Any],
    assessment: Mapping[str, Any],
    *,
    evidence_path: str,
) -> dict[str, Any]:
    scope = decision.get("fact_scope") or {}
    evidence = decision.get("evidence") or {}
    api_name, simple, descriptor = _api_display(scope)
    member_kind = str(scope.get("member_kind") or decision.get("fact_kind") or "class")
    if str(scope.get("member_name") or "") == "<init>":
        member_kind = "constructor"
    if member_kind not in {"method", "field", "class", "constructor"}:
        member_kind = "class"
    change_kind = str(scope.get("member_change_kind") or "implementation_changed")
    change_type = _product_change_type(decision)
    coord, old_version, new_version = _artifact_coord_parts(decision)
    incompatible = change_type in {"REMOVED", "SIGNATURE_CHANGED", "ACCESS_REDUCED"}
    change_label = _CHANGE_LABELS.get(change_kind, change_kind)
    api_signature = (
        jvm_method_parameter_signature(descriptor)
        if member_kind in {"method", "constructor"} and descriptor.startswith("(")
        else ""
    )
    if str(decision.get("fact_kind") or "") == "member_resolution":
        base_resolution = evidence.get("base_resolution") or {}
        current_resolution = evidence.get("current_resolution") or {}
        old_value = str(base_resolution.get("resolved_owner") or base_resolution.get("member_resolution_status") or "")
        new_value = str(current_resolution.get("resolved_owner") or current_resolution.get("member_resolution_status") or "")
    else:
        old_value = json.dumps(
            evidence.get("base_contract") or evidence.get("base_member_fingerprint") or "",
            ensure_ascii=False, sort_keys=True,
        )
        new_value = json.dumps(
            evidence.get("current_contract") or evidence.get("current_member_fingerprint") or "",
            ensure_ascii=False, sort_keys=True,
        )
    return {
        "conclusion": "二进制运行时有效变化",
        "change_summary": f"{change_label}：{api_name}{descriptor}",
        "review_reason": (
            f"依赖 {coord} 的运行时有效制品发生变化；"
            f"裁决原因 {decision.get('reason_code') or '-'}"
        ),
        "coord": coord,
        "old_version": old_version,
        "new_version": new_version,
        "change_type": change_type,
        "api_name": api_name,
        "api_simple": simple,
        "symbol_kind": member_kind,
        "api_signature": api_signature,
        "change_fact_identity": str(
            decision.get("change_fact_identity") or ""
        ),
        "decision_identity": str(decision.get("decision_identity") or ""),
        "confirmed": "true",
        "severity": DEFAULT_SEVERITY.get(change_type, "P1"),
        "source": "classfile_contract",
        "binary_compatible": "false" if incompatible else "true",
        "source_compatible": "false" if incompatible else "unknown",
        "compatibility_flags": str(decision.get("reason_code") or ""),
        "reason_code": str(decision.get("reason_code") or ""),
        "data_contract_evidence": "",
        "evidence_path": evidence_path,
        "old_value": old_value,
        "new_value": new_value,
        "field_descriptor": descriptor if member_kind == "field" else "",
        "old_field_has_constant_value": "",
        "constant_field_evidence_json": "",
        "_decision_identity": str(decision.get("decision_identity") or ""),
        "_change_fact_identity": str(decision.get("change_fact_identity") or ""),
        "_projection_status": str(assessment.get("analysis_projection_status") or ""),
        "_projection_coverage_status": str(assessment.get("projection_coverage_status") or ""),
    }


def _trace_metrics_by_change(loaded: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    metrics: dict[str, dict[str, int]] = {}
    for result in loaded["formal"].get("results") or ():
        identity = str(result.get("change_fact_identity") or "")
        item = metrics.setdefault(identity, {
            "exact_api": 0, "possible_api": 0,
            "exact_paths": 0, "possible_paths": 0,
        })
        exact_paths = sum(
            path.get("path_certainty") == "exact" for path in result.get("paths") or ()
        )
        possible_paths = sum(
            path.get("path_certainty") == "possible" for path in result.get("paths") or ()
        )
        item["exact_api"] = max(item["exact_api"], int(bool(result.get("exact_path_exists"))))
        item["possible_api"] = max(item["possible_api"], int(bool(result.get("possible_path_exists"))))
        item["exact_paths"] += exact_paths
        item["possible_paths"] += possible_paths
    return metrics


def prepare_step4_publication_candidate(
    report_dir: str | Path,
    output_dir: str | Path,
    *,
    candidate_activation_identity: str = "",
) -> dict[str, Any]:
    """Stage a private Step4 candidate without gating or publishing it.

    The workflow orchestrator uses this operation while its parent process
    owns the report workflow lock.  The returned transaction remains in
    ``pending_gate`` and cannot change the public report directories.
    """

    _consume_report_publication_prepare_capability(report_dir, "step4")
    return _require_pending_publication_candidate(
        "step4",
        _publish_step4_with_lock(
            report_dir,
            output_dir,
            candidate_activation_identity=candidate_activation_identity,
        ),
    )


def publish_step4(
    report_dir: str | Path,
    output_dir: str | Path,
    *,
    candidate_activation_identity: str = "",
) -> dict[str, Any]:
    if candidate_activation_identity:
        raise BinaryReportError(
            "BINARY_STEP4_CANDIDATE_ACTIVATION_REQUIRES_ORCHESTRATOR",
            str(candidate_activation_identity),
        )
    with _standalone_report_workflow_lock(report_dir):
        with _report_publication_prepare_capability(report_dir, "step4"):
            result = prepare_step4_publication_candidate(
                report_dir,
                output_dir,
            )
        transaction = dict(result.get("publication_transaction") or {})
        destinations = _step4_report_publication_destinations(report_dir)
        try:
            with short_temporary_directory(
                prefix="binary-step4-direct-gate"
            ) as candidate_text:
                candidate = materialize_report_publication_gate_candidate(
                    destinations,
                    Path(candidate_text).resolve(),
                    expected_transaction_id=str(
                        transaction.get("transaction_id") or ""
                    ),
                    expected_binding=dict(transaction.get("binding") or {}),
                    expected_published_content_identity=str(
                        transaction.get("published_content_identity") or ""
                    ),
                )
                candidate_destinations = tuple(
                    Path(item)
                    for item in candidate.get("candidate_destinations") or ()
                )
                if len(candidate_destinations) != 2:
                    raise BinaryReportError(
                        "BINARY_STEP4_PUBLICATION_CANDIDATE_INCOMPLETE",
                        str(candidate_text),
                    )
                from gate import gate_binary_generation

                try:
                    gate_binary_generation(
                        report_dir,
                        candidate_api_dir=candidate_destinations[0],
                        candidate_source_dir=candidate_destinations[1],
                        candidate_activation_identity=(
                            candidate_activation_identity
                        ),
                    )
                except SystemExit as error:
                    raise BinaryReportError(
                        "BINARY_STEP4_PUBLICATION_GATE_FAILED",
                        str(error.code),
                    ) from error
            completion = complete_step4_report_publication_after_gate(
                report_dir,
                expected_transaction_id=transaction["transaction_id"],
                expected_binding=transaction["binding"],
                gate_name="binary_generation",
                strict_risk_gate=False,
                workflow_lock_held=True,
            )
        except BaseException:
            state = report_publication_transaction_state(destinations)
            if state not in {"absent", "committed"}:
                rollback_report_publication(
                    destinations,
                    expected_transaction_id=str(
                        transaction.get("transaction_id") or ""
                    ),
                    expected_binding=dict(transaction.get("binding") or {}),
                )
            raise
        return {
            **result,
            "publication_transaction": None,
            "publication_receipt": completion["publication_receipt"],
            "global_release": completion["global_release"],
        }


def _publish_step4_with_lock(
    report_dir: str | Path,
    output_dir: str | Path,
    *,
    candidate_activation_identity: str = "",
) -> dict[str, Any]:
    _ensure_publication_protocol_marker(report_dir)
    loaded = load_validated_generation(
        report_dir,
        candidate_activation_identity=candidate_activation_identity,
    )
    expected_output = (
        Path(report_dir).resolve() / "evidence" / "api_changes"
    )
    if Path(output_dir).resolve() != expected_output:
        raise BinaryReportError(
            "BINARY_STEP4_PUBLICATION_TARGET_INVALID", str(output_dir)
        )
    source_inputs = _source_inputs_view(loaded)
    source_review_rows = _source_review_rows(loaded)
    source_candidate_rows = _source_candidate_review_rows(loaded)
    decisions = list(loaded["decisions"].get("authoritative_change_facts") or ())
    assessments = {
        str(item.get("decision_identity") or ""): item
        for item in loaded["projections"].get("authoritative_projection_assessments") or ()
    }
    generation = loaded["generation"]
    evidence_path = str(
        (generation / "binary_decisions.json").relative_to(loaded["report_dir"])
    )
    rows = []
    review_rows = []
    for decision in decisions:
        assessment = assessments.get(str(decision.get("decision_identity") or ""), {})
        if assessment.get("analysis_projection_status") == "targetable":
            rows.append(_product_change_row(
                decision, assessment, evidence_path=evidence_path
            ))
        review_rows.append(_review_row(
            decision, assessment, conclusion="正式变化"
        ))
    for decision in loaded["decisions"].get("diagnostic_candidate_facts") or ():
        review_rows.append(_review_row(
            decision, None, conclusion="诊断候选（证据不完整）"
        ))

    trace_metrics = _trace_metrics_by_change(loaded)
    dependencies: dict[str, dict[str, Any]] = {}
    for row in rows:
        dependency = dependencies.setdefault(row["coord"], {
            "rows": [], "change_types": set(), "symbol_kinds": set(),
            "exact_api_ids": set(), "possible_api_ids": set(),
            "exact_paths": 0, "possible_paths": 0,
        })
        dependency["rows"].append(row)
        dependency["change_types"].add(row["change_type"])
        dependency["symbol_kinds"].add(row["symbol_kind"])
        metric = trace_metrics.get(row["_change_fact_identity"], {})
        if metric.get("exact_api"):
            dependency["exact_api_ids"].add(row["_change_fact_identity"])
        if metric.get("possible_api"):
            dependency["possible_api_ids"].add(row["_change_fact_identity"])
        dependency["exact_paths"] += int(metric.get("exact_paths") or 0)
        dependency["possible_paths"] += int(metric.get("possible_paths") or 0)

    output = Path(output_dir).resolve()
    def write(stage: Path) -> None:
        with open_csv_write(stage / "all_changed_apis.csv") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=ALL_CHANGED_APIS_FIELDS, extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(rows)

        dependency_fields = (
            "selection_key", "coord", "dependency_name", "changed_api_count",
            "high_risk_api_count", "business_exact_referenced_api_count",
            "business_candidate_referenced_api_count",
            "business_exact_reference_occurrence_count",
            "business_candidate_reference_occurrence_count",
            "business_reference_occurrence_count", "business_bytecode_scan_status",
            "dependency_source_status", "impact_priority_rank", "recommended",
            "change_types", "symbol_kinds", "review_focus", "detail",
        )
        dependency_rows = []
        ordered_dependencies = sorted(
            dependencies.items(),
            key=lambda item: (
                -len(item[1]["exact_api_ids"]),
                -len(item[1]["possible_api_ids"]),
                -len(item[1]["rows"]),
                item[0],
            ),
        )
        for rank, (coord, item) in enumerate(ordered_dependencies, start=1):
            detail = (
                f"s4_per_dependency/{make_per_dependency_dirname(coord)}/summary.md"
            )
            exact_count = len(item["exact_api_ids"])
            possible_count = len(item["possible_api_ids"] - item["exact_api_ids"])
            dependency_rows.append({
                "selection_key": coord,
                "coord": coord,
                "dependency_name": coord.split(":")[-1],
                "changed_api_count": len(item["rows"]),
                "high_risk_api_count": sum(
                    row["severity"] in {"P0", "P1"} for row in item["rows"]
                ),
                "business_exact_referenced_api_count": exact_count,
                "business_candidate_referenced_api_count": possible_count,
                "business_exact_reference_occurrence_count": item["exact_paths"],
                "business_candidate_reference_occurrence_count": item["possible_paths"],
                "business_reference_occurrence_count": (
                    item["exact_paths"] + item["possible_paths"]
                ),
                "business_bytecode_scan_status": (
                    "complete" if loaded["summary"].get("trace_coverage_status") == "complete"
                    else "incomplete"
                ),
                "dependency_source_status": "not_applicable",
                "impact_priority_rank": rank,
                "recommended": "true" if rank <= 10 else "false",
                "change_types": ", ".join(sorted(item["change_types"])),
                "symbol_kinds": ", ".join(sorted(item["symbol_kinds"])),
                "review_focus": (
                    f"发现 {exact_count} 个精确触达、{possible_count} 个可能触达的变化 API"
                ),
                "detail": detail,
            })
        with open_csv_write(stage / "changed_dependencies.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=dependency_fields)
            writer.writeheader()
            writer.writerows(dependency_rows)

        dependency_lines = [
            "# 发生 API 变化的依赖包", "",
            "本文件列出全部由当前运行时有效二进制制品引起、可进入系统触达分析的依赖包。", "",
            "完整人工裁决：[review.md](review.md)；"
            "需要筛选或批量处理时使用 [all_changed_apis.csv](all_changed_apis.csv)。", "",
            "| 排名 | Top 10 | 依赖包 | 精确触达 API | 可能触达 API | 变化 API 数 | 为什么先看 | 明细 |",
            "|---:|:---:|---|---:|---:|---:|---|---|",
        ]
        if dependency_rows:
            dependency_lines.extend(
                f"| {row['impact_priority_rank']} | "
                f"{'是' if row['recommended'] == 'true' else '否'} | `{row['coord']}` | "
                f"{row['business_exact_referenced_api_count']} | "
                f"{row['business_candidate_referenced_api_count']} | "
                f"{row['changed_api_count']} | {row['review_focus']} | "
                f"[查看]({row['detail']}) |"
                for row in dependency_rows
            )
        else:
            dependency_lines.append("| - | - | - | 0 | 0 | 0 | - | - |")
        _atomic_text(stage / "changed_dependencies.md", "\n".join(dependency_lines) + "\n")

        per_dependency = stage / "s4_per_dependency"
        per_dependency.mkdir()
        for dependency_row in dependency_rows:
            coord = dependency_row["coord"]
            detail_dir = per_dependency / make_per_dependency_dirname(coord)
            detail_dir.mkdir()
            detail_lines = [
                f"# {coord} 变化明细", "",
                f"- 变化 API：{dependency_row['changed_api_count']}",
                f"- 精确触达：{dependency_row['business_exact_referenced_api_count']}",
                f"- 可能触达：{dependency_row['business_candidate_referenced_api_count']}", "",
                "完整裁决上下文：[review.md](../../review.md)；"
                "可筛选明细：[all_changed_apis.csv](../../all_changed_apis.csv)。", "",
                "| 变化对象 | 类型 | 严重级别 | 结论 | 证据 |",
                "|---|---|---|---|---|",
            ]
            for row in dependencies[coord]["rows"]:
                detail_lines.append(
                    f"| `{row['api_name']}{row['api_signature']}` | {row['change_type']} | "
                    f"{row['severity']} | {row['conclusion']} | "
                    "[查看完整裁决](../../review.md) |"
                )
            _atomic_text(detail_dir / "summary.md", "\n".join(detail_lines) + "\n")

        reference_fields = (
            "coord", "api_name", "api_signature", "symbol_kind", "change_type",
            "match_quality", "caller_class", "caller_method", "caller_signature",
            "instruction_offset", "callee_key", "evidence_type", "artifact_entry",
        )
        reference_rows = []
        for row in rows:
            metric = trace_metrics.get(row["_change_fact_identity"], {})
            if metric.get("exact_api") or metric.get("possible_api"):
                reference_rows.append({
                    "coord": row["coord"], "api_name": row["api_name"],
                    "api_signature": row["api_signature"], "symbol_kind": row["symbol_kind"],
                    "change_type": row["change_type"],
                    "match_quality": "exact" if metric.get("exact_api") else "possible",
                    "caller_class": "详见 Step5 调用链",
                    "caller_method": "", "caller_signature": "", "instruction_offset": "",
                    "callee_key": f"{row['api_name']}{row['api_signature']}",
                    "evidence_type": "binary_effective_graph_path",
                    "artifact_entry": evidence_path,
                })
        with open_csv_write(stage / "business_bytecode_changed_api_refs.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=reference_fields)
            writer.writeheader()
            writer.writerows(reference_rows)
        _atomic_json(stage / "business_bytecode_priority_evidence.json", {
            "schema": "java-upgrade-analyzer.step4-business-priority-evidence.v1",
            "authority": "binary_first",
            "scan_status": (
                "complete" if loaded["summary"].get("trace_coverage_status") == "complete"
                else "incomplete"
            ),
            "reason_codes": list(loaded["coverage"].get("trace_coverage_gaps") or ()),
            "evidence_file": "business_bytecode_changed_api_refs.csv",
            "matched_dependency_count": sum(
                bool(row["business_reference_occurrence_count"]) for row in dependency_rows
            ),
            "exact_referenced_api_count": sum(
                row["business_exact_referenced_api_count"] for row in dependency_rows
            ),
            "candidate_referenced_api_count": sum(
                row["business_candidate_referenced_api_count"] for row in dependency_rows
            ),
        })

        source_fields = (
            "源码归属", "归属类型", "二进制制品", "二进制方法", "源码位置", "模块", "语言",
            "源码声明", "注解", "修饰符",
        )
        with open_csv_write(stage / "source_overlay.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=source_fields)
            writer.writeheader()
            writer.writerows(source_review_rows)
        source_gap_fields = (
            "原因", "语言", "源码归属", "模块", "源码文件", "解析器", "错误节点",
        )
        source_gap_rows = [{
            "原因": (
                "该语言暂不提供源码位置/内联证明映射"
                if gap.get("reason_code") == "BINARY_SOURCE_LANGUAGE_NOT_MAPPED"
                else "源码解析不完整"
            ),
            "语言": str(gap.get("language") or ""),
            "源码归属": str(gap.get("owner_coord") or ""),
            "模块": str(gap.get("module") or ""),
            "源码文件": str(gap.get("logical_path") or ""),
            "解析器": str(gap.get("actual_parser") or ""),
            "错误节点": str(gap.get("error_nodes") or ""),
        } for gap in source_inputs["coverage_gaps"]]
        with open_csv_write(stage / "source_coverage_gaps.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=source_gap_fields)
            writer.writeheader()
            writer.writerows(source_gap_rows)
        _atomic_json(
            stage / "source_snapshot.json", loaded["source_attestation"]
        )
        language_summary = "、".join(
            f"{language} {count} 个"
            for language, count in sorted(
                source_inputs["language_file_counts"].items()
            )
        ) or "未提供源码文件"
        source_lines = [
            "# 源码辅助证据", "",
            f"- 源码状态：{source_inputs['label']}",
            f"- 覆盖状态：`{source_inputs['coverage_status']}`",
            f"- 已映射方法：{source_inputs['mapped_count']}",
            f"- 源码文件：{language_summary}",
            f"- 未映射/解析缺口：{len(source_gap_rows)} 个；"
            "[查看逐文件缺口](coverage_gaps.csv)",
            "- 完整源码快照与 SHA：[source_snapshot.json](source_snapshot.json)", "",
            source_inputs["effect"], "",
        ]
        if source_review_rows:
            source_lines.extend((
                "| 源码归属 | 二进制制品 | 二进制方法 | 源码位置 | 源码声明 | 注解 |",
                "|---|---|---|---|---|---|",
            ))
            source_lines.extend(
                f"| `{row['源码归属']}` | `{row['二进制制品']}` | "
                f"`{row['二进制方法']}` | `{row['源码位置']}` | "
                f"{row['源码声明'] or '-'} | {row['注解'] or '-'} |"
                for row in source_review_rows
            )
        elif source_inputs["coverage_status"] == "not_provided":
            source_lines.append("本次没有可用源码输入，因此没有源码映射行；这不影响二进制正式结论。")
        else:
            source_lines.append("已使用源码，但没有方法完成精确 descriptor 映射；请结合覆盖状态和冲突计数复核。")
        candidate_fields = (
            "源码归属", "二进制制品", "调用方", "源码位置", "候选目标",
            "证据类型", "置信度", "权威边界",
        )
        with open_csv_write(stage / "source_candidate_relationships.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=candidate_fields)
            writer.writeheader()
            writer.writerows(source_candidate_rows)
        source_lines.extend(("", "## 源码候选关系", ""))
        if source_candidate_rows:
            source_lines.extend((
                "以下关系用于人工解释和候选复核，不能替代字节码可执行边。", "",
                "| 源码归属 | 调用方 | 候选目标 | 源码位置 | 置信度 |",
                "|---|---|---|---|---|",
            ))
            source_lines.extend(
                f"| `{row['源码归属']}` | `{row['调用方']}` | `{row['候选目标']}` | "
                f"`{row['源码位置']}` | `{row['置信度']}` |"
                for row in source_candidate_rows
            )
        else:
            source_lines.append("本次没有生成源码候选调用关系。")
        _atomic_text(stage / "source_overlay.md", "\n".join(source_lines) + "\n")

        summary = {
            "schema": "java-upgrade-analyzer.binary-step4-summary.v1",
            "authority": "binary_first",
            "result_generation_identity": loaded["manifest"]["result_generation_identity"],
            "analysis_context_identity": loaded["manifest"]["analysis_context_identity"],
            "authoritative_change_fact_count": len(decisions),
            "targetable_change_fact_count": sum(
                item.get("analysis_projection_status") == "targetable"
                for item in assessments.values()
            ),
            "confirmed_unprojectable_fact_count": len(
                loaded["projections"].get("confirmed_unprojectable_facts") or ()
            ),
            "diagnostic_candidate_fact_count": len(
                loaded["decisions"].get("diagnostic_candidate_facts") or ()
            ),
            "excluded_decision_count": len(loaded["decisions"].get("excluded_decisions") or ()),
            "dependency_count": len(dependency_rows),
            "published_api_change_count": len(rows),
            "source_inputs": source_inputs,
            "decision_coverage_status": loaded["summary"].get(
                "decision_coverage_status"
            ),
            "trace_coverage_status": loaded["summary"].get(
                "trace_coverage_status"
            ),
            "coverage": loaded["coverage"],
        }
        _atomic_json(stage / "summary.json", summary)
        summary_lines = [
            "# Binary-first 运行时变化事实", "",
            "人工复核请先看 `changed_dependencies.md`，再进入依赖明细；"
            "需要筛选或批量处理时使用 `all_changed_apis.csv`。", "",
            f"- 权威变化事实：{summary['authoritative_change_fact_count']}",
            f"- 可投影变化事实：{summary['targetable_change_fact_count']}",
            f"- 确认但不可投影：{summary['confirmed_unprojectable_fact_count']}",
            f"- 诊断候选事实：{summary['diagnostic_candidate_fact_count']}",
            f"- 排除裁决：{summary['excluded_decision_count']}",
            f"- 涉及依赖：{summary['dependency_count']}",
            f"- 源码输入：{source_inputs['label']}",
            f"- 源码映射：{source_inputs['mapped_count']} 个，覆盖状态 `{source_inputs['coverage_status']}`",
            "",
        ]
        summary_lines.extend((
            source_inputs["effect"], "",
            "源码辅助证据：`../source_analysis/review.md`；"
            "结构化映射：`../source_analysis/method_mappings.csv`；"
            "候选关系：`../source_analysis/candidate_relationships.csv`；"
            "逐文件缺口：`../source_analysis/coverage_gaps.csv`。", "",
        ))
        _atomic_text(stage / "summary.md", "\n".join(summary_lines))

        review_lines = [
            "# 运行时变化人工复核", "",
            "本报告按引起变化的依赖包分组。`正式变化` 来自完整二进制裁决；"
            "`诊断候选` 表示证据仍有缺口，不能解释为无影响。", "",
            f"- 源码输入：{source_inputs['label']}",
            f"- 源码覆盖：`{source_inputs['coverage_status']}`；已映射 {source_inputs['mapped_count']} 个方法",
            f"- 作用边界：{source_inputs['effect']}", "",
        ]
        review_dependencies = sorted({row["依赖包"] for row in review_rows})
        for dependency in review_dependencies:
            review_lines.extend((f"## {dependency}", ""))
            for row in (item for item in review_rows if item["依赖包"] == dependency):
                review_lines.extend((
                    f"### {row['变化对象']}", "",
                    f"- 制品：`{row['升级前制品']}` → `{row['升级后制品']}`",
                    f"- 变化：{row['变化类型']}",
                    f"- 结论：{row['裁决结论']}",
                    f"- 原因：`{row['裁决原因']}`",
                    f"- 投影/覆盖：{row['投影状态']} / {row['覆盖状态']}",
                    f"- 需要人工复核：{row['需人工复核']}",
                    f"- 证据缺口：{row['证据缺口']}",
                    f"- 裁决身份：`{row['decision_identity']}`", "",
                ))
        _atomic_text(stage / "review.md", "\n".join(review_lines))
    source_output = loaded["report_dir"] / "evidence" / "source_analysis"

    def publish_source(stage: Path, prepared: Mapping[Path, Path]) -> None:
        prepared_output = prepared[output]
        shutil.copyfile(prepared_output / "source_overlay.md", stage / "review.md")
        shutil.copyfile(prepared_output / "source_overlay.csv", stage / "method_mappings.csv")
        shutil.copyfile(
            prepared_output / "source_candidate_relationships.csv",
            stage / "candidate_relationships.csv",
        )
        shutil.copyfile(
            prepared_output / "source_coverage_gaps.csv",
            stage / "coverage_gaps.csv",
        )
        shutil.copyfile(
            prepared_output / "source_snapshot.json",
            stage / "source_snapshot.json",
        )
        for obsolete_source_file in (
            "source_overlay.md", "source_overlay.csv",
            "source_candidate_relationships.csv",
            "source_coverage_gaps.csv", "source_snapshot.json",
        ):
            (prepared_output / obsolete_source_file).unlink()

    # Every formal publication is gated before public rename.  Direct CLI/API
    # use runs the same independent candidate gate in-process; orchestrated
    # use returns the retained transaction to run_step.
    retain_publication_transaction = True
    transaction_binding = {
        "result_generation_identity": loaded["manifest"][
            "result_generation_identity"
        ],
        "validation_run_identity": loaded["active"][
            "validation_run_identity"
        ],
        "validation_result_sha256": loaded["active"][
            "validation_result_sha256"
        ],
    }
    if _is_sha256_identity(loaded["active"].get("activation_identity")):
        transaction_binding["activation_identity"] = str(
            loaded["active"]["activation_identity"]
        )
    publication_transaction = _stage_directory_group((
        (output, lambda stage, _prepared: write(stage)),
        (source_output, publish_source),
    ),
        retain_transaction=retain_publication_transaction,
        transaction_binding=transaction_binding,
        trusted_root=Path(report_dir).resolve(),
    )
    return {
        "phase": "step4",
        "change_fact_count": len(rows),
        "output_dir": str(output),
        "publication_transaction": publication_transaction,
    }


def _result_item(api: Mapping[str, Any]) -> dict[str, Any]:
    owner = str(api.get("display_owner") or "").replace("/", ".")
    member = str(api.get("display_member") or "")
    name = owner if not member or member == "<class>" else f"{owner}.{member}"
    dependency = _dependency_view(api)
    paths = list(api.get("paths") or ())
    primary_path = next(
        (item for item in paths if item.get("path_certainty") == "exact"),
        paths[0] if paths else {},
    )
    descriptor = str(api.get("display_descriptor") or "")
    api_signature = (
        jvm_method_parameter_signature(descriptor)
        if descriptor.startswith("(") else ""
    )
    return {
        "coord": dependency["dependency"],
        "target_coord": dependency["dependency"],
        "base_dependency": dependency["base_dependency"],
        "current_dependency": dependency["current_dependency"],
        "api": name,
        "changed_symbol": name,
        "api_signature": api_signature,
        "symbol_kind": str(api.get("display_member_kind") or ""),
        "reported_api_identity": api.get("reported_api_identity"),
        "reachability_status": api.get("reachability_status"),
        "path_status": api.get("reachability_status"),
        "impact_conclusion": api.get("impact_conclusion"),
        "static_linkage_status": api.get("static_linkage_status"),
        "runtime_verification_status": api.get("runtime_verification_status"),
        "path_set_complete": bool(api.get("path_set_complete")),
        "exact_path_exists": bool(api.get("exact_path_exists")),
        "possible_path_exists": bool(api.get("possible_path_exists")),
        "path_text": str(primary_path.get("path_text") or ""),
        "path_certainty": str(primary_path.get("path_certainty") or ""),
        "paths": paths,
        "reason": "二进制运行时有效变化的系统触达结果",
        "contributing_change_fact_ids": list(api.get("contributing_change_fact_ids") or ()),
    }


LEGACY_ALERT_FIELDS = (
    "conclusion", "change_summary", "review_reason", "chain_summary",
    "review_focus", "chain_entry", "chain_target", "chain_hop_count",
    "chain_detail", "api_identity", "reported_api_identity",
    "change_fact_identity", "decision_identity", "path_id", "target_coord",
    "changed_symbol", "api_signature", "symbol_kind", "compile_impact",
    "runtime_link_impact", "change_type", "severity", "path_status",
    "uncertainty_kind", "business_reachable", "entry_kind", "reach_kind",
    "business_entry", "consumer_coord", "consumer_class", "consumer_method",
    "consumer_signature", "path_text", "path_occurrence_count",
    "evidence_files", "detail_file",
)


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _change_row_key(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("coord") or "").strip(),
        str(row.get("api_name") or row.get("api") or "").strip(),
        str(row.get("api_signature") or "").strip(),
        str(row.get("symbol_kind") or "").strip(),
    )


def _change_rows_by_result(
    report_dir: str | Path,
    *,
    api_changes_dir: str | Path | None = None,
) -> tuple[list[dict[str, str]], dict[tuple[str, str, str, str], dict[str, str]]]:
    api_root = (
        Path(api_changes_dir)
        if api_changes_dir is not None
        else Path(report_dir).resolve() / "evidence" / "api_changes"
    )
    rows = _read_csv_rows(
        api_root / "all_changed_apis.csv"
    )
    lookup: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for row in rows:
        lookup.setdefault(_change_row_key(row), row)
    return rows, lookup


def _legacy_result_item(
    item: Mapping[str, Any],
    change_row: Mapping[str, Any] | None,
) -> dict[str, Any]:
    change = dict(change_row or {})
    paths = [
        str(path.get("path_text") or "").strip()
        for path in item.get("paths") or []
        if str(path.get("path_text") or "").strip()
    ]
    if not paths and str(item.get("path_text") or "").strip():
        paths = [str(item.get("path_text") or "").strip()]
    state = str(item.get("reachability_status") or "not_analyzed")
    if state == "reachable":
        user_conclusion = "已确认影响"
        reason_code = "RUNTIME_VERIFICATION_REQUIRED"
        user_reason = (
            "已确认当前系统存在到该变化 API 的精确静态可执行调用关系；"
            "这里确认的是调用关系受到 API 变化影响，不表示运行时故障已经发生，"
            "仍需定向测试验证。"
        )
    elif state == "uncertain":
        user_conclusion = "结论未确定（存在候选证据）" if paths else "结论未确定（静态分析能力边界）"
        reason_code = "BINARY_REACHABILITY_UNCERTAIN"
        user_reason = "存在候选证据或静态分析边界，当前不能确认实际影响。"
    elif state == "not_found_in_static_analysis":
        user_conclusion = "未发现调用路径"
        reason_code = "NOT_FOUND_IN_STATIC_ANALYSIS"
        user_reason = "当前完整静态范围内未发现调用路径；该结论不能解释为安全。"
    else:
        user_conclusion = "本次未完成分析"
        reason_code = "BINARY_TRACE_NOT_ANALYZED"
        user_reason = "二进制触达分析未形成可采用结果，不能解释为未受影响。"
    api = str(item.get("api") or "")
    api_signature = str(item.get("api_signature") or "")
    effective_coord = str(
        change.get("coord") or item.get("coord") or ""
    )
    effective_symbol_kind = str(
        change.get("symbol_kind") or item.get("symbol_kind") or ""
    )
    old_version = str(change.get("old_version") or "")
    new_version = str(change.get("new_version") or "")
    business_entry = paths[0].split(" → ", 1)[0] if paths else ""
    primary_path = next(
        (
            candidate for candidate in item.get("paths") or []
            if candidate.get("path_text") == (paths[0] if paths else "")
        ),
        {},
    )
    return {
        **dict(item),
        "coord": effective_coord,
        "target_coord": effective_coord,
        "api_identity": "|".join((
            effective_coord, api, api_signature,
            effective_symbol_kind, str(change.get("change_type") or ""),
            str(change.get("change_fact_identity") or ""),
        )),
        "change_fact_identity": str(
            change.get("change_fact_identity") or ""
        ),
        "decision_identity": str(change.get("decision_identity") or ""),
        "old_version": old_version,
        "new_version": new_version,
        "api_name": api,
        "api_simple": api.rsplit(".", 1)[-1],
        "change_type": str(change.get("change_type") or ""),
        "symbol_kind": effective_symbol_kind,
        "severity": str(change.get("severity") or "P1"),
        "confirmed": str(change.get("confirmed") or "true"),
        "source": str(change.get("source") or "binary_first"),
        "analysis_status": state,
        "uncertainty_kind": (
            "candidate_evidence" if state == "uncertain" and paths
            else "analysis_limitation" if state == "uncertain" else ""
        ),
        "reason_code": reason_code,
        "reason": user_reason,
        "reachable_note": user_reason,
        "direct_callers": len(paths),
        "business_reach_depth": max(len(paths[0].split(" → ")) - 1, 0) if paths else 0,
        "dependency_chain_coords": [],
        "call_paths": paths,
        "path_details": [
            {
                "path_status": state,
                "path_text": path,
                "path_certainty": str(
                    next((candidate.get("path_certainty") for candidate in item.get("paths") or [] if candidate.get("path_text") == path), "")
                ),
                "entry_kinds": list(
                    next((candidate.get("entry_kinds") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "entry_kind_labels": list(
                    next((candidate.get("entry_kind_labels") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "entrypoint_dependency_coords": list(
                    next((candidate.get("entrypoint_dependency_coords") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "entrypoint_activation_reasons": list(
                    next((candidate.get("entrypoint_activation_reasons") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "mechanism_kinds": list(
                    next((candidate.get("mechanism_kinds") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "mechanism_labels": list(
                    next((candidate.get("mechanism_labels") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
            }
            for path in paths
        ],
        "evidence_paths": [],
        "verification": ["执行相关单元测试、集成测试或运行时回归验证。"] if state == "reachable" else [],
        "priority_score": 0,
        "priority_factors": {},
        "user_conclusion": user_conclusion,
        "decision_bucket": "probable_impact" if state == "reachable" else state,
        "user_reason": user_reason,
        "recommended_action": (
            "根据已定位调用关系执行定向回归验证。" if state == "reachable"
            else "复核证据边界并补充缺失输入或测试。"
        ),
        "key_evidence": paths[0] if paths else "",
        "business_entry": business_entry,
        "entry_kind": " / ".join(primary_path.get("entry_kind_labels") or ()),
        "entrypoint_dependency": " / ".join(
            primary_path.get("entrypoint_dependency_coords") or ()
        ),
        "change_summary": str(change.get("change_summary") or ""),
        "old_value": str(change.get("old_value") or ""),
        "new_value": str(change.get("new_value") or ""),
        "review_reason": str(change.get("review_reason") or user_reason),
    }


def _legacy_alert_rows(items: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows = []
    for item in items:
        paths = list(item.get("call_paths") or []) or [""]
        for index, path in enumerate(paths, start=1):
            path_detail = next(
                (
                    candidate for candidate in item.get("path_details") or ()
                    if str(candidate.get("path_text") or "") == str(path)
                ),
                {},
            )
            entry_kind = " / ".join(
                str(value) for value in path_detail.get("entry_kind_labels") or ()
                if str(value)
            )
            entrypoint_dependency = " / ".join(
                str(value)
                for value in path_detail.get("entrypoint_dependency_coords") or ()
                if str(value)
            )
            mechanism_labels = " / ".join(
                str(value)
                for value in path_detail.get("mechanism_labels") or ()
                if str(value)
            )
            nodes = [part.strip() for part in str(path).split(" → ") if part.strip()]
            entry = nodes[0] if nodes else str(item.get("business_entry") or "")
            target = nodes[-1] if nodes else f"{item.get('api') or ''}{item.get('api_signature') or ''}"
            identity = str(item.get("api_identity") or "")
            digest = hashlib.sha1(f"{identity}|{path}|{index}".encode("utf-8")).hexdigest()[:12]
            status = str(item.get("analysis_status") or "not_analyzed")
            entry_prefix, separator, entry_signature = entry.partition("(")
            entry_signature = f"({entry_signature}" if separator else ""
            consumer_class, dot, consumer_method = entry_prefix.rpartition(".")
            if not dot:
                consumer_class, consumer_method = entry_prefix, ""
            rows.append({
                "conclusion": str(item.get("user_conclusion") or ""),
                "change_summary": str(item.get("change_summary") or ""),
                "review_reason": str(item.get("review_reason") or item.get("user_reason") or ""),
                "chain_summary": (
                    f"入口类型：{entry_kind or '业务字节码入口'}；入口：{entry}；"
                    f"路径机制：{mechanism_labels or '字节码直接调用'}；"
                    f"终点：{target}；{max(len(nodes) - 1, 0)} 次调用（{len(nodes)} 个节点）"
                    if path else f"未形成完整链路；目标 API：{target}"
                ),
                "review_focus": str(item.get("recommended_action") or ""),
                "chain_entry": entry,
                "chain_target": target,
                "chain_hop_count": str(max(len(nodes) - 1, 0)),
                "chain_detail": " -> ".join(f"{position}. {node}" for position, node in enumerate(nodes, start=1)),
                "api_identity": identity,
                "reported_api_identity": str(
                    item.get("reported_api_identity") or ""
                ),
                "change_fact_identity": str(
                    item.get("change_fact_identity") or ""
                ),
                "decision_identity": str(
                    item.get("decision_identity") or ""
                ),
                "path_id": f"PATH-{digest}",
                "target_coord": str(item.get("coord") or ""),
                "changed_symbol": str(item.get("api") or ""),
                "api_signature": str(item.get("api_signature") or ""),
                "symbol_kind": str(item.get("symbol_kind") or ""),
                "compile_impact": str(item.get("static_linkage_status") or ""),
                "runtime_link_impact": str(item.get("impact_conclusion") or ""),
                "change_type": str(item.get("change_type") or ""),
                "severity": str(item.get("severity") or "P1"),
                "path_status": status,
                "uncertainty_kind": str(item.get("uncertainty_kind") or ""),
                "business_reachable": "true" if status == "reachable" else "unknown",
                "entry_kind": entry_kind or ("业务字节码入口" if entry else ""),
                "reach_kind": mechanism_labels or ("字节码直接调用" if path else ""),
                "business_entry": entry,
                "consumer_coord": entrypoint_dependency or ("业务制品" if entry else ""),
                "consumer_class": consumer_class,
                "consumer_method": consumer_method,
                "consumer_signature": entry_signature,
                "path_text": str(path),
                "path_occurrence_count": "1",
                "evidence_files": ".runtime/binary_authority/active_binary_generation.json",
                "detail_file": "",
            })
    return rows


def _safe_detail_filename(item: Mapping[str, Any]) -> str:
    identity = str(item.get("api_identity") or item.get("reported_api_identity") or "api")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", identity).strip("_")[:96] or "api"
    return f"{slug}_{hashlib.sha1(identity.encode('utf-8')).hexdigest()[:12]}.json"


def _legacy_coverage(loaded: Mapping[str, Any]) -> dict[str, Any]:
    def reason_codes(values: Any) -> list[str]:
        result = []
        for value in values or ():
            if isinstance(value, Mapping):
                code = str(value.get("reason_code") or value.get("code") or "").strip()
            else:
                code = str(value or "").strip()
            if code and code not in result:
                result.append(code)
        return result

    summary = dict(loaded.get("summary") or {})
    binary = dict(loaded.get("coverage") or {})
    decision_status = str(summary.get("decision_coverage_status") or "unknown")
    trace_status = str(summary.get("trace_coverage_status") or "unknown")
    components = [
        {
            "id": "binary_api_diff",
            "status": "complete" if decision_status == "complete" else "partial",
            "reason_codes": reason_codes(
                summary.get("decision_coverage_gaps")
                or binary.get("decision_coverage_gaps")
            ),
            "evidence": [".runtime/binary_authority/active_binary_generation.json"],
        },
        {
            "id": "business_reachability",
            "status": "complete" if trace_status == "complete" else "partial",
            "reason_codes": reason_codes(
                summary.get("trace_coverage_gaps")
                or binary.get("trace_coverage_gaps")
            ),
            "evidence": ["evidence/call_chain/alerts.csv"],
        },
    ]
    critical = [item["id"] for item in components if item["status"] != "complete"]
    return {
        "schema": "java-upgrade-analyzer.coverage.v1",
        "overall_status": "complete" if not critical else "partial",
        "critical_incomplete": critical,
        "components": components,
        "binary": binary,
    }


def _step4_report_publication_destinations(
    report_dir: str | Path,
) -> tuple[Path, Path]:
    report = Path(report_dir).resolve()
    return (
        report / "evidence" / "api_changes",
        report / "evidence" / "source_analysis",
    )


def _step5_report_publication_destinations(
    report_dir: str | Path,
) -> tuple[Path, Path, Path]:
    report = Path(report_dir).resolve()
    return (
        report / "evidence" / "call_chain",
        report / "evidence" / "binary_analysis",
        report / ".runtime" / "indexes",
    )


def _step6_report_publication_destinations(
    report_dir: str | Path,
) -> tuple[Path, Path]:
    report = Path(report_dir).resolve()
    return (
        report / "deliverables",
        report / ".runtime" / "findings",
    )


def _downstream_publication_binding_matches_loaded(
    binding: Mapping[str, Any], loaded: Mapping[str, Any]
) -> bool:
    expected_core = _active_release_core(loaded)
    if any(binding.get(key) != value for key, value in expected_core.items()):
        return False
    active_activation = loaded["active"].get("activation_identity")
    declared_activation = binding.get("activation_identity")
    if _is_sha256_identity(active_activation):
        return declared_activation == active_activation
    return declared_activation is None or _is_sha256_identity(
        declared_activation
    )


def complete_step4_report_publication_after_gate(
    report_dir: str | Path,
    *,
    expected_transaction_id: str,
    expected_binding: Mapping[str, Any],
    gate_name: str,
    strict_risk_gate: bool,
    workflow_lock_held: bool = False,
) -> dict[str, Any]:
    """Commit a gated Step4 re-render only for the still-active generation."""

    formal_gate_name = _require_formal_publication_gate("step4", gate_name)
    if not workflow_lock_held:
        with _standalone_report_workflow_lock(report_dir):
            return complete_step4_report_publication_after_gate(
                report_dir,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
                gate_name=gate_name,
                strict_risk_gate=strict_risk_gate,
                workflow_lock_held=True,
            )
    report = Path(report_dir).resolve()
    destinations = _step4_report_publication_destinations(report)
    with _active_generation_publication_lock(report):
        transaction = report_publication_transaction_receipt(
            destinations,
            expected_transaction_id=expected_transaction_id,
            expected_binding=expected_binding,
        )
        loaded = load_validated_generation(report)
        if (
            transaction.get("state") != "pending_gate"
            or not _step4_publication_binding_matches_loaded(
                transaction.get("binding") or {}, loaded
            )
        ):
            rollback_report_publication(
                destinations,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
            )
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_UPSTREAM_CHANGED", "step4"
            )
        try:
            gate_receipt = mark_report_publication_gate_passed(
                destinations,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
                gate_name=formal_gate_name,
                strict_risk_gate=strict_risk_gate,
            )
            publish_report_publication(
                destinations,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
            )
            commit_report_publication(
                destinations,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
            )
            committed_receipt = report_publication_committed_receipt(
                destinations
            )
            global_release = reconcile_current_release(
                report,
                workflow_lock_held=True,
                active_lock_held=True,
            )
        except BaseException:
            state = report_publication_transaction_state(destinations)
            if state not in {"absent", "committed"}:
                rollback_report_publication(
                    destinations,
                    expected_transaction_id=expected_transaction_id,
                    expected_binding=expected_binding,
                )
            raise
    if global_release["step4"].get(
        "committed_receipt_identity"
    ) != committed_receipt.get("committed_receipt_identity"):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_STAGE_RECEIPT_MISMATCH", "step4"
        )
    return {
        "stage": "step4",
        "gate_receipt": gate_receipt,
        "publication_receipt": committed_receipt,
        "global_release": global_release,
    }


def complete_downstream_report_publication_after_gate(
    report_dir: str | Path,
    stage: str,
    *,
    expected_transaction_id: str,
    expected_binding: Mapping[str, Any],
    gate_name: str,
    strict_risk_gate: bool,
    workflow_lock_held: bool = False,
) -> dict[str, Any]:
    """Atomically revalidate and commit a gated Step5/6 transaction."""

    if stage not in {"step5", "step6"}:
        raise ValueError(f"unsupported downstream publication stage: {stage}")
    formal_gate_name = _require_formal_publication_gate(stage, gate_name)
    if not workflow_lock_held:
        with _standalone_report_workflow_lock(report_dir):
            return complete_downstream_report_publication_after_gate(
                report_dir,
                stage,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
                gate_name=gate_name,
                strict_risk_gate=strict_risk_gate,
                workflow_lock_held=True,
            )
    report = Path(report_dir).resolve()
    destinations = (
        _step5_report_publication_destinations(report)
        if stage == "step5"
        else _step6_report_publication_destinations(report)
    )
    upstream_stage = "step4" if stage == "step5" else "step5"
    with _active_generation_publication_lock(report):
        transaction = report_publication_transaction_receipt(
            destinations,
            expected_transaction_id=expected_transaction_id,
            expected_binding=expected_binding,
        )
        if transaction.get("state") != "pending_gate":
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_STATE_INVALID",
                str(transaction.get("state") or "absent"),
            )
        loaded = load_validated_generation(report)
        binding = dict(transaction.get("binding") or {})
        release = require_current_release_stage(
            report,
            upstream_stage,
            workflow_lock_held=True,
            active_lock_held=True,
        )
        step4_receipt = report_publication_committed_receipt(
            _step4_report_publication_destinations(report)
        )
        live_publication_input_identity = ""
        if stage == "step5":
            with short_temporary_directory(
                prefix="binary-step5-precommit-candidate"
            ) as candidate_text:
                candidate = materialize_report_publication_gate_candidate(
                    destinations,
                    Path(candidate_text).resolve(),
                    expected_transaction_id=expected_transaction_id,
                    expected_binding=expected_binding,
                    expected_published_content_identity=str(
                        transaction.get("published_content_identity") or ""
                    ),
                )
                candidate_destinations = tuple(
                    Path(item)
                    for item in candidate.get("candidate_destinations") or ()
                )
                if len(candidate_destinations) != 3:
                    raise BinaryReportError(
                        "BINARY_STEP5_PUBLICATION_SNAPSHOT_INVALID",
                        str(expected_transaction_id),
                    )
                selection = _load_json(
                    candidate_destinations[0] / "selection.json"
                )
                selected_coords = selection.get("selected_coords")
                selected_names = selection.get("selected_names")
                if (
                    selection.get("schema")
                    != "java-upgrade-analyzer.binary-step5-selection.v1"
                    or not isinstance(selected_coords, list)
                    or not isinstance(selected_names, list)
                    or any(not isinstance(item, str) for item in selected_coords)
                    or any(not isinstance(item, str) for item in selected_names)
                ):
                    raise BinaryReportError(
                        "BINARY_STEP5_PUBLICATION_CONTENT_MISMATCH",
                        "selection.json",
                    )
                live_publication_input_identity = (
                    _step5_publication_input_identity(
                        loaded=loaded,
                        step4_receipt=step4_receipt,
                        selected_coords=set(selected_coords),
                        selected_names=set(selected_names),
                    )
                )
        else:
            step5_receipt = report_publication_committed_receipt(
                _step5_report_publication_destinations(report)
            )
            live_publication_input_identity = (
                _step6_publication_input_identity(
                    loaded,
                    step4_receipt,
                    step5_receipt,
                    _step6_upstream_evidence_state(
                        report,
                        require_complete=True,
                    ),
                )
            )
        if (
            not _downstream_publication_binding_matches_loaded(
                binding, loaded
            )
            or binding.get("upstream_publication_receipt_identity")
            != release[upstream_stage].get(
                "committed_receipt_identity"
            )
            or not _is_sha256_identity(
                binding.get("publication_input_identity")
            )
            or binding.get("publication_input_identity")
            != live_publication_input_identity
        ):
            rollback_report_publication(
                destinations,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
            )
            raise BinaryReportError(
                "BINARY_REPORT_PUBLICATION_UPSTREAM_CHANGED", stage
            )
        try:
            gate_receipt = mark_report_publication_gate_passed(
                destinations,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
                gate_name=formal_gate_name,
                strict_risk_gate=strict_risk_gate,
            )
            publish_report_publication(
                destinations,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
            )
            commit_report_publication(
                destinations,
                expected_transaction_id=expected_transaction_id,
                expected_binding=expected_binding,
            )
        except BaseException:
            state = report_publication_transaction_state(destinations)
            if state not in {"absent", "committed"}:
                rollback_report_publication(
                    destinations,
                    expected_transaction_id=expected_transaction_id,
                    expected_binding=expected_binding,
                )
            raise
    committed_receipt = report_publication_committed_receipt(destinations)
    global_release = reconcile_current_release(
        report, workflow_lock_held=True
    )
    if global_release[stage].get("committed_receipt_identity") != (
        committed_receipt.get("committed_receipt_identity")
    ):
        raise BinaryReportError(
            "BINARY_GLOBAL_RELEASE_STAGE_RECEIPT_MISMATCH", stage
        )
    return {
        "stage": stage,
        "gate_receipt": gate_receipt,
        "publication_receipt": committed_receipt,
        "global_release": global_release,
    }


def recover_downstream_report_publications(
    report_dir: str | Path,
    *,
    workflow_lock_held: bool = False,
    reconcile_release: bool = False,
) -> dict[str, Any]:
    """Recover Step5/6 crash markers before any public result is consumed."""

    if not workflow_lock_held:
        with _standalone_report_workflow_lock(report_dir):
            return recover_downstream_report_publications(
                report_dir,
                workflow_lock_held=True,
                reconcile_release=reconcile_release,
            )
    report = Path(report_dir).resolve()
    actions = []
    with _active_generation_publication_lock(report):
        for stage, destinations in (
            ("step5", _step5_report_publication_destinations(report)),
            ("step6", _step6_report_publication_destinations(report)),
        ):
            metadata = report_publication_transaction_recovery_metadata(
                destinations
            )
            state = str(metadata.get("state") or "absent")
            if state == "absent":
                continue
            recovered = recover_report_publication(
                destinations,
                expected_transaction_id=str(metadata["transaction_id"]),
                expected_binding=dict(metadata["binding"]),
            )
            actions.append({
                "stage": stage,
                "prior_state": state,
                "disposition": (
                    "finalized_committed"
                    if state == "committed"
                    else "rolled_back_uncommitted"
                ),
                "recovered": bool(recovered),
            })
    # Startup recovery must not make a stale Step4 implementation receipt a
    # prerequisite for restoring downstream rename state.  The orchestrator
    # first converges these markers, then independently verifies/republishes
    # Step4 before asking for global release reconciliation.
    release = (
        reconcile_current_release(report, workflow_lock_held=True)
        if reconcile_release
        else None
    )
    return {"actions": actions, "global_release": release}


def _loaded_step4_publication_binding(
    loaded: Mapping[str, Any],
) -> dict[str, str]:
    binding = {
        "result_generation_identity": loaded["manifest"].get(
            "result_generation_identity"
        ),
        "validation_run_identity": loaded["active"].get(
            "validation_run_identity"
        ),
        "validation_result_sha256": loaded["active"].get(
            "validation_result_sha256"
        ),
        _REPORT_IMPLEMENTATION_IDENTITY_FIELD: (
            report_implementation_identity()
        ),
    }
    if _is_sha256_identity(loaded["active"].get("activation_identity")):
        binding["activation_identity"] = str(
            loaded["active"]["activation_identity"]
        )
    if not all(_is_sha256_identity(value) for value in binding.values()):
        raise BinaryReportError(
            "BINARY_STEP4_PUBLICATION_BINDING_INVALID",
            str(loaded["manifest"].get("result_generation_identity") or ""),
        )
    return {key: str(value) for key, value in binding.items()}


def _step4_publication_binding_matches_loaded(
    value: Mapping[str, Any],
    loaded: Mapping[str, Any],
) -> bool:
    """Compare a Step4 receipt with the active generation semantically.

    A retained Step4 transaction is rendered and gated while generation
    activation is still reversible, so its durable receipt records the
    activation identity.  Committing that activation deliberately seals the
    active descriptor down to its immutable generation/validation core.  The
    historical activation identity remains valid evidence in the Step4
    receipt; its absence from the sealed descriptor must not make the release
    stale.  While activation is still pending, however, exact activation
    ownership remains mandatory.
    """

    if not isinstance(value, Mapping):
        return False
    actual = dict(value)
    expected = _loaded_step4_publication_binding(loaded)
    # Renderer identity is retained as provenance, but the content digest and
    # immutable generation/validation identities are the release authority.
    actual.pop(_REPORT_IMPLEMENTATION_IDENTITY_FIELD, None)
    expected.pop(_REPORT_IMPLEMENTATION_IDENTITY_FIELD, None)
    if actual == expected:
        return True
    if "activation_identity" in expected:
        return False
    historical_activation = actual.pop("activation_identity", None)
    return (
        _is_sha256_identity(historical_activation)
        and actual == expected
    )


def _step5_publication_input_identity(
    *,
    loaded: Mapping[str, Any],
    step4_receipt: Mapping[str, Any],
    selected_coords: Iterable[str],
    selected_names: Iterable[str],
) -> str:
    return canonical_identity(
        "binary_step5_publication_input_identity",
        {
            "result_generation_identity": loaded["manifest"].get(
                "result_generation_identity"
            ),
            "validation_run_identity": loaded["active"].get(
                "validation_run_identity"
            ),
            "validation_result_sha256": loaded["active"].get(
                "validation_result_sha256"
            ),
            "activation_identity": loaded["active"].get(
                "activation_identity"
            ),
            "step4_publication_receipt_identity": step4_receipt.get(
                "committed_receipt_identity"
            ),
            "selected_coords": sorted({
                str(item).strip() for item in selected_coords
                if str(item).strip()
            }),
            "selected_names": sorted({
                str(item).strip() for item in selected_names
                if str(item).strip()
            }),
        },
        schema_version="1",
    )


def prepare_step5_publication_candidate(
    report_dir: str | Path,
    output_dir: str | Path,
    *,
    selected_coords: tuple[str, ...] = (),
    selected_names: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Stage a private Step5 candidate without gating or publishing it."""

    _consume_report_publication_prepare_capability(report_dir, "step5")
    return _require_pending_publication_candidate(
        "step5",
        _publish_step5_with_lock(
            report_dir,
            output_dir,
            selected_coords=selected_coords,
            selected_names=selected_names,
        ),
    )


def publish_step5(
    report_dir: str | Path,
    output_dir: str | Path,
    *,
    selected_coords: tuple[str, ...] = (),
    selected_names: tuple[str, ...] = (),
) -> dict[str, Any]:
    with _standalone_report_workflow_lock(report_dir):
        with _report_publication_prepare_capability(report_dir, "step5"):
            result = prepare_step5_publication_candidate(
                report_dir,
                output_dir,
                selected_coords=selected_coords,
                selected_names=selected_names,
            )
        transaction = dict(result.get("publication_transaction") or {})
        destinations = _step5_report_publication_destinations(report_dir)
        try:
            with short_temporary_directory(
                prefix="binary-step5-direct-gate"
            ) as candidate_text:
                candidate = materialize_report_publication_gate_candidate(
                    destinations,
                    Path(candidate_text).resolve(),
                    expected_transaction_id=str(
                        transaction.get("transaction_id") or ""
                    ),
                    expected_binding=dict(transaction.get("binding") or {}),
                    expected_published_content_identity=str(
                        transaction.get("published_content_identity") or ""
                    ),
                )
                candidate_destinations = tuple(
                    Path(item)
                    for item in candidate.get("candidate_destinations") or ()
                )
                if len(candidate_destinations) != 3:
                    raise BinaryReportError(
                        "BINARY_STEP5_PUBLICATION_CANDIDATE_INCOMPLETE",
                        str(candidate_text),
                    )
                from gate import gate_binary_report

                try:
                    gate_binary_report(
                        report_dir,
                        candidate_call_chain_dir=candidate_destinations[0],
                        candidate_binary_analysis_dir=(
                            candidate_destinations[1]
                        ),
                        candidate_index_dir=candidate_destinations[2],
                        candidate_publication_binding=transaction["binding"],
                    )
                except SystemExit as error:
                    raise BinaryReportError(
                        "BINARY_STEP5_PUBLICATION_GATE_FAILED",
                        str(error.code),
                    ) from error
            completion = complete_downstream_report_publication_after_gate(
                report_dir,
                "step5",
                expected_transaction_id=transaction["transaction_id"],
                expected_binding=transaction["binding"],
                gate_name="binary_report",
                strict_risk_gate=False,
                workflow_lock_held=True,
            )
        except BaseException:
            state = report_publication_transaction_state(destinations)
            if state not in {"absent", "committed"}:
                rollback_report_publication(
                    destinations,
                    expected_transaction_id=str(
                        transaction.get("transaction_id") or ""
                    ),
                    expected_binding=dict(transaction.get("binding") or {}),
                )
            raise
        return {
            **result,
            "publication_transaction": None,
            "publication_receipt": completion["publication_receipt"],
            "global_release": completion["global_release"],
        }


def _publish_step5_with_lock(
    report_dir: str | Path,
    output_dir: str | Path,
    *,
    selected_coords: tuple[str, ...] = (),
    selected_names: tuple[str, ...] = (),
) -> dict[str, Any]:
    report = Path(report_dir).resolve()
    _ensure_publication_protocol_marker(report)
    expected_output = report / "evidence" / "call_chain"
    if Path(output_dir).resolve() != expected_output:
        raise BinaryReportError(
            "BINARY_STEP5_PUBLICATION_TARGET_INVALID", str(output_dir)
        )
    require_current_release_stage(
        report, "step4", workflow_lock_held=True
    )
    loaded = load_validated_generation(report_dir)
    with short_temporary_directory(
        prefix="binary-step5-reader-snapshot"
    ) as snapshot_text:
        snapshot_root = Path(snapshot_text).resolve()
        step4_receipt = materialize_report_publication_committed_snapshot(
            _step4_report_publication_destinations(report),
            snapshot_root,
        )
        if not _step4_publication_binding_matches_loaded(
            step4_receipt.get("binding") or {}, loaded
        ):
            raise BinaryReportError(
                "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
                str(step4_receipt.get("transaction_id") or ""),
            )
        snapshot_destinations = [
            Path(item)
            for item in step4_receipt.get("snapshot_destinations") or ()
        ]
        if len(snapshot_destinations) != 2:
            raise BinaryReportError(
                "BINARY_STEP4_PUBLICATION_SNAPSHOT_INVALID",
                str(snapshot_root),
            )
        result = _publish_step5_from_snapshot(
            report,
            output_dir,
            loaded=loaded,
            step4_api_changes_dir=snapshot_destinations[0],
            step4_receipt=step4_receipt,
            selected_coords=selected_coords,
            selected_names=selected_names,
        )
        return result


def _publish_step5_from_snapshot(
    report_dir: str | Path,
    output_dir: str | Path,
    *,
    loaded: Mapping[str, Any],
    step4_api_changes_dir: Path,
    step4_receipt: Mapping[str, Any],
    selected_coords: tuple[str, ...] = (),
    selected_names: tuple[str, ...] = (),
) -> dict[str, Any]:
    source_inputs = _source_inputs_view(loaded)
    by_api = list(loaded["formal"].get("by_api") or ())
    raw_items = [_result_item(item) for item in by_api]
    all_resource_items = [
        _resource_activation_item(item)
        for item in loaded["formal"].get("resource_activation_results") or ()
    ]
    _change_rows, change_lookup = _change_rows_by_result(
        report_dir, api_changes_dir=step4_api_changes_dir
    )
    projection_assessments = {
        str(item.get("decision_identity") or ""): item
        for item in loaded["projections"].get("authoritative_projection_assessments") or ()
    }
    changes_by_fact_identity = {}
    for decision in loaded["decisions"].get("authoritative_change_facts") or ():
        fact_identity = str(decision.get("change_fact_identity") or "")
        assessment = projection_assessments.get(
            str(decision.get("decision_identity") or ""), {}
        )
        if fact_identity and assessment.get("analysis_projection_status") == "targetable":
            changes_by_fact_identity[fact_identity] = _product_change_row(
                decision,
                assessment,
                evidence_path=".runtime/binary_authority/active_binary_generation.json",
            )

    def changes_for(item: Mapping[str, Any]) -> list[dict[str, str]]:
        exact_facts = []
        seen = set()
        for fact_identity in item.get("contributing_change_fact_ids") or ():
            exact_fact = changes_by_fact_identity.get(str(fact_identity or ""))
            if exact_fact is None:
                continue
            identity = str(
                exact_fact.get("change_fact_identity")
                or fact_identity
                or ""
            )
            if identity not in seen:
                seen.add(identity)
                exact_facts.append(exact_fact)
        if exact_facts:
            return exact_facts
        exact = change_lookup.get(_change_row_key(item))
        if exact is not None:
            return [exact]
        coord = str(item.get("coord") or "")
        api = str(item.get("api") or "")
        kind = str(item.get("symbol_kind") or "")
        same_kind = next(
            (
                row for key, row in change_lookup.items()
                if key[0] == coord and key[1] == api and key[3] == kind
            ),
            {},
        )
        if same_kind:
            return [same_kind]
        return [next(
            (
                row for key, row in change_lookup.items()
                if key[0] == coord and key[1] == api
            ),
            {},
        )]

    all_items = [
        _legacy_result_item(item, change)
        for item in raw_items
        for change in changes_for(item)
    ]
    items = list(all_items)
    selected_coord_set = {str(item).strip() for item in selected_coords if str(item).strip()}
    selected_name_set = {str(item).strip() for item in selected_names if str(item).strip()}
    step4_receipt_identity = str(
        step4_receipt.get("committed_receipt_identity") or ""
    )
    publication_input_identity = _step5_publication_input_identity(
        loaded=loaded,
        step4_receipt=step4_receipt,
        selected_coords=selected_coord_set,
        selected_names=selected_name_set,
    )
    if not _is_sha256_identity(step4_receipt_identity):
        raise BinaryReportError(
            "BINARY_STEP4_PUBLICATION_RECEIPT_INVALID",
            str(step4_receipt.get("transaction_id") or ""),
        )
    if selected_coord_set or selected_name_set:
        items = [
            item for item in items
            if item["coord"] in selected_coord_set
            or item["coord"].split(":")[-1] in selected_name_set
        ]
    by_state = {
        state: [item for item in items if item["analysis_status"] == state]
        for state in ("reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed")
    }
    binary_summary = loaded["summary"]
    # Step5 scope is the set of runtime-effective change targets, not the raw
    # Step1 inventory.  dep_changes.csv deliberately retains "未变" rows for
    # provenance; including those here turns a zero-change run into incomplete
    # analysis of every packaged dependency.
    all_dependency_coords = sorted({
        str(item.get("coord") or "").strip()
        for item in (*all_items, *all_resource_items)
        if str(item.get("coord") or "").strip()
    })
    if selected_coord_set or selected_name_set:
        unmatched_coords = sorted(
            selected_coord_set - set(all_dependency_coords)
        )
        matched_names = {
            name
            for name in selected_name_set
            if any(
                coord.split(":")[-1] == name
                for coord in all_dependency_coords
            )
        }
        unmatched_names = sorted(selected_name_set - matched_names)
        if unmatched_coords or unmatched_names:
            raise BinaryReportError(
                "BINARY_STEP5_SELECTION_UNMATCHED",
                json.dumps(
                    {
                        "unmatched_coords": unmatched_coords,
                        "unmatched_names": unmatched_names,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        included_dependency_coords = sorted({
            coord for coord in all_dependency_coords
            if coord in selected_coord_set or coord.split(":")[-1] in selected_name_set
        })
        if not included_dependency_coords:
            raise BinaryReportError(
                "BINARY_STEP5_SELECTION_EMPTY",
                "partial selection matched no immutable Step4 target",
            )
    else:
        included_dependency_coords = list(all_dependency_coords)
    resource_items = [
        item for item in all_resource_items
        if item["coord"] in included_dependency_coords
    ]
    excluded_dependency_coords = sorted(
        set(all_dependency_coords) - set(included_dependency_coords)
    )
    scope = {
        "schema": "java-upgrade-analyzer.binary-step5-selection.v1",
        "result_generation_identity": loaded["manifest"][
            "result_generation_identity"
        ],
        "step4_publication_receipt_identity": step4_receipt_identity,
        "step5_publication_input_identity": publication_input_identity,
        "mode": "partial" if selected_coord_set or selected_name_set else "full",
        "validation_status": "passed",
        "selected_coords": sorted(selected_coord_set),
        "selected_names": sorted(selected_name_set),
        "included_dependency_coords": included_dependency_coords,
        "excluded_dependency_coords": excluded_dependency_coords,
        "available_dependency_count": len(all_dependency_coords),
        "included_dependency_count": len(included_dependency_coords),
        "total_api_count": len(all_items),
        "analyzed_api_count": len(items),
        "included_api_count": len(items),
        "included_reported_api_identities": sorted({
            str(item.get("reported_api_identity") or "") for item in items
            if str(item.get("reported_api_identity") or "")
        }),
        "excluded_api_count": len(all_items) - len(items),
    }
    summary = {
        "schema": "java-upgrade-analyzer.binary-step5-summary.v1",
        "status": "done",
        "skip_reason": "",
        "origin_step": "step5",
        "authority": "binary_first",
        "result_generation_identity": loaded["manifest"]["result_generation_identity"],
        "analysis_context_identity": loaded["manifest"]["analysis_context_identity"],
        "step4_publication_receipt_identity": step4_receipt_identity,
        "step5_publication_input_identity": publication_input_identity,
        "total_apis": len(items),
        "reachable": len(by_state["reachable"]),
        "not_impacted": 0,
        "uncertain": len(by_state["uncertain"]),
        "not_found_in_static_analysis": len(by_state["not_found_in_static_analysis"]),
        "not_analyzed": len(by_state["not_analyzed"]),
        "analysis_scope": scope,
        "reachable_apis": by_state["reachable"],
        "not_impacted_apis": [],
        "uncertain_apis": by_state["uncertain"],
        "not_found_apis": by_state["not_found_in_static_analysis"],
        "not_analyzed_apis": by_state["not_analyzed"],
        "resource_activation_results": resource_items,
        "meta": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "total_apis": len(items),
            "reachable": len(by_state["reachable"]),
            "not_impacted": 0,
            "uncertain": len(by_state["uncertain"]),
            "not_analyzed": len(by_state["not_analyzed"]),
            "not_found_in_static_analysis": len(by_state["not_found_in_static_analysis"]),
            "tool": "binary_pipeline.py + binary_report.py",
            "graph_stats": {
                "truncated": binary_summary.get("trace_coverage_status") != "complete",
                "truncation_reasons": list(binary_summary.get("trace_coverage_gaps") or ()),
            },
        },
        "formal_dimensions": {
            "reachability_status": ["reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed"],
            "impact_conclusion": ["probable_impact", "inconclusive"],
            "runtime_verification_status": ["required_not_executed", "undetermined"],
                "static_linkage_status": [
                    "compatible_or_not_applicable", "incompatible_if_executed", "undetermined"
                ],
        },
        "quality_gate": {
            "probable_impact": sum(
                item["impact_conclusion"] == "probable_impact" for item in items
            ),
            "inconclusive": len(by_state["uncertain"]) + len(by_state["not_analyzed"]),
        },
        "user_conclusion_summary": {
            "probable_impact": sum(
                item["impact_conclusion"] == "probable_impact" for item in items
            ),
            "inconclusive": len(by_state["uncertain"]) + len(by_state["not_analyzed"]),
        },
        "diagnostic_guidance": [],
        "candidate_diagnostics": {
            "fact_count": int(binary_summary.get("diagnostic_candidate_fact_count") or 0),
            "trace_result_count": int(binary_summary.get("candidate_trace_result_count") or 0),
            "included_in_formal_totals": False,
        },
        "coverage": loaded["coverage"],
        "source_inputs": source_inputs,
    }
    output = Path(output_dir).resolve()
    expected_output = _step5_report_publication_destinations(report_dir)[0]
    if output != expected_output:
        raise BinaryReportError(
            "BINARY_STEP5_PUBLICATION_TARGET_INVALID", str(output)
        )
    def write(stage: Path) -> None:
        _atomic_json(stage / "summary.json", summary)
        alert_rows = _legacy_alert_rows(items)
        with open_csv_write(stage / "alerts.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=LEGACY_ALERT_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(alert_rows)
        for status in (
            "reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed"
        ):
            status_rows = [row for row in alert_rows if row["path_status"] == status]
            if not status_rows:
                continue
            with open_csv_write(stage / f"alerts_{status}.csv") as handle:
                writer = csv.DictWriter(handle, fieldnames=LEGACY_ALERT_FIELDS, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(status_rows)
        by_api_dir = stage / "by_api"
        by_api_dir.mkdir()
        for item in items:
            _atomic_json(by_api_dir / _safe_detail_filename(item), item)
        dependency_counts = {
            coord: {
                "total": 0,
                "reachable": 0,
                "uncertain": 0,
                "not_found_in_static_analysis": 0,
                "not_analyzed": 0,
            }
            for coord in included_dependency_coords
        }
        for item in items:
            counts = dependency_counts.setdefault(item["coord"], {
                "total": 0,
                "reachable": 0,
                "uncertain": 0,
                "not_found_in_static_analysis": 0,
                "not_analyzed": 0,
            })
            counts["total"] += 1
            counts[str(item["analysis_status"])] += 1
        for item in resource_items:
            counts = dependency_counts.setdefault(item["coord"], {
                "total": 0,
                "reachable": 0,
                "uncertain": 0,
                "not_found_in_static_analysis": 0,
                "not_analyzed": 0,
            })
            counts.setdefault("resource_activation_reachable", 0)
            counts["resource_activation_reachable"] += int(
                item.get("activation_status") == "reachable"
            )
        lines = [
            "# 系统触达证据", "",
            "本报告按引起变化的依赖包汇总。完整筛选表见 `alerts.csv`，逐 API 证据见 `by_api/`。", "",
            f"- 变化 API：{summary['total_apis']}",
            f"- 已发现静态可执行路径：{summary['reachable']}",
            f"- 结论不确定：{summary['uncertain']}",
            f"- 静态范围内未发现路径：{summary['not_found_in_static_analysis']}",
            f"- 未完成分析：{summary['not_analyzed']}", "",
            f"- 源码输入：{source_inputs['label']}",
            f"- 源码映射：{source_inputs['mapped_count']} 个，覆盖状态 `{source_inputs['coverage_status']}`", "",
            source_inputs["effect"], "",
            "`not_found_in_static_analysis` 不是已确认无影响；静态可执行路径也不等于已完成运行时验证。", "",
            "## 运行时资源激活", "",
        ]
        if resource_items:
            lines.extend((
                "| 依赖包 | 资源 | 激活状态 | 当前系统入口 |",
                "|---|---|---|---|",
            ))
            for item in resource_items:
                entries = "<br>".join(
                    f"`{entry}`" for entry in item.get("business_entries") or ()
                ) or "-"
                status_label = {
                    "reachable": "已确认当前系统激活",
                    "uncertain": "存在候选激活关系",
                    "not_found_in_static_analysis": "未发现静态激活关系",
                    "not_analyzed": "未完成激活分析",
                }.get(str(item.get("activation_status") or ""), "未知")
                lines.append(
                    f"| `{item['coord']}` | `{item['resource_name']}` | "
                    f"{status_label} | {entries} |"
                )
        else:
            lines.append("本轮没有可展示的运行时资源变化激活结果。")
        lines.extend([
            "",
            "## 按依赖汇总", "",
            "| 依赖包 | API 数 | 已发现路径 | 资源激活 | 不确定 | 未发现路径 | 未分析 |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ])
        for coord, counts in sorted(dependency_counts.items()):
            lines.append(
                f"| `{coord}` | {counts['total']} | {counts['reachable']} | "
                f"{counts.get('resource_activation_reachable', 0)} | "
                f"{counts['uncertain']} | {counts['not_found_in_static_analysis']} | "
                f"{counts['not_analyzed']} |"
            )
        _atomic_text(stage / "summary.md", "\n".join(lines) + "\n")
        _atomic_json(stage / "selection.json", scope)
        _atomic_json(
            stage / "coverage.json",
            derive_coverage_report(
                Path(report_dir).resolve(),
                api_changes_dir=step4_api_changes_dir,
                call_chain_dir=stage,
            ),
        )

    binary_review = Path(report_dir).resolve() / "evidence" / "binary_analysis"
    def write_binary_review(stage: Path, _prepared) -> None:
        _atomic_text(
            stage / "system-reachability.md",
            "\n".join((
            "# 二进制系统触达执行摘要", "",
            "该文件记录新引擎执行信息；面向人工复核的正式结果仍从 `deliverables/report.md` 开始阅读。", "",
            f"- 变化 API：{summary['total_apis']}",
            f"- 已发现静态可执行路径：{summary['reachable']}",
            f"- 结论不确定：{summary['uncertain']}",
            f"- 未发现静态路径：{summary['not_found_in_static_analysis']}",
            f"- 未完成分析：{summary['not_analyzed']}",
            f"- 源码输入：{source_inputs['label']}", "",
            source_inputs["effect"], "",
            )),
        )
    query_index = {
        "schema": "java-upgrade-analyzer.s5-query-index.v1",
        "authority": "binary_first",
        "result_generation_identity": loaded["manifest"]["result_generation_identity"],
        "step4_publication_receipt_identity": step4_receipt_identity,
        "step5_publication_input_identity": publication_input_identity,
        "methods": {},
        "lookup_keys_by_symbol": {},
        "reverse_edges": {},
        "target_apis": [
            {
                "coord": item["coord"],
                "api_name": item["api"],
                "api_signature": item["api_signature"],
                "symbol_kind": item["symbol_kind"],
                "api_identity": item["api_identity"],
                "reported_api_identity": item["reported_api_identity"],
                "change_fact_identity": item["change_fact_identity"],
                "decision_identity": item["decision_identity"],
                "change_type": item["change_type"],
            }
            for item in items
        ],
        "stats": {
            "methods_indexed": 0,
            "reverse_edge_keys": 0,
            "target_apis_indexed": len(items),
            "query_path_source": "evidence/call_chain/alerts.csv",
        },
    }
    query_index_dir = Path(report_dir).resolve() / ".runtime" / "indexes"
    def write_query_index(stage: Path, _prepared) -> None:
        _atomic_json(stage / "s5_query_index.json", query_index)

    retain_publication_transaction = True
    transaction_binding = {
        "result_generation_identity": loaded["manifest"][
            "result_generation_identity"
        ],
        "validation_run_identity": loaded["active"][
            "validation_run_identity"
        ],
        "validation_result_sha256": loaded["active"][
            "validation_result_sha256"
        ],
        "upstream_publication_receipt_identity": step4_receipt_identity,
        "publication_input_identity": publication_input_identity,
    }
    if _is_sha256_identity(loaded["active"].get("activation_identity")):
        transaction_binding["activation_identity"] = str(
            loaded["active"]["activation_identity"]
        )
    with _active_generation_publication_lock(report_dir):
        refreshed = load_validated_generation(report_dir)
        if _loaded_step4_publication_binding(refreshed) != (
            _loaded_step4_publication_binding(loaded)
        ):
            raise BinaryReportError(
                "BINARY_STEP5_ACTIVE_GENERATION_CHANGED",
                str(Path(report_dir).resolve()),
            )
        report_publication_committed_receipt(
            _step4_report_publication_destinations(report_dir),
            expected_transaction_id=step4_receipt["transaction_id"],
            expected_binding=step4_receipt["binding"],
        )
        publication_transaction = _stage_directory_group(
            (
                (output, lambda stage, _prepared: write(stage)),
                (binary_review, write_binary_review),
                (query_index_dir, write_query_index),
            ),
            retain_transaction=retain_publication_transaction,
            transaction_binding=transaction_binding,
            trusted_root=Path(report_dir).resolve(),
        )
    return {
        "phase": "step5",
        "api_count": len(items),
        "output_dir": str(output),
        "step4_publication_receipt_identity": step4_receipt_identity,
        "publication_input_identity": publication_input_identity,
        "selection_identity": publication_input_identity,
        "publication_transaction": publication_transaction,
    }


def _step6_publication_input_identity(
    loaded: Mapping[str, Any],
    step4_receipt: Mapping[str, Any],
    step5_receipt: Mapping[str, Any],
    upstream_evidence_inputs: Mapping[str, Any],
) -> str:
    return canonical_identity(
        "binary_step6_publication_input_identity",
        {
            "result_generation_identity": loaded["manifest"].get(
                "result_generation_identity"
            ),
            "validation_run_identity": loaded["active"].get(
                "validation_run_identity"
            ),
            "validation_result_sha256": loaded["active"].get(
                "validation_result_sha256"
            ),
            "activation_identity": loaded["active"].get(
                "activation_identity"
            ),
            "step4_publication_receipt_identity": step4_receipt.get(
                "committed_receipt_identity"
            ),
            "step5_publication_receipt_identity": step5_receipt.get(
                "committed_receipt_identity"
            ),
            "step5_publication_content_identity": step5_receipt.get(
                "published_content_identity"
            ),
            "step5_publication_input_identity": (
                (step5_receipt.get("binding") or {}).get(
                    "publication_input_identity"
                )
            ),
            "upstream_evidence_inputs": upstream_evidence_inputs,
        },
        schema_version="1",
    )


def _require_step5_snapshot_binding(
    loaded: Mapping[str, Any],
    step4_receipt: Mapping[str, Any],
    step5_snapshot: Mapping[str, Any],
) -> tuple[Path, Path, Path]:
    binding = dict(step5_snapshot.get("binding") or {})
    expected_core = {
        "result_generation_identity": loaded["manifest"].get(
            "result_generation_identity"
        ),
        "validation_run_identity": loaded["active"].get(
            "validation_run_identity"
        ),
        "validation_result_sha256": loaded["active"].get(
            "validation_result_sha256"
        ),
        "upstream_publication_receipt_identity": step4_receipt.get(
            "committed_receipt_identity"
        ),
    }
    if any(binding.get(key) != value for key, value in expected_core.items()):
        raise BinaryReportError(
            "BINARY_STEP5_PUBLICATION_BINDING_MISMATCH",
            str(step5_snapshot.get("transaction_id") or ""),
        )
    active_activation = loaded["active"].get("activation_identity")
    if (
        "activation_identity" in binding
        and binding.get("activation_identity") != active_activation
    ) or (
        _is_sha256_identity(active_activation)
        and binding.get("activation_identity") != active_activation
    ):
        raise BinaryReportError(
            "BINARY_STEP5_PUBLICATION_BINDING_MISMATCH",
            str(step5_snapshot.get("transaction_id") or ""),
        )
    if not _is_sha256_identity(binding.get("publication_input_identity")):
        raise BinaryReportError(
            "BINARY_STEP5_PUBLICATION_BINDING_MISMATCH",
            str(step5_snapshot.get("transaction_id") or ""),
        )
    gate_receipt = dict(step5_snapshot.get("gate_receipt") or {})
    if gate_receipt.get("gate_name") != "binary_report":
        raise BinaryReportError(
            "BINARY_STEP5_PUBLICATION_GATE_POLICY_MISMATCH",
            str(gate_receipt.get("gate_name") or ""),
        )
    snapshots = tuple(
        Path(item)
        for item in step5_snapshot.get("snapshot_destinations") or ()
    )
    if len(snapshots) != 3:
        raise BinaryReportError(
            "BINARY_STEP5_PUBLICATION_SNAPSHOT_INVALID",
            str(step5_snapshot.get("transaction_id") or ""),
        )
    summary = _load_json(snapshots[0] / "summary.json")
    selection = _load_json(snapshots[0] / "selection.json")
    if (
        summary.get("schema")
        != "java-upgrade-analyzer.binary-step5-summary.v1"
        or summary.get("result_generation_identity")
        != expected_core["result_generation_identity"]
        or summary.get("step4_publication_receipt_identity")
        != expected_core["upstream_publication_receipt_identity"]
        or summary.get("step5_publication_input_identity")
        != binding["publication_input_identity"]
        or selection.get("schema")
        != "java-upgrade-analyzer.binary-step5-selection.v1"
        or selection.get("step5_publication_input_identity")
        != binding["publication_input_identity"]
        or selection.get("step4_publication_receipt_identity")
        != expected_core["upstream_publication_receipt_identity"]
    ):
        raise BinaryReportError(
            "BINARY_STEP5_PUBLICATION_CONTENT_MISMATCH",
            str(snapshots[0]),
        )
    return snapshots


def _copy_step6_input_directory(source: Path, destination: Path) -> None:
    if not _publication_path_exists(source):
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    _copy_report_directory_secure(source, destination)


_STEP6_UPSTREAM_EVIDENCE_FILES = (
    "evidence/dependencies/dep_changes.csv",
    "evidence/dependencies/build_provenance.json",
    "evidence/dependencies/dependency_jars.json",
    "evidence/context/context.json",
    "evidence/static_scan/s3_jdk_removed_api.csv",
    "evidence/static_scan/s3_jdk_javax_refs.csv",
    "evidence/static_scan/s3_jdk_internal_api.csv",
    "evidence/static_scan/s3_jdk_reflection.csv",
    "evidence/static_scan/s3_jdk_serialization.txt",
    "evidence/static_scan/s3_jdk_runtime_flags.csv",
    "evidence/static_scan/s3_springboot_config.csv",
    "evidence/static_scan/s3_springboot_autoconfig.txt",
    "evidence/static_scan/s3_dependency_compat.csv",
    "evidence/static_scan/s3_dependency_classfile.csv",
    "evidence/static_scan/s3_database_contract_summary.json",
    "evidence/static_scan/s3_database_contract_changes.csv",
    "evidence/static_scan/s3_database_contract_changes.md",
    ".runtime/coverage/s3_coverage.json",
)
_STEP6_DYNAMIC_UPSTREAM_EVIDENCE_PREFIXES = (
    "evidence/static_scan/",
    ".runtime/coverage/",
)
_STEP6_DYNAMIC_UPSTREAM_EVIDENCE_SUFFIXES = frozenset({
    ".csv", ".json", ".jsonl", ".md", ".txt",
})
_STEP6_DYNAMIC_UPSTREAM_MAX_PATHS = 128
_STEP6_DYNAMIC_UPSTREAM_MAX_DEPTH = 6
_STEP6_DYNAMIC_UPSTREAM_MAX_FILE_BYTES = 16 * 1024 * 1024
_STEP6_DYNAMIC_UPSTREAM_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_STEP6_EXCLUDED_UPSTREAM_EVIDENCE_PARTS = frozenset({
    "s1_artifacts",
    "s1_dependency_jars",
})


def _normalized_step6_upstream_evidence_path(raw: Any) -> str:
    text = str(raw or "").split("#", 1)[0].replace("\\", "/").strip()
    relative = Path(text)
    dynamic_prefix_requested = any(
        text.startswith(prefix)
        for prefix in _STEP6_DYNAMIC_UPSTREAM_EVIDENCE_PREFIXES
    )
    if (
        not text
        or "\x00" in text
        or relative.is_absolute()
        or ".." in relative.parts
        or "." in relative.parts
        or len(relative.parts) < 2
        or any(
            part in _STEP6_EXCLUDED_UPSTREAM_EVIDENCE_PARTS
            for part in relative.parts
        )
    ):
        if dynamic_prefix_requested:
            raise BinaryReportError(
                "BINARY_STEP6_UPSTREAM_EVIDENCE_PATH_INVALID", text
            )
        return ""
    normalized = relative.as_posix()
    if normalized in _STEP6_UPSTREAM_EVIDENCE_FILES:
        return normalized
    if any(
        normalized.startswith(prefix)
        for prefix in _STEP6_DYNAMIC_UPSTREAM_EVIDENCE_PREFIXES
    ):
        if (
            len(relative.parts) > _STEP6_DYNAMIC_UPSTREAM_MAX_DEPTH
            or relative.suffix.lower()
            not in _STEP6_DYNAMIC_UPSTREAM_EVIDENCE_SUFFIXES
        ):
            raise BinaryReportError(
                "BINARY_STEP6_UPSTREAM_EVIDENCE_PATH_INVALID", normalized
            )
        return normalized
    return ""


def _step6_upstream_evidence_files(
    report_root: Path,
    *,
    evidence_source_root: Path | None = None,
    referenced_files_out: set[str] | None = None,
) -> set[str]:
    """Return the bounded regular-file set actually consumed by Step6."""

    evidence_files = set(_STEP6_UPSTREAM_EVIDENCE_FILES)
    coverage_relative = "evidence/call_chain/coverage.json"
    coverage_path = report_root / coverage_relative
    if not _publication_path_exists(coverage_path):
        return evidence_files
    coverage_path = _require_step6_upstream_regular_file(
        report_root, coverage_relative
    )
    coverage = _load_json(coverage_path)
    components = coverage.get("components")
    if not isinstance(components, list) or any(
        not isinstance(component, Mapping) for component in components
    ):
        raise BinaryReportError(
            "BINARY_STEP6_UPSTREAM_EVIDENCE_PATH_INVALID",
            "coverage.components must be a list of objects",
        )
    referenced_files = set()
    for component in components:
        evidence = component.get("evidence", [])
        if not isinstance(evidence, list) or any(
            not isinstance(raw, str) for raw in evidence
        ):
            raise BinaryReportError(
                "BINARY_STEP6_UPSTREAM_EVIDENCE_PATH_INVALID",
                "coverage component evidence must be a list of text paths",
            )
        for raw in evidence:
            normalized = _normalized_step6_upstream_evidence_path(raw)
            if normalized:
                referenced_files.add(normalized)
    if referenced_files_out is not None:
        referenced_files_out.update(referenced_files)
    dynamic_files = referenced_files.difference(evidence_files)
    if len(dynamic_files) > _STEP6_DYNAMIC_UPSTREAM_MAX_PATHS:
        raise BinaryReportError(
            "BINARY_STEP6_UPSTREAM_EVIDENCE_BUDGET_EXCEEDED",
            json.dumps(
                {
                    "kind": "path_count",
                    "actual": len(dynamic_files),
                    "limit": _STEP6_DYNAMIC_UPSTREAM_MAX_PATHS,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    source_root = (
        Path(evidence_source_root).resolve()
        if evidence_source_root is not None
        else report_root
    )
    total_bytes = 0
    for relative_text in sorted(dynamic_files):
        source = source_root / relative_text
        if not _publication_path_exists(source):
            continue
        source = _require_step6_upstream_regular_file(
            source_root, relative_text
        )
        size = int(os.lstat(source).st_size)
        if size > _STEP6_DYNAMIC_UPSTREAM_MAX_FILE_BYTES:
            raise BinaryReportError(
                "BINARY_STEP6_UPSTREAM_EVIDENCE_BUDGET_EXCEEDED",
                json.dumps(
                    {
                        "kind": "file_bytes",
                        "path": relative_text,
                        "actual": size,
                        "limit": _STEP6_DYNAMIC_UPSTREAM_MAX_FILE_BYTES,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        total_bytes += size
        if total_bytes > _STEP6_DYNAMIC_UPSTREAM_MAX_TOTAL_BYTES:
            raise BinaryReportError(
                "BINARY_STEP6_UPSTREAM_EVIDENCE_BUDGET_EXCEEDED",
                json.dumps(
                    {
                        "kind": "total_bytes",
                        "actual": total_bytes,
                        "limit": _STEP6_DYNAMIC_UPSTREAM_MAX_TOTAL_BYTES,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
    evidence_files.update(dynamic_files)
    return evidence_files


def _require_step6_upstream_regular_file(
    report_root: Path,
    relative_text: str,
) -> Path:
    """Reject symlinked/non-directory parents before a secure file read."""

    relative = Path(relative_text)
    current = report_root
    unsafe_parent_path = False
    try:
        root_stat = os.lstat(current)
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(
            root_stat.st_mode
        ):
            unsafe_parent_path = True
            raise OSError("report root is not a directory")
        for part in relative.parts[:-1]:
            current = current / part
            current_stat = os.lstat(current)
            if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(
                current_stat.st_mode
            ):
                unsafe_parent_path = True
                raise OSError("evidence parent is not a real directory")
        leaf = report_root / relative
        leaf_stat = os.lstat(leaf)
        if (
            stat.S_ISLNK(leaf_stat.st_mode)
            or not stat.S_ISREG(leaf_stat.st_mode)
            or leaf_stat.st_nlink != 1
        ):
            raise OSError("evidence input is not a private regular file")
    except OSError as error:
        contract_error = BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
            f"{report_root / relative}: {error}",
        )
        contract_error.unsafe_parent_path = unsafe_parent_path
        raise contract_error from error
    return report_root / relative


def _materialize_step6_upstream_evidence(
    report_root: Path,
    render_root: Path,
    *,
    require_complete: bool = True,
) -> dict[str, dict[str, str]]:
    """Snapshot only the Step1-3 regular files consumed by Step6.

    Step1 retains deployed applications and dependency JARs below the same
    evidence directory.  Recursively copying that directory made Step6 cost
    proportional to the complete runtime closure even though the renderer
    never reads those bytes.  The immutable Step6 input is therefore an
    explicit file set, plus bounded files explicitly referenced by coverage.
    """

    evidence_files = _step6_upstream_evidence_files(
        render_root,
        evidence_source_root=report_root,
    )
    path_findings: dict[str, Any] = {"diagnostics": []}
    for relative_text in sorted(evidence_files):
        source = report_root / relative_text
        if not _publication_path_exists(source):
            continue
        try:
            _require_step6_upstream_regular_file(
                report_root, relative_text
            )
        except BinaryReportError as error:
            if getattr(error, "unsafe_parent_path", False):
                raise
            _append_step6_internal_input_diagnostic(
                path_findings,
                artifact=relative_text,
                stage="path_contract",
                path=source,
                error_type=type(error).__name__,
                message=str(error),
                owner_step=step6_internal_input_owner_for_path(
                    relative_text
                ),
            )
    if require_complete:
        _raise_step6_internal_input_failure(path_findings)
    for relative_text in sorted(evidence_files):
        source = report_root / relative_text
        if not _publication_path_exists(source):
            continue
        source = _require_step6_upstream_regular_file(
            report_root, relative_text
        )
        destination = render_root / relative_text
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _copy_report_file_secure(source, destination)
    return _step6_upstream_evidence_state(
        render_root, require_complete=require_complete
    )


_STEP6_REQUIRED_UPSTREAM_EVIDENCE_FILES = frozenset({
    "evidence/dependencies/dep_changes.csv",
    "evidence/dependencies/build_provenance.json",
    "evidence/dependencies/dependency_jars.json",
    "evidence/context/context.json",
    ".runtime/coverage/s3_coverage.json",
})


def _required_step6_upstream_evidence_files(
    report_root: Path,
    *,
    context: Mapping[str, Any] | None = None,
) -> set[str]:
    required = set(_STEP6_REQUIRED_UPSTREAM_EVIDENCE_FILES)
    context = dict(context or {})
    if context.get("jdk_upgraded"):
        required.update({
            "evidence/static_scan/s3_jdk_removed_api.csv",
            "evidence/static_scan/s3_jdk_javax_refs.csv",
            "evidence/static_scan/s3_jdk_internal_api.csv",
            "evidence/static_scan/s3_jdk_reflection.csv",
            "evidence/static_scan/s3_jdk_serialization.txt",
            "evidence/static_scan/s3_jdk_runtime_flags.csv",
        })
    if context.get("springboot_major_upgrade"):
        required.update({
            "evidence/static_scan/s3_jdk_javax_refs.csv",
            "evidence/static_scan/s3_springboot_config.csv",
            "evidence/static_scan/s3_springboot_autoconfig.txt",
        })
    if (
        report_root
        / "evidence/dependencies/deps_current_resolved.csv"
    ).is_file() or (
        report_root / "evidence/dependencies/dep_changes.csv"
    ).is_file():
        required.update({
            "evidence/static_scan/s3_dependency_compat.csv",
            "evidence/static_scan/s3_dependency_classfile.csv",
        })
    if _publication_path_exists(
        report_root / "evidence/dependencies/dependency_jars.json"
    ):
        required.update({
            "evidence/static_scan/s3_database_contract_summary.json",
            "evidence/static_scan/s3_database_contract_changes.csv",
            "evidence/static_scan/s3_database_contract_changes.md",
        })
    return required


def _step6_upstream_evidence_state(
    report_root: Path,
    *,
    require_complete: bool,
) -> dict[str, dict[str, str]]:
    state: dict[str, dict[str, str]] = {}
    referenced_files: set[str] = set()
    evidence_files = _step6_upstream_evidence_files(
        report_root,
        referenced_files_out=referenced_files,
    )
    preflight: dict[str, Any] = {"diagnostics": []}
    if require_complete:
        _augment_step6_internal_input_diagnostics(
            report_root, preflight
        )
        for relative_text in sorted(evidence_files):
            path = report_root / relative_text
            if not _publication_path_exists(path):
                continue
            try:
                _require_step6_upstream_regular_file(
                    report_root, relative_text
                )
            except BinaryReportError as error:
                if getattr(error, "unsafe_parent_path", False):
                    raise
                _append_step6_internal_input_diagnostic(
                    preflight,
                    artifact=relative_text,
                    stage="path_contract",
                    path=path,
                    error_type=type(error).__name__,
                    message=str(error),
                    owner_step=step6_internal_input_owner_for_path(
                        relative_text
                    ),
                )
        context: Mapping[str, Any] = {}
        context_relative = "evidence/context/context.json"
        context_path = report_root / context_relative
        context_invalid = any(
            str(item.get("artifact") or "") == "context"
            for item in preflight.get("diagnostics") or ()
            if isinstance(item, Mapping)
        )
        if (
            not context_invalid
            and _publication_path_exists(context_path)
        ):
            context_path = _require_step6_upstream_regular_file(
                report_root, context_relative
            )
            context = _load_json(context_path)
        required_files = _required_step6_upstream_evidence_files(
            report_root, context=context
        )
        required_files.update(
            referenced_files
        )
        for relative_text in sorted(required_files):
            path = report_root / relative_text
            if _publication_path_exists(path):
                continue
            owner_step = step6_internal_input_owner_for_path(
                relative_text
            )
            _append_step6_internal_input_diagnostic(
                preflight,
                artifact=relative_text,
                stage="artifact_missing",
                path=path,
                error_type="FileNotFoundError",
                message="required Step6 upstream evidence is missing",
                owner_step=owner_step,
            )
        _raise_step6_internal_input_failure(preflight)
    for relative_text in sorted(evidence_files):
        path = report_root / relative_text
        if not _publication_path_exists(path):
            state[relative_text] = {
                "status": "missing",
                "content_identity": "",
            }
            continue
        path = _require_step6_upstream_regular_file(
            report_root, relative_text
        )
        state[relative_text] = {
            "status": "present",
            "content_identity": _report_file_sha256(path),
        }
    return state


_STEP6_INTERNAL_INPUT_FAILURE_SCHEMA = (
    "java-upgrade-analyzer.step6-internal-input-failure.v1"
)
_STEP6_INTERNAL_INPUT_FATAL_STAGES = frozenset({
    "artifact_missing",
    "path_contract",
    "json_missing",
    "json_load",
    "json_contract",
    "csv_missing",
    "csv_load",
    "csv_stream",
    "csv_contract",
    "csv_consistency",
    "cross_artifact_contract",
    "identity_consistency",
    "text_load",
    "text_contract",
})
_STEP6_INTERNAL_INPUT_STEP1_ARTIFACTS = frozenset({
    "dependency_changes",
    "build_provenance",
    "dependency_jars",
})
_STEP6_INTERNAL_INPUT_STEP2_ARTIFACTS = frozenset({"context"})


def step6_internal_input_owner_for_path(value: str | Path) -> str | None:
    """Map a Step6-consumed internal path to its earliest producer."""

    normalized = str(value or "").replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("evidence/dependencies/"):
        return "step1"
    if normalized.startswith("evidence/context/"):
        return "step2"
    if normalized.startswith("evidence/static_scan/") or normalized.startswith(
        ".runtime/coverage/"
    ):
        return "step3"
    return None


def _step6_internal_input_diagnostic_owner(
    diagnostic: Mapping[str, Any],
) -> str | None:
    artifact = str(diagnostic.get("artifact") or "").strip()
    stage = str(diagnostic.get("stage") or "").strip()
    if stage not in _STEP6_INTERNAL_INPUT_FATAL_STAGES:
        return None
    declared_owner = str(diagnostic.get("owner_step") or "").strip()
    if declared_owner in {"step1", "step2", "step3"}:
        return declared_owner
    if artifact in _STEP6_INTERNAL_INPUT_STEP1_ARTIFACTS:
        return "step1"
    if artifact in _STEP6_INTERNAL_INPUT_STEP2_ARTIFACTS:
        return "step2"
    if artifact.startswith("step3_"):
        return "step3"
    return None


def step6_internal_input_contract_failures(
    findings: Mapping[str, Any],
) -> list[dict[str, str]]:
    """Return fatal Step1-3 format/consistency failures in stable order.

    Coverage limitations and analysis uncertainty are intentionally absent:
    only malformed analyzer-owned inputs and violated serialization contracts
    are publication blockers.
    """

    failures: list[dict[str, str]] = []
    seen = set()
    for raw in findings.get("diagnostics") or ():
        if not isinstance(raw, Mapping):
            continue
        owner = _step6_internal_input_diagnostic_owner(raw)
        if owner is None:
            continue
        item = {
            "owner_step": owner,
            "artifact": str(raw.get("artifact") or "").strip(),
            "stage": str(raw.get("stage") or "").strip(),
            "error_type": str(raw.get("error_type") or "").strip(),
            "path": str(raw.get("path") or "").strip(),
            "message": str(raw.get("message") or "").strip(),
        }
        identity = tuple(item.values())
        if identity not in seen:
            seen.add(identity)
            failures.append(item)
    return sorted(
        failures,
        key=lambda item: (
            int(item["owner_step"][-1]),
            item["artifact"],
            item["stage"],
            item["path"],
            item["message"],
        ),
    )


def step6_internal_input_failure_owner(
    findings: Mapping[str, Any],
) -> str | None:
    """Return the earliest Step1-3 owner whose output must be rebuilt."""

    failures = step6_internal_input_contract_failures(findings)
    return failures[0]["owner_step"] if failures else None


def step6_internal_input_failure_contract(
    findings: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the machine-readable rewind contract used by the orchestrator."""

    failures = step6_internal_input_contract_failures(findings)
    return {
        "schema": _STEP6_INTERNAL_INPUT_FAILURE_SCHEMA,
        "status": "failed" if failures else "passed",
        "owner_step": failures[0]["owner_step"] if failures else None,
        "failures": failures,
    }


def _raise_step6_internal_input_failure(
    findings: Mapping[str, Any],
) -> None:
    contract = step6_internal_input_failure_contract(findings)
    if contract["status"] != "failed":
        return
    reason_code = (
        "BINARY_STEP6_UPSTREAM_EVIDENCE_MISSING"
        if all(
            item.get("stage") == "artifact_missing"
            for item in contract["failures"]
        )
        else "BINARY_STEP6_INTERNAL_INPUT_INVALID"
    )
    message = json.dumps(
        {
            **contract,
            "reason_code": reason_code,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    error = BinaryReportError(
        reason_code, message
    )
    error.owner_step = contract["owner_step"]
    error.failure_contract = contract
    raise error


_STEP6_INTERNAL_INPUT_CSV_CONTRACTS = {
    "evidence/dependencies/dep_changes.csv": (
        "dependency_changes",
        (
            {"coord"},
            {"old_version"},
            {"new_version"},
            {"change_type"},
            {"risk"},
            {"scope"},
            {"resolution_status"},
            {"base_lib_entry"},
            {"current_lib_entry"},
        ),
    ),
    "evidence/static_scan/s3_jdk_removed_api.csv": (
        "step3_jdk_removed_api",
        ({"文件"}, {"行号"}, {"API"}, {"状态"}),
    ),
    "evidence/static_scan/s3_jdk_javax_refs.csv": (
        "step3_jdk_javax_refs",
        ({"文件"}, {"行号"}, {"引用类型"}, {"需迁移"}),
    ),
    "evidence/static_scan/s3_jdk_internal_api.csv": (
        "step3_jdk_internal_api",
        ({"文件"}, {"行号"}, {"API类型"}),
    ),
    "evidence/static_scan/s3_jdk_reflection.csv": (
        "step3_jdk_reflection",
        ({"文件"}, {"行号"}, {"反射类型"}),
    ),
    "evidence/static_scan/s3_jdk_runtime_flags.csv": (
        "step3_jdk_runtime_flags",
        ({"文件"}, {"行号"}, {"参数"}, {"风险"}),
    ),
    "evidence/static_scan/s3_springboot_config.csv": (
        "step3_springboot_config",
        ({"文件"}, {"行号"}, {"配置键"}, {"当前值"}),
    ),
    "evidence/static_scan/s3_dependency_compat.csv": (
        "step3_dependency_compat",
        ({"坐标"}, {"版本"}, {"风险类型"}, {"证据"}),
    ),
    "evidence/static_scan/s3_dependency_classfile.csv": (
        "step3_dependency_classfile",
        ({"依赖坐标"}, {"版本"}, {"最高所需Java版本"}, {"扫描结论"}),
    ),
    "evidence/static_scan/s3_database_contract_changes.csv": (
        "step3_database_contract_changes",
        tuple(
            {column}
            for column in (
                "依赖包", "变化类型", "契约类型", "可信度", "表", "列",
                "契约位置", "语句或字段", "人工复核建议",
            )
        ),
    ),
}
_STEP6_INTERNAL_INPUT_TEXT_CONTRACTS = {
    "evidence/static_scan/s3_jdk_serialization.txt": (
        "step3_jdk_serialization"
    ),
    "evidence/static_scan/s3_springboot_autoconfig.txt": (
        "step3_springboot_autoconfig"
    ),
    "evidence/static_scan/s3_database_contract_changes.md": (
        "step3_database_contract_review"
    ),
}


def _append_step6_internal_input_diagnostic(
    findings: dict[str, Any],
    *,
    artifact: str,
    stage: str,
    path: Path,
    error_type: str,
    message: str,
    owner_step: str | None = None,
) -> None:
    diagnostics = findings.setdefault("diagnostics", [])
    item = {
        "artifact": artifact,
        "stage": stage,
        "path": str(path),
        "error_type": error_type,
        "message": message,
    }
    if owner_step in {"step1", "step2", "step3"}:
        item["owner_step"] = owner_step
    if not any(
        all(existing.get(key) == value for key, value in item.items())
        for existing in diagnostics
        if isinstance(existing, Mapping)
    ):
        diagnostics.append(item)


def _validate_step6_internal_json_input(
    report_root: Path,
    relative_text: str,
    artifact: str,
    validator: Callable[[Mapping[str, Any]], list[str]],
    findings: dict[str, Any],
) -> None:
    path = report_root / relative_text
    if not _publication_path_exists(path):
        return
    try:
        path = _require_step6_upstream_regular_file(
            report_root, relative_text
        )
    except BinaryReportError as error:
        if getattr(error, "unsafe_parent_path", False):
            raise
        _append_step6_internal_input_diagnostic(
            findings,
            artifact=artifact,
            stage="json_load",
            path=path,
            error_type=type(error).__name__,
            message=str(error),
        )
        return
    try:
        with path.open(encoding="utf-8") as source:
            payload = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        _append_step6_internal_input_diagnostic(
            findings,
            artifact=artifact,
            stage="json_load",
            path=path,
            error_type=type(error).__name__,
            message=str(error),
        )
        return
    if not isinstance(payload, Mapping):
        issues = [f"expected object root, got {type(payload).__name__}"]
    else:
        issues = validator(payload)
    if issues:
        _append_step6_internal_input_diagnostic(
            findings,
            artifact=artifact,
            stage="json_contract",
            path=path,
            error_type="ArtifactContentError",
            message="; ".join(dict.fromkeys(issues)),
        )


def _validate_step6_internal_csv_input(
    report_root: Path,
    relative_text: str,
    artifact: str,
    required_column_groups: tuple[set[str], ...],
    findings: dict[str, Any],
) -> None:
    path = report_root / relative_text
    if not _publication_path_exists(path):
        return
    try:
        path = _require_step6_upstream_regular_file(
            report_root, relative_text
        )
    except BinaryReportError as error:
        if getattr(error, "unsafe_parent_path", False):
            raise
        _append_step6_internal_input_diagnostic(
            findings,
            artifact=artifact,
            stage="csv_load",
            path=path,
            error_type=type(error).__name__,
            message=str(error),
        )
        return
    try:
        with open_csv_read(path) as source:
            reader = csv.DictReader(source, strict=True)
            header = [str(value or "").strip() for value in (reader.fieldnames or ())]
            if (
                not header
                or any(not value or "\x00" in value for value in header)
                or len(header) != len(set(header))
            ):
                raise ValueError("CSV header is missing, blank, or duplicated")
            header_set = set(header)
            missing_groups = [
                sorted(group)
                for group in required_column_groups
                if not header_set.intersection(group)
            ]
            if missing_groups:
                raise ValueError(
                    f"required columns missing: {missing_groups}"
                )
            for row in reader:
                if row is None:
                    continue
                if None in row:
                    raise ValueError(
                        "CSV row contains more values than the header"
                    )
                if any(
                    value is not None and "\x00" in str(value)
                    for value in row.values()
                ):
                    raise ValueError("CSV row contains a NUL byte")
    except (OSError, UnicodeError, csv.Error, ValueError) as error:
        _append_step6_internal_input_diagnostic(
            findings,
            artifact=artifact,
            stage=(
                "csv_contract" if isinstance(error, ValueError)
                else "csv_load"
            ),
            path=path,
            error_type=type(error).__name__,
            message=str(error),
        )


def _augment_step6_internal_input_diagnostics(
    report_root: Path,
    findings: dict[str, Any],
) -> None:
    def context_contract(payload: Mapping[str, Any]) -> list[str]:
        issues = []
        for field in ("build_tool", "base_branch", "current_branch"):
            value = payload.get(field)
            if not isinstance(value, str) or not value.strip():
                issues.append(f"{field} is missing or not non-empty text")
        for field in ("jdk_base", "jdk_current"):
            if field not in payload or not isinstance(payload.get(field), str):
                issues.append(f"{field} is missing or not text")
        for field in ("springboot_base", "springboot_current"):
            value = payload.get(field)
            if value is not None and not isinstance(value, str):
                issues.append(f"{field} is not text")
        for field in ("jdk_upgraded", "springboot_major_upgrade"):
            if field not in payload or not isinstance(
                payload.get(field), bool
            ):
                issues.append(f"{field} is missing or not boolean")
        tech_flags = payload.get("tech_flags")
        if not isinstance(tech_flags, Mapping):
            issues.append("tech_flags is not an object")
        elif any(
            not isinstance(key, str) or not isinstance(value, bool)
            for key, value in tech_flags.items()
        ):
            issues.append("tech_flags contains a non-boolean flag")
        jdk_base = str(payload.get("jdk_base") or "").strip()
        jdk_current = str(payload.get("jdk_current") or "").strip()
        expected_jdk_upgraded = bool(
            jdk_base
            and jdk_current
            and jdk_base != jdk_current
            and jdk_base not in {"", "unknown"}
            and jdk_current not in {"", "unknown"}
        )
        if isinstance(payload.get("jdk_upgraded"), bool) and (
            payload.get("jdk_upgraded") != expected_jdk_upgraded
        ):
            issues.append("jdk_upgraded conflicts with JDK versions")

        def major(value: Any) -> int | None:
            text = str(value or "").strip()
            if not text or text in {"-", "unknown"}:
                return None
            try:
                return int(text.split(".", 1)[0])
            except (TypeError, ValueError):
                return None

        spring_base = payload.get("springboot_base")
        spring_current = payload.get("springboot_current")
        spring_upgraded = bool(
            spring_base
            and spring_current
            and spring_base != spring_current
            and spring_base != "-"
            and spring_current != "-"
        )
        spring_base_major = major(spring_base)
        spring_current_major = major(spring_current)
        expected_spring_major = bool(
            spring_upgraded
            and spring_base_major
            and spring_current_major
            and spring_current_major > spring_base_major
        )
        if isinstance(payload.get("springboot_major_upgrade"), bool) and (
            payload.get("springboot_major_upgrade")
            != expected_spring_major
        ):
            issues.append(
                "springboot_major_upgrade conflicts with Spring Boot versions"
            )
        return issues

    def provenance_contract(payload: Mapping[str, Any]) -> list[str]:
        issues = []
        if payload.get("schema") != "java-upgrade-analyzer.build-provenance.v2":
            issues.append("unsupported build provenance schema")
        if payload.get("both_builds_succeeded") is not True:
            issues.append("both_builds_succeeded is not true")
        sides = payload.get("sides")
        if not isinstance(sides, list):
            issues.append("sides is not a list")
        else:
            if len(sides) != 2 or any(
                not isinstance(item, Mapping) for item in sides
            ):
                issues.append("sides must contain exactly two objects")
            valid_sides = [
                item for item in sides if isinstance(item, Mapping)
            ]
            identities = [
                str(item.get("side") or "").strip()
                for item in valid_sides
            ]
            if len(identities) != 2 or set(identities) != {
                "base", "current"
            }:
                issues.append("sides must uniquely identify base and current")
            if any(
                not _is_sha256_identity(item.get("artifact_sha256"))
                for item in valid_sides
            ):
                issues.append("each side must bind an artifact SHA-256")
        return issues

    def dependency_jars_contract(payload: Mapping[str, Any]) -> list[str]:
        issues = []
        if payload.get("schema") != (
            "java-upgrade-analyzer.step1-dependency-jars.v3"
        ):
            issues.append("unsupported dependency JAR manifest schema")
        for field in ("items", "business_artifacts"):
            value = payload.get(field)
            if not isinstance(value, list):
                issues.append(f"{field} is not a list")
            elif any(not isinstance(item, Mapping) for item in value):
                issues.append(f"{field} contains non-object entries")
        if not isinstance(payload.get("runtime_closure"), Mapping):
            issues.append("runtime_closure is not an object")
        return issues

    def step3_coverage_contract(payload: Mapping[str, Any]) -> list[str]:
        issues = []
        if payload.get("schema") != (
            "java-upgrade-analyzer.step3-coverage.v1"
        ):
            issues.append("unsupported Step3 coverage schema")
        if payload.get("status") not in {
            "complete", "partial", "insufficient", "not_applicable"
        }:
            issues.append("status is not recognized")
        for field in ("reason_codes", "planned_scans", "executed_scans"):
            value = payload.get(field, [])
            if not isinstance(value, list) or any(
                not isinstance(item, str) for item in value
            ):
                issues.append(f"{field} is not a list of text values")
        return issues

    def database_summary_contract(payload: Mapping[str, Any]) -> list[str]:
        issues = []
        if payload.get("schema") != (
            "java-upgrade-analyzer.database-contract-changes.v1"
        ):
            issues.append("unsupported database contract summary schema")
        if payload.get("coverage_status") not in {
            "complete", "partial", "insufficient"
        }:
            issues.append("coverage_status is not recognized")
        count = payload.get("change_count", 0)
        if type(count) is not int or count < 0:
            issues.append("change_count is not a non-negative integer")
        gaps = payload.get("coverage_gaps", [])
        if not isinstance(gaps, list) or any(
            not isinstance(item, str) for item in gaps
        ):
            issues.append("coverage_gaps is not a list of text values")
        return issues

    for relative_text, artifact, validator in (
        (
            "evidence/context/context.json",
            "context",
            context_contract,
        ),
        (
            "evidence/dependencies/build_provenance.json",
            "build_provenance",
            provenance_contract,
        ),
        (
            "evidence/dependencies/dependency_jars.json",
            "dependency_jars",
            dependency_jars_contract,
        ),
        (
            ".runtime/coverage/s3_coverage.json",
            "step3_coverage",
            step3_coverage_contract,
        ),
        (
            "evidence/static_scan/s3_database_contract_summary.json",
            "step3_database_contract_summary",
            database_summary_contract,
        ),
    ):
        _validate_step6_internal_json_input(
            report_root,
            relative_text,
            artifact,
            validator,
            findings,
        )
    for relative_text, (
        artifact, required_column_groups
    ) in _STEP6_INTERNAL_INPUT_CSV_CONTRACTS.items():
        _validate_step6_internal_csv_input(
            report_root,
            relative_text,
            artifact,
            required_column_groups,
            findings,
        )
    for relative_text, artifact in (
        _STEP6_INTERNAL_INPUT_TEXT_CONTRACTS.items()
    ):
        path = report_root / relative_text
        if not _publication_path_exists(path):
            continue
        try:
            path = _require_step6_upstream_regular_file(
                report_root, relative_text
            )
        except BinaryReportError as error:
            if getattr(error, "unsafe_parent_path", False):
                raise
            _append_step6_internal_input_diagnostic(
                findings,
                artifact=artifact,
                stage="text_load",
                path=path,
                error_type=type(error).__name__,
                message=str(error),
            )
            continue
        try:
            with path.open(encoding="utf-8") as source:
                for _line in source:
                    pass
        except (OSError, UnicodeError) as error:
            _append_step6_internal_input_diagnostic(
                findings,
                artifact=artifact,
                stage="text_load",
                path=path,
                error_type=type(error).__name__,
                message=str(error),
            )


def _collect_step6_findings_for_publication(
    report_root: Path,
) -> dict[str, Any]:
    """Collect findings only after analyzer-owned inputs pass their contract."""

    preflight: dict[str, Any] = {"diagnostics": []}
    _augment_step6_internal_input_diagnostics(report_root, preflight)
    _raise_step6_internal_input_failure(preflight)
    findings = s6_report.collect_findings(report_root)
    _augment_step6_internal_input_diagnostics(report_root, findings)
    _raise_step6_internal_input_failure(findings)
    return findings


def _bind_step6_findings_to_release(
    findings: dict[str, Any],
    *,
    loaded: Mapping[str, Any],
    step4_receipt: Mapping[str, Any],
    step5_receipt: Mapping[str, Any],
    step6_input_identity: str,
    upstream_evidence_inputs: Mapping[str, Any],
) -> None:
    """Attach the immutable release facts used by both writer and gate."""

    findings["schema"] = "java-upgrade-analyzer.binary-findings.v2"
    findings["authority"] = "binary_first"
    findings["result_generation_identity"] = loaded["manifest"][
        "result_generation_identity"
    ]
    findings["analysis_context_identity"] = loaded["manifest"][
        "analysis_context_identity"
    ]
    findings["step4_publication_receipt_identity"] = step4_receipt[
        "committed_receipt_identity"
    ]
    findings["step5_publication_receipt_identity"] = step5_receipt[
        "committed_receipt_identity"
    ]
    findings["step6_publication_input_identity"] = step6_input_identity
    findings["step6_upstream_evidence_inputs"] = dict(
        upstream_evidence_inputs
    )
    findings["source_inputs"] = _source_inputs_view(loaded)
    scope = dict(findings.get("analysis_scope") or {})
    included_reported_identities = {
        str(identity or "").strip()
        for identity in scope.get("included_reported_api_identities") or ()
        if str(identity or "").strip()
    }
    included_dependency_coords = {
        str(coord or "").strip()
        for coord in scope.get("included_dependency_coords") or ()
        if str(coord or "").strip()
    }
    generation_by_api = list(loaded["formal"].get("by_api") or ())
    selected_by_api = [
        item for item in generation_by_api
        if str(item.get("reported_api_identity") or "")
        in included_reported_identities
    ]
    generation_resource_impacts = [
        _resource_activation_item(item)
        for item in loaded["formal"].get("resource_activation_results") or ()
    ]
    findings["resource_impacts"] = [
        item for item in generation_resource_impacts
        if str(item.get("coord") or "") in included_dependency_coords
    ]

    def binary_dimensions(rows):
        return {
        "reachability_status": {
            state: sum(
                item.get("reachability_status") == state
                for item in rows
            )
            for state in (
                "reachable", "uncertain",
                "not_found_in_static_analysis", "not_analyzed",
            )
        },
        "impact_conclusion": {
            "probable_impact": sum(
                item.get("impact_conclusion") == "probable_impact"
                for item in rows
            ),
            "inconclusive": sum(
                item.get("impact_conclusion") != "probable_impact"
                for item in rows
            ),
        },
        "runtime_verification_status": "not_executed",
        }

    findings["binary_dimensions"] = binary_dimensions(selected_by_api)
    findings["generation_binary_dimensions"] = binary_dimensions(
        generation_by_api
    )
    findings.setdefault("artifacts", {})
    findings["artifacts"].update({
        "binary_generation": str(loaded["generation"]),
        "binary_formal_results": str(
            loaded["generation"] / "binary_formal_results.json"
        ),
        "binary_candidate_results": str(
            loaded["generation"] / "binary_candidate_results.json"
        ),
        "binary_change_review_md": "evidence/api_changes/review.md",
        "source_analysis_review_md": "evidence/source_analysis/review.md",
    })


def _write_step6_artifact_set(
    render_root: Path,
    findings: dict[str, Any],
) -> tuple[Path, Path]:
    """Render the complete deterministic Step6 candidate into a private root."""

    report_path = render_root / "deliverables" / "report.md"
    findings_path = (
        render_root / ".runtime" / "findings" / "s6_findings.json"
    )
    s6_report.cleanup_legacy_s6_detail_artifacts(render_root)
    findings["artifacts"].update(
        s6_report.write_changed_api_split_artifacts(render_root)
    )
    findings["artifacts"]["analysis_scope_md"] = (
        s6_report.write_analysis_scope_artifact(render_root, findings)
    )
    diagnostic_detail = s6_report.write_diagnostic_detail_artifact(
        render_root, findings
    )
    if diagnostic_detail:
        findings["artifacts"]["diagnostic_detail_md"] = diagnostic_detail
    primary_artifacts, api_model, dependency_model = (
        s6_report.write_primary_report_artifacts(render_root, findings)
    )
    findings["artifacts"].update(primary_artifacts)
    findings["report_population"] = {
        "schema": "java-upgrade-analyzer.step6-report-population.v1",
        "apis": {
            "total_count": int(api_model["total_count"]),
            "completed_count": int(api_model["completed_count"]),
            "incomplete_count": int(api_model["incomplete_count"]),
            "population_unconfirmed": bool(
                api_model.get("population_unconfirmed")
            ),
        },
        "dependencies": {
            "total_count": int(dependency_model["total_count"]),
            "completed_count": int(dependency_model["completed_count"]),
            "incomplete_count": int(dependency_model["incomplete_count"]),
            "population_unconfirmed": bool(
                dependency_model.get("population_unconfirmed")
            ),
        },
    }
    _atomic_json(findings_path, findings)
    _atomic_text(report_path, s6_report.generate_report(findings))
    return report_path, findings_path


def _read_step6_contract_csv(
    path: Path,
    expected_fields: tuple[str, ...],
) -> list[dict[str, str]]:
    _report_file_sha256(path)
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != expected_fields:
                raise BinaryReportError(
                    "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                    f"{path}: CSV header mismatch",
                )
            rows = [dict(row) for row in reader]
    except BinaryReportError:
        raise
    except (OSError, UnicodeError, csv.Error) as error:
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            f"{path}: {error}",
        ) from error
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            f"{path}: malformed CSV row",
        )
    return rows


def _step6_api_result_label(row: Mapping[str, Any]) -> str:
    conclusion = str(row.get("conclusion") or "").strip()
    return {
        "已确认影响": "确认有影响",
        "已确认不受影响": "确认不受影响",
        "可能影响": "未确认影响（存在候选关系）",
        "结论未确定（存在候选证据）": "未确认影响（存在候选关系）",
        "结论未确定（静态分析能力边界）": (
            "未确认影响（静态分析能力边界）"
        ),
        "未发现调用路径": "未确认影响",
        "输入不足，结论未确定": "未完成分析",
        "本次未完成分析": "未完成分析",
    }.get(conclusion, conclusion or "未完成分析")


def _validate_step6_deliverable_semantics(
    deliverables: Path,
    findings: Mapping[str, Any],
) -> None:
    """Independently parse the human views and check their fact equations."""

    for key in (
        "dependency_changes", "changed_api_inventory", "probable_impact",
        "uncertain", "not_impacted", "not_analyzed", "not_found",
        "diagnostics",
    ):
        if not isinstance(findings.get(key), list):
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                f"findings.{key}",
            )
    scope = findings.get("analysis_scope")
    if not isinstance(scope, Mapping):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "findings.analysis_scope",
        )
    for key in (
        "available_dependency_count", "included_dependency_count",
        "total_api_count", "analyzed_api_count", "included_api_count",
        "excluded_api_count",
    ):
        if not isinstance(scope.get(key), int) or scope[key] < 0:
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                f"findings.analysis_scope.{key}",
            )
    if (
        scope["included_dependency_count"]
        > scope["available_dependency_count"]
        or scope["included_api_count"] != scope["analyzed_api_count"]
        or scope["included_api_count"] + scope["excluded_api_count"]
        != scope["total_api_count"]
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "findings.analysis_scope count equation",
        )
    included_reported_identities = scope.get(
        "included_reported_api_identities"
    )
    if not isinstance(included_reported_identities, list) or any(
        not isinstance(identity, str) or not identity.strip()
        for identity in included_reported_identities
    ) or len(set(included_reported_identities)) != len(
        included_reported_identities
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "findings.analysis_scope included reported identities",
        )

    def dimension_totals(name):
        dimensions = findings.get(name)
        if not isinstance(dimensions, Mapping):
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                f"findings.{name}",
            )
        reachability = dimensions.get("reachability_status")
        impact = dimensions.get("impact_conclusion")
        expected_reachability_keys = {
            "reachable", "uncertain",
            "not_found_in_static_analysis", "not_analyzed",
        }
        if (
            not isinstance(reachability, Mapping)
            or set(reachability) != expected_reachability_keys
            or not isinstance(impact, Mapping)
            or set(impact) != {"probable_impact", "inconclusive"}
            or any(
                type(value) is not int or value < 0
                for value in (*reachability.values(), *impact.values())
            )
            or dimensions.get("runtime_verification_status")
            != "not_executed"
        ):
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                f"findings.{name} dimensions",
            )
        reachability_total = sum(reachability.values())
        impact_total = sum(impact.values())
        if reachability_total != impact_total:
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                f"findings.{name} count equation",
            )
        return reachability_total

    selected_dimension_total = dimension_totals("binary_dimensions")
    generation_dimension_total = dimension_totals(
        "generation_binary_dimensions"
    )
    if (
        selected_dimension_total != len(included_reported_identities)
        or generation_dimension_total < selected_dimension_total
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "findings binary dimension population mismatch",
        )
    included_dependency_coords = scope.get("included_dependency_coords")
    if not isinstance(included_dependency_coords, list) or any(
        not isinstance(coord, str) or not coord.strip()
        for coord in included_dependency_coords
    ) or len(set(included_dependency_coords)) != len(
        included_dependency_coords
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "findings.analysis_scope included dependencies",
        )
    resource_impacts = findings.get("resource_impacts")
    if (
        not isinstance(resource_impacts, list)
        or any(not isinstance(item, Mapping) for item in resource_impacts)
        or any(
            str(item.get("coord") or "")
            not in set(included_dependency_coords)
            for item in resource_impacts
        )
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "findings.resource_impacts selection mismatch",
        )

    api_model = s6_report.build_human_api_analysis(findings)
    dependency_model = s6_report.build_human_dependency_analysis(
        findings, api_model
    )
    population = findings.get("report_population")
    expected_population = {
        "schema": "java-upgrade-analyzer.step6-report-population.v1",
        "apis": {
            "total_count": int(api_model["total_count"]),
            "completed_count": int(api_model["completed_count"]),
            "incomplete_count": int(api_model["incomplete_count"]),
            "population_unconfirmed": bool(
                api_model.get("population_unconfirmed")
            ),
        },
        "dependencies": {
            "total_count": int(dependency_model["total_count"]),
            "completed_count": int(dependency_model["completed_count"]),
            "incomplete_count": int(dependency_model["incomplete_count"]),
            "population_unconfirmed": bool(
                dependency_model.get("population_unconfirmed")
            ),
        },
    }
    if population != expected_population:
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "findings.report_population",
        )
    for model_name, model in (
        ("apis", api_model), ("dependencies", dependency_model)
    ):
        if (
            int(model["completed_count"])
            + int(model["incomplete_count"])
            != int(model["total_count"])
        ):
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                f"{model_name} count equation",
            )

    dependency_rows = _read_step6_contract_csv(
        deliverables / "all-affected-dependencies.csv",
        tuple(s6_report._FULL_DEPENDENCY_CSV_FIELDS),
    )
    expected_dependency_rows = [
        *list(dependency_model.get("incomplete") or ()),
        *list(dependency_model.get("completed") or ()),
    ]
    actual_dependency_keys = [
        (row["依赖"], row["分析结果"])
        for row in dependency_rows
    ]
    expected_dependency_keys = [
        (
            str(row.get("coord") or "依赖身份未记录"),
            str(row.get("analysis_conclusion") or ""),
        )
        for row in expected_dependency_rows
    ]
    if (
        len(dependency_rows) != len(expected_dependency_rows)
        or actual_dependency_keys != expected_dependency_keys
        or any(
            any(not str(row.get(field) or "").strip() for field in (
                "依赖", "版本变化", "API 分析（已完成/总数）",
                "当前系统调用关系", "分析结果", "结果说明",
            ))
            for row in dependency_rows
        )
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "all-affected-dependencies.csv semantic mismatch",
        )

    api_rows = _read_step6_contract_csv(
        deliverables / "all-impact-details.csv",
        tuple(s6_report._FULL_API_CSV_FIELDS),
    )
    expected_api_rows = [
        *list(api_model.get("incomplete") or ()),
        *[
            row
            for _coord, rows in s6_report._completed_api_rows_by_dependency(
                api_model
            )
            for row in rows
        ],
    ]

    def expected_api_label(row):
        api = str(row.get("api") or row.get("api_name") or "").strip()
        signature = str(row.get("api_signature") or "").strip()
        if signature and "(" not in api:
            api = f"{api}{signature}"
        aggregate_count = int(row.get("aggregate_count") or 1)
        if aggregate_count > 1:
            api = f"{api}（{aggregate_count} 个）"
        return api or "API 身份未记录"

    actual_api_keys = [
        (row["依赖"], row["API"], row["分析结果"])
        for row in api_rows
    ]
    expected_api_keys = [
        (
            str(row.get("coord") or "依赖身份未记录"),
            expected_api_label(row),
            _step6_api_result_label(row),
        )
        for row in expected_api_rows
    ]
    if (
        len(api_rows) != len(expected_api_rows)
        or actual_api_keys != expected_api_keys
        or any(
            any(not str(row.get(field) or "").strip() for field in (
                "依赖", "API", "新版本中的变化",
                "当前系统调用关系", "分析结果", "结果说明",
            ))
            for row in api_rows
        )
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "all-impact-details.csv semantic mismatch",
        )

    markdown_contracts = (
        (
            "all-affected-dependencies.md",
            "# 完整依赖分析明细",
            dependency_model,
            expected_dependency_rows,
        ),
        (
            "all-impact-details.md",
            "# 完整 API 分析与调用关系明细",
            api_model,
            expected_api_rows,
        ),
    )
    for filename, title, model, expected_rows in markdown_contracts:
        path = deliverables / filename
        _report_file_sha256(path)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                f"{path}: {error}",
            ) from error
        normalized = text.replace("\\|", "|")
        if (
            not text.startswith(title + "\n")
            or f"| {int(model['completed_count'])} |" not in text
            or any(
                str(row.get("coord") or "依赖身份未记录") not in normalized
                for row in expected_rows
            )
        ):
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                filename,
            )

    report_path = deliverables / "report.md"
    scope_path = deliverables / "analysis-scope.md"
    _report_file_sha256(report_path)
    _report_file_sha256(scope_path)
    try:
        report_text = report_path.read_text(encoding="utf-8")
        scope_text = scope_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH", str(error)
        ) from error
    required_report_links = (
        "all-affected-dependencies.md", "all-affected-dependencies.csv",
        "all-impact-details.md", "all-impact-details.csv",
        "analysis-scope.md",
    )
    if (
        not report_text.startswith("# Java 依赖升级影响报告\n")
        or any(link not in report_text for link in required_report_links)
        or not scope_text.startswith("# 本轮分析范围\n")
        or (
            f"总数 {scope['available_dependency_count']}；"
            f"纳入本轮分析 {scope['included_dependency_count']}；"
        ) not in scope_text
        or (
            f"总数 {scope['total_api_count']}；"
            f"纳入本轮分析 {scope['analyzed_api_count']}；"
        ) not in scope_text
        or any(
            str(coord) not in scope_text
            for coord in (
                list(scope.get("included_dependency_coords") or ())
                + list(scope.get("excluded_dependency_coords") or ())
            )
        )
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            "report.md/analysis-scope.md semantic mismatch",
        )


def validate_step6_publication_candidate(
    report_dir: str | Path,
    *,
    candidate_deliverables_dir: str | Path,
    candidate_findings_dir: str | Path,
    candidate_publication_binding: Mapping[str, Any],
) -> None:
    """Validate a Step6 candidate while owning the workflow read lock."""

    with _report_workflow_read_lock(report_dir):
        return _validate_step6_candidate_under_parent_workflow_lock(
            report_dir,
            candidate_deliverables_dir=candidate_deliverables_dir,
            candidate_findings_dir=candidate_findings_dir,
            candidate_publication_binding=candidate_publication_binding,
        )


def _validate_step6_candidate_under_parent_workflow_lock(
    report_dir: str | Path,
    *,
    candidate_deliverables_dir: str | Path,
    candidate_findings_dir: str | Path,
    candidate_publication_binding: Mapping[str, Any],
) -> None:
    """Validate a private candidate while the parent owns the workflow lock."""

    report = Path(report_dir).resolve()
    release = require_current_release_stage(
        report, "step5", workflow_lock_held=True
    )
    loaded = load_validated_generation(report)
    step4_receipt = report_publication_committed_receipt(
        _step4_report_publication_destinations(report)
    )
    step5_receipt = report_publication_committed_receipt(
        _step5_report_publication_destinations(report)
    )
    binding = dict(candidate_publication_binding or {})
    upstream_evidence = _step6_upstream_evidence_state(
        report,
        require_complete=True,
    )
    expected_input_identity = _step6_publication_input_identity(
        loaded, step4_receipt, step5_receipt, upstream_evidence
    )
    expected_binding = {
        **_active_release_core(loaded),
        "upstream_publication_receipt_identity": release["step5"][
            "committed_receipt_identity"
        ],
        "publication_input_identity": expected_input_identity,
    }
    if any(
        binding.get(key) != value
        for key, value in expected_binding.items()
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_BINDING_MISMATCH",
            str(binding.get("publication_input_identity") or ""),
        )

    deliverables = Path(candidate_deliverables_dir).resolve()
    findings_dir = Path(candidate_findings_dir).resolve()
    required_deliverables = (
        "report.md",
        "all-affected-dependencies.md",
        "all-affected-dependencies.csv",
        "all-impact-details.md",
        "all-impact-details.csv",
        "analysis-scope.md",
    )
    missing = [
        name for name in required_deliverables
        if not (deliverables / name).is_file()
    ]
    findings_path = findings_dir / "s6_findings.json"
    if missing or not findings_path.is_file():
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CANDIDATE_INCOMPLETE",
            ",".join((
                *missing,
                *(("s6_findings.json",) if not findings_path.is_file() else ()),
            )),
        )
    findings = _load_json(findings_path)
    if (
        findings.get("schema")
        != "java-upgrade-analyzer.binary-findings.v2"
        or findings.get("authority") != "binary_first"
        or findings.get("result_generation_identity")
        != loaded["manifest"].get("result_generation_identity")
        or findings.get("step4_publication_receipt_identity")
        != step4_receipt.get("committed_receipt_identity")
        or findings.get("step5_publication_receipt_identity")
        != step5_receipt.get("committed_receipt_identity")
        or findings.get("step6_publication_input_identity")
        != expected_input_identity
        or findings.get("step6_upstream_evidence_inputs")
        != upstream_evidence
    ):
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            str(findings_path),
        )
    try:
        generated_at = str(findings.get("generated_at") or "")
        datetime.fromisoformat(generated_at)
    except (TypeError, ValueError) as error:
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            f"findings.generated_at: {error}",
        ) from error

    # Rebuild from immutable Step4/5 receipts and a freshly snapshotted
    # Step1-3 evidence set.  Byte equality kills omissions/extra files, while
    # the parser above/below enforces facts independently of prose rendering.
    with short_temporary_directory(
        prefix="binary-step6-candidate-gate"
    ) as temporary_text:
        temporary_root = Path(temporary_text).resolve()
        step4_root = temporary_root / "step4"
        step5_root = temporary_root / "step5"
        expected_root = temporary_root / "expected"
        step4_root.mkdir()
        step5_root.mkdir()
        expected_root.mkdir()
        step4_snapshot = materialize_report_publication_committed_snapshot(
            _step4_report_publication_destinations(report), step4_root
        )
        if not _step4_publication_binding_matches_loaded(
            step4_snapshot.get("binding") or {}, loaded
        ):
            raise BinaryReportError(
                "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
                str(step4_snapshot.get("transaction_id") or ""),
            )
        step5_snapshot = materialize_report_publication_committed_snapshot(
            _step5_report_publication_destinations(report), step5_root
        )
        step5_sources = _require_step5_snapshot_binding(
            loaded, step4_snapshot, step5_snapshot
        )
        step4_sources = tuple(
            Path(item)
            for item in step4_snapshot.get("snapshot_destinations") or ()
        )
        if len(step4_sources) != 2:
            raise BinaryReportError(
                "BINARY_STEP4_PUBLICATION_SNAPSHOT_INVALID",
                str(step4_snapshot.get("transaction_id") or ""),
            )
        for source, relative in (
            (step4_sources[0], Path("evidence/api_changes")),
            (step4_sources[1], Path("evidence/source_analysis")),
            (step5_sources[0], Path("evidence/call_chain")),
            (step5_sources[1], Path("evidence/binary_analysis")),
            (step5_sources[2], Path(".runtime/indexes")),
        ):
            _copy_step6_input_directory(source, expected_root / relative)
        rebuilt_upstream_evidence = _materialize_step6_upstream_evidence(
            report, expected_root
        )
        if rebuilt_upstream_evidence != upstream_evidence:
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                "upstream evidence snapshot changed",
            )
        expected_findings = _collect_step6_findings_for_publication(
            expected_root
        )
        expected_findings["generated_at"] = generated_at
        _bind_step6_findings_to_release(
            expected_findings,
            loaded=loaded,
            step4_receipt=step4_snapshot,
            step5_receipt=step5_snapshot,
            step6_input_identity=expected_input_identity,
            upstream_evidence_inputs=rebuilt_upstream_evidence,
        )
        _write_step6_artifact_set(expected_root, expected_findings)
        rebuilt_findings = _load_json(
            expected_root
            / ".runtime"
            / "findings"
            / "s6_findings.json"
        )
        if rebuilt_findings != findings:
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                "s6_findings.json differs from immutable inputs",
            )
        _validate_step6_deliverable_semantics(deliverables, findings)
        if (
            _directory_content_identity(deliverables)
            != _directory_content_identity(expected_root / "deliverables")
            or _directory_content_identity(findings_dir)
            != _directory_content_identity(
                expected_root / ".runtime" / "findings"
            )
        ):
            raise BinaryReportError(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                "candidate bytes differ from immutable-input rendering",
            )


def prepare_step6_publication_candidate(
    report_dir: str | Path,
    output_findings: str | Path,
    output_report: str | Path,
) -> dict[str, Any]:
    """Stage a private Step6 candidate without gating or publishing it."""

    _consume_report_publication_prepare_capability(report_dir, "step6")
    return _require_pending_publication_candidate(
        "step6",
        _publish_step6_with_lock(
            report_dir,
            output_findings,
            output_report,
            prepare_candidate_only=True,
        ),
    )


def publish_step6(
    report_dir: str | Path,
    output_findings: str | Path,
    output_report: str | Path,
) -> dict[str, Any]:
    with _standalone_report_workflow_lock(report_dir):
        return _publish_step6_with_lock(
            report_dir,
            output_findings,
            output_report,
            prepare_candidate_only=False,
        )


def _publish_step6_with_lock(
    report_dir: str | Path,
    output_findings: str | Path,
    output_report: str | Path,
    *,
    prepare_candidate_only: bool,
) -> dict[str, Any]:
    """Render and stage every Step6 byte from immutable upstream snapshots."""

    report_root = Path(report_dir).resolve()
    _ensure_publication_protocol_marker(report_root)
    findings_path = Path(output_findings).resolve()
    report_path = Path(output_report).resolve()
    expected_findings = (
        report_root / ".runtime" / "findings" / "s6_findings.json"
    )
    expected_report = report_root / "deliverables" / "report.md"
    if findings_path != expected_findings or report_path != expected_report:
        raise BinaryReportError(
            "BINARY_STEP6_PUBLICATION_TARGET_INVALID",
            f"{findings_path},{report_path}",
        )
    require_current_release_stage(
        report_root, "step5", workflow_lock_held=True
    )
    loaded = load_validated_generation(report_root)
    with short_temporary_directory(
        prefix="binary-step6-release"
    ) as temporary_text:
        temporary_root = Path(temporary_text).resolve()
        step4_snapshot_root = temporary_root / "step4"
        step5_snapshot_root = temporary_root / "step5"
        render_root = temporary_root / "report"
        step4_snapshot_root.mkdir()
        step5_snapshot_root.mkdir()
        render_root.mkdir()
        step4_snapshot = materialize_report_publication_committed_snapshot(
            _step4_report_publication_destinations(report_root),
            step4_snapshot_root,
        )
        if not _step4_publication_binding_matches_loaded(
            step4_snapshot.get("binding") or {}, loaded
        ):
            raise BinaryReportError(
                "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
                str(step4_snapshot.get("transaction_id") or ""),
            )
        step5_snapshot = materialize_report_publication_committed_snapshot(
            _step5_report_publication_destinations(report_root),
            step5_snapshot_root,
        )
        step5_sources = _require_step5_snapshot_binding(
            loaded, step4_snapshot, step5_snapshot
        )
        step4_sources = tuple(
            Path(item)
            for item in step4_snapshot.get("snapshot_destinations") or ()
        )
        if len(step4_sources) != 2:
            raise BinaryReportError(
                "BINARY_STEP4_PUBLICATION_SNAPSHOT_INVALID",
                str(step4_snapshot.get("transaction_id") or ""),
            )
        for source, relative in (
            (step4_sources[0], Path("evidence/api_changes")),
            (step4_sources[1], Path("evidence/source_analysis")),
            (step5_sources[0], Path("evidence/call_chain")),
            (step5_sources[1], Path("evidence/binary_analysis")),
            (step5_sources[2], Path(".runtime/indexes")),
        ):
            _copy_step6_input_directory(source, render_root / relative)
        upstream_evidence_inputs = _materialize_step6_upstream_evidence(
            report_root, render_root
        )

        findings = _collect_step6_findings_for_publication(render_root)
        step6_input_identity = _step6_publication_input_identity(
            loaded,
            step4_snapshot,
            step5_snapshot,
            upstream_evidence_inputs,
        )
        return _render_and_publish_step6_from_snapshots(
            report_root=report_root,
            findings_path=findings_path,
            report_path=report_path,
            loaded=loaded,
            render_root=render_root,
            findings=findings,
            step4_snapshot=step4_snapshot,
            step5_snapshot=step5_snapshot,
            step6_input_identity=step6_input_identity,
            upstream_evidence_inputs=upstream_evidence_inputs,
            prepare_candidate_only=prepare_candidate_only,
        )


def _render_and_publish_step6_from_snapshots(
    *,
    report_root: Path,
    findings_path: Path,
    report_path: Path,
    loaded: Mapping[str, Any],
    render_root: Path,
    findings: dict[str, Any],
    step4_snapshot: Mapping[str, Any],
    step5_snapshot: Mapping[str, Any],
    step6_input_identity: str,
    upstream_evidence_inputs: Mapping[str, Any],
    prepare_candidate_only: bool,
) -> dict[str, Any]:
    _bind_step6_findings_to_release(
        findings,
        loaded=loaded,
        step4_receipt=step4_snapshot,
        step5_receipt=step5_snapshot,
        step6_input_identity=step6_input_identity,
        upstream_evidence_inputs=upstream_evidence_inputs,
    )
    temporary_report_path, temporary_findings_path = (
        _write_step6_artifact_set(render_root, findings)
    )

    transaction_binding = {
        "result_generation_identity": loaded["manifest"][
            "result_generation_identity"
        ],
        "validation_run_identity": loaded["active"][
            "validation_run_identity"
        ],
        "validation_result_sha256": loaded["active"][
            "validation_result_sha256"
        ],
        "upstream_publication_receipt_identity": step5_snapshot[
            "committed_receipt_identity"
        ],
        "publication_input_identity": step6_input_identity,
    }
    if _is_sha256_identity(loaded["active"].get("activation_identity")):
        transaction_binding["activation_identity"] = str(
            loaded["active"]["activation_identity"]
        )
    destinations = (report_path.parent, findings_path.parent)
    with _active_generation_publication_lock(report_root):
        refreshed = load_validated_generation(report_root)
        if _loaded_step4_publication_binding(refreshed) != (
            _loaded_step4_publication_binding(loaded)
        ):
            raise BinaryReportError(
                "BINARY_STEP6_ACTIVE_GENERATION_CHANGED", str(report_root)
            )
        report_publication_committed_receipt(
            _step4_report_publication_destinations(report_root),
            expected_transaction_id=step4_snapshot["transaction_id"],
            expected_binding=step4_snapshot["binding"],
        )
        report_publication_committed_receipt(
            _step5_report_publication_destinations(report_root),
            expected_transaction_id=step5_snapshot["transaction_id"],
            expected_binding=step5_snapshot["binding"],
        )
        publication_transaction = _stage_directory_group(
            (
                (
                    report_path.parent,
                    lambda stage, _prepared: _copy_report_directory_secure(
                        temporary_report_path.parent,
                        stage,
                        destination_exists=True,
                    ),
                ),
                (
                    findings_path.parent,
                    lambda stage, _prepared: _copy_report_directory_secure(
                        temporary_findings_path.parent,
                        stage,
                        destination_exists=True,
                    ),
                ),
            ),
            retain_transaction=True,
            transaction_binding=transaction_binding,
            trusted_root=report_root,
        )
    result = {
        "phase": "step6",
        "api_count": int(findings.get("call_chain_target_count") or 0),
        "report": str(report_path),
        "step5_publication_receipt_identity": step5_snapshot[
            "committed_receipt_identity"
        ],
        "publication_input_identity": step6_input_identity,
        "publication_transaction": publication_transaction,
    }
    if prepare_candidate_only:
        return result

    try:
        with short_temporary_directory(
            prefix="binary-step6-direct-gate"
        ) as candidate_text:
            candidate = materialize_report_publication_gate_candidate(
                destinations,
                Path(candidate_text).resolve(),
                expected_transaction_id=publication_transaction[
                    "transaction_id"
                ],
                expected_binding=publication_transaction["binding"],
                expected_published_content_identity=(
                    publication_transaction["published_content_identity"]
                ),
            )
            candidate_destinations = tuple(
                Path(item)
                for item in candidate.get("candidate_destinations") or ()
            )
            if len(candidate_destinations) != 2:
                raise BinaryReportError(
                    "BINARY_STEP6_PUBLICATION_CANDIDATE_INCOMPLETE",
                    str(candidate_text),
                )
            _validate_step6_candidate_under_parent_workflow_lock(
                report_root,
                candidate_deliverables_dir=candidate_destinations[0],
                candidate_findings_dir=candidate_destinations[1],
                candidate_publication_binding=publication_transaction[
                    "binding"
                ],
            )
        completion = complete_downstream_report_publication_after_gate(
            report_root,
            "step6",
            expected_transaction_id=publication_transaction[
                "transaction_id"
            ],
            expected_binding=publication_transaction["binding"],
            gate_name="binary_final_report",
            strict_risk_gate=False,
            workflow_lock_held=True,
        )
    except BaseException:
        state = report_publication_transaction_state(destinations)
        if state not in {"absent", "committed"}:
            rollback_report_publication(
                destinations,
                expected_transaction_id=publication_transaction[
                    "transaction_id"
                ],
                expected_binding=publication_transaction["binding"],
            )
        raise
    return {
        **result,
        "publication_transaction": None,
        "publication_receipt": completion["publication_receipt"],
        "global_release": completion["global_release"],
    }

def binary_report_publication_failure_result(
    error: BinaryFirstContractError,
    *,
    phase: str,
) -> dict[str, Any]:
    """Serialize one report/gate failure for a parent orchestrator."""

    owner_step = str(
        getattr(error, "owner_step", "") or ""
    ).strip() or None
    failure_contract = getattr(error, "failure_contract", None)
    if not isinstance(failure_contract, Mapping):
        failure_contract = {
            "schema": _STEP6_INTERNAL_INPUT_FAILURE_SCHEMA,
            "status": "failed",
            "owner_step": owner_step,
            "failures": [],
        }
    return {
        "schema": (
            "java-upgrade-analyzer.binary-report-publication-failure.v1"
        ),
        "status": "failed",
        "phase": str(phase or ""),
        "reason_code": str(getattr(error, "reason_code", "") or ""),
        "owner_step": owner_step,
        "failure_contract": dict(failure_contract),
        "message": str(error),
    }


def write_binary_report_publication_failure_result(
    path: str | Path,
    error: BinaryFirstContractError,
    *,
    phase: str,
) -> dict[str, Any]:
    result = binary_report_publication_failure_result(error, phase=phase)
    _atomic_json(Path(path).resolve(), result)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Publish validated binary generation reports")
    parser.add_argument("--phase", choices=("step4", "step5", "step6"), required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--output-findings", default="")
    parser.add_argument("--output-report", default="")
    parser.add_argument("--result-json", default="")
    parser.add_argument(
        "--prepare-publication-candidate",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--candidate-activation-identity",
        default="",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--selected-coord", action="append", default=[])
    parser.add_argument("--selected-name", action="append", default=[])
    args = parser.parse_args(argv)
    if args.candidate_activation_identity and (
        not args.prepare_publication_candidate or args.phase != "step4"
    ):
        parser.error(
            "--candidate-activation-identity requires "
            "--phase step4 --prepare-publication-candidate"
        )
    try:
        if args.prepare_publication_candidate:
            raise BinaryReportError(
                "BINARY_REPORT_PREPARE_CLI_FORBIDDEN",
                args.phase,
            )
        if args.phase == "step4":
            if not args.output_dir:
                parser.error("--output-dir is required for step4")
            result = publish_step4(args.report_dir, args.output_dir)
        elif args.phase == "step5":
            if not args.output_dir:
                parser.error("--output-dir is required for step5")
            result = publish_step5(
                args.report_dir,
                args.output_dir,
                selected_coords=tuple(args.selected_coord),
                selected_names=tuple(args.selected_name),
            )
        else:
            if not args.output_findings or not args.output_report:
                parser.error(
                    "--output-findings and --output-report are required for step6"
                )
            result = publish_step6(
                args.report_dir,
                args.output_findings,
                args.output_report,
            )
    except BinaryReportError as error:
        failure_result = binary_report_publication_failure_result(
            error, phase=args.phase
        )
        if args.result_json:
            _atomic_json(Path(args.result_json).resolve(), failure_result)
        print(
            json.dumps(
                failure_result,
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise
    if args.result_json:
        _atomic_json(Path(args.result_json).resolve(), result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
