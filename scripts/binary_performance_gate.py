#!/usr/bin/env python3
"""Reproducible 400-JAR/100k-class binary-first performance measurement.

The scale dataset is generated from one compiled class by length-preserving
constant-pool owner replacement.  Every resulting class is a distinct valid
classfile and every JAR has a stable content identity.  Dataset generation is
outside measured analysis time.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from contextlib import closing, contextmanager
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable, Mapping
import zipfile

from binary_asm_helper import resolve_asm_jar
from binary_fact_store import BinaryFactStore
from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_first_model import ArtifactInstance, RuntimeProfile
from binary_performance_identity import (
    GENERATION_SUPPORT_MANIFEST_LOGICAL_PATH,
    generation_source_identity as _generation_source_identity_from_records,
    harness_source_identity as _shared_harness_source_identity,
    is_sha256_identity as _is_sha256_identity,
    runtime_implementation_identity as _runtime_implementation_identity,
    source_implementation_identity as _source_implementation_identity,
)
from binary_performance_release_policy import (
    DATASET_SCHEMA,
    FULL_PIPELINE_PHASES,
    VALIDATED_GENERATION_ACTIVATION_SCOPE,
    release_policy,
    release_policy_identity,
)
from binary_snapshot_cache import cached_snapshot_archive
from compat import run_managed_subprocess
from javap_contract import javap_command
from jdk_preflight import preflight_jdk_home
from path_runtime import short_temporary_directory
from process_metrics import windows_current_process_usage

try:
    import resource as _resource
except ImportError:  # The resource module is unavailable on Windows.
    _resource = None


SCHEMA = "java-upgrade-analyzer.binary-first-performance-result.v1"
PROBE_WORKER_SCHEMA = "java-upgrade-analyzer.binary-performance-probe-worker.v1"
CLI_FAILURE_SCHEMA = "java-upgrade-analyzer.binary-performance-cli-failure.v1"
_PERFORMANCE_RECOVERY_RESULT_NAME = "performance_result_recovery.json"
_PERFORMANCE_RECOVERY_MAX_BYTES = 16 * 1024 * 1024
_CANDIDATE_PROBE_AUTHORITY_MODE = "candidate_source_measurement"
_RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE = "release_recapture_measurement"
_RECORDED_GATE_TOP_LEVEL_FIELDS = frozenset({
    "schema",
    "status",
    "blocks_binary_authority_switch",
    "reason_code",
    "measurement_protocol",
    "recorded_measurements",
    "thresholds",
    "accuracy_invariants",
    # Explicitly permitted human-facing metadata.  These fields are still
    # type-checked below and are never consulted as release authority.
    "rerun_command",
    "scope_note",
})
_PERFORMANCE_IMPLEMENTATION_FIELDS = frozenset({
    "generation_source_identity",
    "validator_source_identity",
    "oracle_support_manifest_identity",
    "harness_source_identity",
    "source_implementation_identity",
    "pipeline_generation_implementation_identity",
    "validator_implementation_identity",
    "jdk_preflight_identity",
    "runtime_implementation_identity",
})
_RECORDED_MEASUREMENT_FIELDS = frozenset({
    "captured_at",
    "warmup_end_to_end_seconds",
    "warmup_cpu_seconds",
    "warmup_average_cpu_cores",
    "warmup_parser_invocations",
    "warmup_cache_hits",
    "warmup_peak_rss_bytes",
    "warmup_class_count",
    "cold_end_to_end_seconds",
    "cold_cpu_seconds",
    "cold_average_cpu_cores",
    "warm_end_to_end_samples_seconds",
    "warm_cpu_seconds_samples",
    "warm_average_cpu_cores_samples",
    "warm_end_to_end_p50_seconds",
    "warm_end_to_end_p95_seconds",
    "cpu_measurement_status",
    "legacy_end_to_end_seconds",
    "legacy_cpu_seconds",
    "legacy_average_cpu_cores",
    "cold_relative_legacy_ratio",
    "warm_relative_legacy_ratio",
    "total_measured_wall_seconds",
    "total_measured_cpu_seconds",
    "average_cpu_cores",
    "cold_stage_seconds",
    "warm_stage_seconds_samples",
    "stage_seconds",
    "peak_rss_bytes",
    "cold_peak_rss_bytes",
    "warm_peak_rss_bytes_samples",
    "legacy_peak_rss_bytes",
    "sqlite_bytes",
    "cache_bytes",
    "disk_bytes",
    "bytes_per_class",
    "bytes_per_edge",
    "class_count",
    "member_count",
    "edge_count",
    "cold_parser_invocations",
    "warm_parser_invocations",
    "warm_parser_invocations_samples",
    "warm_cache_hits",
    "warm_cache_hits_samples",
    "full_pipeline_probe",
    "changed_full_pipeline_probe",
})
_RECORDED_PROBE_FIELDS = frozenset({
    "status",
    "performance_authority_mode",
    "comparison",
    "process_id",
    "rss_measurement_scope",
    "jar_count",
    "current_jar_count",
    "expected_class_count",
    "end_to_end_seconds",
    "pipeline_reported_seconds",
    "pipeline_total_elapsed_scope",
    "pipeline_phase_timings_scope",
    "cpu_seconds",
    "average_cpu_cores",
    "phase_seconds",
    "phase_peak_rss_bytes",
    "pipeline_reported_peak_rss_bytes",
    "post_pipeline_peak_rss_bytes",
    "peak_rss_bytes",
    "pipeline_performance_authority_binding",
    "activation_authority_mode",
    "publication_deferred",
    "checkpoint_retained",
    "activation_candidate_discarded",
    "activation_recapture_discarded",
    "active_generation_absent",
    "pending_generation_absent",
    "validation_checkpoint_absent",
    "parser_invocations",
    "artifact_snapshot_hits",
    "artifact_snapshot_disk_hits",
    "artifact_snapshot_memory_hits",
    "class_count",
    "base_class_count",
    "current_class_count",
    "validation_status",
    "validation_issue_count",
    "authoritative_change_fact_count",
    "authoritative_member_change_kind_counts",
    "formal_api_result_count",
    "formal_reachability_status_counts",
    "formal_impact_conclusion_counts",
    "captured_at",
})
_PROBE_WORKER_INPUT_FIELDS = frozenset({
    "schema",
    "artifacts",
    "current_artifacts",
    "asm_jar",
    "classes_per_jar",
    "expected_implementation",
    "provisional_gate_path",
})
_PROBE_WORKER_ARTIFACT_FIELDS = frozenset({
    "path",
    "sha256",
    "byte_length",
    "jar_index",
    "first_class_index",
    "class_count",
})
_PROBE_WORKER_SUCCESS_FIELDS = frozenset({"schema", "status", "result"})
_PROBE_WORKER_FAILURE_FIELDS = frozenset({"schema", "status", "failure"})
_PROBE_WORKER_FAILURE_DETAIL_FIELDS = frozenset({
    "reason_code", "error_type", "detail",
})
_PERFORMANCE_AUTHORITY_BINDING_FIELDS = frozenset({
    "schema",
    "authority_mode",
    "support_contract_identity",
    "evidence_sha256",
    "source_implementation_identity",
    "binding_identity",
})
_MEASUREMENT_PROTOCOL_FIELDS = frozenset({
    "release_policy_identity",
    "reference_runtime",
    "machine_identity",
    "machine",
    "dataset_schema",
    "dataset_identity",
    "base_template_sha256",
    "changed_template_sha256",
    "dataset_artifact_identities",
    "first_base_artifact_identity",
    "implementation",
    "source_implementation_identity",
    "runtime_implementation_identity",
    "jar_count",
    "class_count",
    "classes_per_jar",
    "full_pipeline_probe",
    "changed_full_pipeline_probe",
    "large_api_query_count",
    "tool_versions",
    "warmup_runs",
    "sample_runs",
    "cpu_time_source",
    "peak_rss_source",
    "p50_method",
    "p95_method",
    "cold_cleanup_rule",
    "warm_cache_rule",
    "rss_sample_semantics",
    "legacy_baseline",
})
_RAW_RESULT_FIELDS = frozenset({
    "schema", "status", "measurement_protocol", "measurements",
})
_RAW_MEASUREMENT_FIELDS = frozenset({
    "warmup",
    "cold",
    "warm_runs",
    "warm_end_to_end_p50_seconds",
    "warm_end_to_end_p95_seconds",
    "legacy",
    "full_pipeline_probe",
    "changed_full_pipeline_probe",
    "cold_relative_legacy_ratio",
    "peak_rss_bytes",
    "disk_bytes",
    "total_measured_wall_seconds",
    "total_measured_cpu_seconds",
    "average_cpu_cores",
})
_RAW_ANALYSIS_RUN_FIELDS = frozenset({
    "end_to_end_seconds",
    "cpu_seconds",
    "average_cpu_cores",
    "stage_seconds",
    "parser_invocations",
    "cache_hits",
    "counts",
    "inventory",
    "overlay_status",
    "report_bytes",
    "db_bytes",
    "cache_bytes",
    "peak_rss_bytes",
    "bytes_per_class",
    "bytes_per_edge",
})
_RAW_STAGE_FIELDS = frozenset({
    "inventory",
    "parse_and_cache",
    "db_write_and_index",
    "overlay",
    "batch_query_10000",
    "report_10000",
})
_RAW_COUNT_FIELDS = frozenset({
    "entries", "classes", "members", "edges", "resources",
})
_RAW_INVENTORY_FIELDS = frozenset({
    "entry_count", "uncompressed_bytes",
})
_RAW_LEGACY_FIELDS = frozenset({
    "end_to_end_seconds",
    "cpu_seconds",
    "average_cpu_cores",
    "class_count",
    "peak_rss_bytes",
    "implementation",
})
_FIXED_TEMPLATE_BASE64 = {
    1: (
        "yv66vgAAADQAFgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+"
        "AQADKClWCgAIAAkHAAoMAAsADAEACXAvQzAwMDAwMAEABXZhbHVlAQADKClJCgAOAA8H"
        "ABAMABEAEgEAEWphdmEvbGFuZy9JbnRlZ2VyAQAIdG9TdHJpbmcBABUoSSlMamF2YS9s"
        "YW5nL1N0cmluZzsBAARDb2RlAQAEdGV4dAEAFCgpTGphdmEvbGFuZy9TdHJpbmc7ACEA"
        "CAACAAAAAAADAAEABQAGAAEAEwAAABEAAQABAAAABSq3AAGxAAAAAAABAAsADAABABMA"
        "AAAOAAEAAQAAAAIErAAAAAAAAQAUABUAAQATAAAAFAABAAEAAAAIKrYAB7gADbAAAAAAA"
        "AA="
    ),
    2: (
        "yv66vgAAADQAFgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+"
        "AQADKClWCgAIAAkHAAoMAAsADAEACXAvQzAwMDAwMAEABXZhbHVlAQADKClJCgAOAA8H"
        "ABAMABEAEgEAEWphdmEvbGFuZy9JbnRlZ2VyAQAIdG9TdHJpbmcBABUoSSlMamF2YS9s"
        "YW5nL1N0cmluZzsBAARDb2RlAQAEdGV4dAEAFCgpTGphdmEvbGFuZy9TdHJpbmc7ACEA"
        "CAACAAAAAAADAAEABQAGAAEAEwAAABEAAQABAAAABSq3AAGxAAAAAAABAAsADAABABMA"
        "AAAOAAEAAQAAAAIFrAAAAAAAAQAUABUAAQATAAAAFAABAAEAAAAIKrYAB7gADbAAAAAAA"
        "AA="
    ),
}
_FIXED_TEMPLATE_SHA256 = {
    1: "d399daf3228dca8d6a46b829b5b72ca287beb8d68f0353861121d509b4c91fed",
    2: "d203be05ee7d26c466b189ed7d03b57db122b89ce9af668fcbcf1fb2f97b53a7",
}
_FIXED_ZIP_POLICY = {
    "container": "zip",
    "compression": "deflate",
    "compresslevel": 1,
    "entry_timestamp": [2026, 1, 1, 0, 0, 0],
    "entry_external_mode": "0100644",
    "entry_order": "ascending_binary_class_name",
}


class PerformanceGateError(RuntimeError):
    def __init__(
        self, message: str, *, failure: Mapping[str, Any] | None = None,
    ):
        super().__init__(message)
        self.failure = dict(failure or {})


def _type_sensitive_equal(expected: Any, actual: Any) -> bool:
    """Compare JSON-shaped values without Python's ``False == 0`` aliasing."""

    if type(expected) is not type(actual):
        return False
    if isinstance(expected, Mapping):
        return set(expected) == set(actual) and all(
            _type_sensitive_equal(expected[key], actual[key])
            for key in expected
        )
    if isinstance(expected, (list, tuple)):
        return len(expected) == len(actual) and all(
            _type_sensitive_equal(left, right)
            for left, right in zip(expected, actual)
        )
    return expected == actual


def _performance_authority_binding_is_valid(
    value: Any, *, expected_mode: str, expected_source_identity: str,
) -> bool:
    return bool(
        isinstance(value, Mapping)
        and set(value) == _PERFORMANCE_AUTHORITY_BINDING_FIELDS
        and value.get("schema")
        == "java-upgrade-analyzer.performance-authority-binding.v2"
        and value.get("authority_mode") == expected_mode
        and value.get("source_implementation_identity")
        == expected_source_identity
        and all(
            _is_sha256_identity(value.get(field))
            for field in _PERFORMANCE_AUTHORITY_BINDING_FIELDS
            - {"schema", "authority_mode"}
        )
        and value.get("binding_identity")
        == canonical_identity(
            "binary_performance_authority_binding_identity",
            {
                "support_contract_identity": value.get(
                    "support_contract_identity"
                ),
                "evidence_sha256": value.get("evidence_sha256"),
                "source_implementation_identity": value.get(
                    "source_implementation_identity"
                ),
                "authority_mode": value.get("authority_mode"),
            },
            schema_version="1",
        )
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _generation_source_identity() -> str:
    """Bind generation-producing source without binding the local runtime.

    Recorded evidence is replayed on Ubuntu while the absolute measurements
    were captured on a reference macOS host.  The cross-host check therefore
    binds source and policy bytes here; the separate runtime implementation
    identity below remains exact for live, same-environment comparisons.
    """

    from binary_pipeline import (
        RUNTIME_REQUIREMENTS_PATH,
        SUPPORT_MANIFEST_PATH,
        _GENERATION_IMPLEMENTATION_SOURCE_PATHS,
        _generation_support_manifest_identity,
        _validate_generation_source_import_closure,
    )

    _validate_generation_source_import_closure()
    scripts_dir = Path(__file__).resolve().parent
    records = [
        {"path": relative, "sha256": _sha256(scripts_dir / relative)}
        for relative in _GENERATION_IMPLEMENTATION_SOURCE_PATHS
    ]
    records.extend((
        {
            # Performance recapture swaps in a private support snapshot.  Its
            # filesystem basename is an implementation detail; generation
            # identity uses the same stable logical path as binary_pipeline.
            "path": GENERATION_SUPPORT_MANIFEST_LOGICAL_PATH,
            "sha256": _generation_support_manifest_identity(),
        },
        {
            "path": "../requirements-runtime.txt",
            "sha256": _sha256(RUNTIME_REQUIREMENTS_PATH),
        },
    ))
    return _generation_source_identity_from_records(records)


def _validator_source_identity() -> str:
    from binary_validation_contract import validator_source_identity

    return validator_source_identity()


def _harness_source_identity() -> str:
    return _shared_harness_source_identity(Path(__file__).resolve().parent)


def _performance_implementation_protocol(
    asm_jar: Path | None = None,
    *,
    include_runtime: bool = True,
    _verified_generation_source_records: (
        Iterable[Mapping[str, Any]] | None
    ) = None,
) -> dict[str, str]:
    """Build the source/runtime identity used by performance authority.

    Production's live commit guard may supply source records that it has just
    re-hashed and compared with its process-start snapshot.  Reusing those
    exact records avoids hashing the same generation closure twice more while
    retaining the default independent collection path for static preflight,
    evidence building, and external replay.
    """

    from binary_validation_contract import oracle_support_manifest_identity

    verified_generation_records = (
        None
        if _verified_generation_source_records is None
        else [dict(item) for item in _verified_generation_source_records]
    )
    components = {
        "generation_source_identity": (
            _generation_source_identity()
            if verified_generation_records is None
            else _generation_source_identity_from_records(
                verified_generation_records
            )
        ),
        "validator_source_identity": _validator_source_identity(),
        "oracle_support_manifest_identity": oracle_support_manifest_identity(),
        "harness_source_identity": _harness_source_identity(),
    }
    components["source_implementation_identity"] = (
        _source_implementation_identity(components)
    )
    if include_runtime:
        if asm_jar is None:
            raise PerformanceGateError(
                "ASM dependency is required for runtime implementation identity"
            )
        from binary_pipeline import _resume_implementation_identity
        from binary_validation_contract import validator_implementation_identity

        components["pipeline_generation_implementation_identity"] = (
            _resume_implementation_identity(
                asm_jar,
                source_records=verified_generation_records,
            )
        )
        components["validator_implementation_identity"] = (
            validator_implementation_identity()
        )
        components["jdk_preflight_identity"] = str(
            preflight_jdk_home(_jdk_home())["jdk_preflight_identity"]
        )
        components["runtime_implementation_identity"] = (
            _runtime_implementation_identity(components)
        )
    return components


def _directory_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _rss_bytes() -> int:
    if _resource is None:
        try:
            usage = windows_current_process_usage()
        except OSError as error:
            raise PerformanceGateError(
                f"Windows peak RSS measurement failed: {error}"
            ) from error
        if usage is None:
            raise PerformanceGateError(
                "peak RSS measurement is unavailable on this platform"
            )
        return usage.peak_rss_bytes
    value = _resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss
    child = _resource.getrusage(_resource.RUSAGE_CHILDREN).ru_maxrss
    multiplier = 1 if sys.platform == "darwin" else 1024
    return int(max(value, child) * multiplier)


def _cpu_seconds() -> float:
    """Return cumulative CPU time for this process and completed children."""
    if _resource is None:
        try:
            usage = windows_current_process_usage()
        except OSError:
            usage = None
        if usage is not None:
            return usage.user_seconds + usage.system_seconds
        return float(time.process_time())
    own = _resource.getrusage(_resource.RUSAGE_SELF)
    children = _resource.getrusage(_resource.RUSAGE_CHILDREN)
    return float(
        own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime
    )


def _timing_metrics(*, started: float, cpu_started: float) -> dict[str, float]:
    elapsed = max(time.perf_counter() - started, 0.0)
    cpu = max(_cpu_seconds() - cpu_started, 0.0)
    return {
        "end_to_end_seconds": elapsed,
        "cpu_seconds": cpu,
        "average_cpu_cores": cpu / elapsed if elapsed else 0.0,
    }


def _command_version(command: list[str]) -> str:
    completed = run_managed_subprocess(
        command, capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=False,
    )
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    return text[0] if text else f"exit={completed.returncode}"


def _jdk_home() -> Path:
    completed = run_managed_subprocess(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            return Path(line.split("=", 1)[1].strip()).resolve()
    raise PerformanceGateError("unable to resolve java.home")


def _java_major(jdk_home: Path) -> int:
    release = (jdk_home / "release").read_text(encoding="utf-8", errors="replace")
    for line in release.splitlines():
        if line.startswith("JAVA_VERSION="):
            version = line.split("=", 1)[1].strip().strip('"')
            return int(version.split(".", 1)[0]) if not version.startswith("1.") else int(version.split(".")[1])
    raise PerformanceGateError("JAVA_VERSION missing")


def _compile_template(
    root: Path, *, return_value: int = 1, label: str = "template"
) -> bytes:
    """Return a checked, toolchain-independent Java 8 template class.

    ``root`` and ``label`` remain in the signature for compatibility with
    callers, but no compiler is invoked.  Generating the scale fixture with
    the ambient javac made the dataset identity differ between the Java 17 CI
    runner and the Java 21 reference host before any product code ran.
    """

    del root, label
    try:
        content = base64.b64decode(
            _FIXED_TEMPLATE_BASE64[int(return_value)], validate=True
        )
        expected_sha256 = _FIXED_TEMPLATE_SHA256[int(return_value)]
    except (KeyError, ValueError) as error:
        raise PerformanceGateError(
            f"unsupported fixed template return value: {return_value}"
        ) from error
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if actual_sha256 != expected_sha256:
        raise PerformanceGateError(
            "fixed performance template digest mismatch: "
            f"expected={expected_sha256}; actual={actual_sha256}"
        )
    if b"p/C000000" not in content:
        raise PerformanceGateError("template class owner constant missing")
    return content


def _physical_directory_identity(
    path: Path, *, field: str, create: bool,
) -> tuple[int, int, int] | None:
    """Return one physical directory identity without following its leaf."""

    try:
        entry = os.lstat(path)
    except FileNotFoundError:
        if not create:
            return None
        try:
            path.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            # A concurrent creator is acceptable only when it created the
            # same kind of physical directory required below.
            pass
        except OSError as error:
            raise PerformanceGateError(
                f"{field} directory cannot be created: {error}"
            ) from error
        try:
            entry = os.lstat(path)
        except OSError as error:
            raise PerformanceGateError(
                f"{field} directory cannot be inspected: {error}"
            ) from error
    except OSError as error:
        raise PerformanceGateError(
            f"{field} directory cannot be inspected: {error}"
        ) from error
    if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
        raise PerformanceGateError(
            f"{field} must be a physical directory, not a link or special file"
        )
    return (int(entry.st_dev), int(entry.st_ino), int(entry.st_mode))


def _same_completed_private_file(
    descriptor_stat: os.stat_result, path_stat: os.stat_result,
) -> bool:
    """Compare a closed temp file without relying on platform timestamp flushes."""

    return bool(
        stat.S_ISREG(descriptor_stat.st_mode)
        and stat.S_ISREG(path_stat.st_mode)
        and descriptor_stat.st_nlink == 1
        and path_stat.st_nlink == 1
        and descriptor_stat.st_dev == path_stat.st_dev
        and descriptor_stat.st_ino == path_stat.st_ino
        and descriptor_stat.st_size == path_stat.st_size
    )


@contextmanager
def _atomic_zip_archive(path: Path, *, field: str):
    """Build a ZIP in an exclusive sibling and replace only its directory entry."""

    directory_identity = _physical_directory_identity(
        path.parent, field=field, create=True
    )
    descriptor = -1
    temporary_path: Path | None = None
    completed_stat: os.stat_result | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary_path = Path(temporary_name)
        created_stat = os.fstat(descriptor)
        if not stat.S_ISREG(created_stat.st_mode) or created_stat.st_nlink != 1:
            raise PerformanceGateError(
                f"{field} temporary archive is not a private regular file"
            )
        stream = os.fdopen(descriptor, "w+b")
        descriptor = -1
        with stream:
            with zipfile.ZipFile(
                stream,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=1,
            ) as archive:
                yield archive
            stream.flush()
            completed_stat = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(completed_stat.st_mode)
                or completed_stat.st_nlink != 1
                or completed_stat.st_dev != created_stat.st_dev
                or completed_stat.st_ino != created_stat.st_ino
            ):
                raise PerformanceGateError(
                    f"{field} temporary archive changed while being written"
                )
        try:
            path_stat = os.lstat(temporary_path)
        except OSError as error:
            raise PerformanceGateError(
                f"{field} temporary archive disappeared before publication: {error}"
            ) from error
        if (
            completed_stat is None
            or not _same_completed_private_file(completed_stat, path_stat)
        ):
            raise PerformanceGateError(
                f"{field} temporary archive was replaced before publication"
            )
        if _physical_directory_identity(
            path.parent, field=field, create=False
        ) != directory_identity:
            raise PerformanceGateError(
                f"{field} directory changed while its archive was built"
            )
        # Replacing the directory entry does not follow an existing target
        # symlink and does not truncate another name in a hardlink set.
        os.replace(temporary_path, path)
        temporary_path = None
    except PerformanceGateError:
        raise
    except OSError as error:
        raise PerformanceGateError(
            f"{field} archive cannot be published safely: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def build_dataset(root: Path, *, jar_count: int, classes_per_jar: int) -> list[dict[str, Any]]:
    dataset = root / "dataset"
    manifest_path = dataset / "manifest.json"
    dataset_identity = _physical_directory_identity(
        dataset, field="performance dataset", create=False
    )
    try:
        manifest_stat = os.lstat(manifest_path)
    except FileNotFoundError:
        manifest_stat = None
    except OSError as error:
        raise PerformanceGateError(
            f"cached dataset manifest cannot be inspected: {error}"
        ) from error
    manifest_is_private_regular = bool(
        manifest_stat is not None
        and stat.S_ISREG(manifest_stat.st_mode)
        and not stat.S_ISLNK(manifest_stat.st_mode)
        and manifest_stat.st_nlink == 1
    )
    if dataset_identity is not None and manifest_is_private_regular:
        try:
            manifest = _json_object_from_exact_bytes(
                manifest_path.read_bytes(), field="dataset_manifest"
            )
            if set(manifest) != {
                "schema", "jar_count", "class_count", "classes_per_jar",
                "base_template_sha256", "artifacts",
            }:
                raise PerformanceGateError(
                    "cached dataset manifest fields are invalid"
                )
            if (
                manifest.get("schema") != DATASET_SCHEMA
                or type(manifest.get("jar_count")) is not int
                or manifest["jar_count"] != jar_count
                or type(manifest.get("classes_per_jar")) is not int
                or manifest["classes_per_jar"] != classes_per_jar
                or type(manifest.get("class_count")) is not int
                or manifest["class_count"] != jar_count * classes_per_jar
                or manifest.get("base_template_sha256")
                != _FIXED_TEMPLATE_SHA256[1]
            ):
                raise PerformanceGateError(
                    "cached dataset manifest metadata is invalid"
                )
            raw_artifacts = manifest.get("artifacts")
            if type(raw_artifacts) is not list or len(raw_artifacts) != jar_count:
                raise PerformanceGateError(
                    "cached dataset artifact count is invalid"
                )
            dataset_root = dataset.resolve()
            for index, raw_artifact in enumerate(raw_artifacts):
                expected_path = str(
                    dataset_root / f"artifact-{index:04d}.jar"
                )
                if (
                    not isinstance(raw_artifact, Mapping)
                    or raw_artifact.get("path") != expected_path
                ):
                    raise PerformanceGateError(
                        "cached dataset artifact path is outside its slot"
                    )
            artifacts = _validate_probe_worker_artifacts(
                raw_artifacts,
                field="dataset_manifest.artifacts",
                classes_per_jar=classes_per_jar,
                verified_files=set(),
            )
            if len(artifacts) != jar_count:
                raise PerformanceGateError(
                    "cached dataset artifact count is invalid"
                )
            return artifacts
        except (OSError, PerformanceGateError):
            # A cache is an optimization only.  Any malformed, stale or
            # special-file entry is rebuilt before measured work begins.
            pass
    if dataset_identity is not None:
        if _physical_directory_identity(
            dataset, field="performance dataset", create=False
        ) != dataset_identity:
            raise PerformanceGateError(
                "performance dataset directory changed before rebuild"
            )
        shutil.rmtree(dataset)
    _physical_directory_identity(
        dataset, field="performance dataset", create=True
    )
    template = _compile_template(root)
    artifacts = []
    class_index = 0
    for jar_index in range(jar_count):
        path = dataset / f"artifact-{jar_index:04d}.jar"
        with _atomic_zip_archive(
            path, field=f"performance dataset artifact {jar_index}"
        ) as archive:
            for _ in range(classes_per_jar):
                owner = f"p/C{class_index:06d}".encode("ascii")
                if len(owner) != len(b"p/C000000"):
                    raise PerformanceGateError("scale dataset class owner length overflow")
                content = template.replace(b"p/C000000", owner)
                info = zipfile.ZipInfo(owner.decode("ascii") + ".class", (2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, content)
                class_index += 1
        artifacts.append({
            "path": str(path.resolve()),
            "sha256": _sha256(path),
            "byte_length": path.stat().st_size,
            "jar_index": jar_index,
            "first_class_index": jar_index * classes_per_jar,
            "class_count": classes_per_jar,
        })
    manifest = {
        "schema": DATASET_SCHEMA,
        "jar_count": jar_count,
        "class_count": class_index,
        "classes_per_jar": classes_per_jar,
        "base_template_sha256": _FIXED_TEMPLATE_SHA256[1],
        "artifacts": artifacts,
    }
    _write_json(manifest_path, manifest)
    return artifacts


def build_changed_current_artifacts(
    root: Path,
    artifacts: list[dict[str, Any]],
    *,
    classes_per_jar: int,
) -> list[dict[str, Any]]:
    """Change every method body in one JAR while preserving its class topology."""

    if not artifacts:
        raise PerformanceGateError("changed-side probe requires at least one artifact")
    changed_directory = root / "changed-dataset"
    _physical_directory_identity(
        changed_directory, field="changed performance dataset", create=True
    )
    changed_path = changed_directory / "artifact-0000.jar"
    template = _compile_template(
        root, return_value=2, label="changed-template"
    )
    first_class = artifacts[0]["first_class_index"]
    with _atomic_zip_archive(
        changed_path, field="changed performance dataset artifact"
    ) as archive:
        for class_index in range(first_class, first_class + classes_per_jar):
            owner = f"p/C{class_index:06d}".encode("ascii")
            if len(owner) != len(b"p/C000000"):
                raise PerformanceGateError(
                    "changed-side class owner length overflow"
                )
            content = template.replace(b"p/C000000", owner)
            info = zipfile.ZipInfo(
                owner.decode("ascii") + ".class", (2026, 1, 1, 0, 0, 0)
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    current = [dict(item) for item in artifacts]
    current[0] = {
        **current[0],
        "path": str(changed_path.resolve()),
        "sha256": _sha256(changed_path),
        "byte_length": changed_path.stat().st_size,
    }
    return current


def _runtime_profile(artifacts: list[dict[str, Any]], jdk_major: int) -> RuntimeProfile:
    descriptors = [
        {
            "logical_location": f"lib/artifact-{index:04d}.jar",
            "content_sha256": item["sha256"],
            "path_kind": "classpath",
            "slot": index,
            "loader_realm": "application-loader",
        }
        for index, item in enumerate(artifacts)
    ]
    payload = {
        "target_jvm": {"vendor": "performance-gate", "major": jdk_major},
        "runtime_platform_image_identity": "performance-platform-image",
        "target_os": platform.system(),
        "target_arch": platform.machine(),
        "container_and_launcher_kind": "java-classpath",
        "ordered_runtime_path_entry_descriptors": descriptors,
        "loader_topology": {
            "coverage_status": "complete",
            "entrypoint_realms": ["application-loader"],
            "realms": [
                {"identity": "platform-loader", "kind": "platform", "delegation": "parent_first"},
                {
                    "identity": "application-loader", "kind": "application",
                    "parent": "platform-loader", "delegation": "parent_first",
                    "module_mode": "unnamed",
                },
            ],
        },
        "runtime_code_source_origin_mapping_identity": "performance-origins-v1",
        "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
        "active_profile_identities": ["performance"],
        "external_config_snapshot_identities": [],
        "agent_transformer_plugin_profile_identities": [],
        "business_entrypoint_profile": {"coverage_status": "complete", "methods": []},
        "runtime_class_closure_coverage_status": "complete",
        "resource_selection_coverage_status": "complete",
    }
    payload["field_coverage"] = {key: "known" for key in RuntimeProfile.REQUIRED_FIELDS}
    return RuntimeProfile(payload)


def _instance(profile: RuntimeProfile, artifact: dict[str, Any], index: int) -> ArtifactInstance:
    return ArtifactInstance(
        outer_artifact_sha256=artifact["sha256"],
        container_entry="<artifact>",
        content_sha256=artifact["sha256"],
        runtime_profile_identity=profile.identity,
        path_owner_loader_realm_identity="application-loader",
        runtime_path_kind="classpath",
        runtime_classpath_index=index,
        container_loader_policy_version="flat-parent-first-v1",
        runtime_code_source_origin_identity=f"performance-artifact-{index:04d}",
        coord=f"performance:artifact-{index:04d}:1",
    )


def _inventory(artifacts: Iterable[dict[str, Any]]) -> dict[str, int]:
    entries = 0
    bytes_total = 0
    for artifact in artifacts:
        with zipfile.ZipFile(artifact["path"]) as archive:
            infos = archive.infolist()
            entries += len(infos)
            bytes_total += sum(info.file_size for info in infos)
    return {"entry_count": entries, "uncompressed_bytes": bytes_total}


def _remove_existing_regular_or_link_leaf(path: Path, *, field: str) -> None:
    """Remove one owned output leaf without following even a dangling link."""

    try:
        entry = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise PerformanceGateError(f"{field} cannot be inspected: {error}") from error
    if not (stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode)):
        raise PerformanceGateError(
            f"{field} must be absent, a regular file, or a file link"
        )
    try:
        path.unlink()
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise PerformanceGateError(f"{field} cannot be removed safely: {error}") from error
    raise PerformanceGateError(f"{field} remained present after removal")


def _analyze_once(
    artifacts: list[dict[str, Any]], *, root: Path, cache_root: Path,
    asm_jar: Path, warm: bool,
) -> dict[str, Any]:
    cache_identity = _physical_directory_identity(
        cache_root, field="performance snapshot cache", create=False
    )
    if not warm and cache_identity is not None:
        if _physical_directory_identity(
            cache_root, field="performance snapshot cache", create=False
        ) != cache_identity:
            raise PerformanceGateError(
                "performance snapshot cache changed before cold cleanup"
            )
        shutil.rmtree(cache_root)
    elif warm and cache_identity is None:
        raise PerformanceGateError("warm performance snapshot cache is absent")
    selected_jdk_home = _jdk_home()
    profile = _runtime_profile(artifacts, _java_major(selected_jdk_home))
    db = root / ("warm.sqlite" if warm else "cold.sqlite")
    _remove_existing_regular_or_link_leaf(
        db, field="performance SQLite output"
    )
    started = time.perf_counter()
    cpu_started = _cpu_seconds()
    inventory_started = time.perf_counter()
    inventory = _inventory(artifacts)
    inventory_seconds = time.perf_counter() - inventory_started
    parse_seconds = 0.0
    db_seconds = 0.0
    parser_invocations = 0
    cache_hits = 0
    db_started = time.perf_counter()
    counts = {"entries": 0, "classes": 0, "members": 0, "edges": 0, "resources": 0}
    store = BinaryFactStore(db)
    db_seconds += time.perf_counter() - db_started
    try:
        for index, artifact in enumerate(artifacts):
            instance = _instance(profile, artifact, index)
            parse_started = time.perf_counter()
            outcome = cached_snapshot_archive(
                artifact["path"],
                artifact_instance_identity=instance.identity,
                expected_sha256=artifact["sha256"],
                cache_root=cache_root,
                asm_jar=asm_jar,
                jdk_home=selected_jdk_home,
                target_jvm_major=int(profile.payload["target_jvm"]["major"]),
            )
            parse_seconds += time.perf_counter() - parse_started
            parser_invocations += outcome.parser_invocation_count
            cache_hits += int(outcome.cache_status == "hit")
            db_started = time.perf_counter()
            added = store.add_artifact_snapshot(instance, outcome.snapshot)
            db_seconds += time.perf_counter() - db_started
            for key, value in added.items():
                counts[key] += value
            del outcome
        db_started = time.perf_counter()
        store.connection.commit()
        db_seconds += time.perf_counter() - db_started
        overlay_started = time.perf_counter()
        # Source is intentionally absent in this scale fixture; exercising the
        # optional overlay must not scan or mutate the binary graph.
        overlay_status = "not_provided"
        overlay_seconds = time.perf_counter() - overlay_started
        query_started = time.perf_counter()
        query_count = 10_000
        connection = store.connection
        for index in range(query_count):
            owner = f"p/C{index % inventory['entry_count']:06d}"
            connection.execute(
                "SELECT member_identity FROM members WHERE class_name=? AND member_name='value' AND descriptor='()I'",
                (owner,),
            ).fetchall()
        query_seconds = time.perf_counter() - query_started
        report_started = time.perf_counter()
        report_payload = {
            "schema": "binary-performance-report-fixture.v1",
            "api_results": [
                {
                    "api": f"p.C{index:06d}.value()I",
                    "reachability_status": "not_found_in_static_analysis",
                    "impact_conclusion": "inconclusive",
                    "runtime_verification_status": "undetermined",
                }
                for index in range(query_count)
            ],
        }
        encoded_report = json.dumps(report_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        report_seconds = time.perf_counter() - report_started
    finally:
        store.close()
    timing = _timing_metrics(started=started, cpu_started=cpu_started)
    return {
        **timing,
        "stage_seconds": {
            "inventory": inventory_seconds,
            "parse_and_cache": parse_seconds,
            "db_write_and_index": db_seconds,
            "overlay": overlay_seconds,
            "batch_query_10000": query_seconds,
            "report_10000": report_seconds,
        },
        "parser_invocations": parser_invocations,
        "cache_hits": cache_hits,
        "counts": counts,
        "inventory": inventory,
        "overlay_status": overlay_status,
        "report_bytes": len(encoded_report),
        "db_bytes": db.stat().st_size,
        "cache_bytes": _directory_bytes(cache_root),
        "peak_rss_bytes": _rss_bytes(),
        "bytes_per_class": (db.stat().st_size + _directory_bytes(cache_root)) / max(counts["classes"], 1),
        "bytes_per_edge": db.stat().st_size / max(counts["edges"], 1),
    }


def _legacy_javap(artifacts: list[dict[str, Any]], classes_per_jar: int) -> dict[str, Any]:
    started = time.perf_counter()
    cpu_started = _cpu_seconds()
    class_count = 0
    for artifact in artifacts:
        first = int(artifact["first_class_index"])
        names = [f"p.C{index:06d}" for index in range(first, first + classes_per_jar)]
        completed = run_managed_subprocess(
            javap_command(
                "javap", "-c", "-s", "-p", "-classpath",
                artifact["path"], *names,
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            raise PerformanceGateError(
                f"javap failed for {artifact['path']}: {completed.stderr[-500:].decode(errors='replace')}"
            )
        class_count += len(names)
    return {
        **_timing_metrics(started=started, cpu_started=cpu_started),
        "class_count": class_count,
        "peak_rss_bytes": _rss_bytes(),
        "implementation": "legacy-javap-c-s-p-batched-per-artifact",
    }


def _full_pipeline_probe(
    artifacts: list[dict[str, Any]],
    *,
    root: Path,
    asm_jar: Path,
    classes_per_jar: int,
    jar_limit: int | None = None,
    current_artifacts: list[dict[str, Any]] | None = None,
    retain_validation_checkpoint: bool = True,
) -> dict[str, Any]:
    """Measure the full runtime and Oracle phases at the requested scale."""
    from binary_output import (
        read_active_binary_generation,
        read_pending_binary_generation,
    )
    from binary_pipeline import (
        _filesystem_entry_absent,
        _resume_checkpoint_path,
        run_pipeline,
    )

    selected_base = (
        artifacts
        if jar_limit is None
        else artifacts[:min(len(artifacts), jar_limit)]
    )
    all_current = artifacts if current_artifacts is None else current_artifacts
    selected_current = (
        all_current
        if jar_limit is None
        else all_current[:min(len(all_current), jar_limit)]
    )
    if len(selected_base) != len(selected_current):
        raise PerformanceGateError(
            "full pipeline base/current artifact counts must match"
        )
    output_root = root / "full-pipeline-probe"
    if output_root.exists() or output_root.is_symlink():
        raise PerformanceGateError(
            f"private full-pipeline output root already exists: {output_root}"
        )

    def runtime_artifacts(selected):
        return [
            {
                "path": item["path"],
                "logical_location": f"lib/artifact-{index:04d}.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": index,
                "coord": f"performance:artifact-{index:04d}:1",
                "lineage": f"performance:artifact-{index:04d}",
                "runtime_code_source_origin_identity": (
                    f"performance-artifact-{index:04d}"
                ),
            }
            for index, item in enumerate(selected)
        ]
    runtime_profile = {
        "container_and_launcher_kind": "java-classpath",
        "loader_topology": {
            "coverage_status": "complete",
            "entrypoint_realms": ["application-loader"],
            "realms": [
                {
                    "identity": "platform-loader",
                    "kind": "platform",
                    "delegation": "parent_first",
                    "module_mode": "named-platform",
                },
                {
                    "identity": "application-loader",
                    "kind": "application",
                    "parent": "platform-loader",
                    "delegation": "parent_first",
                    "module_mode": "unnamed",
                },
            ],
        },
        "runtime_security_and_package_sealing_policy_identity": (
            "standard-unsealed-unsigned-v1"
        ),
        "active_profile_identities": ["performance"],
        "external_config_snapshot_identities": [],
        "agent_transformer_plugin_profile_identities": [],
        "business_entrypoint_profile": {
            "coverage_status": "complete",
            "methods": [],
        },
        "runtime_class_closure_coverage_status": "complete",
        "resource_selection_coverage_status": "complete",
    }
    jdk_home = str(_jdk_home())
    started = time.perf_counter()
    cpu_started = _cpu_seconds()
    result = run_pipeline(
        {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "performance_fixture",
            },
            "asm_jar": str(asm_jar),
            "base": {
                "jdk_home": jdk_home,
                "artifacts": runtime_artifacts(selected_base),
                "runtime_profile": runtime_profile,
            },
            "current": {
                "jdk_home": jdk_home,
                "artifacts": runtime_artifacts(selected_current),
                "runtime_profile": runtime_profile,
            },
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        },
        output_root=output_root,
        retain_validation_checkpoint=retain_validation_checkpoint,
    )
    timing = _timing_metrics(started=started, cpu_started=cpu_started)
    evidence = _full_pipeline_evidence(result)
    process_tree_peak_rss_bytes = _rss_bytes()
    phase_peak_rss_bytes = {
        str(item["phase"]): max(
            int(item.get("peak_rss_bytes") or 0),
            int(item.get("completed_child_peak_rss_bytes") or 0),
        )
        for item in result["phase_timings"]
    }
    activation_phases = [
        item for item in result["phase_timings"]
        if item.get("phase") == "validated_generation_activation"
    ]
    if len(activation_phases) != 1:
        raise PerformanceGateError(
            "full pipeline returned an invalid activation timing record"
        )
    activation_phase = activation_phases[0]
    active_absent = (
        read_active_binary_generation(output_root, missing_ok=True) is None
    )
    pending_absent = (
        read_pending_binary_generation(output_root, missing_ok=True) is None
    )
    checkpoint_absent = _filesystem_entry_absent(
        _resume_checkpoint_path(output_root)
    )
    if not (active_absent and pending_absent and checkpoint_absent):
        raise PerformanceGateError(
            "benchmark full pipeline left publication or checkpoint state"
        )
    comparison = (
        "identical-base-current-cold-output"
        if [item.get("sha256") for item in selected_base]
        == [item.get("sha256") for item in selected_current]
        else "nonidentical-base-current-cold-output"
    )
    return {
        "status": "passed",
        "comparison": comparison,
        "process_id": os.getpid(),
        "rss_measurement_scope": (
            "dedicated_probe_process_and_completed_children"
        ),
        "jar_count": len(selected_base),
        "current_jar_count": len(selected_current),
        "expected_class_count": len(selected_base) * classes_per_jar,
        # The harness timer encloses the complete production call, including
        # final observability and result return.  Preserve the pipeline's own
        # timer separately so the non-negative boundary overhead is auditable.
        "end_to_end_seconds": timing["end_to_end_seconds"],
        "pipeline_reported_seconds": float(result["total_elapsed_seconds"]),
        "pipeline_total_elapsed_scope": result.get("total_elapsed_scope"),
        "pipeline_phase_timings_scope": result.get("phase_timings_scope"),
        "cpu_seconds": timing["cpu_seconds"],
        "average_cpu_cores": timing["average_cpu_cores"],
        "phase_seconds": {
            str(item["phase"]): float(item["elapsed_seconds"])
            for item in result["phase_timings"]
        },
        "phase_peak_rss_bytes": phase_peak_rss_bytes,
        "pipeline_reported_peak_rss_bytes": int(
            result.get("peak_rss_bytes") or 0
        ),
        "post_pipeline_peak_rss_bytes": process_tree_peak_rss_bytes,
        "peak_rss_bytes": max([
            process_tree_peak_rss_bytes,
            *phase_peak_rss_bytes.values(),
        ]),
        "pipeline_performance_authority_binding": dict(
            result.get("performance_authority_gate_binding") or {}
        ),
        "activation_authority_mode": activation_phase.get(
            "activation_authority_mode"
        ),
        "publication_deferred": activation_phase.get(
            "publication_deferred"
        ),
        "checkpoint_retained": activation_phase.get("checkpoint_retained"),
        "activation_candidate_discarded": activation_phase.get(
            "activation_candidate_discarded"
        ),
        "activation_recapture_discarded": bool(
            result.get("activation_recapture_discarded", False)
        ),
        "active_generation_absent": active_absent,
        "pending_generation_absent": pending_absent,
        "validation_checkpoint_absent": checkpoint_absent,
        "parser_invocations": int(
            result["cache_metrics"]["classfile_parser_invocations"]
        ),
        "artifact_snapshot_hits": int(
            result["cache_metrics"]["artifact_snapshot_hits"]
        ),
        "artifact_snapshot_disk_hits": int(
            result["cache_metrics"].get("artifact_snapshot_disk_hits") or 0
        ),
        "artifact_snapshot_memory_hits": int(
            result["cache_metrics"].get("artifact_snapshot_memory_hits") or 0
        ),
        **evidence,
    }


def _safe_error_text(error: BaseException, *, limit: int = 8192) -> str:
    try:
        detail = str(error)
    except BaseException as rendering_error:
        detail = (
            f"<unprintable {type(error).__name__}: "
            f"str raised {type(rendering_error).__name__}>"
        )
    if len(detail) > limit:
        detail = detail[:limit] + "...[truncated]"
    return detail


def _bounded_json_value(value: Any, *, depth: int = 0) -> Any:
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        return value if math.isfinite(value) else str(value)
    if type(value) is str:
        return value[:8192] + ("...[truncated]" if len(value) > 8192 else "")
    if depth >= 4:
        return f"<{type(value).__name__}>"
    if isinstance(value, Mapping):
        normalized = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 64:
                normalized["__truncated__"] = True
                break
            try:
                normalized_key = str(key)
            except BaseException:
                normalized_key = f"<unprintable-{type(key).__name__}>"
            normalized[normalized_key[:512]] = _bounded_json_value(
                item, depth=depth + 1
            )
        return normalized
    if isinstance(value, (list, tuple)):
        normalized = [
            _bounded_json_value(item, depth=depth + 1)
            for item in value[:64]
        ]
        if len(value) > 64:
            normalized.append("...[truncated]")
        return normalized
    try:
        rendered = repr(value)
    except BaseException:
        rendered = f"<unprintable-{type(value).__name__}>"
    return rendered[:8192]


def _probe_failure(error: BaseException) -> dict[str, Any]:
    structured = getattr(error, "failure", {})
    structured_reason = (
        structured.get("reason_code")
        if isinstance(structured, Mapping)
        else None
    )
    reason_code = str(
        structured_reason
        or
        getattr(error, "reason_code", "")
        or "BINARY_PERFORMANCE_FULL_PIPELINE_PROBE_FAILED"
    )
    return {
        "reason_code": reason_code,
        "error_type": type(error).__name__,
        "detail": _safe_error_text(error),
    }


def _probe_worker_input_error(field: str, detail: str) -> None:
    raise PerformanceGateError(
        f"probe worker input is invalid at {field}: {detail}",
        failure={
            "reason_code": "BINARY_PERFORMANCE_PROBE_INPUT_INVALID",
            "field": field,
            "detail": detail,
        },
    )


def _probe_artifact_stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000))),
    )


def _verify_probe_worker_artifact_file(
    path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    field: str,
) -> None:
    """Verify one stable regular artifact before the worker may consume it."""

    descriptor = -1
    try:
        path_before = os.lstat(path)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or stat.S_ISLNK(path_before.st_mode)
            or path_before.st_size != expected_size
        ):
            _probe_worker_input_error(
                field, "artifact is not the declared regular file"
            )
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        descriptor_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_before.st_mode)
            or _probe_artifact_stat_identity(path_before)
            != _probe_artifact_stat_identity(descriptor_before)
        ):
            _probe_worker_input_error(field, "artifact changed before verification")
        digest = hashlib.sha256()
        observed_size = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            observed_size += len(block)
            if observed_size > expected_size:
                _probe_worker_input_error(field, "artifact byte length changed")
            digest.update(block)
        descriptor_after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if (
            observed_size != expected_size
            or _probe_artifact_stat_identity(descriptor_before)
            != _probe_artifact_stat_identity(descriptor_after)
            or _probe_artifact_stat_identity(descriptor_after)
            != _probe_artifact_stat_identity(path_after)
        ):
            _probe_worker_input_error(field, "artifact changed during verification")
        if digest.hexdigest() != expected_sha256:
            _probe_worker_input_error(field, "artifact SHA-256 does not match")
    except PerformanceGateError:
        raise
    except OSError as error:
        _probe_worker_input_error(field, f"artifact cannot be verified: {error}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _validate_probe_worker_artifacts(
    value: Any,
    *,
    field: str,
    classes_per_jar: int,
    verified_files: set[tuple[str, int, str]],
) -> list[dict[str, Any]]:
    if type(value) is not list:
        _probe_worker_input_error(field, "expected an array")
    artifacts: list[dict[str, Any]] = []
    for index, raw_item in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(raw_item, Mapping):
            _probe_worker_input_error(item_field, "expected an object")
        item = dict(raw_item)
        if set(item) != _PROBE_WORKER_ARTIFACT_FIELDS:
            _probe_worker_input_error(
                item_field,
                "artifact fields must match the exact worker schema",
            )
        raw_path = item.get("path")
        if type(raw_path) is not str or not raw_path:
            _probe_worker_input_error(f"{item_field}.path", "expected a path string")
        artifact_path = Path(raw_path)
        if not artifact_path.is_absolute() or str(artifact_path.resolve()) != raw_path:
            _probe_worker_input_error(
                f"{item_field}.path", "path must be canonical and absolute"
            )
        if not _is_sha256_identity(item.get("sha256")):
            _probe_worker_input_error(
                f"{item_field}.sha256", "expected a lowercase SHA-256 identity"
            )
        for name in ("byte_length", "jar_index", "first_class_index", "class_count"):
            if type(item.get(name)) is not int or item[name] < 0:
                _probe_worker_input_error(
                    f"{item_field}.{name}", "expected a non-negative integer"
                )
        if item["byte_length"] <= 0:
            _probe_worker_input_error(
                f"{item_field}.byte_length", "expected a positive byte length"
            )
        if item["jar_index"] != index:
            _probe_worker_input_error(
                f"{item_field}.jar_index", "does not match the array slot"
            )
        if item["first_class_index"] != index * classes_per_jar:
            _probe_worker_input_error(
                f"{item_field}.first_class_index",
                "does not match the declared dataset layout",
            )
        if item["class_count"] != classes_per_jar:
            _probe_worker_input_error(
                f"{item_field}.class_count",
                "does not match classes_per_jar",
            )
        verification_key = (raw_path, item["byte_length"], item["sha256"])
        if verification_key not in verified_files:
            _verify_probe_worker_artifact_file(
                artifact_path,
                expected_size=item["byte_length"],
                expected_sha256=item["sha256"],
                field=item_field,
            )
            verified_files.add(verification_key)
        artifacts.append(item)
    return artifacts


def _validate_probe_worker_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _probe_worker_input_error("root", "expected an object")
    spec = dict(value)
    if set(spec) != _PROBE_WORKER_INPUT_FIELDS:
        _probe_worker_input_error("root", "fields must match the exact worker schema")
    if spec.get("schema") != PROBE_WORKER_SCHEMA:
        _probe_worker_input_error("schema", "unexpected schema")
    classes_per_jar = spec.get("classes_per_jar")
    if type(classes_per_jar) is not int or classes_per_jar <= 0:
        _probe_worker_input_error(
            "classes_per_jar", "expected a positive integer"
        )
    raw_asm_jar = spec.get("asm_jar")
    if type(raw_asm_jar) is not str or not raw_asm_jar:
        _probe_worker_input_error("asm_jar", "expected a path string")
    asm_path = Path(raw_asm_jar)
    if not asm_path.is_absolute() or str(asm_path.resolve()) != raw_asm_jar:
        _probe_worker_input_error(
            "asm_jar", "path must be canonical and absolute"
        )
    implementation = spec.get("expected_implementation")
    if not isinstance(implementation, Mapping):
        _probe_worker_input_error(
            "expected_implementation", "expected an object"
        )
    implementation = dict(implementation)
    if set(implementation) != _PERFORMANCE_IMPLEMENTATION_FIELDS or any(
        not _is_sha256_identity(implementation.get(name))
        for name in _PERFORMANCE_IMPLEMENTATION_FIELDS
    ):
        _probe_worker_input_error(
            "expected_implementation",
            "expected the exact nine SHA-256 implementation fields",
        )
    if (
        _source_implementation_identity(implementation)
        != implementation["source_implementation_identity"]
        or _runtime_implementation_identity(implementation)
        != implementation["runtime_implementation_identity"]
    ):
        _probe_worker_input_error(
            "expected_implementation",
            "aggregate implementation identities are inconsistent",
        )
    verified_files: set[tuple[str, int, str]] = set()
    artifacts = _validate_probe_worker_artifacts(
        spec.get("artifacts"),
        field="artifacts",
        classes_per_jar=classes_per_jar,
        verified_files=verified_files,
    )
    if not artifacts:
        _probe_worker_input_error(
            "artifacts", "the full pipeline probe requires at least one artifact"
        )
    raw_current = spec.get("current_artifacts")
    current_artifacts = None
    if raw_current is not None:
        current_artifacts = _validate_probe_worker_artifacts(
            raw_current,
            field="current_artifacts",
            classes_per_jar=classes_per_jar,
            verified_files=verified_files,
        )
        if len(current_artifacts) != len(artifacts):
            _probe_worker_input_error(
                "current_artifacts", "base/current artifact counts differ"
            )
    provisional_gate_path = spec.get("provisional_gate_path")
    if type(provisional_gate_path) is not str:
        _probe_worker_input_error(
            "provisional_gate_path", "expected a string"
        )
    if provisional_gate_path:
        provisional_path = Path(provisional_gate_path)
        if (
            not provisional_path.is_absolute()
            or str(provisional_path.resolve()) != provisional_gate_path
        ):
            _probe_worker_input_error(
                "provisional_gate_path", "path must be canonical and absolute"
            )
    return {
        **spec,
        "artifacts": artifacts,
        "current_artifacts": current_artifacts,
        "expected_implementation": implementation,
    }


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    _write_exact_bytes(
        path,
        (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8"),
    )


def _write_exact_bytes(path: Path, content: bytes) -> None:
    """Atomically persist the exact bytes supplied by an authority caller."""

    if type(content) is not bytes:
        raise PerformanceGateError("authority evidence must be exact bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = -1
    temporary: Path | None = None
    completed_stat: os.stat_result | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        created_stat = os.fstat(descriptor)
        if not stat.S_ISREG(created_stat.st_mode) or created_stat.st_nlink != 1:
            raise PerformanceGateError(
                "authority output temporary is not a private regular file"
            )
        stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with stream:
            stream.write(content)
            stream.flush()
            completed_stat = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(completed_stat.st_mode)
                or completed_stat.st_nlink != 1
                or completed_stat.st_dev != created_stat.st_dev
                or completed_stat.st_ino != created_stat.st_ino
            ):
                raise PerformanceGateError(
                    "authority output temporary changed while being written"
                )
        path_stat = os.lstat(temporary)
        if (
            completed_stat is None
            or not _same_completed_private_file(completed_stat, path_stat)
        ):
            raise PerformanceGateError(
                "authority output temporary was replaced before publication"
            )
        os.replace(temporary, path)
        temporary = None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _performance_recovery_bytes(result: Mapping[str, Any]) -> bytes:
    content = (
        json.dumps(
            dict(result),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(content) > _PERFORMANCE_RECOVERY_MAX_BYTES:
        raise PerformanceGateError(
            "completed benchmark result exceeds the recovery size limit"
        )
    return content


def _persist_completed_benchmark_recovery(
    root: Path,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Preserve completed long-run evidence when the requested sink fails."""

    try:
        content = _performance_recovery_bytes(result)
    except BaseException as error:
        return {
            "schema": (
                "java-upgrade-analyzer."
                "binary-performance-result-recovery-receipt.v1"
            ),
            "result_sha256": "",
            "result_size_bytes": 0,
            "recovery_path": "",
            "recovery_is_temporary": False,
            "result_encoding_error": _safe_error_text(error),
        }
    digest = hashlib.sha256(content).hexdigest()
    recovery_path = (
        root / "binary_observability" / _PERFORMANCE_RECOVERY_RESULT_NAME
    )
    recovery_error = ""
    try:
        from binary_pipeline import _write_non_authoritative_json

        persisted = _write_non_authoritative_json(
            recovery_path,
            result,
            durable=True,
        )
        if persisted:
            return {
                "schema": (
                    "java-upgrade-analyzer."
                    "binary-performance-result-recovery-receipt.v1"
                ),
                "result_sha256": digest,
                "result_size_bytes": len(content),
                "recovery_path": str(recovery_path.resolve()),
                "recovery_is_temporary": False,
            }
        recovery_error = "work-root recovery writer rejected the destination"
    except BaseException as error:
        recovery_error = _safe_error_text(error)

    descriptor = -1
    fallback_path: Path | None = None
    try:
        descriptor, fallback_name = tempfile.mkstemp(
            prefix="jua-binary-performance-recovery-",
            suffix=".json",
        )
        fallback_path = Path(fallback_name)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            completed = os.fstat(handle.fileno())
        path_stat = os.lstat(fallback_path)
        if not _same_completed_private_file(completed, path_stat):
            raise OSError("temporary recovery file changed while being written")
        return {
            "schema": (
                "java-upgrade-analyzer."
                "binary-performance-result-recovery-receipt.v1"
            ),
            "result_sha256": digest,
            "result_size_bytes": len(content),
            "recovery_path": str(fallback_path.resolve()),
            "recovery_is_temporary": True,
            "work_root_recovery_error": recovery_error,
        }
    except BaseException as error:
        if fallback_path is not None:
            try:
                fallback_path.unlink()
            except OSError:
                pass
        return {
            "schema": (
                "java-upgrade-analyzer."
                "binary-performance-result-recovery-receipt.v1"
            ),
            "result_sha256": digest,
            "result_size_bytes": len(content),
            "recovery_path": "",
            "recovery_is_temporary": False,
            "work_root_recovery_error": recovery_error,
            "temporary_recovery_error": _safe_error_text(error),
        }
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _emit_performance_cli_failure(
    output_path: Path,
    *,
    reason_code: str,
    phase: str,
    error: BaseException,
    core_benchmark_status: str,
    core_result_receipt: Mapping[str, Any] | None = None,
    primary_failure: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    failure = {
        "schema": CLI_FAILURE_SCHEMA,
        "status": "failed",
        "reason_code": reason_code,
        "phase": phase,
        "detail": f"{type(error).__name__}: {_safe_error_text(error)}",
        "output_path": str(output_path),
        "core_benchmark_status": core_benchmark_status,
        "core_result_receipt": _bounded_json_value(
            dict(core_result_receipt or {})
        ),
        "primary_failure": _bounded_json_value(
            dict(primary_failure or {})
        ),
    }
    try:
        _write_json(output_path, failure)
    except BaseException as persist_error:
        failure["failure_result_persist_error"] = (
            f"{type(persist_error).__name__}: "
            f"{_safe_error_text(persist_error)}"
        )
    print(
        json.dumps(
            failure,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
        ),
        file=sys.stderr,
    )
    return failure


def _snapshot_provisional_gate(
    root: Path, content: bytes,
) -> tuple[Path, str]:
    """Freeze replayed provisional bytes for every long-running probe.

    The caller has already parsed and replayed ``content``.  Keeping the
    probes bound to this private copy prevents a later replacement of the
    user-supplied path from giving the two independent probes different
    authorities after hours of otherwise valid work.
    """

    if type(content) is not bytes:
        raise PerformanceGateError(
            "provisional performance gate snapshot requires exact bytes"
        )
    authority_root = root.resolve() / "provisional-authority"
    directory_identity = _physical_directory_identity(
        authority_root,
        field="provisional performance authority snapshot",
        create=True,
    )
    expected_sha256 = hashlib.sha256(content).hexdigest()
    snapshot_path = authority_root / (
        f"provisional-gate-{expected_sha256}.json"
    )
    try:
        _write_exact_bytes(snapshot_path, content)
    except PerformanceGateError:
        raise
    except OSError as error:
        raise PerformanceGateError(
            "provisional performance authority snapshot cannot be "
            f"persisted: {error}"
        ) from error

    descriptor = -1
    try:
        path_before = os.lstat(snapshot_path)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or stat.S_ISLNK(path_before.st_mode)
            or path_before.st_nlink != 1
            or path_before.st_size != len(content)
        ):
            raise PerformanceGateError(
                "provisional performance authority snapshot is not a "
                "private regular file"
            )
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(snapshot_path, flags)
        descriptor_before = os.fstat(descriptor)
        if (
            descriptor_before.st_nlink != 1
            or _probe_artifact_stat_identity(path_before)
            != _probe_artifact_stat_identity(descriptor_before)
        ):
            raise PerformanceGateError(
                "provisional performance authority snapshot changed before "
                "verification"
            )
        observed = bytearray()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            observed.extend(block)
            if len(observed) > len(content):
                raise PerformanceGateError(
                    "provisional performance authority snapshot byte length "
                    "changed"
                )
        descriptor_after = os.fstat(descriptor)
        path_after = os.lstat(snapshot_path)
        if (
            descriptor_after.st_nlink != 1
            or _probe_artifact_stat_identity(descriptor_before)
            != _probe_artifact_stat_identity(descriptor_after)
            or _probe_artifact_stat_identity(descriptor_after)
            != _probe_artifact_stat_identity(path_after)
            or bytes(observed) != content
            or hashlib.sha256(observed).hexdigest() != expected_sha256
        ):
            raise PerformanceGateError(
                "provisional performance authority snapshot does not match "
                "the replayed bytes"
            )
        if _physical_directory_identity(
            authority_root,
            field="provisional performance authority snapshot",
            create=False,
        ) != directory_identity:
            raise PerformanceGateError(
                "provisional performance authority snapshot directory changed"
            )
    except PerformanceGateError:
        raise
    except OSError as error:
        raise PerformanceGateError(
            f"provisional performance authority snapshot cannot be verified: "
            f"{error}"
        ) from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return snapshot_path, expected_sha256


@contextmanager
def _candidate_performance_authority(
    root: Path,
    implementation: Mapping[str, str],
    *,
    provisional_gate_path: Path | None = None,
):
    """Authorize one isolated candidate probe or one explicit recapture."""

    import binary_pipeline

    original_gate_path = binary_pipeline.PERFORMANCE_GATE_PATH
    original_support_path = binary_pipeline.SUPPORT_MANIFEST_PATH
    bootstrap_context_token = None
    recapture_context_token = None
    recapture_root_token = None
    authority_mode = ""
    output_root = (root / "full-pipeline-probe").resolve()
    try:
        support = _json_object_from_exact_bytes(
            original_support_path.read_bytes(),
            field="support_manifest",
        )
        source_identity = str(
            implementation.get("source_implementation_identity") or ""
        )
        support_performance = support.get("performance_gate") or {}
        authority_root = root / "candidate-performance-authority"
        candidate_gate_path = authority_root / "performance_gate.json"
        candidate_support_path = authority_root / "support_manifest.json"
        if provisional_gate_path is not None:
            try:
                provisional_content = provisional_gate_path.read_bytes()
                evidence = _json_object_from_exact_bytes(
                    provisional_content,
                    field="provisional_gate",
                )
            except (OSError, PerformanceGateError) as error:
                raise PerformanceGateError(
                    f"provisional performance gate is unreadable: {error}"
                ) from error
            verification = evaluate_provisional_gate(
                evidence,
                _current_source_implementation=implementation,
            )
            if verification.get("status") != "passed":
                raise PerformanceGateError(
                    "provisional performance evidence failed replay",
                    failure={
                        "reason_code": (
                            "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID"
                        ),
                        "issues": list(verification.get("issues") or ()),
                    },
                )
            # The recapture probe's binding must name the exact provisional
            # bytes supplied to the official final builder.  Re-serializing a
            # semantically identical JSON object would silently break that
            # evidence chain whenever whitespace or key order differs.
            _write_exact_bytes(candidate_gate_path, provisional_content)
            authority_mode = "release_recapture_measurement"
        else:
            evidence = _json_object_from_exact_bytes(
                original_gate_path.read_bytes(),
                field="recorded_performance_gate",
            )
            candidate_protocol = dict(
                evidence.get("measurement_protocol") or {}
            )
            candidate_protocol["implementation"] = dict(implementation)
            candidate_protocol["source_implementation_identity"] = (
                source_identity
            )
            if implementation.get("runtime_implementation_identity"):
                candidate_protocol["runtime_implementation_identity"] = str(
                    implementation["runtime_implementation_identity"]
                )
            candidate_evidence = dict(evidence)
            candidate_evidence["measurement_protocol"] = candidate_protocol
            candidate_evidence["measurement_bootstrap"] = {
                "mode": "candidate_source_measurement",
                "source_implementation_identity": source_identity,
                "not_release_evidence": True,
            }
            _write_json(candidate_gate_path, candidate_evidence)
            authority_mode = "candidate_source_measurement"
        candidate_support = dict(support)
        candidate_performance = dict(support_performance)
        candidate_performance.update({
            "status": "passed",
            "path": binary_pipeline.PERFORMANCE_GATE_CONTRACT_PATH,
            "sha256": _sha256(candidate_gate_path),
            "source_implementation_identity": source_identity,
            "warm_parser_invocations": 0,
            "blocks_binary_authority_switch": False,
        })
        candidate_support["performance_gate"] = candidate_performance
        _write_json(candidate_support_path, candidate_support)

        binary_pipeline.PERFORMANCE_GATE_PATH = candidate_gate_path
        binary_pipeline.SUPPORT_MANIFEST_PATH = candidate_support_path
        if provisional_gate_path is not None:
            recapture_context_token = (
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                    binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
                )
            )
            recapture_root_token = (
                binary_pipeline
                ._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(output_root)
            )
        else:
            bootstrap_context_token = (
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.set(
                    binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY
                )
            )
        observed_binding = binary_pipeline._performance_authority_gate_binding(
            candidate_support
        )
        if observed_binding.get("authority_mode") != authority_mode:
            raise PerformanceGateError(
                "benchmark authority mode did not match the requested probe"
            )
        yield authority_mode
    finally:
        try:
            if bootstrap_context_token is not None:
                # The pipeline normally consumes both artefacts immediately
                # after measuring private activation.  This exact cleanup also
                # covers a failure between creation and normal consumption.
                binary_pipeline._cleanup_performance_measurement_state(
                    output_root
                )
            if recapture_context_token is not None:
                binary_pipeline._cleanup_performance_recapture_state(
                    output_root
                )
            if output_root.exists() or output_root.is_symlink():
                shutil.rmtree(output_root)
            if output_root.exists() or output_root.is_symlink():
                raise PerformanceGateError(
                    "private performance output root cleanup failed"
                )
        finally:
            if recapture_root_token is not None:
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                    recapture_root_token
                )
            if recapture_context_token is not None:
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                    recapture_context_token
                )
            if bootstrap_context_token is not None:
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.reset(
                    bootstrap_context_token
                )
            binary_pipeline.PERFORMANCE_GATE_PATH = original_gate_path
            binary_pipeline.SUPPORT_MANIFEST_PATH = original_support_path


def _preflight_performance_authority(
    implementation: Mapping[str, str],
    *,
    provisional_gate_path: Path,
) -> None:
    """Exercise the exact recapture authority before expensive scale work."""

    try:
        with short_temporary_directory(
            prefix="jua-performance-authority-preflight-"
        ) as private_directory:
            private_root = Path(private_directory).resolve()
            private_stat = os.lstat(private_root)
            if (
                not stat.S_ISDIR(private_stat.st_mode)
                or stat.S_IMODE(private_stat.st_mode) & 0o077
                or any(private_root.iterdir())
            ):
                raise PerformanceGateError(
                    "performance authority preflight root is not a private "
                    "empty directory"
                )
            with _candidate_performance_authority(
                private_root,
                implementation,
                provisional_gate_path=provisional_gate_path,
            ):
                pass
    except PerformanceGateError:
        raise
    except Exception as error:
        raise PerformanceGateError(
            "performance authority preflight failed: "
            f"{type(error).__name__}: {error}",
            failure={
                "reason_code": "BINARY_PERFORMANCE_AUTHORITY_PREFLIGHT_FAILED",
                "detail": f"{type(error).__name__}: {error}",
            },
        ) from error


def _run_probe_worker(input_path: Path, output_path: Path) -> int:
    """Execute one full probe and always preserve a structured outcome."""

    try:
        spec = _validate_probe_worker_input(
            _json_object_from_exact_bytes(
                input_path.read_bytes(), field="probe_worker_input"
            )
        )
        artifacts = spec["artifacts"]
        current_artifacts = spec["current_artifacts"]
        asm_jar = Path(spec["asm_jar"])
        expected_implementation = spec["expected_implementation"]
        before = _performance_implementation_protocol(asm_jar)
        for field in _PERFORMANCE_IMPLEMENTATION_FIELDS:
            if before.get(field) != expected_implementation.get(field):
                raise PerformanceGateError(
                    f"probe worker implementation changed before run: {field}"
                )
        raw_provisional_path = spec["provisional_gate_path"]
        provisional_gate_path = (
            Path(raw_provisional_path) if raw_provisional_path else None
        )
        # Never accept an activation root from worker input.  A hidden CLI is
        # still an external input surface, so the worker creates its own
        # unpredictable 0700 directory and removes it before returning.
        with short_temporary_directory(
            prefix="jua-isolated-performance-probe-"
        ) as private_directory:
            probe_root = Path(private_directory).resolve()
            private_stat = os.lstat(probe_root)
            if (
                not stat.S_ISDIR(private_stat.st_mode)
                or stat.S_IMODE(private_stat.st_mode) & 0o077
                or any(probe_root.iterdir())
            ):
                raise PerformanceGateError(
                    "isolated probe root is not a private empty directory"
                )
            with _candidate_performance_authority(
                probe_root,
                before,
                provisional_gate_path=provisional_gate_path,
            ) as performance_authority_mode:
                result = _full_pipeline_probe(
                    artifacts,
                    current_artifacts=current_artifacts,
                    root=probe_root,
                    asm_jar=asm_jar,
                    classes_per_jar=spec["classes_per_jar"],
                    retain_validation_checkpoint=(
                        performance_authority_mode
                        == _CANDIDATE_PROBE_AUTHORITY_MODE
                    ),
                )
        result["performance_authority_mode"] = performance_authority_mode
        after = _performance_implementation_protocol(asm_jar)
        if before != after:
            raise PerformanceGateError(
                "probe worker implementation changed during run"
            )
        response = {
            "schema": PROBE_WORKER_SCHEMA,
            "status": "passed",
            "result": result,
        }
        returncode = 0
    except BaseException as error:
        response = {
            "schema": PROBE_WORKER_SCHEMA,
            "status": "failed",
            "failure": _probe_failure(error),
        }
        returncode = 1
    try:
        _write_json(output_path, response)
    except BaseException as write_error:
        print(
            json.dumps({
                "schema": PROBE_WORKER_SCHEMA,
                "status": "failed",
                "failure": _probe_failure(write_error),
                "unpersisted_response": response,
            }, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    return returncode


def _validate_probe_worker_result_contract(
    result: Mapping[str, Any],
    *,
    artifacts: list[dict[str, Any]],
    current_artifacts: list[dict[str, Any]] | None,
    classes_per_jar: int,
    expected_mode: str,
) -> None:
    """Reject semantically impossible worker success before accepting timing."""

    def reject(field: str, detail: str) -> None:
        raise PerformanceGateError(
            f"probe worker result is invalid at {field}: {detail}",
            failure={
                "reason_code": "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
                "field": field,
                "detail": detail,
            },
        )

    effective_current = artifacts if current_artifacts is None else current_artifacts
    base_sha = [item["sha256"] for item in artifacts]
    current_sha = [item["sha256"] for item in effective_current]
    changed_jar_count = sum(
        left != right for left, right in zip(base_sha, current_sha)
    )
    expected_comparison = (
        "identical-base-current-cold-output"
        if changed_jar_count == 0
        else "nonidentical-base-current-cold-output"
    )
    expected_class_count = len(artifacts) * classes_per_jar
    exact_values = {
        "status": "passed",
        "comparison": expected_comparison,
        "rss_measurement_scope": (
            "dedicated_probe_process_and_completed_children"
        ),
        "pipeline_total_elapsed_scope": "current_pipeline_attempt",
        "pipeline_phase_timings_scope": "current_pipeline_attempt",
        "activation_authority_mode": expected_mode,
        "validation_status": "passed",
        "jar_count": len(artifacts),
        "current_jar_count": len(effective_current),
        "expected_class_count": expected_class_count,
        "class_count": expected_class_count,
        "base_class_count": expected_class_count,
        "current_class_count": expected_class_count,
        "validation_issue_count": 0,
        "publication_deferred": False,
        "checkpoint_retained": False,
        "active_generation_absent": True,
        "pending_generation_absent": True,
        "validation_checkpoint_absent": True,
        "activation_candidate_discarded": (
            expected_mode == _CANDIDATE_PROBE_AUTHORITY_MODE
        ),
        "activation_recapture_discarded": (
            expected_mode == _RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE
        ),
    }
    for field, expected in exact_values.items():
        if not _type_sensitive_equal(expected, result.get(field)):
            reject(field, f"expected {expected!r}; actual={result.get(field)!r}")

    phase_total = sum(float(value) for value in result["phase_seconds"].values())
    pipeline_seconds = float(result["pipeline_reported_seconds"])
    outer_seconds = float(result["end_to_end_seconds"])
    if phase_total > pipeline_seconds + 0.01:
        reject("phase_seconds", "phase total exceeds pipeline wall time")
    if pipeline_seconds > outer_seconds + 0.01:
        reject(
            "pipeline_reported_seconds",
            "pipeline wall time exceeds its enclosing worker timer",
        )

    expected_peak = max([
        int(result["post_pipeline_peak_rss_bytes"]),
        *[int(value) for value in result["phase_peak_rss_bytes"].values()],
    ])
    ordered_phase_peaks = [
        int(result["phase_peak_rss_bytes"][name])
        for name in FULL_PIPELINE_PHASES
    ]
    if any(
        current < previous
        for previous, current in zip(
            ordered_phase_peaks, ordered_phase_peaks[1:]
        )
    ):
        reject(
            "phase_peak_rss_bytes",
            "phase high-water marks must be non-decreasing",
        )
    if result["peak_rss_bytes"] != expected_peak:
        reject("peak_rss_bytes", "does not equal the declared lifecycle peak")
    if result["pipeline_reported_peak_rss_bytes"] > result["peak_rss_bytes"]:
        reject(
            "pipeline_reported_peak_rss_bytes",
            "pipeline peak exceeds the enclosing probe peak",
        )

    if result["artifact_snapshot_hits"] != (
        result["artifact_snapshot_disk_hits"]
        + result["artifact_snapshot_memory_hits"]
    ):
        reject(
            "artifact_snapshot_hits",
            "does not equal disk plus memory snapshot hits",
        )
    if changed_jar_count == 0:
        expected_parser_invocations = len(artifacts)
        expected_snapshot_hits = 0
    else:
        expected_parser_invocations = len(artifacts) + changed_jar_count
        expected_snapshot_hits = len(artifacts) - changed_jar_count
    if result["parser_invocations"] != expected_parser_invocations:
        reject(
            "parser_invocations",
            f"expected {expected_parser_invocations} for the declared comparison",
        )
    if result["artifact_snapshot_hits"] != expected_snapshot_hits:
        reject(
            "artifact_snapshot_hits",
            f"expected {expected_snapshot_hits} for the declared comparison",
        )

    histograms = (
        (
            "authoritative_member_change_kind_counts",
            "authoritative_change_fact_count",
        ),
        ("formal_reachability_status_counts", "formal_api_result_count"),
        ("formal_impact_conclusion_counts", "formal_api_result_count"),
    )
    for histogram_field, total_field in histograms:
        if sum(result[histogram_field].values()) != result[total_field]:
            reject(histogram_field, f"does not conserve {total_field}")
    expected_changed_class_count = changed_jar_count * classes_per_jar
    if result["authoritative_change_fact_count"] != expected_changed_class_count:
        reject(
            "authoritative_change_fact_count",
            f"expected {expected_changed_class_count} changed method facts",
        )
    if result["formal_api_result_count"] != expected_changed_class_count:
        reject(
            "formal_api_result_count",
            f"expected {expected_changed_class_count} formal API results",
        )
    expected_histograms = {
        "authoritative_member_change_kind_counts": (
            {"implementation_changed": expected_changed_class_count}
            if expected_changed_class_count else {}
        ),
        "formal_reachability_status_counts": (
            {"not_found_in_static_analysis": expected_changed_class_count}
            if expected_changed_class_count else {}
        ),
        "formal_impact_conclusion_counts": (
            {"inconclusive": expected_changed_class_count}
            if expected_changed_class_count else {}
        ),
    }
    for field, expected in expected_histograms.items():
        if not _type_sensitive_equal(expected, result.get(field)):
            reject(field, f"unexpected fixed-fixture distribution: {result.get(field)!r}")


def _run_isolated_full_pipeline_probe(
    artifacts: list[dict[str, Any]],
    *,
    root: Path,
    asm_jar: Path,
    classes_per_jar: int,
    expected_implementation: Mapping[str, str],
    current_artifacts: list[dict[str, Any]] | None = None,
    provisional_gate_path: Path | None = None,
) -> dict[str, Any]:
    """Run one probe in a fresh interpreter so peak RSS belongs to that probe."""

    _physical_directory_identity(
        root, field="isolated full-pipeline probe", create=True
    )
    input_path = root / "isolated_probe_input.json"
    output_path = root / "isolated_probe_result.json"
    try:
        output_path.unlink()
    except FileNotFoundError:
        pass
    _write_json(input_path, {
        "schema": PROBE_WORKER_SCHEMA,
        "artifacts": artifacts,
        "current_artifacts": current_artifacts,
        "asm_jar": str(asm_jar),
        "classes_per_jar": classes_per_jar,
        "expected_implementation": dict(expected_implementation),
        "provisional_gate_path": (
            str(provisional_gate_path.resolve())
            if provisional_gate_path is not None else ""
        ),
    })
    completed = run_managed_subprocess(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--probe-worker-input", str(input_path),
            "--probe-worker-output", str(output_path),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    try:
        response = _json_object_from_exact_bytes(
            output_path.read_bytes(), field="probe_worker_output"
        )
    except (OSError, PerformanceGateError) as error:
        failure = {
            "reason_code": "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
            "error_type": type(error).__name__,
            "detail": str(error),
            "worker_returncode": completed.returncode,
            "worker_stderr": (completed.stderr or "")[-2000:],
        }
        raise PerformanceGateError(
            json.dumps(failure, ensure_ascii=False, sort_keys=True),
            failure=failure,
        ) from error
    status = response.get("status")
    if status == "failed":
        raw_failure = response.get("failure")
        valid_failure = bool(
            response.get("schema") == PROBE_WORKER_SCHEMA
            and set(response) == _PROBE_WORKER_FAILURE_FIELDS
            and isinstance(raw_failure, Mapping)
            and set(raw_failure) == _PROBE_WORKER_FAILURE_DETAIL_FIELDS
            and all(
                type(raw_failure.get(name)) is str and raw_failure[name]
                for name in _PROBE_WORKER_FAILURE_DETAIL_FIELDS
            )
            and completed.returncode != 0
        )
        if not valid_failure:
            failure = {
                "reason_code": "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
                "detail": "worker failure response violated its exact schema",
            }
        else:
            failure = dict(raw_failure)
        failure["worker_returncode"] = completed.returncode
        failure["worker_stderr"] = (completed.stderr or "")[-2000:]
        raise PerformanceGateError(
            json.dumps(failure, ensure_ascii=False, sort_keys=True),
            failure=failure,
        )
    if (
        status != "passed"
        or response.get("schema") != PROBE_WORKER_SCHEMA
        or set(response) != _PROBE_WORKER_SUCCESS_FIELDS
        or completed.returncode != 0
    ):
        failure = {
            "reason_code": "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
            "detail": "worker success response violated its exact schema",
            "worker_returncode": completed.returncode,
            "worker_stderr": (completed.stderr or "")[-2000:],
        }
        raise PerformanceGateError(failure["detail"], failure=failure)
    expected_mode = (
        _RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE
        if provisional_gate_path is not None
        else _CANDIDATE_PROBE_AUTHORITY_MODE
    )
    try:
        result = _validate_raw_probe(
            response.get("result"),
            field="probe_worker.result",
            expected_mode=expected_mode,
            expected_source_identity=str(
                expected_implementation.get("source_implementation_identity") or ""
            ),
        )
        _validate_probe_worker_result_contract(
            result,
            artifacts=artifacts,
            current_artifacts=current_artifacts,
            classes_per_jar=classes_per_jar,
            expected_mode=expected_mode,
        )
    except PerformanceGateError as error:
        failure = {
            "reason_code": "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
            "detail": str(error),
            "worker_returncode": completed.returncode,
            "worker_stderr": (completed.stderr or "")[-2000:],
        }
        raise PerformanceGateError(failure["detail"], failure=failure) from error
    if result["process_id"] == os.getpid():
        failure = {
            "reason_code": "BINARY_PERFORMANCE_PROBE_NOT_ISOLATED",
            "detail": "full pipeline probe reused the benchmark parent process",
        }
        raise PerformanceGateError(failure["detail"], failure=failure)
    return result


def _full_pipeline_evidence(result: dict[str, Any]) -> dict[str, Any]:
    """Read measured conservation and Oracle values from persisted evidence."""
    generation = Path(result["generation_directory"])
    validation = json.loads(
        Path(result["validation_result_path"]).read_text(encoding="utf-8")
    )
    decisions = json.loads(
        (generation / "binary_decisions.json").read_text(encoding="utf-8")
    )
    formal = json.loads(
        (generation / "binary_formal_results.json").read_text(encoding="utf-8")
    )

    def class_count(side: str) -> int:
        with closing(
            sqlite3.connect(generation / f"{side}_binary_facts.sqlite")
        ) as connection:
            return int(
                connection.execute("SELECT COUNT(*) FROM classes").fetchone()[0]
            )

    base_class_count = class_count("base")
    current_class_count = class_count("current")
    authoritative = list(decisions.get("authoritative_change_facts") or ())
    formal_by_api = list(formal.get("by_api") or ())

    def histogram(values: Iterable[Any]) -> dict[str, int]:
        return dict(sorted(Counter(str(value) for value in values).items()))

    return {
        # Retain the historical aggregate field for gate/result consumers, but
        # also expose both observed sides so conservation cannot be inferred
        # from the configured fixture size.
        "class_count": base_class_count,
        "base_class_count": base_class_count,
        "current_class_count": current_class_count,
        "validation_status": str(validation.get("status") or ""),
        "validation_issue_count": int(validation.get("issue_count") or 0),
        "authoritative_change_fact_count": len(authoritative),
        "authoritative_member_change_kind_counts": histogram(
            (item.get("fact_scope") or {}).get("member_change_kind")
            for item in authoritative
        ),
        "formal_api_result_count": len(formal_by_api),
        "formal_reachability_status_counts": histogram(
            item.get("reachability_status") for item in formal_by_api
        ),
        "formal_impact_conclusion_counts": histogram(
            item.get("impact_conclusion") for item in formal_by_api
        ),
    }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise PerformanceGateError("percentile requires samples")
    if not 0 < percentile <= 1:
        raise PerformanceGateError("percentile must be in (0, 1]")
    ordered = sorted(values)
    return float(ordered[max(0, math.ceil(percentile * len(ordered)) - 1)])


def _p50(values: list[float]) -> float:
    return _percentile(values, 0.50)


def _p95(values: list[float]) -> float:
    return _percentile(values, 0.95)


def _dataset_identity(
    artifacts: Iterable[Mapping[str, Any]], *, classes_per_jar: int,
) -> str:
    return canonical_identity(
        "binary_performance_dataset_identity",
        {
            "schema": DATASET_SCHEMA,
            "base_template_sha256": _FIXED_TEMPLATE_SHA256[1],
            "changed_template_sha256": _FIXED_TEMPLATE_SHA256[2],
            "artifact_sha256": [str(item["sha256"]) for item in artifacts],
            "classes_per_jar": classes_per_jar,
        },
        schema_version="1",
    )


def _changed_artifact_derivation_identity(
    *,
    base_artifact_identity: str,
    current_artifact_identity: str,
    classes_per_jar: int,
) -> str:
    """Bind the changed probe JAR to a portable logical construction.

    We deliberately do not recompress the JAR during recorded replay: DEFLATE
    output is not a promised cross-zlib byte contract.  The measured byte SHA
    remains explicit, while this identity proves which fixed template, base
    slot and archive policy that SHA was recorded to represent.
    """

    if (
        not _is_sha256_identity(base_artifact_identity)
        or not _is_sha256_identity(current_artifact_identity)
        or type(classes_per_jar) is not int
        or classes_per_jar <= 0
    ):
        raise PerformanceGateError(
            "changed artifact derivation inputs are invalid"
        )
    return canonical_identity(
        "binary_performance_changed_artifact_derivation_identity",
        {
            "dataset_schema": DATASET_SCHEMA,
            "base_template_sha256": _FIXED_TEMPLATE_SHA256[1],
            "changed_template_sha256": _FIXED_TEMPLATE_SHA256[2],
            "base_artifact_identity": base_artifact_identity,
            "current_artifact_identity": current_artifact_identity,
            "first_class_index": 0,
            "classes_per_jar": classes_per_jar,
            "zip_policy": _FIXED_ZIP_POLICY,
        },
        schema_version="1",
    )


def _reference_runtime_protocol(
    asm_jar: Path,
    implementation: Mapping[str, str],
) -> dict[str, Any]:
    machine = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
    }
    tool_versions = {
        "python": platform.python_version(),
        "java": _command_version(["java", "-version"]),
        "javap": _command_version(javap_command("javap", "-version")),
        "asm_jar_sha256": _sha256(asm_jar),
    }
    return {
        "schema": (
            "java-upgrade-analyzer.binary-performance-reference-runtime.v1"
        ),
        "machine_identity": canonical_identity(
            "performance_machine_identity", machine, schema_version="1"
        ),
        "machine": machine,
        "python_implementation": platform.python_implementation(),
        "tool_versions": tool_versions,
        "jdk_preflight_identity": implementation[
            "jdk_preflight_identity"
        ],
        "cpu_time_source": (
            "resource.getrusage(self+completed_children)"
            if _resource is not None
            else "win32.GetProcessTimes(self_only)"
            if sys.platform == "win32"
            else "time.process_time(self_only_fallback)"
        ),
        "peak_rss_source": (
            "resource.getrusage(self+completed_children)"
            if _resource is not None
            else "win32.GetProcessMemoryInfo(self_peak_working_set)"
            if sys.platform == "win32"
            else "unavailable"
        ),
    }


def _require_provisional_probe_binding(
    result: Mapping[str, Any],
    *,
    expected_evidence_sha256: str,
    field: str,
) -> None:
    binding = result.get("pipeline_performance_authority_binding")
    observed_evidence_sha256 = (
        binding.get("evidence_sha256")
        if isinstance(binding, Mapping)
        else None
    )
    if observed_evidence_sha256 != expected_evidence_sha256:
        raise PerformanceGateError(
            f"{field} was not bound to the replayed provisional snapshot",
            failure={
                "reason_code": "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
                "field": (
                    f"{field}.pipeline_performance_authority_binding."
                    "evidence_sha256"
                ),
                "expected": expected_evidence_sha256,
                "actual": observed_evidence_sha256,
            },
        )


def run_benchmark(
    root: Path, *, jar_count: int = 400, classes_per_jar: int = 250,
    warm_samples: int = 3, include_legacy: bool = True,
    provisional_gate_path: Path | None = None,
) -> dict[str, Any]:
    _physical_directory_identity(
        root, field="performance work root", create=True
    )
    asm_jar = resolve_asm_jar()
    implementation = _performance_implementation_protocol(asm_jar)
    provisional_snapshot_sha256: str | None = None
    if provisional_gate_path is not None:
        try:
            provisional_content = provisional_gate_path.read_bytes()
            provisional_evidence = _json_object_from_exact_bytes(
                provisional_content, field="provisional_gate"
            )
        except (OSError, PerformanceGateError) as error:
            raise PerformanceGateError(
                f"provisional performance gate is unreadable: {error}",
                failure={
                    "reason_code": (
                        "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID"
                    ),
                    "detail": str(error),
                },
            ) from error
        provisional_verification = evaluate_provisional_gate(
            provisional_evidence,
            _current_source_implementation=implementation,
        )
        if provisional_verification.get("status") != "passed":
            raise PerformanceGateError(
                "provisional performance evidence failed pre-run replay",
                failure={
                    "reason_code": (
                        "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID"
                    ),
                    "issues": list(
                        provisional_verification.get("issues") or ()
                    ),
                },
            )
        try:
            provisional_gate_path, provisional_snapshot_sha256 = (
                _snapshot_provisional_gate(root, provisional_content)
            )
        except PerformanceGateError as error:
            raise PerformanceGateError(
                "provisional performance evidence could not be frozen before "
                f"the benchmark: {error}",
                failure={
                    "reason_code": (
                        "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID"
                    ),
                    "detail": str(error),
                },
            ) from error
        _preflight_performance_authority(
            implementation,
            provisional_gate_path=provisional_gate_path,
        )
    reference_runtime = _reference_runtime_protocol(
        asm_jar, implementation
    )
    release_capture = (
        jar_count == 400
        and classes_per_jar == 250
        and warm_samples == 3
        and include_legacy
    )
    if (
        release_capture
        and reference_runtime != release_policy()["reference_runtime"]
    ):
        raise PerformanceGateError(
            "reference runtime does not match the source-bound release policy",
            failure={
                "reason_code": (
                    "BINARY_PERFORMANCE_REFERENCE_RUNTIME_MISMATCH"
                ),
                "expected": release_policy()["reference_runtime"],
                "actual": reference_runtime,
            },
        )
    if release_capture:
        reference_implementation = release_policy()[
            "reference_implementation"
        ]
        observed_reference_implementation = {
            "pipeline_generation_implementation_identity": implementation[
                "pipeline_generation_implementation_identity"
            ],
            "validator_implementation_identity": implementation[
                "validator_implementation_identity"
            ],
        }
        expected_reference_implementation = {
            field: reference_implementation.get(field)
            for field in observed_reference_implementation
        }
        if not _type_sensitive_equal(
            expected_reference_implementation,
            observed_reference_implementation,
        ):
            raise PerformanceGateError(
                "live runtime implementation does not match release policy pins",
                failure={
                    "reason_code": (
                        "BINARY_PERFORMANCE_REFERENCE_IMPLEMENTATION_MISMATCH"
                    ),
                    "expected": expected_reference_implementation,
                    "actual": observed_reference_implementation,
                },
            )
    artifacts = build_dataset(
        root, jar_count=jar_count, classes_per_jar=classes_per_jar
    )
    changed_artifacts = build_changed_current_artifacts(
        root, artifacts, classes_per_jar=classes_per_jar
    )
    if release_capture:
        required_protocol = release_policy()["measurement_protocol"]
        observed_dataset = {
            "dataset_identity": _dataset_identity(
                artifacts, classes_per_jar=classes_per_jar
            ),
            "first_base_artifact_identity": artifacts[0]["sha256"],
            "current_artifact_identity": changed_artifacts[0]["sha256"],
            "logical_artifact_derivation_identity": (
                _changed_artifact_derivation_identity(
                    base_artifact_identity=artifacts[0]["sha256"],
                    current_artifact_identity=changed_artifacts[0]["sha256"],
                    classes_per_jar=classes_per_jar,
                )
            ),
        }
        expected_dataset = {
            "dataset_identity": required_protocol["dataset_identity"],
            "first_base_artifact_identity": required_protocol[
                "first_base_artifact_identity"
            ],
            "current_artifact_identity": required_protocol[
                "changed_full_pipeline_probe"
            ]["current_artifact_identity"],
            "logical_artifact_derivation_identity": required_protocol[
                "changed_full_pipeline_probe"
            ]["logical_artifact_derivation_identity"],
        }
        if observed_dataset != expected_dataset:
            raise PerformanceGateError(
                "release dataset does not match the source-bound policy",
                failure={
                    "reason_code": (
                        "BINARY_PERFORMANCE_RELEASE_DATASET_MISMATCH"
                    ),
                    "expected": expected_dataset,
                    "actual": observed_dataset,
                },
            )
    cache_root = root / "cache"
    # Execute the declared unmeasured warmup, then deliberately repeat the
    # cold cleanup so neither its cache nor SQLite bytes influence the cold
    # sample or the measured totals.
    warmup = _analyze_once(
        artifacts, root=root, cache_root=cache_root, asm_jar=asm_jar,
        warm=False,
    )
    cold = _analyze_once(
        artifacts, root=root, cache_root=cache_root, asm_jar=asm_jar, warm=False
    )
    warm_runs = [
        _analyze_once(
            artifacts, root=root, cache_root=cache_root, asm_jar=asm_jar, warm=True
        )
        for _ in range(warm_samples)
    ]
    if any(item["parser_invocations"] != 0 for item in warm_runs):
        raise PerformanceGateError("warm cache parser invocation must be zero")
    expected_classes = jar_count * classes_per_jar
    if cold["counts"]["classes"] != expected_classes:
        raise PerformanceGateError(
            f"class conservation failed: {cold['counts']['classes']} != {expected_classes}"
        )
    legacy = _legacy_javap(artifacts, classes_per_jar) if include_legacy else None
    full_pipeline_probe = _run_isolated_full_pipeline_probe(
        artifacts,
        root=root / "identical-full-pipeline",
        asm_jar=asm_jar,
        classes_per_jar=classes_per_jar,
        expected_implementation=implementation,
        provisional_gate_path=provisional_gate_path,
    )
    if provisional_snapshot_sha256 is not None:
        _require_provisional_probe_binding(
            full_pipeline_probe,
            expected_evidence_sha256=provisional_snapshot_sha256,
            field="full_pipeline_probe",
        )
    changed_full_pipeline_probe = _run_isolated_full_pipeline_probe(
        artifacts,
        current_artifacts=changed_artifacts,
        root=root / "changed-full-pipeline",
        asm_jar=asm_jar,
        classes_per_jar=classes_per_jar,
        expected_implementation=implementation,
        provisional_gate_path=provisional_gate_path,
    )
    if provisional_snapshot_sha256 is not None:
        _require_provisional_probe_binding(
            changed_full_pipeline_probe,
            expected_evidence_sha256=provisional_snapshot_sha256,
            field="changed_full_pipeline_probe",
        )
    if _performance_implementation_protocol(asm_jar) != implementation:
        raise PerformanceGateError(
            "performance implementation changed during benchmark"
        )
    dataset_identity = _dataset_identity(
        artifacts, classes_per_jar=classes_per_jar
    )
    warm_seconds = [item["end_to_end_seconds"] for item in warm_runs]
    warm_p50 = _p50(warm_seconds)
    warm_p95 = _p95(warm_seconds)
    measured_runs = [
        cold,
        *warm_runs,
        *([legacy] if legacy else []),
        full_pipeline_probe,
        changed_full_pipeline_probe,
    ]
    total_measured_wall = sum(
        float(item["end_to_end_seconds"]) for item in measured_runs
    )
    total_measured_cpu = sum(float(item["cpu_seconds"]) for item in measured_runs)
    relative = (
        cold["end_to_end_seconds"] / legacy["end_to_end_seconds"]
        if legacy and legacy["end_to_end_seconds"] else None
    )
    machine = reference_runtime["machine"]
    machine_identity = reference_runtime["machine_identity"]
    tool_versions = reference_runtime["tool_versions"]
    cpu_time_source = reference_runtime["cpu_time_source"]
    peak_rss_source = reference_runtime["peak_rss_source"]
    return {
        "schema": SCHEMA,
        "status": "measured",
        "measurement_protocol": {
            "release_policy_identity": release_policy_identity(),
            "reference_runtime": reference_runtime,
            "machine_identity": machine_identity,
            "machine": machine,
            "dataset_schema": DATASET_SCHEMA,
            "dataset_identity": dataset_identity,
            "base_template_sha256": _FIXED_TEMPLATE_SHA256[1],
            "changed_template_sha256": _FIXED_TEMPLATE_SHA256[2],
            "dataset_artifact_identities": [item["sha256"] for item in artifacts],
            "first_base_artifact_identity": artifacts[0]["sha256"],
            "implementation": implementation,
            "source_implementation_identity": implementation[
                "source_implementation_identity"
            ],
            "runtime_implementation_identity": implementation[
                "runtime_implementation_identity"
            ],
            "jar_count": jar_count,
            "class_count": expected_classes,
            "classes_per_jar": classes_per_jar,
            "full_pipeline_probe": {
                "jar_count": full_pipeline_probe["jar_count"],
                "class_count": full_pipeline_probe["class_count"],
                "comparison": full_pipeline_probe["comparison"],
                "process_isolation": "dedicated_python_process",
                "includes": list(FULL_PIPELINE_PHASES),
                "validated_generation_activation_scope": (
                    VALIDATED_GENERATION_ACTIVATION_SCOPE
                ),
            },
            "changed_full_pipeline_probe": {
                "jar_count": changed_full_pipeline_probe["jar_count"],
                "class_count": changed_full_pipeline_probe["class_count"],
                "comparison": changed_full_pipeline_probe["comparison"],
                "process_isolation": "dedicated_python_process",
                "changed_jar_count": 1,
                "changed_class_count": classes_per_jar,
                "current_artifact_identity": changed_artifacts[0]["sha256"],
                "logical_artifact_derivation_identity": (
                    _changed_artifact_derivation_identity(
                        base_artifact_identity=artifacts[0]["sha256"],
                        current_artifact_identity=changed_artifacts[0]["sha256"],
                        classes_per_jar=classes_per_jar,
                    )
                ),
                "includes": list(FULL_PIPELINE_PHASES),
                "validated_generation_activation_scope": (
                    VALIDATED_GENERATION_ACTIVATION_SCOPE
                ),
            },
            "large_api_query_count": 10_000,
            "tool_versions": tool_versions,
            "warmup_runs": 1,
            "sample_runs": {
                "cold": 1,
                "warm": warm_samples,
                "legacy": int(include_legacy),
                "full_pipeline": 1,
                "changed_full_pipeline": 1,
            },
            "cpu_time_source": cpu_time_source,
            "peak_rss_source": peak_rss_source,
            "p50_method": "nearest-rank",
            "p95_method": "nearest-rank",
            "cold_cleanup_rule": "delete binary snapshot cache and SQLite before run",
            "warm_cache_rule": "all content+parser cache entries must pass digest validation; parser_invocations=0",
            "rss_sample_semantics": release_policy()[
                "measurement_protocol"
            ]["rss_sample_semantics"],
            "legacy_baseline": (
                "javap -c -s -p, all 100000 classes, "
                "batched once per artifact"
            ),
        },
        "measurements": {
            "warmup": warmup,
            "cold": cold,
            "warm_runs": warm_runs,
            "warm_end_to_end_p50_seconds": warm_p50,
            "warm_end_to_end_p95_seconds": warm_p95,
            "legacy": legacy,
            "full_pipeline_probe": full_pipeline_probe,
            "changed_full_pipeline_probe": changed_full_pipeline_probe,
            "cold_relative_legacy_ratio": relative,
            "peak_rss_bytes": max(
                [
                    warmup["peak_rss_bytes"],
                    cold["peak_rss_bytes"],
                    *[item["peak_rss_bytes"] for item in warm_runs],
                    legacy["peak_rss_bytes"] if legacy else 0,
                    full_pipeline_probe["peak_rss_bytes"],
                    changed_full_pipeline_probe["peak_rss_bytes"],
                ]
            ),
            "disk_bytes": cold["db_bytes"] + cold["cache_bytes"],
            "total_measured_wall_seconds": total_measured_wall,
            "total_measured_cpu_seconds": total_measured_cpu,
            "average_cpu_cores": (
                total_measured_cpu / total_measured_wall
                if total_measured_wall else 0.0
            ),
        },
    }


def _raw_result_contract_error(field: str, detail: str) -> None:
    raise PerformanceGateError(
        f"raw performance result is invalid at {field}: {detail}",
        failure={
            "reason_code": "BINARY_PERFORMANCE_RAW_RESULT_INVALID",
            "field": field,
            "detail": detail,
        },
    )


def _raw_exact_mapping(
    value: Any, expected_fields: Iterable[str], *, field: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raw_result_contract_error(
            field, f"expected object; actual={type(value).__name__}"
        )
    result = dict(value)
    expected = set(expected_fields)
    if set(result) != expected:
        _raw_result_contract_error(
            field,
            f"expected keys={sorted(expected)!r}; actual={sorted(result)!r}",
        )
    return result


def _raw_nonnegative_number(value: Any) -> bool:
    return bool(
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0.0
    )


def _raw_positive_number(value: Any) -> bool:
    return _raw_nonnegative_number(value) and float(value) > 0.0


def _raw_nonnegative_integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _raw_number_matches(actual: Any, expected: Any) -> bool:
    return bool(
        _raw_nonnegative_number(actual)
        and _raw_nonnegative_number(expected)
        and math.isclose(
            float(actual), float(expected), rel_tol=1e-12, abs_tol=1e-9
        )
    )


def _validate_raw_analysis_run(value: Any, *, field: str) -> dict[str, Any]:
    run = _raw_exact_mapping(value, _RAW_ANALYSIS_RUN_FIELDS, field=field)
    for name in (
        "end_to_end_seconds",
        "cpu_seconds",
        "average_cpu_cores",
        "bytes_per_class",
        "bytes_per_edge",
    ):
        predicate = (
            _raw_positive_number
            if name in {"end_to_end_seconds", "bytes_per_class", "bytes_per_edge"}
            else _raw_nonnegative_number
        )
        if not predicate(run.get(name)):
            _raw_result_contract_error(
                f"{field}.{name}", "expected a finite numeric value"
            )
    for name in (
        "parser_invocations",
        "cache_hits",
        "report_bytes",
        "db_bytes",
        "cache_bytes",
        "peak_rss_bytes",
    ):
        if not _raw_nonnegative_integer(run.get(name)):
            _raw_result_contract_error(
                f"{field}.{name}", "expected a non-negative integer"
            )
    counts = _raw_exact_mapping(
        run.get("counts"), _RAW_COUNT_FIELDS, field=f"{field}.counts"
    )
    for name, count in counts.items():
        if not _raw_nonnegative_integer(count):
            _raw_result_contract_error(
                f"{field}.counts.{name}", "expected a non-negative integer"
            )
    inventory = _raw_exact_mapping(
        run.get("inventory"),
        _RAW_INVENTORY_FIELDS,
        field=f"{field}.inventory",
    )
    for name, count in inventory.items():
        if not _raw_nonnegative_integer(count):
            _raw_result_contract_error(
                f"{field}.inventory.{name}",
                "expected a non-negative integer",
            )
    stages = _raw_exact_mapping(
        run.get("stage_seconds"), _RAW_STAGE_FIELDS,
        field=f"{field}.stage_seconds",
    )
    if not all(_raw_nonnegative_number(item) for item in stages.values()):
        _raw_result_contract_error(
            f"{field}.stage_seconds", "all stage values must be finite numbers"
        )
    if sum(float(item) for item in stages.values()) > (
        float(run["end_to_end_seconds"]) + 0.01
    ):
        _raw_result_contract_error(
            f"{field}.stage_seconds", "stage total exceeds the enclosing wall time"
        )
    if run.get("overlay_status") != "not_provided":
        _raw_result_contract_error(
            f"{field}.overlay_status", "expected not_provided"
        )
    expected_cores = float(run["cpu_seconds"]) / float(
        run["end_to_end_seconds"]
    )
    if not _raw_number_matches(run.get("average_cpu_cores"), expected_cores):
        _raw_result_contract_error(
            f"{field}.average_cpu_cores", "does not equal cpu_seconds / wall"
        )
    class_count = counts["classes"]
    edge_count = counts["edges"]
    if class_count <= 0 or edge_count <= 0:
        _raw_result_contract_error(
            f"{field}.counts", "classes and edges must both be positive"
        )
    disk_bytes = run["db_bytes"] + run["cache_bytes"]
    if not _raw_number_matches(
        run.get("bytes_per_class"), disk_bytes / class_count
    ):
        _raw_result_contract_error(
            f"{field}.bytes_per_class", "does not match raw byte counts"
        )
    if not _raw_number_matches(
        run.get("bytes_per_edge"), run["db_bytes"] / edge_count
    ):
        _raw_result_contract_error(
            f"{field}.bytes_per_edge", "does not match raw byte counts"
        )
    return run


def _validate_raw_probe(
    value: Any,
    *,
    field: str,
    expected_mode: str,
    expected_source_identity: str,
) -> dict[str, Any]:
    probe = _raw_exact_mapping(
        value,
        _RECORDED_PROBE_FIELDS - {"captured_at"},
        field=field,
    )
    for name in (
        "status",
        "performance_authority_mode",
        "comparison",
        "rss_measurement_scope",
        "pipeline_total_elapsed_scope",
        "pipeline_phase_timings_scope",
        "activation_authority_mode",
        "validation_status",
    ):
        if not isinstance(probe.get(name), str) or not probe[name]:
            _raw_result_contract_error(
                f"{field}.{name}", "expected a non-empty string"
            )
    if (
        probe["performance_authority_mode"] != expected_mode
        or probe["activation_authority_mode"] != expected_mode
    ):
        _raw_result_contract_error(
            f"{field}.performance_authority_mode",
            f"expected exact mode {expected_mode}",
        )
    for name in (
        "process_id",
        "jar_count",
        "current_jar_count",
        "expected_class_count",
        "pipeline_reported_peak_rss_bytes",
        "post_pipeline_peak_rss_bytes",
        "peak_rss_bytes",
        "parser_invocations",
        "artifact_snapshot_hits",
        "artifact_snapshot_disk_hits",
        "artifact_snapshot_memory_hits",
        "class_count",
        "base_class_count",
        "current_class_count",
        "validation_issue_count",
        "authoritative_change_fact_count",
        "formal_api_result_count",
    ):
        if not _raw_nonnegative_integer(probe.get(name)) or (
            name == "process_id" and probe[name] <= 0
        ):
            _raw_result_contract_error(
                f"{field}.{name}", "expected a non-negative integer"
            )
    for name in (
        "end_to_end_seconds",
        "pipeline_reported_seconds",
        "cpu_seconds",
        "average_cpu_cores",
    ):
        predicate = (
            _raw_positive_number
            if name in {"end_to_end_seconds", "pipeline_reported_seconds"}
            else _raw_nonnegative_number
        )
        if not predicate(probe.get(name)):
            _raw_result_contract_error(
                f"{field}.{name}", "expected a finite numeric value"
            )
    expected_cores = float(probe["cpu_seconds"]) / float(
        probe["end_to_end_seconds"]
    )
    if not _raw_number_matches(probe["average_cpu_cores"], expected_cores):
        _raw_result_contract_error(
            f"{field}.average_cpu_cores", "does not equal cpu_seconds / wall"
        )
    for name in (
        "publication_deferred",
        "checkpoint_retained",
        "activation_candidate_discarded",
        "activation_recapture_discarded",
        "active_generation_absent",
        "pending_generation_absent",
        "validation_checkpoint_absent",
    ):
        if type(probe.get(name)) is not bool:
            _raw_result_contract_error(
                f"{field}.{name}", "expected a JSON boolean"
            )
    phase_seconds = _raw_exact_mapping(
        probe.get("phase_seconds"), FULL_PIPELINE_PHASES,
        field=f"{field}.phase_seconds",
    )
    phase_peaks = _raw_exact_mapping(
        probe.get("phase_peak_rss_bytes"), FULL_PIPELINE_PHASES,
        field=f"{field}.phase_peak_rss_bytes",
    )
    if not all(_raw_nonnegative_number(item) for item in phase_seconds.values()):
        _raw_result_contract_error(
            f"{field}.phase_seconds", "all phase values must be finite numbers"
        )
    if not all(_raw_nonnegative_integer(item) for item in phase_peaks.values()):
        _raw_result_contract_error(
            f"{field}.phase_peak_rss_bytes",
            "all phase RSS values must be non-negative integers",
        )
    for name in (
        "authoritative_member_change_kind_counts",
        "formal_reachability_status_counts",
        "formal_impact_conclusion_counts",
    ):
        histogram = probe.get(name)
        if not isinstance(histogram, Mapping) or any(
            not isinstance(key, str)
            or not key
            or not _raw_nonnegative_integer(count)
            for key, count in histogram.items()
        ):
            _raw_result_contract_error(
                f"{field}.{name}", "expected string-to-integer counts"
            )
    if not _performance_authority_binding_is_valid(
        probe.get("pipeline_performance_authority_binding"),
        expected_mode=expected_mode,
        expected_source_identity=expected_source_identity,
    ):
        _raw_result_contract_error(
            f"{field}.pipeline_performance_authority_binding",
            "binding is not exact or canonically derived",
        )
    return probe


def _validate_raw_release_result(
    result: Any, *, expected_probe_mode: str,
) -> dict[str, Any]:
    raw = _raw_exact_mapping(result, _RAW_RESULT_FIELDS, field="root")
    if raw.get("schema") != SCHEMA or raw.get("status") != "measured":
        _raw_result_contract_error(
            "root", "schema/status is not a measured benchmark result"
        )
    protocol = _raw_exact_mapping(
        raw.get("measurement_protocol"),
        _MEASUREMENT_PROTOCOL_FIELDS,
        field="measurement_protocol",
    )
    implementation = _raw_exact_mapping(
        protocol.get("implementation"),
        _PERFORMANCE_IMPLEMENTATION_FIELDS,
        field="measurement_protocol.implementation",
    )
    if any(
        not _is_sha256_identity(implementation.get(name))
        for name in _PERFORMANCE_IMPLEMENTATION_FIELDS
    ):
        _raw_result_contract_error(
            "measurement_protocol.implementation",
            "every implementation component must be a SHA-256 identity",
        )
    if (
        _source_implementation_identity(implementation)
        != implementation["source_implementation_identity"]
        or _runtime_implementation_identity(implementation)
        != implementation["runtime_implementation_identity"]
        or protocol.get("source_implementation_identity")
        != implementation["source_implementation_identity"]
        or protocol.get("runtime_implementation_identity")
        != implementation["runtime_implementation_identity"]
    ):
        _raw_result_contract_error(
            "measurement_protocol.implementation",
            "aggregate implementation identities are inconsistent",
        )
    measured = _raw_exact_mapping(
        raw.get("measurements"),
        _RAW_MEASUREMENT_FIELDS,
        field="measurements",
    )
    warmup = _validate_raw_analysis_run(
        measured.get("warmup"), field="measurements.warmup"
    )
    cold = _validate_raw_analysis_run(
        measured.get("cold"), field="measurements.cold"
    )
    raw_warm = measured.get("warm_runs")
    if not isinstance(raw_warm, list):
        _raw_result_contract_error("measurements.warm_runs", "expected an array")
    warm = [
        _validate_raw_analysis_run(
            item, field=f"measurements.warm_runs[{index}]"
        )
        for index, item in enumerate(raw_warm)
    ]
    expected_warm_count = (
        (protocol.get("sample_runs") or {}).get("warm")
        if isinstance(protocol.get("sample_runs"), Mapping) else None
    )
    if type(expected_warm_count) is not int or len(warm) != expected_warm_count:
        _raw_result_contract_error(
            "measurements.warm_runs", "sample count does not match the protocol"
        )
    legacy = _raw_exact_mapping(
        measured.get("legacy"), _RAW_LEGACY_FIELDS,
        field="measurements.legacy",
    )
    for name in ("class_count", "peak_rss_bytes"):
        if not _raw_nonnegative_integer(legacy.get(name)):
            _raw_result_contract_error(
                f"measurements.legacy.{name}",
                "expected a non-negative integer",
            )
    for name in (
        "end_to_end_seconds", "cpu_seconds", "average_cpu_cores",
    ):
        predicate = (
            _raw_positive_number
            if name == "end_to_end_seconds" else _raw_nonnegative_number
        )
        if not predicate(legacy.get(name)):
            _raw_result_contract_error(
                f"measurements.legacy.{name}",
                "expected a finite numeric value",
            )
    if legacy.get("implementation") != (
        "legacy-javap-c-s-p-batched-per-artifact"
    ):
        _raw_result_contract_error(
            "measurements.legacy.implementation", "unexpected legacy baseline"
        )
    if not _raw_number_matches(
        legacy["average_cpu_cores"],
        float(legacy["cpu_seconds"]) / float(legacy["end_to_end_seconds"]),
    ):
        _raw_result_contract_error(
            "measurements.legacy.average_cpu_cores",
            "does not equal cpu_seconds / wall",
        )
    full = _validate_raw_probe(
        measured.get("full_pipeline_probe"),
        field="measurements.full_pipeline_probe",
        expected_mode=expected_probe_mode,
        expected_source_identity=implementation["source_implementation_identity"],
    )
    changed = _validate_raw_probe(
        measured.get("changed_full_pipeline_probe"),
        field="measurements.changed_full_pipeline_probe",
        expected_mode=expected_probe_mode,
        expected_source_identity=implementation["source_implementation_identity"],
    )
    if not _type_sensitive_equal(
        full["pipeline_performance_authority_binding"],
        changed["pipeline_performance_authority_binding"],
    ):
        _raw_result_contract_error(
            "measurements.changed_full_pipeline_probe."
            "pipeline_performance_authority_binding",
            "the two release probes must share one exact authority binding",
        )
    warm_seconds = [item["end_to_end_seconds"] for item in warm]
    for name, expected in (
        ("warm_end_to_end_p50_seconds", _p50(warm_seconds)),
        ("warm_end_to_end_p95_seconds", _p95(warm_seconds)),
        (
            "cold_relative_legacy_ratio",
            cold["end_to_end_seconds"] / legacy["end_to_end_seconds"],
        ),
    ):
        if not _raw_number_matches(measured.get(name), expected):
            _raw_result_contract_error(
                f"measurements.{name}", "raw aggregate does not match samples"
            )
    measured_runs = [cold, *warm, legacy, full, changed]
    expected_wall = sum(item["end_to_end_seconds"] for item in measured_runs)
    expected_cpu = sum(item["cpu_seconds"] for item in measured_runs)
    for name, expected in (
        ("total_measured_wall_seconds", expected_wall),
        ("total_measured_cpu_seconds", expected_cpu),
        ("average_cpu_cores", expected_cpu / expected_wall),
    ):
        if not _raw_number_matches(measured.get(name), expected):
            _raw_result_contract_error(
                f"measurements.{name}", "raw aggregate does not match samples"
            )
    expected_peak = max([
        warmup["peak_rss_bytes"],
        cold["peak_rss_bytes"],
        *[item["peak_rss_bytes"] for item in warm],
        legacy["peak_rss_bytes"],
        full["peak_rss_bytes"],
        changed["peak_rss_bytes"],
    ])
    if type(measured.get("peak_rss_bytes")) is not int or (
        measured["peak_rss_bytes"] != expected_peak
    ):
        _raw_result_contract_error(
            "measurements.peak_rss_bytes",
            "raw peak does not include the full declared sample lifecycle",
        )
    expected_disk = cold["db_bytes"] + cold["cache_bytes"]
    if type(measured.get("disk_bytes")) is not int or (
        measured["disk_bytes"] != expected_disk
    ):
        _raw_result_contract_error(
            "measurements.disk_bytes", "does not match cold DB + cache bytes"
        )
    return raw


def _recorded_measurements_from_result(
    result: Mapping[str, Any], *, captured_at: str,
) -> dict[str, Any]:
    """Deterministically reduce raw benchmark output to replayable evidence."""

    measured = result.get("measurements")
    if not isinstance(measured, Mapping):
        raise PerformanceGateError("benchmark measurements are missing")
    warmup = dict(measured.get("warmup") or {})
    cold = dict(measured.get("cold") or {})
    warm = [dict(item) for item in measured.get("warm_runs") or ()]
    legacy = dict(measured.get("legacy") or {})
    full = deepcopy(dict(measured.get("full_pipeline_probe") or {}))
    changed = deepcopy(dict(
        measured.get("changed_full_pipeline_probe") or {}
    ))
    if not warm or not legacy or not full or not changed:
        raise PerformanceGateError(
            "release evidence requires warm, legacy and both pipeline probes"
        )
    for probe in (full, changed):
        probe["captured_at"] = captured_at

    warm_seconds = [item["end_to_end_seconds"] for item in warm]
    measured_runs = [cold, *warm, legacy, full, changed]
    total_wall = sum(
        item["end_to_end_seconds"] for item in measured_runs
    )
    total_cpu = sum(item["cpu_seconds"] for item in measured_runs)
    class_count = cold["counts"]["classes"]
    edge_count = cold["counts"]["edges"]
    sqlite_bytes = cold["db_bytes"]
    cache_bytes = cold["cache_bytes"]
    stage_samples = [deepcopy(dict(item["stage_seconds"])) for item in warm]
    return {
        "captured_at": captured_at,
        "warmup_end_to_end_seconds": warmup.get("end_to_end_seconds"),
        "warmup_cpu_seconds": warmup.get("cpu_seconds"),
        "warmup_average_cpu_cores": warmup.get("average_cpu_cores"),
        "warmup_parser_invocations": warmup.get("parser_invocations"),
        "warmup_cache_hits": warmup.get("cache_hits"),
        "warmup_peak_rss_bytes": warmup.get("peak_rss_bytes"),
        "warmup_class_count": (warmup.get("counts") or {}).get("classes"),
        "cold_end_to_end_seconds": cold.get("end_to_end_seconds"),
        "cold_cpu_seconds": cold.get("cpu_seconds"),
        "cold_average_cpu_cores": cold.get("average_cpu_cores"),
        "warm_end_to_end_samples_seconds": warm_seconds,
        "warm_cpu_seconds_samples": [item.get("cpu_seconds") for item in warm],
        "warm_average_cpu_cores_samples": [
            item.get("average_cpu_cores") for item in warm
        ],
        "warm_end_to_end_p50_seconds": _p50(warm_seconds),
        "warm_end_to_end_p95_seconds": _p95(warm_seconds),
        "cpu_measurement_status": "recorded",
        "legacy_end_to_end_seconds": legacy.get("end_to_end_seconds"),
        "legacy_cpu_seconds": legacy.get("cpu_seconds"),
        "legacy_average_cpu_cores": legacy.get("average_cpu_cores"),
        "cold_relative_legacy_ratio": (
            cold["end_to_end_seconds"] / legacy["end_to_end_seconds"]
        ),
        "warm_relative_legacy_ratio": (
            _p95(warm_seconds) / legacy["end_to_end_seconds"]
        ),
        "total_measured_wall_seconds": total_wall,
        "total_measured_cpu_seconds": total_cpu,
        "average_cpu_cores": total_cpu / total_wall,
        "cold_stage_seconds": deepcopy(dict(cold["stage_seconds"])),
        "warm_stage_seconds_samples": stage_samples,
        "stage_seconds": {
            "cold_inventory": cold["stage_seconds"]["inventory"],
            "cold_parse_and_cache": cold["stage_seconds"]["parse_and_cache"],
            "cold_db_write_and_index": cold["stage_seconds"][
                "db_write_and_index"
            ],
            "warm_parse_and_cache_p95": _p95([
                item["parse_and_cache"] for item in stage_samples
            ]),
            "warm_db_write_and_index_p95": _p95([
                item["db_write_and_index"] for item in stage_samples
            ]),
            "batch_query_10000_p95": _p95([
                item["batch_query_10000"] for item in stage_samples
            ]),
            "report_10000_p95": _p95([
                item["report_10000"] for item in stage_samples
            ]),
            "cold_batch_query_10000": cold["stage_seconds"][
                "batch_query_10000"
            ],
            "cold_report_10000": cold["stage_seconds"]["report_10000"],
        },
        "peak_rss_bytes": max([
            warmup["peak_rss_bytes"],
            cold["peak_rss_bytes"],
            *[item["peak_rss_bytes"] for item in warm],
            legacy["peak_rss_bytes"],
            full["peak_rss_bytes"],
            changed["peak_rss_bytes"],
        ]),
        "cold_peak_rss_bytes": cold.get("peak_rss_bytes"),
        "warm_peak_rss_bytes_samples": [
            item.get("peak_rss_bytes") for item in warm
        ],
        "legacy_peak_rss_bytes": legacy.get("peak_rss_bytes"),
        "sqlite_bytes": sqlite_bytes,
        "cache_bytes": cache_bytes,
        "disk_bytes": sqlite_bytes + cache_bytes,
        "bytes_per_class": (sqlite_bytes + cache_bytes) / class_count,
        "bytes_per_edge": sqlite_bytes / edge_count,
        "class_count": class_count,
        "member_count": cold["counts"]["members"],
        "edge_count": edge_count,
        "cold_parser_invocations": cold.get("parser_invocations"),
        "warm_parser_invocations": max(
            item["parser_invocations"] for item in warm
        ),
        "warm_parser_invocations_samples": [
            item.get("parser_invocations") for item in warm
        ],
        "warm_cache_hits": min(
            item["cache_hits"] for item in warm
        ),
        "warm_cache_hits_samples": [item.get("cache_hits") for item in warm],
        "full_pipeline_probe": full,
        "changed_full_pipeline_probe": changed,
    }


def _strict_json_object_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _json_object_from_exact_bytes(content: Any, *, field: str) -> dict[str, Any]:
    if type(content) is not bytes:
        raise PerformanceGateError(f"{field} must be supplied as exact bytes")
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_strict_json_object_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise PerformanceGateError(
            f"{field} is not strict UTF-8 JSON: {error}"
        ) from error
    if not isinstance(value, Mapping):
        raise PerformanceGateError(f"{field} JSON root must be an object")
    return dict(value)


def _is_canonical_utc_captured_at(value: Any) -> bool:
    """Accept one unambiguous, second-precision UTC evidence timestamp."""

    if type(value) is not str or len(value) != 20:
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value


def _paths_alias(left: Path, right: Path) -> bool:
    if left == right:
        return True
    try:
        return os.path.samefile(left, right)
    except (FileNotFoundError, OSError):
        return False


def _distinct_cli_output_path(
    parser: argparse.ArgumentParser,
    output_value: str,
    *,
    protected_values: Iterable[str],
) -> Path:
    lexical_output = Path(output_value).expanduser()
    if lexical_output.name in {"", ".", ".."}:
        parser.error("--output must name a dedicated file leaf")
    output = lexical_output.parent.resolve() / lexical_output.name
    try:
        output_entry = os.lstat(output)
    except FileNotFoundError:
        output_entry = None
    except OSError as error:
        parser.error(f"--output cannot be inspected safely: {error}")
    if output_entry is not None and (
        stat.S_ISLNK(output_entry.st_mode)
        or not stat.S_ISREG(output_entry.st_mode)
    ):
        parser.error("--output must be absent or an existing regular file")
    protected = [
        Path(value).expanduser().resolve()
        for value in protected_values
        if value
    ]
    if any(_paths_alias(output, path) for path in protected):
        parser.error("--output must differ from every protected input path")
    return output


def build_recorded_gate_from_result(
    raw_result_content: bytes,
    *,
    captured_at: str,
    provisional: bool,
    provisional_gate_content: bytes | None = None,
) -> dict[str, Any]:
    """Build and immediately replay provisional or final evidence bytes.

    File identities are derived inside this source-owned builder from the exact
    input bytes.  Callers cannot provide a claimed digest separately from the
    bytes that were parsed and reduced.
    """

    if type(provisional) is not bool:
        raise PerformanceGateError("provisional must be an exact JSON boolean")
    if not _is_canonical_utc_captured_at(captured_at):
        raise PerformanceGateError(
            "captured_at must be canonical UTC RFC3339 (YYYY-MM-DDTHH:MM:SSZ)"
        )
    if provisional and provisional_gate_content is not None:
        raise PerformanceGateError(
            "a provisional build cannot consume another provisional gate"
        )
    if not provisional and type(provisional_gate_content) is not bytes:
        raise PerformanceGateError(
            "a final build requires the exact provisional gate bytes"
        )
    result = _json_object_from_exact_bytes(
        raw_result_content, field="raw_result"
    )
    raw_result_sha256 = hashlib.sha256(raw_result_content).hexdigest()
    expected_mode = (
        _CANDIDATE_PROBE_AUTHORITY_MODE
        if provisional else _RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE
    )
    result = _validate_raw_release_result(
        result, expected_probe_mode=expected_mode
    )
    protocol = deepcopy(dict(result["measurement_protocol"]))
    policy = release_policy()
    for field in (
        "dataset_schema", "dataset_identity", "base_template_sha256",
        "changed_template_sha256", "first_base_artifact_identity",
        "jar_count", "class_count", "classes_per_jar",
        "large_api_query_count", "warmup_runs", "sample_runs",
        "p50_method", "p95_method", "cold_cleanup_rule",
        "warm_cache_rule", "rss_sample_semantics", "legacy_baseline",
        "full_pipeline_probe", "changed_full_pipeline_probe",
    ):
        if not _type_sensitive_equal(
            policy["measurement_protocol"][field], protocol.get(field)
        ):
            raise PerformanceGateError(
                f"raw performance protocol is not release-scale: {field}"
            )
    live_implementation = _performance_implementation_protocol(
        resolve_asm_jar()
    )
    if not _type_sensitive_equal(
        live_implementation, protocol.get("implementation")
    ):
        raise PerformanceGateError(
            "raw result implementation is not the live builder implementation"
        )
    verified_provisional_sha256 = ""
    if not provisional:
        provisional_evidence = _json_object_from_exact_bytes(
            provisional_gate_content, field="provisional_gate"
        )
        provisional_verification = evaluate_provisional_gate(
            provisional_evidence,
            _current_source_implementation=live_implementation,
        )
        if provisional_verification.get("status") != "passed":
            raise PerformanceGateError(
                "provisional evidence failed replay before final reduction",
                failure={
                    "reason_code": (
                        "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID"
                    ),
                    "issues": list(
                        provisional_verification.get("issues") or ()
                    ),
                },
            )
        provisional_captured_at = (
            (provisional_evidence.get("recorded_measurements") or {}).get(
                "captured_at"
            )
            if isinstance(
                provisional_evidence.get("recorded_measurements"), Mapping
            )
            else None
        )
        if (
            not _is_canonical_utc_captured_at(provisional_captured_at)
            or datetime.strptime(captured_at, "%Y-%m-%dT%H:%M:%SZ")
            <= datetime.strptime(
                provisional_captured_at, "%Y-%m-%dT%H:%M:%SZ"
            )
        ):
            raise PerformanceGateError(
                "final captured_at must be later than provisional captured_at"
            )
        provisional_protocol = provisional_evidence.get(
            "measurement_protocol"
        ) or {}
        if not _type_sensitive_equal(
            provisional_protocol.get("implementation"),
            protocol.get("implementation"),
        ):
            raise PerformanceGateError(
                "recapture raw result does not use the provisional implementation"
            )
        verified_provisional_sha256 = hashlib.sha256(
            provisional_gate_content
        ).hexdigest()
        for name in ("full_pipeline_probe", "changed_full_pipeline_probe"):
            binding = result["measurements"][name][
                "pipeline_performance_authority_binding"
            ]
            if binding.get("evidence_sha256") != verified_provisional_sha256:
                raise PerformanceGateError(
                    f"raw {name} is not bound to the supplied provisional bytes"
                )
    recorded = _recorded_measurements_from_result(
        result, captured_at=captured_at
    )
    gate = {
        "schema": "java-upgrade-analyzer.binary-first-performance-gate.v1",
        "status": "passed",
        "blocks_binary_authority_switch": False,
        "reason_code": "BINARY_PERFORMANCE_GATE_PASSED",
        "measurement_protocol": protocol,
        "recorded_measurements": recorded,
        "thresholds": deepcopy(policy["thresholds"]),
        "accuracy_invariants": deepcopy(policy["accuracy_invariants"]),
        "rerun_command": (
            "python3 scripts/binary_performance_gate.py --work-root "
            "/tmp/jua-binary-performance-400x250 --output "
            "/tmp/jua-binary-performance-result.json"
        ),
        "scope_note": (
            f"Source-owned deterministic {'provisional' if provisional else 'final'} "
            f"release evidence captured at {captured_at}; raw result sha256="
            f"{raw_result_sha256}"
            + (
                f"; provisional gate sha256={verified_provisional_sha256}."
                if verified_provisional_sha256 else "."
            )
        ),
    }
    if provisional:
        gate["measurement_provisional"] = {
            "schema": (
                "java-upgrade-analyzer.binary-performance-provisional.v1"
            ),
            "purpose": "isolated_release_path_recapture_only",
            "source_implementation_identity": protocol.get(
                "source_implementation_identity"
            ),
            "runtime_implementation_identity": protocol.get(
                "runtime_implementation_identity"
            ),
            "dataset_identity": protocol.get("dataset_identity"),
            "candidate_probe_authority_mode": (
                _CANDIDATE_PROBE_AUTHORITY_MODE
            ),
            "candidate_result_sha256": raw_result_sha256,
            "public_activation_allowed": False,
        }
        verification = evaluate_provisional_gate(
            gate,
            _current_source_implementation=live_implementation,
        )
    else:
        verification = evaluate_recorded_gate(gate)
    if verification.get("status") != "passed":
        raise PerformanceGateError(
            "built performance evidence failed its own formal replay",
            failure={
                "reason_code": "BINARY_PERFORMANCE_BUILT_EVIDENCE_INVALID",
                "issues": list(verification.get("issues") or ()),
            },
        )
    return gate


def evaluate_gate(result: dict[str, Any], gate: dict[str, Any]) -> dict[str, Any]:
    issues = []
    protocol = result.get("measurement_protocol") or {}
    required_protocol = gate.get("measurement_protocol") or {}
    for field in (
        "machine_identity", "dataset_identity", "jar_count", "class_count",
        "source_implementation_identity", "runtime_implementation_identity",
    ):
        if not _type_sensitive_equal(
            required_protocol.get(field), protocol.get(field)
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_PROTOCOL_MISMATCH",
                "field": field,
                "expected": required_protocol.get(field),
                "actual": protocol.get(field),
            })
    required_probe = required_protocol.get("full_pipeline_probe") or {}
    actual_probe_protocol = protocol.get("full_pipeline_probe") or {}
    for field in (
        "jar_count", "class_count", "comparison", "process_isolation",
        "includes",
    ):
        if (
            field in required_probe
            and not _type_sensitive_equal(
                required_probe[field], actual_probe_protocol.get(field)
            )
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_PROTOCOL_MISMATCH",
                "field": f"full_pipeline_probe.{field}",
                "expected": required_probe[field],
                "actual": actual_probe_protocol.get(field),
            })
    required_changed_probe = (
        required_protocol.get("changed_full_pipeline_probe") or {}
    )
    actual_changed_probe_protocol = (
        protocol.get("changed_full_pipeline_probe") or {}
    )
    for field in (
        "jar_count", "class_count", "comparison", "changed_jar_count",
        "changed_class_count", "current_artifact_identity",
        "logical_artifact_derivation_identity", "process_isolation", "includes",
    ):
        if (
            field in required_changed_probe
            and not _type_sensitive_equal(
                required_changed_probe[field],
                actual_changed_probe_protocol.get(field),
            )
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_PROTOCOL_MISMATCH",
                "field": f"changed_full_pipeline_probe.{field}",
                "expected": required_changed_probe[field],
                "actual": actual_changed_probe_protocol.get(field),
            })
    implementation = dict(protocol.get("implementation") or {})
    implementation_fields = (
        "generation_source_identity",
        "validator_source_identity",
        "oracle_support_manifest_identity",
        "harness_source_identity",
        "source_implementation_identity",
        "pipeline_generation_implementation_identity",
        "validator_implementation_identity",
        "jdk_preflight_identity",
        "runtime_implementation_identity",
    )
    if any(
        not _is_sha256_identity(implementation.get(field))
        for field in implementation_fields
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_IMPLEMENTATION_IDENTITY_INVALID",
            "field": "measurement_protocol.implementation",
        })
    else:
        derived_source = _source_implementation_identity(implementation)
        derived_runtime = _runtime_implementation_identity(implementation)
        if (
            derived_source != implementation["source_implementation_identity"]
            or derived_source != protocol.get("source_implementation_identity")
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_IMPLEMENTATION_IDENTITY_INVALID",
                "field": "source_implementation_identity",
                "expected": derived_source,
                "actual": protocol.get("source_implementation_identity"),
            })
        if (
            derived_runtime != implementation["runtime_implementation_identity"]
            or derived_runtime != protocol.get("runtime_implementation_identity")
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_IMPLEMENTATION_IDENTITY_INVALID",
                "field": "runtime_implementation_identity",
                "expected": derived_runtime,
                "actual": protocol.get("runtime_implementation_identity"),
            })
    measurements = result.get("measurements") or {}
    thresholds = gate.get("thresholds") or {}
    cold = measurements.get("cold") or {}
    warm_runs = list(measurements.get("warm_runs") or ())

    if warm_runs:
        warm_seconds = [float(item["end_to_end_seconds"]) for item in warm_runs]
        for metric, expected in (
            ("warm_end_to_end_p50_seconds", _p50(warm_seconds)),
            ("warm_end_to_end_p95_seconds", _p95(warm_seconds)),
        ):
            actual = measurements.get(metric)
            if actual is None or not math.isclose(
                float(actual), expected, rel_tol=1e-12, abs_tol=1e-12
            ):
                issues.append({
                    "reason_code": "BINARY_PERFORMANCE_DERIVATION_INVALID",
                    "metric": metric,
                    "expected": expected,
                    "actual": actual,
                })

    if protocol.get("cpu_time_source"):
        cpu_runs = {
            "cold": cold,
            **{
                f"warm[{index}]": item
                for index, item in enumerate(warm_runs)
            },
            "full_pipeline_probe": measurements.get("full_pipeline_probe") or {},
            "changed_full_pipeline_probe": (
                measurements.get("changed_full_pipeline_probe") or {}
            ),
        }
        if measurements.get("legacy"):
            cpu_runs["legacy"] = measurements["legacy"]
        for label, measured in cpu_runs.items():
            wall = measured.get("end_to_end_seconds")
            cpu = measured.get("cpu_seconds")
            average = measured.get("average_cpu_cores")
            valid = False
            try:
                wall_value = float(wall)
                cpu_value = float(cpu)
                average_value = float(average)
                valid = (
                    not isinstance(wall, bool)
                    and not isinstance(cpu, bool)
                    and not isinstance(average, bool)
                    and wall_value > 0
                    and cpu_value >= 0
                    and average_value >= 0
                    and math.isclose(
                        average_value,
                        cpu_value / wall_value,
                        rel_tol=1e-9,
                        abs_tol=1e-12,
                    )
                )
            except (TypeError, ValueError):
                pass
            if not valid:
                issues.append({
                    "reason_code": "BINARY_PERFORMANCE_CPU_MEASUREMENT_INVALID",
                    "run": label,
                    "wall_seconds": wall,
                    "cpu_seconds": cpu,
                    "average_cpu_cores": average,
                })

    def upper(metric: str, actual: float | int | None, limit: float | int | None):
        try:
            actual_value = float(actual)
            limit_value = float(limit)
            valid = (
                not isinstance(actual, bool)
                and not isinstance(limit, bool)
                and math.isfinite(actual_value)
                and math.isfinite(limit_value)
                and actual_value >= 0
                and limit_value >= 0
                and actual_value <= limit_value
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_THRESHOLD_EXCEEDED",
                "metric": metric, "actual": actual, "limit": limit,
            })

    upper("cold_end_to_end_seconds", cold.get("end_to_end_seconds"), thresholds.get("cold_end_to_end_seconds"))
    upper(
        "warm_end_to_end_p50_seconds",
        measurements.get("warm_end_to_end_p50_seconds"),
        thresholds.get("warm_end_to_end_p50_seconds"),
    )
    upper(
        "warm_end_to_end_p95_seconds",
        measurements.get("warm_end_to_end_p95_seconds"),
        thresholds.get("warm_end_to_end_p95_seconds"),
    )
    upper("peak_rss_bytes", measurements.get("peak_rss_bytes"), thresholds.get("peak_rss_bytes"))
    upper("disk_bytes", measurements.get("disk_bytes"), thresholds.get("disk_bytes"))
    upper("bytes_per_class", cold.get("bytes_per_class"), thresholds.get("bytes_per_class"))
    upper("bytes_per_edge", cold.get("bytes_per_edge"), thresholds.get("bytes_per_edge"))
    upper(
        "cold_relative_legacy_ratio",
        measurements.get("cold_relative_legacy_ratio"),
        thresholds.get("cold_relative_legacy_ratio"),
    )
    legacy_seconds = float(((measurements.get("legacy") or {}).get("end_to_end_seconds") or 0))
    warm_ratio = (
        float(measurements.get("warm_end_to_end_p95_seconds") or 0) / legacy_seconds
        if legacy_seconds else None
    )
    upper("warm_relative_legacy_ratio", warm_ratio, thresholds.get("warm_relative_legacy_ratio"))
    full_pipeline = measurements.get("full_pipeline_probe") or {}
    if "full_pipeline_end_to_end_seconds" in thresholds:
        upper(
            "full_pipeline_end_to_end_seconds",
            full_pipeline.get("end_to_end_seconds"),
            thresholds.get("full_pipeline_end_to_end_seconds"),
        )
    if "full_pipeline_peak_rss_bytes" in thresholds:
        upper(
            "full_pipeline_peak_rss_bytes",
            full_pipeline.get("peak_rss_bytes"),
            thresholds.get("full_pipeline_peak_rss_bytes"),
        )
    for phase, limit in (
        thresholds.get("full_pipeline_phase_seconds") or {}
    ).items():
        upper(
            f"full_pipeline.{phase}",
            (full_pipeline.get("phase_seconds") or {}).get(phase),
            limit,
        )
    changed_full_pipeline = (
        measurements.get("changed_full_pipeline_probe") or {}
    )
    if "changed_full_pipeline_end_to_end_seconds" in thresholds:
        upper(
            "changed_full_pipeline_end_to_end_seconds",
            changed_full_pipeline.get("end_to_end_seconds"),
            thresholds.get("changed_full_pipeline_end_to_end_seconds"),
        )
    if "changed_full_pipeline_peak_rss_bytes" in thresholds:
        upper(
            "changed_full_pipeline_peak_rss_bytes",
            changed_full_pipeline.get("peak_rss_bytes"),
            thresholds.get("changed_full_pipeline_peak_rss_bytes"),
        )
    for phase, limit in (
        thresholds.get("changed_full_pipeline_phase_seconds") or {}
    ).items():
        upper(
            f"changed_full_pipeline.{phase}",
            (changed_full_pipeline.get("phase_seconds") or {}).get(phase),
            limit,
        )
    stage_limits = thresholds.get("stage_p95_seconds") or {}
    upper("cold.inventory", (cold.get("stage_seconds") or {}).get("inventory"), stage_limits.get("inventory"))
    upper("cold.parse_and_cache", (cold.get("stage_seconds") or {}).get("parse_and_cache"), stage_limits.get("parse_and_cache"))
    upper("cold.db_write_and_index", (cold.get("stage_seconds") or {}).get("db_write_and_index"), stage_limits.get("db_write_and_index"))
    upper(
        "warm.batch_query_10000",
        _p95([(item.get("stage_seconds") or {}).get("batch_query_10000", float("inf")) for item in warm_runs]),
        stage_limits.get("batch_query_10000"),
    )
    upper(
        "warm.report_10000",
        _p95([(item.get("stage_seconds") or {}).get("report_10000", float("inf")) for item in warm_runs]),
        stage_limits.get("report_10000"),
    )
    invariants = gate.get("accuracy_invariants") or {}
    expected = invariants.get(
        "expected_class_count", required_protocol.get("class_count")
    )
    counts = cold.get("counts") or {}
    if not _type_sensitive_equal(expected, counts.get("classes")):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_CLASS_CONSERVATION_FAILED",
            "expected": expected, "actual": counts.get("classes"),
        })
    for count_key, invariant_key in (
        ("members", "expected_member_count"),
        ("edges", "expected_edge_count"),
    ):
        expected_count = invariants.get(invariant_key)
        if expected_count is not None and not _type_sensitive_equal(
            expected_count, counts.get(count_key)
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FACT_CONSERVATION_FAILED",
                "fact_kind": count_key,
                "expected": expected_count,
                "actual": counts.get(count_key),
            })
    expected_warm_parses = invariants.get("warm_parser_invocations", 0)
    if any(
        not _type_sensitive_equal(
            expected_warm_parses, item.get("parser_invocations")
        )
        for item in warm_runs
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_WARM_PARSE_NOT_ZERO",
        })
    expected_probe_classes = invariants.get("full_pipeline_expected_class_count")
    if expected_probe_classes is not None:
        observed_sides = {
            "base": full_pipeline.get(
                "base_class_count", full_pipeline.get("class_count")
            ),
            "current": full_pipeline.get(
                "current_class_count", full_pipeline.get("class_count")
            ),
        }
        for side, actual_count in observed_sides.items():
            if not _type_sensitive_equal(expected_probe_classes, actual_count):
                issues.append({
                    "reason_code": (
                        "BINARY_PERFORMANCE_FULL_PIPELINE_CLASS_CONSERVATION_FAILED"
                    ),
                    "side": side,
                    "expected": expected_probe_classes,
                    "actual": actual_count,
                })
    for result_key, invariant_key in (
        (
            "parser_invocations",
            "full_pipeline_expected_parser_invocations",
        ),
        (
            "artifact_snapshot_hits",
            "full_pipeline_expected_artifact_snapshot_hits",
        ),
    ):
        expected_count = invariants.get(invariant_key)
        if (
            expected_count is not None
            and not _type_sensitive_equal(
                expected_count, full_pipeline.get(result_key)
            )
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_CACHE_MISMATCH",
                "metric": result_key,
                "expected": expected_count,
                "actual": full_pipeline.get(result_key),
            })
    expected_validation_issues = invariants.get(
        "full_pipeline_validation_issue_count"
    )
    if (
        expected_validation_issues is not None
        and not _type_sensitive_equal(
            expected_validation_issues,
            full_pipeline.get("validation_issue_count"),
        )
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_VALIDATION_FAILED",
            "expected": expected_validation_issues,
            "actual": full_pipeline.get("validation_issue_count"),
        })
    for result_key, invariant_key in (
        (
            "authoritative_change_fact_count",
            "full_pipeline_expected_authoritative_change_fact_count",
        ),
        ("formal_api_result_count", "full_pipeline_expected_formal_api_result_count"),
    ):
        expected_count = invariants.get(invariant_key)
        if (
            expected_count is not None
            and not _type_sensitive_equal(
                expected_count, full_pipeline.get(result_key)
            )
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH",
                "metric": result_key,
                "expected": expected_count,
                "actual": full_pipeline.get(result_key),
            })
    for result_key, invariant_key in (
        (
            "authoritative_member_change_kind_counts",
            "full_pipeline_expected_authoritative_member_change_kind_counts",
        ),
        (
            "formal_reachability_status_counts",
            "full_pipeline_expected_formal_reachability_status_counts",
        ),
        (
            "formal_impact_conclusion_counts",
            "full_pipeline_expected_formal_impact_conclusion_counts",
        ),
    ):
        expected_distribution = invariants.get(invariant_key)
        if (
            expected_distribution is not None
            and not _type_sensitive_equal(
                expected_distribution, full_pipeline.get(result_key)
            )
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH",
                "metric": result_key,
                "expected": expected_distribution,
                "actual": full_pipeline.get(result_key),
            })
    expected_changed_classes = invariants.get(
        "changed_full_pipeline_expected_class_count"
    )
    if expected_changed_classes is not None:
        observed_sides = {
            "base": changed_full_pipeline.get(
                "base_class_count", changed_full_pipeline.get("class_count")
            ),
            "current": changed_full_pipeline.get(
                "current_class_count", changed_full_pipeline.get("class_count")
            ),
        }
        for side, actual_count in observed_sides.items():
            if not _type_sensitive_equal(expected_changed_classes, actual_count):
                issues.append({
                    "reason_code": (
                        "BINARY_PERFORMANCE_FULL_PIPELINE_CLASS_CONSERVATION_FAILED"
                    ),
                    "probe": "changed_full_pipeline_probe",
                    "side": side,
                    "expected": expected_changed_classes,
                    "actual": actual_count,
                })
    for result_key, invariant_key in (
        (
            "parser_invocations",
            "changed_full_pipeline_expected_parser_invocations",
        ),
        (
            "artifact_snapshot_hits",
            "changed_full_pipeline_expected_artifact_snapshot_hits",
        ),
    ):
        expected_count = invariants.get(invariant_key)
        if (
            expected_count is not None
            and not _type_sensitive_equal(
                expected_count, changed_full_pipeline.get(result_key)
            )
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_CACHE_MISMATCH",
                "probe": "changed_full_pipeline_probe",
                "metric": result_key,
                "expected": expected_count,
                "actual": changed_full_pipeline.get(result_key),
            })
    expected_changed_validation_issues = invariants.get(
        "changed_full_pipeline_validation_issue_count"
    )
    if (
        expected_changed_validation_issues is not None
        and not _type_sensitive_equal(
            expected_changed_validation_issues,
            changed_full_pipeline.get("validation_issue_count"),
        )
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_VALIDATION_FAILED",
            "probe": "changed_full_pipeline_probe",
            "expected": expected_changed_validation_issues,
            "actual": changed_full_pipeline.get("validation_issue_count"),
        })
    for result_key, invariant_key in (
        (
            "authoritative_change_fact_count",
            "changed_full_pipeline_expected_authoritative_change_fact_count",
        ),
        (
            "formal_api_result_count",
            "changed_full_pipeline_expected_formal_api_result_count",
        ),
    ):
        expected_count = invariants.get(invariant_key)
        if (
            expected_count is not None
            and not _type_sensitive_equal(
                expected_count, changed_full_pipeline.get(result_key)
            )
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH",
                "probe": "changed_full_pipeline_probe",
                "metric": result_key,
                "expected": expected_count,
                "actual": changed_full_pipeline.get(result_key),
            })
    for result_key, invariant_key in (
        (
            "authoritative_member_change_kind_counts",
            "changed_full_pipeline_expected_authoritative_member_change_kind_counts",
        ),
        (
            "formal_reachability_status_counts",
            "changed_full_pipeline_expected_formal_reachability_status_counts",
        ),
        (
            "formal_impact_conclusion_counts",
            "changed_full_pipeline_expected_formal_impact_conclusion_counts",
        ),
    ):
        expected_distribution = invariants.get(invariant_key)
        if (
            expected_distribution is not None
            and not _type_sensitive_equal(
                expected_distribution,
                changed_full_pipeline.get(result_key),
            )
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH",
                "probe": "changed_full_pipeline_probe",
                "metric": result_key,
                "expected": expected_distribution,
                "actual": changed_full_pipeline.get(result_key),
            })
    return {
        "schema": "java-upgrade-analyzer.binary-performance-gate-evaluation.v1",
        "status": "passed" if not issues else "failed",
        "issue_count": len(issues),
        "issues": issues,
        "warm_relative_legacy_ratio": warm_ratio,
    }


def _recorded_gate_input_failure(
    reason_code: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "schema": (
            "java-upgrade-analyzer.recorded-performance-gate-verification.v1"
        ),
        "status": "failed",
        "issue_count": 1,
        "issues": [{
            "reason_code": reason_code,
            "detail": detail,
        }],
        "jar_count": None,
        "class_count": None,
        "changed_class_count": None,
        "recorded_measurements_replayed": False,
    }


def _evaluate_recorded_gate(
    gate: Mapping[str, Any],
    *,
    current_source_implementation: Mapping[str, Any] | None = None,
    required_probe_authority_mode: str = _RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE,
    require_live_runtime_implementation: bool = False,
) -> dict[str, Any]:
    """Re-evaluate checked-in scale evidence instead of trusting its status."""
    issues: list[dict[str, Any]] = []
    protocol = dict(gate.get("measurement_protocol") or {})
    recorded = dict(gate.get("recorded_measurements") or {})
    sample_runs = dict(protocol.get("sample_runs") or {})
    warm_samples = list(
        recorded.get("warm_end_to_end_samples_seconds") or ()
    )
    warm_cpu_samples = list(recorded.get("warm_cpu_seconds_samples") or ())
    warm_core_samples = list(
        recorded.get("warm_average_cpu_cores_samples") or ()
    )
    warm_parser_samples = list(
        recorded.get("warm_parser_invocations_samples") or ()
    )
    warm_cache_hit_samples = list(
        recorded.get("warm_cache_hits_samples") or ()
    )
    warm_peak_samples = list(
        recorded.get("warm_peak_rss_bytes_samples") or ()
    )
    warm_stage_samples = list(
        recorded.get("warm_stage_seconds_samples") or ()
    )
    cold_stage = dict(recorded.get("cold_stage_seconds") or {})
    stage = dict(recorded.get("stage_seconds") or {})
    authoritative_policy = release_policy()
    required_protocol = authoritative_policy["measurement_protocol"]
    required_reference_runtime = authoritative_policy["reference_runtime"]
    required_reference_implementation = authoritative_policy[
        "reference_implementation"
    ]
    required_thresholds = authoritative_policy["thresholds"]
    required_invariants = authoritative_policy["accuracy_invariants"]

    def structural(reason_code: str, field: str, expected: Any, actual: Any):
        if not _type_sensitive_equal(expected, actual):
            issues.append({
                "reason_code": reason_code,
                "field": field,
                "expected": expected,
                "actual": actual,
            })

    def nonnegative_number(value: Any, *, integer: bool = False) -> bool:
        if isinstance(value, bool):
            return False
        if integer:
            return type(value) is int and value >= 0
        return (
            isinstance(value, (int, float))
            and math.isfinite(float(value))
            and float(value) >= 0
        )

    def derived_number(
        field: str,
        actual: Any,
        expected: Any,
        *,
        rel_tol: float = 1e-12,
        abs_tol: float = 1e-9,
    ) -> None:
        try:
            matches = (
                not isinstance(actual, bool)
                and not isinstance(expected, bool)
                and math.isfinite(float(actual))
                and math.isfinite(float(expected))
                and math.isclose(
                    float(actual), float(expected),
                    rel_tol=rel_tol, abs_tol=abs_tol,
                )
            )
        except (TypeError, ValueError):
            matches = False
        if not matches:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_DERIVATION_INVALID",
                "field": field,
                "expected": expected,
                "actual": actual,
            })

    structural(
        "BINARY_PERFORMANCE_RECORDED_POLICY_MISMATCH",
        "top_level.keys",
        sorted(_RECORDED_GATE_TOP_LEVEL_FIELDS),
        sorted(gate),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_POLICY_MISMATCH",
        "release_policy_identity",
        release_policy_identity(),
        protocol.get("release_policy_identity"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_POLICY_MISMATCH",
        "measurement_protocol.keys",
        sorted(_MEASUREMENT_PROTOCOL_FIELDS),
        sorted(protocol),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_POLICY_MISMATCH",
        "recorded_measurements.keys",
        sorted(_RECORDED_MEASUREMENT_FIELDS),
        sorted(recorded),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_POLICY_MISMATCH",
        "thresholds",
        required_thresholds,
        gate.get("thresholds"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_POLICY_MISMATCH",
        "accuracy_invariants",
        required_invariants,
        gate.get("accuracy_invariants"),
    )
    for field in (
        "dataset_schema",
        "dataset_identity",
        "base_template_sha256",
        "changed_template_sha256",
        "first_base_artifact_identity",
        "jar_count",
        "class_count",
        "classes_per_jar",
        "large_api_query_count",
        "warmup_runs",
        "sample_runs",
        "p50_method",
        "p95_method",
        "cold_cleanup_rule",
        "warm_cache_rule",
        "rss_sample_semantics",
        "legacy_baseline",
    ):
        structural(
            "BINARY_PERFORMANCE_RECORDED_POLICY_MISMATCH",
            f"measurement_protocol.{field}",
            required_protocol[field],
            protocol.get(field),
        )
    for probe_name in (
        "full_pipeline_probe", "changed_full_pipeline_probe",
    ):
        actual_probe = protocol.get(probe_name) or {}
        for field, expected in required_protocol[probe_name].items():
            structural(
                "BINARY_PERFORMANCE_RECORDED_POLICY_MISMATCH",
                f"measurement_protocol.{probe_name}.{field}",
                expected,
                actual_probe.get(field),
            )
    structural(
        "BINARY_PERFORMANCE_RECORDED_RUNTIME_MISMATCH",
        "measurement_protocol.reference_runtime",
        required_reference_runtime,
        protocol.get("reference_runtime"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_RUNTIME_MISMATCH",
        "measurement_protocol.machine_identity",
        required_reference_runtime["machine_identity"],
        protocol.get("machine_identity"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_RUNTIME_MISMATCH",
        "measurement_protocol.machine",
        required_reference_runtime["machine"],
        protocol.get("machine"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_RUNTIME_MISMATCH",
        "measurement_protocol.tool_versions",
        required_reference_runtime["tool_versions"],
        protocol.get("tool_versions"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_RUNTIME_MISMATCH",
        "measurement_protocol.cpu_time_source",
        required_reference_runtime["cpu_time_source"],
        protocol.get("cpu_time_source"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_RUNTIME_MISMATCH",
        "measurement_protocol.peak_rss_source",
        required_reference_runtime["peak_rss_source"],
        protocol.get("peak_rss_source"),
    )
    reference_implementation_fields = {
        "schema",
        "pipeline_generation_implementation_identity",
        "validator_implementation_identity",
    }
    if not require_live_runtime_implementation and (
        not isinstance(required_reference_implementation, Mapping)
        or set(required_reference_implementation)
        != reference_implementation_fields
        or required_reference_implementation.get("schema")
        != (
            "java-upgrade-analyzer."
            "binary-performance-reference-implementation.v1"
        )
        or any(
            not _is_sha256_identity(
                required_reference_implementation.get(field)
            )
            or required_reference_implementation.get(field) == "0" * 64
            for field in (
                "pipeline_generation_implementation_identity",
                "validator_implementation_identity",
            )
        )
    ):
        issues.append({
            "reason_code": (
                "BINARY_PERFORMANCE_REFERENCE_IMPLEMENTATION_INVALID"
            ),
            "actual": dict(required_reference_implementation or {}),
        })
    try:
        derived_machine_identity = canonical_identity(
            "performance_machine_identity",
            dict(protocol.get("machine") or {}),
            schema_version="1",
        )
    except (BinaryFirstContractError, TypeError, ValueError):
        derived_machine_identity = None
    structural(
        "BINARY_PERFORMANCE_RECORDED_RUNTIME_MISMATCH",
        "measurement_protocol.machine_identity_derivation",
        derived_machine_identity,
        protocol.get("machine_identity"),
    )

    structural(
        "BINARY_PERFORMANCE_RECORDED_SCHEMA_INVALID", "schema",
        "java-upgrade-analyzer.binary-first-performance-gate.v1",
        gate.get("schema"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_AUTHORITY_STATE_INVALID",
        "reason_code",
        "BINARY_PERFORMANCE_GATE_PASSED",
        gate.get("reason_code"),
    )
    for metadata_field in ("rerun_command", "scope_note"):
        metadata_value = gate.get(metadata_field)
        if not isinstance(metadata_value, str) or not metadata_value.strip():
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_METADATA_INVALID",
                "field": metadata_field,
                "actual": metadata_value,
            })
    captured_at = recorded.get("captured_at")
    if not _is_canonical_utc_captured_at(captured_at):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_METADATA_INVALID",
            "field": "recorded_measurements.captured_at",
            "actual": captured_at,
        })
    structural(
        "BINARY_PERFORMANCE_RECORDED_SCALE_INVALID", "jar_count",
        400, protocol.get("jar_count"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_SCALE_INVALID", "class_count",
        100_000, protocol.get("class_count"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_SCALE_INVALID", "classes_per_jar",
        250, protocol.get("classes_per_jar"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID", "dataset_schema",
        DATASET_SCHEMA, protocol.get("dataset_schema"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
        "base_template_sha256", _FIXED_TEMPLATE_SHA256[1],
        protocol.get("base_template_sha256"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
        "changed_template_sha256", _FIXED_TEMPLATE_SHA256[2],
        protocol.get("changed_template_sha256"),
    )
    for probe_name in (
        "full_pipeline_probe", "changed_full_pipeline_probe",
    ):
        structural(
            "BINARY_PERFORMANCE_RECORDED_PROCESS_ISOLATION_INVALID",
            f"{probe_name}.process_isolation",
            "dedicated_python_process",
            (protocol.get(probe_name) or {}).get("process_isolation"),
        )
        includes = list((protocol.get(probe_name) or {}).get("includes") or ())
        if "static_preflight" not in includes:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_PHASE_INVALID",
                "field": f"{probe_name}.includes",
                "expected_phase": "static_preflight",
                "actual": includes,
            })
    if current_source_implementation is None:
        try:
            current_source_implementation = _performance_implementation_protocol(
                resolve_asm_jar() if require_live_runtime_implementation else None,
                include_runtime=require_live_runtime_implementation,
            )
        except Exception as error:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_UNAVAILABLE",
                "error_type": type(error).__name__,
                "detail": str(error),
            })
            current_source_implementation = {}
    else:
        current_source_implementation = dict(current_source_implementation)
    recorded_implementation = dict(protocol.get("implementation") or {})
    structural(
        "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
        "measurement_protocol.implementation.keys",
        sorted(_PERFORMANCE_IMPLEMENTATION_FIELDS),
        sorted(recorded_implementation),
    )
    source_implementation_fields = (
        "generation_source_identity",
        "validator_source_identity",
        "oracle_support_manifest_identity",
        "harness_source_identity",
        "source_implementation_identity",
    )
    live_implementation_fields = (
        _PERFORMANCE_IMPLEMENTATION_FIELDS
        if require_live_runtime_implementation
        else source_implementation_fields
    )
    for field in live_implementation_fields:
        structural(
            "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
            field,
            current_source_implementation.get(field),
            recorded_implementation.get(field),
        )
    if not require_live_runtime_implementation:
        for field in (
            "pipeline_generation_implementation_identity",
            "validator_implementation_identity",
        ):
            structural(
                "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
                f"implementation.{field}.reference_capture",
                required_reference_implementation[field],
                recorded_implementation.get(field),
            )
    structural(
        "BINARY_PERFORMANCE_RECORDED_RUNTIME_MISMATCH",
        "implementation.jdk_preflight_identity",
        required_reference_runtime["jdk_preflight_identity"],
        recorded_implementation.get("jdk_preflight_identity"),
    )
    try:
        derived_source_implementation_identity = (
            _source_implementation_identity(recorded_implementation)
        )
        derived_runtime_implementation_identity = (
            _runtime_implementation_identity(recorded_implementation)
        )
    except (BinaryFirstContractError, TypeError, ValueError):
        derived_source_implementation_identity = None
        derived_runtime_implementation_identity = None
    structural(
        "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
        "implementation.source_implementation_identity.derivation",
        derived_source_implementation_identity,
        recorded_implementation.get("source_implementation_identity"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
        "measurement_protocol.source_implementation_identity.derivation",
        derived_source_implementation_identity,
        protocol.get("source_implementation_identity"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
        "implementation.runtime_implementation_identity.derivation",
        derived_runtime_implementation_identity,
        recorded_implementation.get("runtime_implementation_identity"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
        "measurement_protocol.runtime_implementation_identity.derivation",
        derived_runtime_implementation_identity,
        protocol.get("runtime_implementation_identity"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
        "source_implementation_identity",
        current_source_implementation.get("source_implementation_identity"),
        protocol.get("source_implementation_identity"),
    )
    artifact_identities = list(
        protocol.get("dataset_artifact_identities") or ()
    )
    jar_count = protocol.get("jar_count")
    classes_per_jar = protocol.get("classes_per_jar")
    valid_artifact_identities = bool(
        type(jar_count) is int
        and len(artifact_identities) == jar_count
        and len(set(artifact_identities)) == len(artifact_identities)
        and all(_is_sha256_identity(value) for value in artifact_identities)
    )
    if not valid_artifact_identities:
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
            "field": "dataset_artifact_identities",
            "expected_count": jar_count,
            "actual_count": len(artifact_identities),
        })
    else:
        structural(
            "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
            "first_base_artifact_identity",
            artifact_identities[0],
            protocol.get("first_base_artifact_identity"),
        )
        try:
            derived_dataset_identity = _dataset_identity(
                ({"sha256": value} for value in artifact_identities),
                classes_per_jar=int(classes_per_jar),
            )
        except (TypeError, ValueError) as error:
            derived_dataset_identity = None
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
                "field": "dataset_identity",
                "detail": str(error),
            })
        structural(
            "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
            "dataset_identity",
            derived_dataset_identity,
            protocol.get("dataset_identity"),
        )
    changed_artifact_identity = (
        (protocol.get("changed_full_pipeline_probe") or {}).get(
            "current_artifact_identity"
        )
    )
    if (
        not _is_sha256_identity(changed_artifact_identity)
        or changed_artifact_identity in set(artifact_identities)
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
            "field": (
                "changed_full_pipeline_probe.current_artifact_identity"
            ),
            "actual": changed_artifact_identity,
        })
    else:
        try:
            expected_changed_derivation = (
                _changed_artifact_derivation_identity(
                    base_artifact_identity=artifact_identities[0],
                    current_artifact_identity=changed_artifact_identity,
                    classes_per_jar=int(classes_per_jar),
                )
            )
        except (IndexError, TypeError, ValueError, PerformanceGateError) as error:
            expected_changed_derivation = None
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
                "field": (
                    "changed_full_pipeline_probe."
                    "logical_artifact_derivation_identity"
                ),
                "detail": str(error),
            })
        structural(
            "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
            (
                "changed_full_pipeline_probe."
                "logical_artifact_derivation_identity"
            ),
            expected_changed_derivation,
            (protocol.get("changed_full_pipeline_probe") or {}).get(
                "logical_artifact_derivation_identity"
            ),
        )
    try:
        product = int(protocol.get("jar_count")) * int(
            protocol.get("classes_per_jar")
        )
    except (TypeError, ValueError):
        product = None
    structural(
        "BINARY_PERFORMANCE_RECORDED_SCALE_INVALID", "scale_product",
        protocol.get("class_count"), product,
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_SAMPLE_COUNT_INVALID", "warm_samples",
        sample_runs.get("warm"), len(warm_samples),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_SAMPLE_COUNT_INVALID",
        "warm_cpu_samples", len(warm_samples), len(warm_cpu_samples),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_SAMPLE_COUNT_INVALID",
        "warm_average_cpu_cores_samples", len(warm_samples),
        len(warm_core_samples),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_SAMPLE_COUNT_INVALID",
        "warm_parser_invocations_samples", len(warm_samples),
        len(warm_parser_samples),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_SAMPLE_COUNT_INVALID",
        "warm_cache_hits_samples", len(warm_samples),
        len(warm_cache_hit_samples),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_SAMPLE_COUNT_INVALID",
        "warm_peak_rss_bytes_samples", len(warm_samples),
        len(warm_peak_samples),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_SAMPLE_COUNT_INVALID",
        "warm_stage_seconds_samples", len(warm_samples),
        len(warm_stage_samples),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_CONSERVATION_INVALID", "class_count",
        protocol.get("class_count"), recorded.get("class_count"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_CONSERVATION_INVALID",
        "warmup_class_count",
        required_invariants["warmup_expected_class_count"],
        recorded.get("warmup_class_count"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
        "warmup_parser_invocations",
        required_invariants["warmup_expected_parser_invocations"],
        recorded.get("warmup_parser_invocations"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
        "warmup_cache_hits",
        required_invariants["warmup_expected_cache_hits"],
        recorded.get("warmup_cache_hits"),
    )
    for field in (
        "class_count",
        "member_count",
        "edge_count",
        "cold_parser_invocations",
        "warm_parser_invocations",
        "warm_cache_hits",
        "warmup_parser_invocations",
        "warmup_cache_hits",
        "warmup_class_count",
    ):
        if not nonnegative_number(recorded.get(field), integer=True):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_NUMERIC_INVALID",
                "field": field,
                "actual": recorded.get(field),
            })
    structural(
        "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
        "cold_parser_invocations", protocol.get("jar_count"),
        recorded.get("cold_parser_invocations"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
        "warm_parser_invocations", 0,
        recorded.get("warm_parser_invocations"),
    )
    structural(
        "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
        "warm_cache_hits", protocol.get("jar_count"),
        recorded.get("warm_cache_hits"),
    )
    for index, value in enumerate(warm_parser_samples):
        structural(
            "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
            f"warm_parser_invocations_samples[{index}]",
            recorded.get("warm_parser_invocations"),
            value,
        )
    for index, value in enumerate(warm_cache_hit_samples):
        structural(
            "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
            f"warm_cache_hits_samples[{index}]",
            recorded.get("warm_cache_hits"),
            value,
        )
    try:
        disk_sum = int(recorded.get("sqlite_bytes")) + int(
            recorded.get("cache_bytes")
        )
    except (TypeError, ValueError):
        disk_sum = None
    structural(
        "BINARY_PERFORMANCE_RECORDED_DERIVATION_INVALID", "disk_bytes",
        disk_sum, recorded.get("disk_bytes"),
    )
    for field in (
        "sqlite_bytes",
        "cache_bytes",
        "disk_bytes",
        "bytes_per_class",
        "bytes_per_edge",
        "cold_peak_rss_bytes",
        "warmup_peak_rss_bytes",
        "legacy_peak_rss_bytes",
        "peak_rss_bytes",
    ):
        if not nonnegative_number(recorded.get(field)):
            issues.append({
                "reason_code": (
                    "BINARY_PERFORMANCE_RECORDED_NUMERIC_INVALID"
                ),
                "field": field,
                "actual": recorded.get(field),
            })
    if all(nonnegative_number(value) for value in warm_peak_samples):
        pass
    else:
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_NUMERIC_INVALID",
            "field": "warm_peak_rss_bytes_samples",
            "actual": warm_peak_samples,
        })
    lifecycle_rss_samples = [
        recorded.get("warmup_peak_rss_bytes"),
        recorded.get("cold_peak_rss_bytes"),
        *warm_peak_samples,
        recorded.get("legacy_peak_rss_bytes"),
    ]
    if all(nonnegative_number(value) for value in lifecycle_rss_samples):
        if any(
            float(current) < float(previous)
            for previous, current in zip(
                lifecycle_rss_samples, lifecycle_rss_samples[1:]
            )
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_RSS_INVALID",
                "field": "cold_warm_legacy_peak_rss_lifecycle",
                "actual": lifecycle_rss_samples,
            })
    try:
        class_count_value = int(recorded.get("class_count"))
        edge_count_value = int(recorded.get("edge_count"))
        expected_bytes_per_class = disk_sum / class_count_value
        expected_bytes_per_edge = int(recorded.get("sqlite_bytes")) / edge_count_value
    except (TypeError, ValueError, ZeroDivisionError):
        expected_bytes_per_class = None
        expected_bytes_per_edge = None
    derived_number(
        "bytes_per_class",
        recorded.get("bytes_per_class"),
        expected_bytes_per_class,
    )
    derived_number(
        "bytes_per_edge",
        recorded.get("bytes_per_edge"),
        expected_bytes_per_edge,
    )
    if warm_samples:
        structural(
            "BINARY_PERFORMANCE_RECORDED_DERIVATION_INVALID", "warm_p50",
            recorded.get("warm_end_to_end_p50_seconds"),
            _p50([float(value) for value in warm_samples]),
        )
        structural(
            "BINARY_PERFORMANCE_RECORDED_DERIVATION_INVALID", "warm_p95",
            recorded.get("warm_end_to_end_p95_seconds"),
            _p95([float(value) for value in warm_samples]),
        )

    cpu_runs = [
        (
            "cold",
            recorded.get("cold_end_to_end_seconds"),
            recorded.get("cold_cpu_seconds"),
            recorded.get("cold_average_cpu_cores"),
        ),
        *[
            (
                f"warm[{index}]", wall,
                warm_cpu_samples[index] if index < len(warm_cpu_samples) else None,
                warm_core_samples[index] if index < len(warm_core_samples) else None,
            )
            for index, wall in enumerate(warm_samples)
        ],
        (
            "legacy",
            recorded.get("legacy_end_to_end_seconds"),
            recorded.get("legacy_cpu_seconds"),
            recorded.get("legacy_average_cpu_cores"),
        ),
        (
            "full_pipeline_probe",
            (recorded.get("full_pipeline_probe") or {}).get(
                "end_to_end_seconds"
            ),
            (recorded.get("full_pipeline_probe") or {}).get("cpu_seconds"),
            (recorded.get("full_pipeline_probe") or {}).get(
                "average_cpu_cores"
            ),
        ),
        (
            "changed_full_pipeline_probe",
            (recorded.get("changed_full_pipeline_probe") or {}).get(
                "end_to_end_seconds"
            ),
            (recorded.get("changed_full_pipeline_probe") or {}).get(
                "cpu_seconds"
            ),
            (recorded.get("changed_full_pipeline_probe") or {}).get(
                "average_cpu_cores"
            ),
        ),
    ]
    warmup_cpu_run = (
        recorded.get("warmup_end_to_end_seconds"),
        recorded.get("warmup_cpu_seconds"),
        recorded.get("warmup_average_cpu_cores"),
    )
    try:
        warmup_wall = float(warmup_cpu_run[0])
        warmup_cpu = float(warmup_cpu_run[1])
        warmup_average = float(warmup_cpu_run[2])
        warmup_cpu_valid = (
            all(not isinstance(value, bool) for value in warmup_cpu_run)
            and warmup_wall > 0
            and warmup_cpu >= 0
            and warmup_average >= 0
            and warmup_average <= float(
                required_reference_runtime["machine"]["logical_cpu_count"]
            ) + 1e-6
            and math.isclose(
                warmup_average,
                warmup_cpu / warmup_wall,
                rel_tol=1e-9,
                abs_tol=1e-12,
            )
        )
    except (TypeError, ValueError):
        warmup_cpu_valid = False
    if not warmup_cpu_valid:
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
            "field": "warmup",
            "wall_seconds": warmup_cpu_run[0],
            "cpu_seconds": warmup_cpu_run[1],
            "average_cpu_cores": warmup_cpu_run[2],
        })
    if not protocol.get("cpu_time_source") or recorded.get(
        "cpu_measurement_status"
    ) != "recorded":
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
            "field": "cpu_measurement_status",
            "actual": recorded.get("cpu_measurement_status"),
        })
    for label, wall, cpu, average in cpu_runs:
        try:
            wall_value = float(wall)
            cpu_value = float(cpu)
            average_value = float(average)
            valid = (
                not isinstance(wall, bool)
                and not isinstance(cpu, bool)
                and not isinstance(average, bool)
                and wall_value > 0
                and cpu_value >= 0
                and average_value >= 0
                and average_value <= float(
                    required_reference_runtime["machine"][
                        "logical_cpu_count"
                    ]
                ) + 1e-6
                and math.isclose(
                    average_value, cpu_value / wall_value,
                    rel_tol=1e-9, abs_tol=1e-12,
                )
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
                "field": label,
                "wall_seconds": wall,
                "cpu_seconds": cpu,
                "average_cpu_cores": average,
            })
    try:
        derived_wall = sum(float(item[1]) for item in cpu_runs)
        derived_cpu = sum(float(item[2]) for item in cpu_runs)
        total_wall = float(recorded.get("total_measured_wall_seconds"))
        total_cpu = float(recorded.get("total_measured_cpu_seconds"))
        total_average = float(recorded.get("average_cpu_cores"))
        total_valid = (
            not isinstance(recorded.get("total_measured_wall_seconds"), bool)
            and not isinstance(recorded.get("total_measured_cpu_seconds"), bool)
            and not isinstance(recorded.get("average_cpu_cores"), bool)
            and math.isclose(
                total_wall, derived_wall, rel_tol=1e-12, abs_tol=1e-9
            )
            and math.isclose(total_cpu, derived_cpu, rel_tol=1e-12, abs_tol=1e-9)
            and math.isclose(
                total_average, total_cpu / total_wall,
                rel_tol=1e-9, abs_tol=1e-12,
            )
            and total_average <= float(
                required_reference_runtime["machine"][
                    "logical_cpu_count"
                ]
            ) + 1e-6
        )
    except (TypeError, ValueError, ZeroDivisionError):
        total_valid = False
        derived_wall = None
        derived_cpu = None
    if not total_valid:
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
            "field": "total_measured_cpu",
            "expected_wall_seconds": derived_wall,
            "expected_cpu_seconds": derived_cpu,
            "actual_wall_seconds": recorded.get("total_measured_wall_seconds"),
            "actual_cpu_seconds": recorded.get("total_measured_cpu_seconds"),
            "actual_average_cpu_cores": recorded.get("average_cpu_cores"),
        })
    try:
        cold_ratio = float(recorded.get("cold_end_to_end_seconds")) / float(
            recorded.get("legacy_end_to_end_seconds")
        )
        ratio_matches = math.isclose(
            cold_ratio, float(recorded.get("cold_relative_legacy_ratio")),
            rel_tol=1e-6, abs_tol=1e-9,
        )
    except (TypeError, ValueError, ZeroDivisionError):
        ratio_matches = False
        cold_ratio = None
    if not ratio_matches:
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_DERIVATION_INVALID",
            "field": "cold_relative_legacy_ratio",
            "expected": cold_ratio,
            "actual": recorded.get("cold_relative_legacy_ratio"),
        })
    try:
        warm_ratio = float(
            recorded.get("warm_end_to_end_p95_seconds")
        ) / float(recorded.get("legacy_end_to_end_seconds"))
    except (TypeError, ValueError, ZeroDivisionError):
        warm_ratio = None
    derived_number(
        "warm_relative_legacy_ratio",
        recorded.get("warm_relative_legacy_ratio"),
        warm_ratio,
        rel_tol=1e-6,
    )

    probe_measurements: dict[str, dict[str, Any]] = {
        name: dict(recorded.get(name) or {})
        for name in (
            "full_pipeline_probe", "changed_full_pipeline_probe",
        )
    }
    probe_process_ids: list[int] = []
    probe_authority_bindings: list[dict[str, Any]] = []
    for probe_name, measured_probe in probe_measurements.items():
        required_probe = required_protocol[probe_name]
        structural(
            "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
            f"{probe_name}.keys",
            sorted(_RECORDED_PROBE_FIELDS),
            sorted(measured_probe),
        )
        for field, expected in (
            ("status", "passed"),
            (
                "performance_authority_mode",
                required_probe_authority_mode,
            ),
            ("comparison", required_probe["comparison"]),
            ("jar_count", required_probe["jar_count"]),
            ("current_jar_count", required_probe["jar_count"]),
            ("expected_class_count", required_probe["class_count"]),
            ("class_count", required_probe["class_count"]),
            ("base_class_count", required_probe["class_count"]),
            ("current_class_count", required_probe["class_count"]),
            (
                "rss_measurement_scope",
                "dedicated_probe_process_and_completed_children",
            ),
            ("validation_status", "passed"),
            ("pipeline_total_elapsed_scope", "current_pipeline_attempt"),
            ("pipeline_phase_timings_scope", "current_pipeline_attempt"),
        ):
            structural(
                "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                f"{probe_name}.{field}",
                expected,
                measured_probe.get(field),
            )
        validation_issue_count = measured_probe.get(
            "validation_issue_count"
        )
        expected_validation_issue_count = required_invariants[
            (
                "full_pipeline_validation_issue_count"
                if probe_name == "full_pipeline_probe"
                else "changed_full_pipeline_validation_issue_count"
            )
        ]
        structural(
            "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
            f"{probe_name}.validation_issue_count",
            expected_validation_issue_count,
            validation_issue_count,
        )
        if (
            type(validation_issue_count) is not int
            or validation_issue_count < 0
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                "field": f"{probe_name}.validation_issue_count.type",
                "actual": validation_issue_count,
            })
        structural(
            "BINARY_PERFORMANCE_RECORDED_METADATA_INVALID",
            f"{probe_name}.captured_at",
            captured_at,
            measured_probe.get("captured_at"),
        )
        parser_invocations = measured_probe.get("parser_invocations")
        if not nonnegative_number(parser_invocations, integer=True):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                "field": f"{probe_name}.parser_invocations.type",
                "actual": parser_invocations,
            })
        authority_binding = measured_probe.get(
            "pipeline_performance_authority_binding"
        )
        if not _performance_authority_binding_is_valid(
            authority_binding,
            expected_mode=required_probe_authority_mode,
            expected_source_identity=str(
                protocol.get("source_implementation_identity") or ""
            ),
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                "field": (
                    f"{probe_name}.pipeline_performance_authority_binding"
                ),
                "actual": authority_binding,
            })
        else:
            probe_authority_bindings.append(dict(authority_binding))
        expected_candidate_discarded = (
            required_probe_authority_mode
            == _CANDIDATE_PROBE_AUTHORITY_MODE
        )
        expected_recapture_discarded = (
            required_probe_authority_mode
            == _RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE
        )
        for field, expected in (
            ("activation_authority_mode", required_probe_authority_mode),
            ("publication_deferred", False),
            ("checkpoint_retained", False),
            (
                "activation_candidate_discarded",
                expected_candidate_discarded,
            ),
            (
                "activation_recapture_discarded",
                expected_recapture_discarded,
            ),
            ("active_generation_absent", True),
            ("pending_generation_absent", True),
            ("validation_checkpoint_absent", True),
        ):
            structural(
                "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                f"{probe_name}.{field}",
                expected,
                measured_probe.get(field),
            )
        process_id = measured_probe.get("process_id")
        if type(process_id) is not int or process_id <= 0:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                "field": f"{probe_name}.process_id",
                "actual": process_id,
            })
        else:
            probe_process_ids.append(process_id)

        phase_seconds = dict(measured_probe.get("phase_seconds") or {})
        phase_peaks = dict(
            measured_probe.get("phase_peak_rss_bytes") or {}
        )
        structural(
            "BINARY_PERFORMANCE_RECORDED_PHASE_INVALID",
            f"{probe_name}.phase_seconds.keys",
            sorted(FULL_PIPELINE_PHASES),
            sorted(phase_seconds),
        )
        structural(
            "BINARY_PERFORMANCE_RECORDED_PHASE_INVALID",
            f"{probe_name}.phase_peak_rss_bytes.keys",
            sorted(FULL_PIPELINE_PHASES),
            sorted(phase_peaks),
        )
        valid_phase_seconds = all(
            nonnegative_number(phase_seconds.get(phase))
            for phase in FULL_PIPELINE_PHASES
        )
        valid_phase_peaks = all(
            nonnegative_number(phase_peaks.get(phase), integer=True)
            for phase in FULL_PIPELINE_PHASES
        )
        if not valid_phase_seconds:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_PHASE_INVALID",
                "field": f"{probe_name}.phase_seconds",
                "actual": phase_seconds,
            })
        if not valid_phase_peaks:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_RSS_INVALID",
                "field": f"{probe_name}.phase_peak_rss_bytes",
                "actual": phase_peaks,
            })
        phase_total = None
        if valid_phase_seconds:
            try:
                phase_total = sum(
                    float(phase_seconds[phase])
                    for phase in FULL_PIPELINE_PHASES
                )
                wall_total = float(measured_probe.get("end_to_end_seconds"))
                phases_fit_wall = (
                    math.isfinite(wall_total)
                    and wall_total > 0
                    and phase_total <= wall_total + 0.01
                )
            except (TypeError, ValueError):
                phases_fit_wall = False
                phase_total = None
            if not phases_fit_wall:
                issues.append({
                    "reason_code": "BINARY_PERFORMANCE_RECORDED_PHASE_INVALID",
                    "field": f"{probe_name}.phase_total",
                    "phase_total_seconds": phase_total,
                    "end_to_end_seconds": measured_probe.get(
                        "end_to_end_seconds"
                    ),
                })
        if valid_phase_peaks:
            ordered_peaks = [
                int(phase_peaks[phase]) for phase in FULL_PIPELINE_PHASES
            ]
            if any(
                current < previous
                for previous, current in zip(
                    ordered_peaks, ordered_peaks[1:]
                )
            ):
                issues.append({
                    "reason_code": "BINARY_PERFORMANCE_RECORDED_RSS_INVALID",
                    "field": f"{probe_name}.phase_peak_rss_bytes",
                    "actual": ordered_peaks,
                })
            pipeline_peak = measured_probe.get(
                "pipeline_reported_peak_rss_bytes"
            )
            post_pipeline_peak = measured_probe.get(
                "post_pipeline_peak_rss_bytes"
            )
            if not all(
                nonnegative_number(value, integer=True)
                for value in (pipeline_peak, post_pipeline_peak)
            ):
                issues.append({
                    "reason_code": "BINARY_PERFORMANCE_RECORDED_RSS_INVALID",
                    "field": f"{probe_name}.raw_peak_rss_bytes",
                    "pipeline_reported": pipeline_peak,
                    "post_pipeline": post_pipeline_peak,
                })
            else:
                structural(
                    "BINARY_PERFORMANCE_RECORDED_RSS_INVALID",
                    f"{probe_name}.peak_rss_bytes",
                    max(ordered_peaks + [pipeline_peak, post_pipeline_peak]),
                    measured_probe.get("peak_rss_bytes"),
                )

        pipeline_seconds = measured_probe.get("pipeline_reported_seconds")
        outer_seconds = measured_probe.get("end_to_end_seconds")
        try:
            pipeline_seconds_valid = (
                not isinstance(pipeline_seconds, bool)
                and not isinstance(outer_seconds, bool)
                and math.isfinite(float(pipeline_seconds))
                and math.isfinite(float(outer_seconds))
                and float(pipeline_seconds) > 0
                and float(outer_seconds) > 0
                and (
                    phase_total is None
                    or phase_total <= float(pipeline_seconds) + 0.01
                )
                and float(pipeline_seconds) <= float(outer_seconds) + 0.01
            )
        except (TypeError, ValueError):
            pipeline_seconds_valid = False
        if not pipeline_seconds_valid:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                "field": f"{probe_name}.pipeline_reported_seconds",
                "pipeline_reported_seconds": pipeline_seconds,
                "end_to_end_seconds": outer_seconds,
            })

        snapshot_hits = measured_probe.get("artifact_snapshot_hits")
        disk_hits = measured_probe.get("artifact_snapshot_disk_hits")
        memory_hits = measured_probe.get("artifact_snapshot_memory_hits")
        if not all(
            nonnegative_number(value, integer=True)
            for value in (snapshot_hits, disk_hits, memory_hits)
        ) or snapshot_hits != disk_hits + memory_hits:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
                "field": f"{probe_name}.artifact_snapshot_hits",
                "total": snapshot_hits,
                "disk": disk_hits,
                "memory": memory_hits,
            })
        for histogram_field, count_field in (
            (
                "authoritative_member_change_kind_counts",
                "authoritative_change_fact_count",
            ),
            ("formal_reachability_status_counts", "formal_api_result_count"),
            ("formal_impact_conclusion_counts", "formal_api_result_count"),
        ):
            histogram = measured_probe.get(histogram_field)
            valid_histogram = bool(
                isinstance(histogram, Mapping)
                and all(
                    isinstance(key, str)
                    and key
                    and nonnegative_number(value, integer=True)
                    for key, value in histogram.items()
                )
            )
            expected_total = measured_probe.get(count_field)
            if (
                not valid_histogram
                or not nonnegative_number(expected_total, integer=True)
                or sum(histogram.values()) != expected_total
            ):
                issues.append({
                    "reason_code": (
                        "BINARY_PERFORMANCE_RECORDED_CONSERVATION_INVALID"
                    ),
                    "field": f"{probe_name}.{histogram_field}",
                    "expected_total": expected_total,
                    "actual": histogram,
                })

    if len(probe_process_ids) == 2 and len(set(probe_process_ids)) != 2:
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_PROCESS_ISOLATION_INVALID",
            "field": "recorded_probe_process_ids",
            "actual": probe_process_ids,
        })
    if (
        len(probe_authority_bindings) == 2
        and not _type_sensitive_equal(
            probe_authority_bindings[0], probe_authority_bindings[1]
        )
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
            "field": "pipeline_performance_authority_binding.consistency",
            "actual": probe_authority_bindings,
        })

    expected_raw_stage_keys = {
        "inventory", "parse_and_cache", "db_write_and_index", "overlay",
        "batch_query_10000", "report_10000",
    }
    expected_aggregate_stage_keys = {
        "cold_inventory",
        "cold_parse_and_cache",
        "cold_db_write_and_index",
        "warm_parse_and_cache_p95",
        "warm_db_write_and_index_p95",
        "batch_query_10000_p95",
        "report_10000_p95",
        "cold_batch_query_10000",
        "cold_report_10000",
    }
    if (
        set(stage) != expected_aggregate_stage_keys
        or not all(nonnegative_number(value) for value in stage.values())
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
            "field": "stage_seconds",
            "expected_keys": sorted(expected_aggregate_stage_keys),
            "actual": stage,
        })
    valid_cold_stage = bool(
        set(cold_stage) == expected_raw_stage_keys
        and all(nonnegative_number(value) for value in cold_stage.values())
    )
    if not valid_cold_stage:
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
            "field": "cold_stage_seconds",
            "expected_keys": sorted(expected_raw_stage_keys),
            "actual": cold_stage,
        })
    else:
        for raw_name, aggregate_name in (
            ("inventory", "cold_inventory"),
            ("parse_and_cache", "cold_parse_and_cache"),
            ("db_write_and_index", "cold_db_write_and_index"),
            ("batch_query_10000", "cold_batch_query_10000"),
            ("report_10000", "cold_report_10000"),
        ):
            derived_number(
                f"stage_seconds.{aggregate_name}",
                stage.get(aggregate_name),
                cold_stage[raw_name],
            )
        cold_stage_total = sum(float(value) for value in cold_stage.values())
        try:
            cold_wall = float(recorded.get("cold_end_to_end_seconds"))
            cold_stage_fits = (
                math.isfinite(cold_wall)
                and cold_wall > 0
                and cold_stage_total <= cold_wall + 0.01
            )
        except (TypeError, ValueError):
            cold_stage_fits = False
        if not cold_stage_fits:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "field": "cold_stage_seconds.total",
                "stage_total_seconds": cold_stage_total,
                "end_to_end_seconds": recorded.get(
                    "cold_end_to_end_seconds"
                ),
            })
    valid_warm_stage_samples = True
    for index, sample in enumerate(warm_stage_samples):
        if (
            not isinstance(sample, Mapping)
            or set(sample) != expected_raw_stage_keys
            or not all(nonnegative_number(value) for value in sample.values())
        ):
            valid_warm_stage_samples = False
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "field": f"warm_stage_seconds_samples[{index}]",
                "actual": sample,
            })
        else:
            stage_total = sum(float(value) for value in sample.values())
            try:
                wall = float(warm_samples[index])
                stage_fits = (
                    math.isfinite(wall)
                    and wall > 0
                    and stage_total <= wall + 0.01
                )
            except (IndexError, TypeError, ValueError):
                stage_fits = False
            if not stage_fits:
                issues.append({
                    "reason_code": (
                        "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID"
                    ),
                    "field": f"warm_stage_seconds_samples[{index}].total",
                    "stage_total_seconds": stage_total,
                    "end_to_end_seconds": (
                        warm_samples[index]
                        if index < len(warm_samples) else None
                    ),
                })
    if valid_warm_stage_samples and warm_stage_samples:
        for stage_name, aggregate_name in (
            ("parse_and_cache", "warm_parse_and_cache_p95"),
            ("db_write_and_index", "warm_db_write_and_index_p95"),
            ("batch_query_10000", "batch_query_10000_p95"),
            ("report_10000", "report_10000_p95"),
        ):
            derived_number(
                f"stage_seconds.{aggregate_name}",
                stage.get(aggregate_name),
                _p95([
                    float(sample[stage_name])
                    for sample in warm_stage_samples
                ]),
            )

    probe_peaks = [
        probe_measurements[name].get("peak_rss_bytes")
        for name in (
            "full_pipeline_probe", "changed_full_pipeline_probe",
        )
    ]
    peak_components = [
        recorded.get("warmup_peak_rss_bytes"),
        recorded.get("cold_peak_rss_bytes"),
        *warm_peak_samples,
        recorded.get("legacy_peak_rss_bytes"),
        *probe_peaks,
    ]
    if all(nonnegative_number(value) for value in peak_components):
        structural(
            "BINARY_PERFORMANCE_RECORDED_RSS_INVALID",
            "peak_rss_bytes",
            max(peak_components),
            recorded.get("peak_rss_bytes"),
        )

    warm_runs = [
        {
            "end_to_end_seconds": value,
            "cpu_seconds": (
                warm_cpu_samples[index]
                if index < len(warm_cpu_samples) else None
            ),
            "average_cpu_cores": (
                warm_core_samples[index]
                if index < len(warm_core_samples) else None
            ),
            "parser_invocations": (
                warm_parser_samples[index]
                if index < len(warm_parser_samples) else None
            ),
            "cache_hits": (
                warm_cache_hit_samples[index]
                if index < len(warm_cache_hit_samples) else None
            ),
            "peak_rss_bytes": (
                warm_peak_samples[index]
                if index < len(warm_peak_samples) else None
            ),
            "stage_seconds": (
                dict(warm_stage_samples[index])
                if index < len(warm_stage_samples)
                and isinstance(warm_stage_samples[index], Mapping)
                else {}
            ),
        }
        for index, value in enumerate(warm_samples)
    ]
    # Keep evaluation total on malformed evidence: an empty synthetic sample
    # creates explicit threshold issues rather than crashing the verifier.
    if not warm_runs:
        warm_runs = [{
            "end_to_end_seconds": None,
            "parser_invocations": None,
            "cache_hits": None,
            "peak_rss_bytes": None,
            "stage_seconds": {},
        }]
    replay = {
        "schema": SCHEMA,
        "status": "measured",
        "measurement_protocol": protocol,
        "measurements": {
            "cold": {
                "end_to_end_seconds": recorded.get("cold_end_to_end_seconds"),
                "cpu_seconds": recorded.get("cold_cpu_seconds"),
                "average_cpu_cores": recorded.get(
                    "cold_average_cpu_cores"
                ),
                "stage_seconds": {
                    "inventory": stage.get("cold_inventory"),
                    "parse_and_cache": stage.get("cold_parse_and_cache"),
                    "db_write_and_index": stage.get("cold_db_write_and_index"),
                },
                "parser_invocations": recorded.get("cold_parser_invocations"),
                "counts": {
                    "classes": recorded.get("class_count"),
                    "members": recorded.get("member_count"),
                    "edges": recorded.get("edge_count"),
                },
                "bytes_per_class": recorded.get("bytes_per_class"),
                "bytes_per_edge": recorded.get("bytes_per_edge"),
                "peak_rss_bytes": recorded.get("cold_peak_rss_bytes"),
            },
            "warm_runs": warm_runs,
            "warm_end_to_end_p50_seconds": recorded.get(
                "warm_end_to_end_p50_seconds"
            ),
            "warm_end_to_end_p95_seconds": recorded.get(
                "warm_end_to_end_p95_seconds"
            ),
            "legacy": {
                "end_to_end_seconds": recorded.get("legacy_end_to_end_seconds"),
                "cpu_seconds": recorded.get("legacy_cpu_seconds"),
                "average_cpu_cores": recorded.get(
                    "legacy_average_cpu_cores"
                ),
                "peak_rss_bytes": recorded.get("legacy_peak_rss_bytes"),
            },
            "full_pipeline_probe": dict(
                recorded.get("full_pipeline_probe") or {}
            ),
            "changed_full_pipeline_probe": dict(
                recorded.get("changed_full_pipeline_probe") or {}
            ),
            "cold_relative_legacy_ratio": recorded.get(
                "cold_relative_legacy_ratio"
            ),
            "peak_rss_bytes": recorded.get("peak_rss_bytes"),
            "disk_bytes": recorded.get("disk_bytes"),
        },
    }
    try:
        source_gate_protocol = {
            **required_protocol,
            "machine_identity": required_reference_runtime[
                "machine_identity"
            ],
            "source_implementation_identity": (
                current_source_implementation.get(
                    "source_implementation_identity"
                )
            ),
            # This value cannot be embedded in the policy source because the
            # runtime identity includes the policy-bound source identity.  Its
            # components and canonical derivation are checked independently
            # above before it is used here.
            "runtime_implementation_identity": (
                recorded_implementation.get(
                    "runtime_implementation_identity"
                )
            ),
        }
        replay_evaluation = evaluate_gate(
            replay,
            {
                "measurement_protocol": source_gate_protocol,
                "thresholds": required_thresholds,
                "accuracy_invariants": required_invariants,
            },
        )
    except (KeyError, TypeError, ValueError, PerformanceGateError) as error:
        replay_evaluation = {
            "status": "failed",
            "issues": [{
                "reason_code": "BINARY_PERFORMANCE_RECORDED_REPLAY_INVALID",
                "detail": f"{type(error).__name__}: {error}",
            }],
        }
    issues.extend(replay_evaluation.get("issues") or ())
    if gate.get("status") != "passed" or gate.get(
        "blocks_binary_authority_switch"
    ) is not False:
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_RECORDED_AUTHORITY_STATE_INVALID",
            "status": gate.get("status"),
            "blocks_binary_authority_switch": gate.get(
                "blocks_binary_authority_switch"
            ),
        })
    return {
        "schema": "java-upgrade-analyzer.recorded-performance-gate-verification.v1",
        "status": "passed" if not issues else "failed",
        "issue_count": len(issues),
        "issues": issues,
        "jar_count": protocol.get("jar_count"),
        "class_count": protocol.get("class_count"),
        "changed_class_count": (
            protocol.get("changed_full_pipeline_probe") or {}
        ).get("changed_class_count"),
        "recorded_measurements_replayed": True,
    }


def evaluate_recorded_gate(
    gate: Any,
    *,
    _current_source_implementation: Mapping[str, Any] | None = None,
    _required_probe_authority_mode: str = (
        _RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE
    ),
    _require_live_runtime_implementation: bool = False,
) -> dict[str, Any]:
    """Totally validate recorded evidence and return a structured failure.

    Release verification consumes an artifact, not a trusted Python object.
    Malformed nested JSON shapes must therefore fail closed instead of
    escaping as ``AttributeError``/``ValueError`` and bypassing normal gate
    reporting.
    """

    if not isinstance(gate, Mapping):
        return _recorded_gate_input_failure(
            "BINARY_PERFORMANCE_RECORDED_ROOT_INVALID",
            f"expected object; actual={type(gate).__name__}",
        )

    def finite_json_numbers(value: Any) -> bool:
        if isinstance(value, float):
            return math.isfinite(value)
        if isinstance(value, Mapping):
            return all(finite_json_numbers(item) for item in value.values())
        if isinstance(value, (list, tuple)):
            return all(finite_json_numbers(item) for item in value)
        return True

    if not finite_json_numbers(gate):
        return _recorded_gate_input_failure(
            "BINARY_PERFORMANCE_RECORDED_NONFINITE_NUMBER",
            "NaN and Infinity are not valid performance evidence",
        )
    if "measurement_bootstrap" in gate:
        return _recorded_gate_input_failure(
            "BINARY_PERFORMANCE_RECORDED_BOOTSTRAP_FORBIDDEN",
            "candidate measurement bootstrap is not release evidence",
        )
    if "measurement_provisional" in gate:
        return _recorded_gate_input_failure(
            "BINARY_PERFORMANCE_RECORDED_PROVISIONAL_FORBIDDEN",
            "provisional recapture evidence is not release evidence",
        )

    def require_mappings(
        container: Mapping[str, Any],
        prefix: str,
        fields: Iterable[str],
    ) -> dict[str, Any] | None:
        for field in fields:
            if field in container and not isinstance(container[field], Mapping):
                return _recorded_gate_input_failure(
                    "BINARY_PERFORMANCE_RECORDED_STRUCTURE_INVALID",
                    f"{prefix}{field} must be an object; "
                    f"actual={type(container[field]).__name__}",
                )
        return None

    top_level_invalid = require_mappings(
        gate,
        "",
        (
            "measurement_protocol",
            "recorded_measurements",
            "thresholds",
            "accuracy_invariants",
        ),
    )
    if top_level_invalid is not None:
        return top_level_invalid
    protocol = gate.get("measurement_protocol") or {}
    recorded = gate.get("recorded_measurements") or {}
    thresholds = gate.get("thresholds") or {}
    for container, prefix, fields in (
        (
            protocol,
            "measurement_protocol.",
            (
                "machine",
                "implementation",
                "sample_runs",
                "tool_versions",
                "full_pipeline_probe",
                "changed_full_pipeline_probe",
            ),
        ),
        (
            recorded,
            "recorded_measurements.",
            (
                "cold_stage_seconds",
                "stage_seconds",
                "full_pipeline_probe",
                "changed_full_pipeline_probe",
            ),
        ),
        (
            thresholds,
            "thresholds.",
            (
                "full_pipeline_phase_seconds",
                "changed_full_pipeline_phase_seconds",
                "stage_p95_seconds",
            ),
        ),
    ):
        invalid = require_mappings(container, prefix, fields)
        if invalid is not None:
            return invalid
    for field in (
        "warm_end_to_end_samples_seconds",
        "warm_cpu_seconds_samples",
        "warm_average_cpu_cores_samples",
        "warm_parser_invocations_samples",
        "warm_cache_hits_samples",
        "warm_peak_rss_bytes_samples",
        "warm_stage_seconds_samples",
    ):
        if field in recorded and not isinstance(recorded[field], (list, tuple)):
            return _recorded_gate_input_failure(
                "BINARY_PERFORMANCE_RECORDED_STRUCTURE_INVALID",
                f"recorded_measurements.{field} must be an array; "
                f"actual={type(recorded[field]).__name__}",
            )
    if "dataset_artifact_identities" in protocol and not isinstance(
        protocol["dataset_artifact_identities"], (list, tuple)
    ):
        return _recorded_gate_input_failure(
            "BINARY_PERFORMANCE_RECORDED_STRUCTURE_INVALID",
            "measurement_protocol.dataset_artifact_identities must be an array; "
            f"actual={type(protocol['dataset_artifact_identities']).__name__}",
        )
    for probe_name in (
        "full_pipeline_probe",
        "changed_full_pipeline_probe",
    ):
        probe = protocol.get(probe_name) or {}
        if "includes" in probe and not isinstance(
            probe["includes"], (list, tuple)
        ):
            return _recorded_gate_input_failure(
                "BINARY_PERFORMANCE_RECORDED_STRUCTURE_INVALID",
                f"measurement_protocol.{probe_name}.includes must be an array; "
                f"actual={type(probe['includes']).__name__}",
            )
    try:
        if _current_source_implementation is not None:
            supplied = dict(_current_source_implementation)
            source_fields = (
                tuple(_PERFORMANCE_IMPLEMENTATION_FIELDS)
                if _require_live_runtime_implementation
                else (
                    "generation_source_identity",
                    "validator_source_identity",
                    "oracle_support_manifest_identity",
                    "harness_source_identity",
                    "source_implementation_identity",
                )
            )
            if (
                any(
                    not _is_sha256_identity(supplied.get(field))
                    for field in source_fields
                )
                or _source_implementation_identity(supplied)
                != supplied.get("source_implementation_identity")
                or (
                    _require_live_runtime_implementation
                    and _runtime_implementation_identity(supplied)
                    != supplied.get("runtime_implementation_identity")
                )
            ):
                return _recorded_gate_input_failure(
                    "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_UNAVAILABLE",
                    "supplied current source implementation is invalid",
                )
        return _evaluate_recorded_gate(
            dict(gate),
            current_source_implementation=_current_source_implementation,
            required_probe_authority_mode=_required_probe_authority_mode,
            require_live_runtime_implementation=(
                _require_live_runtime_implementation
            ),
        )
    except Exception as error:
        return _recorded_gate_input_failure(
            "BINARY_PERFORMANCE_RECORDED_STRUCTURE_INVALID",
            f"{type(error).__name__}: {error}",
        )


def evaluate_provisional_gate(
    gate: Any,
    *,
    _current_source_implementation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate candidate measurements for one isolated release recapture.

    This is deliberately separate from :func:`evaluate_recorded_gate`; a
    provisional marker can never become production release evidence.  The
    pipeline additionally requires its process-local recapture capability.
    """

    if not isinstance(gate, Mapping):
        return _recorded_gate_input_failure(
            "BINARY_PERFORMANCE_PROVISIONAL_ROOT_INVALID",
            f"expected object; actual={type(gate).__name__}",
        )
    protocol = gate.get("measurement_protocol")
    marker = gate.get("measurement_provisional")
    implementation = (
        protocol.get("implementation")
        if isinstance(protocol, Mapping) else None
    )
    expected_marker = {
        "schema": (
            "java-upgrade-analyzer.binary-performance-provisional.v1"
        ),
        "purpose": "isolated_release_path_recapture_only",
        "source_implementation_identity": (
            protocol.get("source_implementation_identity")
            if isinstance(protocol, Mapping) else None
        ),
        "runtime_implementation_identity": (
            protocol.get("runtime_implementation_identity")
            if isinstance(protocol, Mapping) else None
        ),
        "dataset_identity": (
            protocol.get("dataset_identity")
            if isinstance(protocol, Mapping) else None
        ),
        "candidate_probe_authority_mode": _CANDIDATE_PROBE_AUTHORITY_MODE,
        "candidate_result_sha256": (
            marker.get("candidate_result_sha256")
            if isinstance(marker, Mapping) else None
        ),
        "public_activation_allowed": False,
    }
    if (
        not isinstance(marker, Mapping)
        or not _type_sensitive_equal(expected_marker, dict(marker))
        or not isinstance(implementation, Mapping)
        or not _is_sha256_identity(
            expected_marker["source_implementation_identity"]
        )
        or not _is_sha256_identity(
            expected_marker["runtime_implementation_identity"]
        )
        or not _is_sha256_identity(expected_marker["dataset_identity"])
        or not _is_sha256_identity(expected_marker["candidate_result_sha256"])
    ):
        return _recorded_gate_input_failure(
            "BINARY_PERFORMANCE_PROVISIONAL_MARKER_INVALID",
            "provisional recapture marker is missing or inconsistent",
        )
    candidate = dict(gate)
    candidate.pop("measurement_provisional", None)
    if _current_source_implementation is None:
        try:
            _current_source_implementation = (
                _performance_implementation_protocol(resolve_asm_jar())
            )
        except Exception as error:
            return _recorded_gate_input_failure(
                "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_UNAVAILABLE",
                f"{type(error).__name__}: {error}",
            )
    verified = evaluate_recorded_gate(
        candidate,
        _current_source_implementation=dict(_current_source_implementation),
        _required_probe_authority_mode=_CANDIDATE_PROBE_AUTHORITY_MODE,
        _require_live_runtime_implementation=True,
    )
    return {
        **verified,
        "schema": (
            "java-upgrade-analyzer."
            "provisional-performance-gate-verification.v1"
        ),
        "provisional_recapture_only": True,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Measure binary-first scale performance")
    parser.add_argument("--work-root", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--jar-count", type=int, default=400)
    parser.add_argument("--classes-per-jar", type=int, default=250)
    parser.add_argument("--warm-samples", type=int, default=3)
    parser.add_argument("--skip-legacy", action="store_true")
    parser.add_argument("--gate", default="")
    parser.add_argument("--verify-recorded-gate", default="")
    build_group = parser.add_mutually_exclusive_group()
    build_group.add_argument(
        "--build-provisional-from-result",
        default="",
        help="build strict provisional evidence from exact candidate result bytes",
    )
    build_group.add_argument(
        "--build-final-from-result",
        default="",
        help="build final evidence from exact recapture result bytes",
    )
    parser.add_argument(
        "--captured-at",
        default="",
        help=(
            "canonical UTC capture timestamp for source-owned evidence builds "
            "(YYYY-MM-DDTHH:MM:SSZ)"
        ),
    )
    parser.add_argument(
        "--provisional-gate",
        default="",
        help=(
            "strict candidate evidence used only for an isolated full "
            "release-path recapture"
        ),
    )
    parser.add_argument(
        "--probe-worker-input", default="", help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--probe-worker-output", default="", help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)
    if args.probe_worker_input or args.probe_worker_output:
        if not args.probe_worker_input or not args.probe_worker_output:
            parser.error(
                "--probe-worker-input and --probe-worker-output are required together"
            )
        worker_output = _distinct_cli_output_path(
            parser,
            args.probe_worker_output,
            protected_values=(args.probe_worker_input,),
        )
        return _run_probe_worker(
            Path(args.probe_worker_input).expanduser().resolve(), worker_output,
        )
    build_input = (
        args.build_provisional_from_result or args.build_final_from_result
    )
    if build_input:
        if not args.output:
            parser.error("--output is required for evidence building")
        if not args.captured_at.strip():
            parser.error("--captured-at is required for evidence building")
        provisional_build = bool(args.build_provisional_from_result)
        if not provisional_build and not args.provisional_gate:
            parser.error(
                "--provisional-gate is required with --build-final-from-result"
            )
        if provisional_build and args.provisional_gate:
            parser.error(
                "--provisional-gate is only valid for recapture or final building"
            )
        raw_path = Path(build_input).expanduser().resolve()
        output_path = _distinct_cli_output_path(
            parser,
            args.output,
            protected_values=(
                build_input,
                args.provisional_gate if not provisional_build else "",
            ),
        )
        provisional_path = (
            Path(args.provisional_gate).expanduser().resolve()
            if not provisional_build else None
        )
        try:
            raw_content = raw_path.read_bytes()
            provisional_content = (
                provisional_path.read_bytes()
                if provisional_path is not None else None
            )
            built = build_recorded_gate_from_result(
                raw_content,
                captured_at=args.captured_at,
                provisional=provisional_build,
                provisional_gate_content=provisional_content,
            )
            _write_json(output_path, built)
        except Exception as error:
            structured = getattr(error, "failure", {})
            if not isinstance(structured, Mapping):
                structured = {}
            reason_code = str(
                structured.get("reason_code")
                or "BINARY_PERFORMANCE_EVIDENCE_BUILD_FAILED"
            )
            detail = f"{type(error).__name__}: {_safe_error_text(error)}"
            issues = []
            raw_issues = structured.get("issues")
            if isinstance(raw_issues, (list, tuple)):
                for raw_issue in raw_issues:
                    if not isinstance(raw_issue, Mapping):
                        continue
                    try:
                        normalized_issue = json.loads(json.dumps(
                            dict(raw_issue),
                            ensure_ascii=False,
                            allow_nan=False,
                        ))
                    except (
                        OverflowError,
                        RecursionError,
                        TypeError,
                        ValueError,
                    ):
                        continue
                    if isinstance(normalized_issue, dict):
                        issues.append(normalized_issue)
            if not issues:
                issues = [{
                    "reason_code": reason_code,
                    "detail": detail,
                }]
            failure = {
                "schema": (
                    "java-upgrade-analyzer."
                    "binary-performance-evidence-build-failure.v1"
                ),
                "status": "failed",
                "reason_code": reason_code,
                "detail": detail,
                "issue_count": len(issues),
                "issues": issues,
            }
            try:
                _write_json(output_path, failure)
            except OSError as persist_error:
                failure["output_persist_error"] = (
                    f"{type(persist_error).__name__}: {persist_error}"
                )
            print(
                json.dumps(failure, ensure_ascii=False, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        print(json.dumps({
            "status": "passed",
            "evidence_kind": "provisional" if provisional_build else "final",
            "output": str(Path(args.output).expanduser().resolve()),
        }, ensure_ascii=False, sort_keys=True))
        return 0
    if args.verify_recorded_gate:
        gate_path = Path(args.verify_recorded_gate).expanduser().resolve()
        verification_output = (
            _distinct_cli_output_path(
                parser,
                args.output,
                protected_values=(args.verify_recorded_gate,),
            )
            if args.output else None
        )
        try:
            verification = evaluate_recorded_gate(
                _json_object_from_exact_bytes(
                    gate_path.read_bytes(), field="recorded_performance_gate"
                )
            )
        except Exception as error:
            verification = {
                "schema": "java-upgrade-analyzer.recorded-performance-gate-verification.v1",
                "status": "failed",
                "issue_count": 1,
                "issues": [{
                    "reason_code": "BINARY_PERFORMANCE_RECORDED_GATE_UNREADABLE",
                    "detail": (
                        f"{type(error).__name__}: {_safe_error_text(error)}"
                    ),
                }],
            }
        if verification_output is not None:
            try:
                verification_output.parent.mkdir(parents=True, exist_ok=True)
                _write_json(verification_output, verification)
            except BaseException as persist_error:
                _emit_performance_cli_failure(
                    verification_output,
                    reason_code=(
                        "BINARY_PERFORMANCE_VERIFICATION_RESULT_PERSIST_FAILED"
                    ),
                    phase="recorded_gate_verification_persistence",
                    error=persist_error,
                    core_benchmark_status="not_run",
                    core_result_receipt={
                        "verification_status": verification.get("status"),
                        "issue_count": verification.get("issue_count"),
                    },
                )
                return 1
        print(json.dumps(verification, ensure_ascii=False, sort_keys=True))
        return 0 if verification["status"] == "passed" else 1
    if not args.output:
        parser.error("--output is required unless --verify-recorded-gate is used")
    if args.jar_count <= 0 or args.classes_per_jar <= 0 or args.warm_samples <= 0:
        parser.error("scale and sample counts must be positive")
    output_path = _distinct_cli_output_path(
        parser,
        args.output,
        protected_values=(args.gate, args.provisional_gate, args.work_root),
    )
    benchmark_gate = None
    if args.gate:
        try:
            benchmark_gate = _json_object_from_exact_bytes(
                Path(args.gate).expanduser().resolve().read_bytes(),
                field="benchmark_gate",
            )
        except (OSError, PerformanceGateError) as error:
            parser.error(f"--gate is invalid: {error}")
    temporary = None
    if args.work_root:
        lexical_root = Path(args.work_root).expanduser()
        if lexical_root.name in {"", ".", ".."}:
            parser.error("--work-root must name a dedicated directory leaf")
        root = lexical_root.parent.resolve() / lexical_root.name
        try:
            _physical_directory_identity(
                root, field="performance work root", create=True
            )
        except PerformanceGateError as error:
            parser.error(f"--work-root is invalid: {error}")
    else:
        temporary = short_temporary_directory(prefix="binary-performance")
        root = Path(temporary.__enter__())
    try:
        try:
            result = run_benchmark(
                root,
                jar_count=args.jar_count,
                classes_per_jar=args.classes_per_jar,
                warm_samples=args.warm_samples,
                include_legacy=not args.skip_legacy,
                provisional_gate_path=(
                    Path(args.provisional_gate).expanduser().resolve()
                    if args.provisional_gate else None
                ),
            )
        except BaseException as error:
            structured_failure = (
                _bounded_json_value(error.failure)
                if isinstance(error, PerformanceGateError)
                and isinstance(error.failure, Mapping)
                and error.failure
                else None
            )
            failure = (
                structured_failure
                if isinstance(structured_failure, dict)
                else _probe_failure(error)
            )
            failed = {
                "schema": SCHEMA,
                "status": "failed",
                "failure": failure,
            }
            try:
                _write_json(output_path, failed)
            except BaseException as persist_error:
                _emit_performance_cli_failure(
                    output_path,
                    reason_code=(
                        "BINARY_PERFORMANCE_FAILURE_RESULT_PERSIST_FAILED"
                    ),
                    phase="benchmark_failure_persistence",
                    error=persist_error,
                    core_benchmark_status="failed",
                    primary_failure=failure,
                )
                return 1
            print(
                json.dumps(
                    failed,
                    ensure_ascii=False,
                    sort_keys=True,
                    allow_nan=False,
                )
            )
            return 1
        evaluation = None
        if benchmark_gate is not None:
            try:
                evaluation = evaluate_gate(result, benchmark_gate)
                result["gate_evaluation"] = evaluation
            except BaseException as evaluation_error:
                receipt = _persist_completed_benchmark_recovery(root, result)
                _emit_performance_cli_failure(
                    output_path,
                    reason_code=(
                        "BINARY_PERFORMANCE_GATE_EVALUATION_FAILED"
                    ),
                    phase="completed_benchmark_gate_evaluation",
                    error=evaluation_error,
                    core_benchmark_status="completed",
                    core_result_receipt=receipt,
                )
                return 1
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            _write_json(output_path, result)
        except BaseException as persist_error:
            receipt = _persist_completed_benchmark_recovery(root, result)
            _emit_performance_cli_failure(
                output_path,
                reason_code="BINARY_PERFORMANCE_RESULT_PERSIST_FAILED",
                phase="completed_benchmark_persistence",
                error=persist_error,
                core_benchmark_status="completed",
                core_result_receipt=receipt,
            )
            return 1
        print(json.dumps({
            "status": result["status"],
            "dataset_identity": result["measurement_protocol"]["dataset_identity"],
            "cold_seconds": result["measurements"]["cold"]["end_to_end_seconds"],
            "warm_p95_seconds": result["measurements"]["warm_end_to_end_p95_seconds"],
            "warm_p50_seconds": result["measurements"]["warm_end_to_end_p50_seconds"],
            "cpu_seconds": result["measurements"]["total_measured_cpu_seconds"],
            "average_cpu_cores": result["measurements"]["average_cpu_cores"],
            "legacy_seconds": (result["measurements"]["legacy"] or {}).get("end_to_end_seconds"),
            "full_pipeline_seconds": (
                result["measurements"]["full_pipeline_probe"]
            ).get("end_to_end_seconds"),
            "changed_full_pipeline_seconds": (
                result["measurements"]["changed_full_pipeline_probe"]
            ).get("end_to_end_seconds"),
            "gate_status": (evaluation or {}).get("status"),
        }, sort_keys=True))
        return 0 if not evaluation or evaluation["status"] == "passed" else 1
    finally:
        if temporary is not None:
            temporary.__exit__(None, None, None)


if __name__ == "__main__":
    raise SystemExit(main())
