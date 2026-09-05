#!/usr/bin/env python3
"""Independent validation of a completed binary generation.

The validator consumes raw artifacts, target-JDK observations and immutable
generation sidecars.  It does not call the production ASM parser, provider
resolver, member resolver, dispatch resolver, decision engine or tracer.
"""

from __future__ import annotations

import argparse
from collections import OrderedDict, defaultdict
from concurrent.futures import (
    FIRST_COMPLETED,
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    wait,
)
from concurrent.futures.process import BrokenProcessPool
from contextlib import contextmanager
import csv
from dataclasses import dataclass
import errno
from functools import lru_cache
import gc
import hashlib
import heapq
import io
from itertools import chain
import json
import multiprocessing
import ntpath
import os
from pathlib import Path
import pickle
import re
import secrets
import sqlite3
import stat
import sys
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import unquote, urlparse
import xml.etree.ElementTree as ET
import zipfile
import zlib

from artifact_safety import is_allowed_duplicate_archive_entry
from binary_first_contract import (
    BinaryFirstContractError,
    canonical_identity,
    canonical_identity_native_json,
    canonical_identity_streaming,
    surrogate_safe_json_bytes,
    surrogate_safe_json_dumps,
    transport_jvm_text,
)
from binary_validation_contract import (
    VALIDATION_POLICY_VERSION,
    oracle_support_manifest_identity,
    validator_implementation_identity,
)
from binary_tool_execution import execute_binary_tool, tool_failure_is_retryable
from jdk_preflight import (
    JdkPreflightError,
    jdk_tool_path,
    preflight_jdk_home,
    resolve_jdk_release,
)
from progress_logging import emit_progress
from process_metrics import system_available_memory_bytes
from streaming_json import (
    StreamingJsonReadError,
    files_equal,
    fsync_directory,
    iter_canonical_json_object_array,
    iter_json_bytes,
    load_canonical_json_top_level_value,
    prime_canonical_json_fields,
    stream_json,
    write_json_streaming_atomic,
)
from path_runtime import short_temporary_directory
from final_artifact_edge_oracle import (
    LINKER_BOOTSTRAP_OWNERS,
    METHOD_HANDLE_REFERENCE_KIND_BY_TAG,
    METHOD_HANDLE_REFERENCE_KINDS,
    clear_immutable_oracle_cache,
    parse_structural_javap,
    scan_final_artifact,
)
from javap_session import (
    CompiledJavapSessionBinding,
    JavapSessionError,
    capture_compiled_javap_session_binding,
    install_compiled_javap_session_binding,
)


ORACLE_SOURCE = Path(__file__).with_name("java") / "RuntimeOutcomeOracle.java"
MIN_MULTI_RELEASE_VERSION = 8
ACC_MODULE = 0x8000
POLICY_VERSION = VALIDATION_POLICY_VERSION
LOADING_CONSTRAINT_TYPE_OWNERS_KEY = "loading_constraint_type_owners"
# A single target-JVM process retains every Class object it defines until its
# URLClassLoader and process exit.  Loading a 100k-class application in one
# invocation therefore makes validation memory scale with the entire runtime
# closure.  Batching preserves the independent JVM observation while bounding
# metaspace, reflection metadata and captured JSON for each child process.
MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS = 12_000
LOW_AVAILABLE_MEMORY_WARNING_BYTES = 4 * 1024 * 1024 * 1024
MAX_VALIDATION_STRING_POOL_ENTRIES = 250_000
MAX_VALIDATION_POOLED_STRING_CHARS = 4_096
# Formal paths commonly reuse the same direct-edge evidence. Keep only a
# bounded working set so repeated path checks avoid three SQLite lookups while
# a wide result set cannot turn the optimisation into another memory spike.
MAX_CLOSED_WORLD_EVIDENCE_CACHE_ENTRIES = 8_192
_LARGE_SIDECAR_FIELDS = {
    "binary_decisions.json": (
        "analysis_context_identity",
        "authoritative_change_facts",
        "diagnostic_candidate_facts",
    ),
    "binary_entrypoints.json": (
        "coverage_gaps", "coverage_status", "records",
    ),
    "binary_formal_results.json": (
        "by_api", "resource_activation_results", "results",
    ),
    "binary_projections.json": (
        "authoritative_projection_assessments", "formal_projections",
    ),
    "binary_runtime_semantic_overlay.json": (
        "coverage_gaps", "rows",
    ),
}
_NATIVE_ARTIFACT_IDENTITY_MAX_ROWS = 50_000
_NATIVE_ARTIFACT_IDENTITY_MAX_ESTIMATED_BYTES = 16 * 1024 * 1024
# Avoid process-startup concurrency for tiny projects/tests. Above this point
# each batch has enough reflection work to amortize one isolated JVM process.
MIN_CLASSES_FOR_CONCURRENT_RUNTIME_ORACLE = 4_000
MIN_ARTIFACTS_FOR_PROCESS_ORACLE_SCAN = 16
MAX_PROCESS_ORACLE_SCAN_WORKERS = 6
_ORACLE_RECONCILIATION_KIND_CODES = {
    "provider_binding": 1,
    "class_definition": 2,
    "member_resolution": 3,
    "dispatch_resolution": 4,
    "type_resolution": 5,
    "class_initialization_resolution": 6,
    "linkage_resolution": 7,
    "resource_selection": 8,
}
_ORACLE_SOURCE_FILE_LANGUAGES = {
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin_script",
    ".scala": "scala", ".groovy": "groovy",
}
_ORACLE_XML_DOCTYPE = re.compile(
    br"<!DOCTYPE\s+[^>]+>", re.IGNORECASE | re.DOTALL
)
_ORACLE_ALLOWED_MYBATIS_DTDS = (
    b"mybatis.org/dtd/mybatis-3-mapper.dtd",
    b"mybatis.org/dtd/mybatis-3-config.dtd",
)


ValidationProgressCallback = Callable[
    [str, str, int | None, int | None, str | None], None
]


def _runtime_oracle_execution_shape(
    class_count: int,
) -> tuple[int, int, int | None]:
    """Choose a JVM batch/concurrency shape from current physical headroom.

    Every class is still observed with ``-Xverify:all``. The shape only
    amortizes process startup when memory permits and serializes/smaller-batches
    before the OS starts paging when it does not.
    """

    try:
        available = system_available_memory_bytes()
    except Exception:
        available = None
    gib = 1024 * 1024 * 1024
    if available is None:
        adaptive_limit = 4_000
        memory_workers = 2
    elif available < 2 * gib:
        adaptive_limit = 500
        memory_workers = 1
    elif available < 4 * gib:
        adaptive_limit = 1_000
        memory_workers = 1
    elif available < 8 * gib:
        adaptive_limit = 4_000
        memory_workers = 1
    elif available < 16 * gib:
        adaptive_limit = 8_000
        memory_workers = 2
    else:
        adaptive_limit = 12_000
        memory_workers = 4
    batch_size = max(
        1, min(int(MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS), adaptive_limit)
    )
    if (
        (available is None or available >= 8 * gib)
        and batch_size <= 2_000
    ):
        # Small batches have a much lower class-metadata footprint and can use
        # the historical three-way concurrency safely.
        memory_workers = 3
    batch_count = max(1, (max(0, int(class_count)) + batch_size - 1) // batch_size)
    workers = (
        min(
            memory_workers,
            max(1, os.cpu_count() or 1),
            batch_count,
        )
        if class_count >= MIN_CLASSES_FOR_CONCURRENT_RUNTIME_ORACLE
        else 1
    )
    return batch_size, workers, available


def _artifact_scan_worker_count(request_count: int) -> tuple[int, int | None]:
    """Bound concurrent archive/JVM scans before they induce OS paging."""

    try:
        available = system_available_memory_bytes()
    except Exception:
        available = None
    gib = 1024 * 1024 * 1024
    if available is None:
        memory_workers = 4
    elif available < 2 * gib:
        memory_workers = 1
    elif available < 4 * gib:
        memory_workers = 2
    elif available < 8 * gib:
        memory_workers = 4
    else:
        memory_workers = 8
    return (
        min(
            max(0, int(request_count)),
            max(1, os.cpu_count() or 1),
            memory_workers,
        ),
        available,
    )


def _runtime_member_projection_cache_limit() -> int:
    """Keep hot resolved-member projections without pushing Windows to page."""

    try:
        available = system_available_memory_bytes()
    except Exception:
        available = None
    gib = 1024 * 1024 * 1024
    if available is None:
        return 100_000
    if available < 2 * gib:
        return 20_000
    if available < 4 * gib:
        return 50_000
    if available < 8 * gib:
        return 100_000
    return 250_000


def _notify_progress(
    callback: ValidationProgressCallback | None,
    phase: str,
    message: str,
    current: int | None = None,
    total: int | None = None,
    item: str | None = None,
) -> None:
    if callback is None:
        return
    try:
        callback(phase, message, current, total, item)
    except Exception:
        # Observability is never allowed to change validation truth or status.
        return


def _artifact_truth_identity(
    namespace: str,
    ordered_rows: list[tuple[Any, ...]],
) -> str:
    """Hash bounded flat per-artifact facts through CPython's C encoder.

    Both identity implementations emit the same frozen canonical bytes.  The
    native encoder is materially faster for ordinary per-JAR sets, while the
    streaming encoder keeps a pathological artifact bounded.  The estimate is
    intentionally conservative: six bytes per text code point covers JSON
    control/surrogate escaping, plus explicit scalar and delimiter overhead.
    Nested or unfamiliar values retain the general streaming path.
    """

    native = len(ordered_rows) <= _NATIVE_ARTIFACT_IDENTITY_MAX_ROWS
    estimated_bytes = 2
    if native:
        for row in ordered_rows:
            if type(row) not in (tuple, list):
                native = False
                break
            estimated_bytes += 2
            for value in row:
                value_type = type(value)
                if value_type is str:
                    estimated_bytes += 2 + 6 * len(value)
                elif value is None:
                    estimated_bytes += 4
                elif value_type is bool:
                    estimated_bytes += 5
                elif value_type is int:
                    estimated_bytes += len(str(value))
                elif value_type is float:
                    estimated_bytes += 32
                else:
                    native = False
                    break
                estimated_bytes += 1
            if (
                not native
                or estimated_bytes
                > _NATIVE_ARTIFACT_IDENTITY_MAX_ESTIMATED_BYTES
            ):
                native = False
                break
    identity = (
        canonical_identity_native_json
        if native else canonical_identity_streaming
    )
    return identity(namespace, ordered_rows, schema_version="1")


def _notify_counted_progress(
    callback: ValidationProgressCallback | None,
    phase: str,
    message: str,
    current: int,
    total: int,
    item: str | None = None,
    *,
    target_updates: int = 20,
) -> None:
    """Emit bounded progress for large item loops.

    Opening and appending the progress JSONL for every JAR caused thousands of
    tiny writes on virtualized Windows disks. Start/end and roughly twenty
    evenly spaced updates retain liveness and ETA evidence without turning
    observability into a material part of Step4 I/O.
    """

    if callback is None:
        return
    normalized_total = max(0, int(total))
    normalized_current = max(0, int(current))
    interval = max(
        1,
        (normalized_total + max(1, int(target_updates)) - 1)
        // max(1, int(target_updates)),
    )
    if (
        normalized_current not in {0, 1, normalized_total}
        and normalized_current % interval
    ):
        return
    _notify_progress(
        callback,
        phase,
        message,
        normalized_current,
        normalized_total,
        item,
    )


def _iter_jsonl_values(payload: str) -> Iterable[Any]:
    """Decode one JSON value per line without copying the output into lines."""

    decoder = json.JSONDecoder()
    cursor = 0
    size = len(payload)
    while cursor < size:
        boundary = payload.find("\n", cursor)
        if boundary < 0:
            boundary = size
        value_start = cursor
        while (
            value_start < boundary
            and payload[value_start] in " \t\r"
        ):
            value_start += 1
        value, value_end = decoder.raw_decode(payload, value_start)
        if payload[value_end:boundary].strip():
            raise json.JSONDecodeError(
                "Extra data", payload, value_end
            )
        yield value
        cursor = boundary + 1


def _environment_progress_callback() -> ValidationProgressCallback | None:
    report_dir = str(os.environ.get("UPGRADE_REPORT_DIR") or "").strip()
    if not report_dir:
        return None
    started = time.perf_counter()

    def report(phase, message, current=None, total=None, item=None):
        emit_progress(
            "step4",
            phase,
            message,
            current=current,
            total=total,
            elapsed=time.perf_counter() - started,
            item=item,
            report_dir=report_dir,
        )

    return report


@dataclass(frozen=True)
class _DirectEdgeTruth:
    """Immutable javap facts reusable only for the same content/JDK key."""

    artifact_sha256: str
    direct_edges: frozenset[tuple[Any, ...]]
    dynamic_handle_edges: frozenset[tuple[Any, ...]]
    discovery_classes: frozenset[str]


@dataclass(frozen=True)
class _StructuralTruth:
    """Normalized structural facts reusable only for the same scan key."""

    type_edges: frozenset[tuple[Any, ...]]
    class_init_edges: frozenset[tuple[Any, ...]]
    clinit_classes: frozenset[str]
    semantic_instructions: frozenset[tuple[Any, ...]]
    declared_members: frozenset[tuple[Any, ...]]
    failures: tuple[str, ...]


@dataclass(frozen=True)
class _OracleScanEvidence:
    """One compact, normalized view shared by direct and structural checks.

    The javap scanner produces a large JSON-shaped object.  Retaining a
    compressed copy and decoding it independently in both validators spends
    CPU on serialization and temporarily materializes the full graph again.
    These immutable sets contain exactly the fields those validators consume.
    """

    artifact_sha256: str
    complete: bool
    failures: tuple[str, ...]
    direct_truth: _DirectEdgeTruth
    structural_truth: _StructuralTruth
    structural_class_names: frozenset[str]


_OBSERVATION_FIELDS = (
    "class_name",
    "provider_resource_url",
    "provider_url",
    "loader_kind",
    "modifiers",
    "super_name",
    "interfaces",
    "class_annotations",
    "class_annotation_imports",
    "class_annotation_resources",
    "class_annotation_values",
    "status",
    "members",
    "member_annotations",
    "member_annotation_values",
    "failure_phase",
    "failure_kind",
    "failure_message",
    "javap_declared_members",
)
_OBSERVATION_FIELD_INDEX = {
    key: index for index, key in enumerate(_OBSERVATION_FIELDS)
}
_MISSING_OBSERVATION_VALUE = object()


class _CompactObservation(Mapping[str, Any]):
    """Tuple-backed immutable view of one target-JVM observation.

    The helper emits the same small field vocabulary for every class. Keeping
    a Python dict (and another copy of those keys) for tens of thousands of
    classes dominated the Oracle's retained heap. Fixed tuple slots provide
    O(1) field lookup while unknown future helper fields remain losslessly
    stored in ``_extras`` so validation fails neither open nor silently.
    """

    __slots__ = (
        "_values", "_extras", "_length", "_declared_members_cache",
    )

    def __init__(self, row: Mapping[str, Any]):
        values = [_MISSING_OBSERVATION_VALUE] * len(_OBSERVATION_FIELDS)
        extras = []
        for key, value in row.items():
            index = _OBSERVATION_FIELD_INDEX.get(key)
            if index is None:
                extras.append((key, value))
            else:
                values[index] = value
        self._values = tuple(values)
        self._extras = tuple(extras)
        self._length = len(row)
        # Derived only from immutable mapping fields and intentionally absent
        # from iteration/canonical identities.
        self._declared_members_cache = None

    def __getitem__(self, key: str) -> Any:
        index = _OBSERVATION_FIELD_INDEX.get(key)
        if index is not None:
            value = self._values[index]
            if value is _MISSING_OBSERVATION_VALUE:
                raise KeyError(key)
            return value
        for extra_key, value in self._extras:
            if key == extra_key:
                return value
        raise KeyError(key)

    def __iter__(self):
        for key, value in zip(_OBSERVATION_FIELDS, self._values):
            if value is not _MISSING_OBSERVATION_VALUE:
                yield key
        for key, _value in self._extras:
            yield key

    def __len__(self) -> int:
        return self._length


_ORACLE_METHOD_ENTRY_KINDS = {
    "Lorg/springframework/scheduling/annotation/Scheduled;": "spring_scheduled",
    "Lorg/springframework/scheduling/annotation/Schedules;": "spring_scheduled",
    "Lorg/springframework/context/event/EventListener;": "spring_event_listener",
    "Lorg/springframework/kafka/annotation/KafkaListener;": "spring_message_listener",
    "Lorg/springframework/amqp/rabbit/annotation/RabbitListener;": "spring_message_listener",
    "Lorg/springframework/amqp/rabbit/annotation/RabbitHandler;": "spring_message_listener",
    "Lorg/springframework/jms/annotation/JmsListener;": "spring_message_listener",
    "Lorg/apache/rocketmq/spring/annotation/RocketMQMessageListener;": "spring_message_listener",
    "Ljavax/annotation/PostConstruct;": "lifecycle_callback",
    "Ljakarta/annotation/PostConstruct;": "lifecycle_callback",
    "Ljavax/persistence/PrePersist;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PostPersist;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PreUpdate;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PostUpdate;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PreRemove;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PostRemove;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PostLoad;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PrePersist;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PostPersist;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PreUpdate;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PostUpdate;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PreRemove;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PostRemove;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PostLoad;": "jpa_lifecycle_callback",
    "Lorg/springframework/web/bind/annotation/RequestMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/GetMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/PostMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/PutMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/DeleteMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/PatchMapping;": "spring_web_endpoint",
    "Lorg/springframework/context/annotation/Bean;": "spring_bean_initialization",
}

_ORACLE_INTERFACE_CALLBACKS = {
    "org/springframework/boot/ApplicationRunner": {"run": "spring_application_runner"},
    "org/springframework/boot/CommandLineRunner": {"run": "spring_command_line_runner"},
    "org/springframework/context/ApplicationListener": {
        "onApplicationEvent": "spring_application_listener"
    },
    "org/springframework/context/Lifecycle": {
        "start": "spring_lifecycle_callback", "stop": "spring_lifecycle_callback",
    },
    "org/springframework/context/SmartLifecycle": {
        "start": "spring_lifecycle_callback", "stop": "spring_lifecycle_callback",
    },
    "org/springframework/beans/factory/InitializingBean": {
        "afterPropertiesSet": "spring_lifecycle_callback",
    },
    "org/springframework/web/servlet/HandlerInterceptor": {
        "preHandle": "spring_web_interceptor",
        "postHandle": "spring_web_interceptor",
        "afterCompletion": "spring_web_interceptor",
    },
    "org/springframework/core/convert/converter/Converter": {
        "convert": "spring_conversion_callback",
    },
    "org/springframework/format/Formatter": {
        "parse": "spring_conversion_callback", "print": "spring_conversion_callback",
    },
    "javax/servlet/Servlet": {"service": "servlet_endpoint"},
    "jakarta/servlet/Servlet": {"service": "servlet_endpoint"},
    "javax/servlet/Filter": {"doFilter": "servlet_filter"},
    "jakarta/servlet/Filter": {"doFilter": "servlet_filter"},
    "javax/servlet/ServletContextListener": {
        "contextInitialized": "servlet_lifecycle_callback",
        "contextDestroyed": "servlet_lifecycle_callback",
    },
    "jakarta/servlet/ServletContextListener": {
        "contextInitialized": "servlet_lifecycle_callback",
        "contextDestroyed": "servlet_lifecycle_callback",
    },
    "org/quartz/Job": {"execute": "quartz_job"},
}

_ORACLE_CLASS_TRIGGER_KINDS = {
    "Lorg/apache/rocketmq/spring/annotation/RocketMQMessageListener;": (
        "spring_message_listener", {"onMessage"},
    ),
    "Lorg/springframework/amqp/rabbit/annotation/RabbitListener;": (
        "spring_message_listener", {"handleMessage", "onMessage"},
    ),
}

_ORACLE_SPRING_FACTORIES_CALLBACKS = {
    "org.springframework.context.ApplicationListener": (
        "onApplicationEvent", "spring_application_listener",
    ),
    "org.springframework.boot.env.EnvironmentPostProcessor": (
        "postProcessEnvironment", "spring_environment_post_processor",
    ),
    "org.springframework.context.ApplicationContextInitializer": (
        "initialize", "spring_application_context_initializer",
    ),
}


class BinaryValidationError(BinaryFirstContractError):
    pass


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


_RESULT_GENERATION_SNAPSHOT_LAYERS = frozenset({
    "decision", "assessment", "formal_projection", "candidate_projection",
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
})
_RESERVED_OPTIONAL_GENERATION_SIDECARS = frozenset({
    "binary_inline_overlay.json",
    "binary_source_attestation.json",
    "binary_source_explanations.json",
})
_AUTHORITATIVE_SQLITE_SIDECARS = (
    "base_binary_facts.sqlite",
    "current_binary_facts.sqlite",
)
_SQLITE_TRANSIENT_SUFFIXES = ("-journal", "-wal", "-shm")


def _expected_result_generation_identity(
    manifest: Mapping[str, Any],
) -> str | None:
    snapshots = manifest.get("active_snapshot_identities")
    sidecars = manifest.get("sidecar_content_identities")
    policies = manifest.get("policy_identities")
    if (
        manifest.get("schema")
        != "java-upgrade-analyzer.binary-result-generation.v1"
        or manifest.get("authority") != "binary_first"
        or not isinstance(snapshots, Mapping)
        or set(snapshots) != _RESULT_GENERATION_SNAPSHOT_LAYERS
        or not all(isinstance(value, str) and value for value in snapshots.values())
        or not isinstance(sidecars, Mapping)
        or not _REQUIRED_PIPELINE_GENERATION_SIDECARS.issubset(sidecars)
        or not isinstance(policies, Mapping)
        or not isinstance(manifest.get("analysis_context_identity"), str)
        or not manifest.get("analysis_context_identity")
        or not isinstance(manifest.get("trace_result_set_digest"), str)
        or not manifest.get("trace_result_set_digest")
    ):
        return None
    return _identity("result_generation_identity", {
        "analysis_context_identity": manifest["analysis_context_identity"],
        "authority": "binary_first",
        "snapshot_identities": {
            str(layer): str(identity)
            for layer, identity in sorted(snapshots.items())
        },
        "trace_result_set_digest": manifest["trace_result_set_digest"],
        "sidecar_content_identities": dict(sidecars),
        "policy_identities": dict(policies),
    })


def _safe_generation_sidecar_name(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
        and Path(value).name == value
    )


def _generation_sidecar_declaration_issues(
    config: Mapping[str, Any],
    generation: Path,
    sidecar_identities: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Reject fixed-name inputs that are absent from the generation identity."""
    issues = [
        _validation_issue(
            "generation_integrity",
            "ORACLE_GENERATION_REQUIRED_SIDECAR_UNDECLARED",
            sidecar=name,
        )
        for name in sorted(
            _REQUIRED_PIPELINE_GENERATION_SIDECARS - set(sidecar_identities)
        )
    ]
    source_sidecars_required = bool(config.get("source_overlay"))
    for name in sorted(_RESERVED_OPTIONAL_GENERATION_SIDECARS):
        sidecar = generation / name
        if source_sidecars_required and name not in sidecar_identities:
            issues.append(_validation_issue(
                "generation_integrity",
                "ORACLE_GENERATION_REQUIRED_SOURCE_SIDECAR_UNDECLARED",
                sidecar=name,
            ))
        elif not source_sidecars_required and name in sidecar_identities:
            issues.append(_validation_issue(
                "generation_integrity",
                "ORACLE_GENERATION_UNEXPECTED_SOURCE_SIDECAR_DECLARED",
                sidecar=name,
            ))
        if name not in sidecar_identities and (
            sidecar.is_symlink() or sidecar.exists()
        ):
            issues.append(_validation_issue(
                "generation_integrity",
                "ORACLE_GENERATION_UNDECLARED_RESERVED_SIDECAR",
                sidecar=name,
            ))
    # A committed WAL is visible to an ordinary read-only SQLite connection
    # even though the manifest binds only the main database bytes.  Never let
    # unbound journal state participate in authoritative validation.
    for database_name in _AUTHORITATIVE_SQLITE_SIDECARS:
        for suffix in _SQLITE_TRANSIENT_SUFFIXES:
            transient_name = f"{database_name}{suffix}"
            transient = generation / transient_name
            if transient.is_symlink() or transient.exists():
                issues.append(_validation_issue(
                    "generation_integrity",
                    "ORACLE_GENERATION_SQLITE_TRANSIENT_SIDECAR_PRESENT",
                    database=database_name,
                    sidecar=transient_name,
                ))
    return issues


def _open_immutable_sqlite(path: Path) -> sqlite3.Connection:
    """Open only the content-addressed main database image.

    ``immutable=1`` is a second line of defence against a journal file being
    created after the generation-integrity scan.  It also prevents validation
    itself from creating lock or shared-memory files beside the generation.
    """

    connection = sqlite3.connect(
        f"{path.expanduser().resolve().as_uri()}?mode=ro&immutable=1",
        uri=True,
    )
    try:
        connection.execute("PRAGMA query_only = ON")
        return connection
    except BaseException:
        # Connection setup is not atomic: connect() may succeed before the
        # defensive query-only contract fails.  Close the native handle on
        # every exceptional path rather than relying on GC/ResourceWarning.
        connection.close()
        raise


def _open_sequential_binary(path: Path):
    """Open a file for large forward-only reads with cache-friendly hints.

    ``O_SEQUENTIAL`` is a Windows CRT hint that allows the cache manager to
    aggressively read ahead and retire pages after use.  It is zero on
    platforms that do not expose it, so the byte stream and failure semantics
    remain those of an ordinary read-only descriptor everywhere else.
    """

    flags = os.O_RDONLY
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_SEQUENTIAL", 0))
    try:
        filesystem_path = os.fspath(path)
    except TypeError:
        # Focused integrations may supply a read-only path facade. It cannot
        # receive platform open flags, but retains the same exact byte stream.
        return path.open("rb")
    descriptor = os.open(filesystem_path, flags)
    try:
        return os.fdopen(descriptor, "rb", buffering=0)
    except BaseException:
        os.close(descriptor)
        raise


def _sha256_file(
    path: Path,
    *,
    progress_callback: ValidationProgressCallback | None = None,
    progress_phase: str = "validation-file-hash",
    progress_message: str = "校验文件 SHA-256",
    progress_item: str | None = None,
) -> str:
    """Hash every byte through one reusable large sequential-read buffer."""

    digest = hashlib.sha256()
    with _open_sequential_binary(path) as handle:
        total = max(0, int(os.fstat(handle.fileno()).st_size))
        buffer = bytearray(min(
            8 * 1024 * 1024,
            max(64 * 1024, total),
        ))
        view = memoryview(buffer)
        completed = 0
        report_interval = max(
            len(buffer),
            (total + 19) // 20 if total else len(buffer),
        )
        next_report = report_interval
        _notify_progress(
            progress_callback,
            progress_phase,
            progress_message,
            0,
            total,
            progress_item or str(path),
        )
        while True:
            count = handle.readinto(buffer)
            if not count:
                break
            digest.update(view[:count])
            completed += count
            if completed >= next_report:
                _notify_progress(
                    progress_callback,
                    progress_phase,
                    progress_message,
                    completed,
                    total,
                    progress_item or str(path),
                )
                next_report = completed + report_interval
        _notify_progress(
            progress_callback,
            progress_phase,
            progress_message,
            completed,
            total,
            progress_item or str(path),
        )
    return digest.hexdigest()


def _sqlite_logical_content_sha256(path: Path) -> str:
    """Hash SQLite content while ignoring non-semantic header counters.

    SQLite backup preserves every database page but may advance the change
    counter, schema cookie and version-valid-for fields in the 100-byte header.
    Those fields affect cache invalidation, not table content. Normalizing them
    lets the Oracle prove that base/current evidence stores are logically
    identical before reusing an otherwise identical validation observation.
    """

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        header = bytearray(handle.read(100))
        if len(header) != 100 or not header.startswith(b"SQLite format 3\x00"):
            return _sha256_file(path)
        for start, end in ((24, 28), (40, 44), (92, 96)):
            header[start:end] = b"\x00" * (end - start)
        digest.update(header)
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sqlite_logical_contents_equal(
    left: Path,
    right: Path,
    *,
    progress_callback: ValidationProgressCallback | None = None,
) -> bool:
    """Compare two SQLite files while ignoring three header-only counters.

    This pairwise form stops on the first semantic byte difference. It is used
    only when every non-database side input is already identical and reusing a
    complete target-JVM observation is therefore possible. The former code
    unconditionally hashed both 11 GiB stores even when their JDK, artifacts
    or runtime profiles already made reuse impossible.
    """

    try:
        total = left.stat().st_size
        if total != right.stat().st_size:
            return False
        with _open_sequential_binary(left) as left_handle, \
                _open_sequential_binary(right) as right_handle:
            left_header = bytearray(left_handle.read(100))
            right_header = bytearray(right_handle.read(100))
            sqlite_header = b"SQLite format 3\x00"
            sqlite_images = (
                len(left_header) == 100
                and len(right_header) == 100
                and left_header.startswith(sqlite_header)
                and right_header.startswith(sqlite_header)
            )
            if sqlite_images:
                for start, end in ((24, 28), (40, 44), (92, 96)):
                    left_header[start:end] = b"\x00" * (end - start)
                    right_header[start:end] = b"\x00" * (end - start)
            if left_header != right_header:
                return False
            buffer_size = min(
                8 * 1024 * 1024,
                max(64 * 1024, total - len(left_header)),
            )
            left_buffer = bytearray(buffer_size)
            right_buffer = bytearray(buffer_size)
            left_view = memoryview(left_buffer)
            right_view = memoryview(right_buffer)
            completed = len(left_header)
            report_interval = max(
                len(left_buffer),
                (total + 19) // 20 if total else len(left_buffer),
            )
            next_report = completed + report_interval
            _notify_progress(
                progress_callback,
                "validation-side-cache",
                "顺序比较 SQLite 逻辑内容",
                completed,
                total,
            )
            while True:
                left_count = left_handle.readinto(left_buffer)
                right_count = right_handle.readinto(right_buffer)
                if left_count != right_count:
                    return False
                if not left_count:
                    _notify_progress(
                        progress_callback,
                        "validation-side-cache",
                        "顺序比较 SQLite 逻辑内容",
                        completed,
                        total,
                    )
                    return True
                if left_view[:left_count] != right_view[:right_count]:
                    return False
                completed += left_count
                if completed >= next_report:
                    _notify_progress(
                        progress_callback,
                        "validation-side-cache",
                        "顺序比较 SQLite 逻辑内容",
                        completed,
                        total,
                    )
                    next_report = completed + report_interval
    except OSError as error:
        raise BinaryValidationError(
            "BINARY_VALIDATION_SQLITE_READ_FAILED", str(error)
        ) from error


def _load_json(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryValidationError("BINARY_VALIDATION_JSON_INVALID", str(error)) from error
    if not isinstance(value, dict):
        raise BinaryValidationError("BINARY_VALIDATION_JSON_INVALID", str(path))
    return value


def _iter_sidecar_object_rows(
    generation: Path,
    sidecar_name: str,
    field_name: str,
    *,
    progress_callback: ValidationProgressCallback | None = None,
    progress_phase: str = "validation-sidecar-stream",
) -> Iterable[dict[str, Any]]:
    """Stream one canonical sidecar array with bounded Python heap usage."""

    path = generation / sidecar_name

    def report(consumed: int, total: int) -> None:
        _notify_progress(
            progress_callback,
            progress_phase,
            f"流式校验 {sidecar_name}:{field_name}",
            consumed,
            total,
            sidecar_name,
        )

    try:
        yield from iter_canonical_json_object_array(
            path,
            field_name,
            progress_callback=report if progress_callback is not None else None,
        )
    except StreamingJsonReadError as error:
        # Focused fixtures and third-party integrations may still emit
        # whitespace-formatted JSON. Preserve compatibility for bounded files
        # without ever recreating a multi-GiB fallback allocation.
        try:
            small_compatibility_payload = path.stat().st_size <= 16 * 1024 * 1024
        except OSError:
            small_compatibility_payload = False
        if small_compatibility_payload:
            payload = _load_json(path)
            rows = payload.get(field_name)
            if isinstance(rows, list) and all(
                isinstance(row, Mapping) for row in rows
            ):
                yield from (dict(row) for row in rows)
                return
        raise BinaryValidationError(
            "BINARY_VALIDATION_JSON_INVALID", str(error)
        ) from error


def _sidecar_top_level_value(
    generation: Path,
    sidecar_name: str,
    field_name: str,
) -> Any:
    try:
        return load_canonical_json_top_level_value(
            generation / sidecar_name,
            field_name,
        )
    except StreamingJsonReadError as error:
        raise BinaryValidationError(
            "BINARY_VALIDATION_JSON_INVALID", str(error)
        ) from error


def _prime_large_sidecar_fields(
    generation: Path,
    progress_callback: ValidationProgressCallback | None = None,
) -> None:
    existing = [
        (name, fields)
        for name, fields in _LARGE_SIDECAR_FIELDS.items()
        if (generation / name).is_file()
    ]
    for index, (name, fields) in enumerate(existing, start=1):
        try:
            prime_canonical_json_fields(generation / name, fields)
        except StreamingJsonReadError as error:
            raise BinaryValidationError(
                "BINARY_VALIDATION_JSON_INVALID", str(error)
            ) from error
        _notify_progress(
            progress_callback,
            "validation-sidecar-index",
            "建立大结果文件字段偏移索引",
            index,
            len(existing),
            name,
        )


def _release_values(jdk_home: Path) -> dict[str, str]:
    try:
        return dict(resolve_jdk_release(jdk_home)["values"])
    except (JdkPreflightError, OSError) as error:
        raise BinaryValidationError("BINARY_ORACLE_JDK_RELEASE_MISSING", str(error)) from error


def _release_major(jdk_home: Path) -> int:
    release = _release_values(jdk_home)
    version = release.get("JAVA_VERSION", "")
    match = re.match(r"(?:1\.)?(\d+)", version)
    if not match:
        raise BinaryValidationError("BINARY_ORACLE_JDK_VERSION_INVALID", version)
    return int(match.group(1))


def _manifest_multi_release(archive: zipfile.ZipFile) -> bool:
    matches = [
        info for info in archive.infolist()
        if not info.is_dir() and info.filename.upper() == "META-INF/MANIFEST.MF"
    ]
    if len(matches) != 1:
        return False
    text = archive.read(matches[0]).decode("utf-8", errors="replace")
    attributes: dict[str, str] = {}
    continued: dict[str, bool] = {}
    physical_header_valid: dict[str, bool] = {}
    current_key = ""
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        # Multi-Release is a main-section attribute.  A same-named attribute
        # in a per-entry section must not activate versioned class selection.
        if not line:
            break
        if line.startswith(" ") and current_key:
            attributes[current_key] += line[1:]
            continued[current_key] = True
            continue
        key, separator, value = line.partition(":")
        current_key = key.strip().lower() if separator else ""
        if current_key:
            attributes[current_key] = value.strip()
            continued[current_key] = False
            physical_header_valid[current_key] = bool(
                key.lower() == current_key and value.lower() == " true"
            )
    return bool(
        attributes.get("multi-release", "").strip().lower() == "true"
        and not continued.get("multi-release", False)
        and physical_header_valid.get("multi-release", False)
    )


def _independent_class_access_flags(content: bytes) -> int | None:
    """Read class access flags without relying on production ASM or javap.

    A class named ``module-info`` is legal JVM bytecode. Only ACC_MODULE makes
    it a module descriptor. Returning ``None`` for malformed bytes keeps the
    entry in the independent universe so the later parser fails closed instead
    of silently classifying corrupt input as metadata.
    """
    data = memoryview(content)
    cursor = 0

    def skip(size: int) -> None:
        nonlocal cursor
        # Callers pass constants or unsigned classfile lengths only.
        if cursor + size > len(data):
            raise ValueError("truncated classfile")
        cursor += size

    def u1() -> int:
        nonlocal cursor
        skip(1)
        return int(data[cursor - 1])

    def u2() -> int:
        nonlocal cursor
        skip(2)
        return int.from_bytes(data[cursor - 2:cursor], "big")

    try:
        if len(data) < 10 or bytes(data[:4]) != b"\xca\xfe\xba\xbe":
            raise ValueError("invalid classfile header")
        cursor = 8
        constant_pool_count = u2()
        if constant_pool_count < 1:
            raise ValueError("invalid constant_pool_count")
        index = 1
        while index < constant_pool_count:
            tag = u1()
            if tag == 1:
                skip(u2())
            elif tag in {3, 4, 9, 10, 11, 12, 17, 18}:
                skip(4)
            elif tag in {5, 6}:
                skip(8)
                index += 1
            elif tag in {7, 8, 16, 19, 20}:
                skip(2)
            elif tag == 15:
                skip(3)
            else:
                raise ValueError(f"unknown constant-pool tag {tag}")
            index += 1
        return u2()
    except ValueError:
        return None


def _independent_archive_class_access_flags(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo,
) -> int | None:
    """Read only the classfile prefix needed to locate ``access_flags``.

    Inventory previously materialized every complete class body merely to
    decide whether it was an ACC_MODULE descriptor. The later immutable javap
    snapshot still performs the full CRC, safety and classfile read for every
    entry; this parser preserves the exact module decision without a second
    full decompression pass during inventory.
    """

    try:
        with archive.open(info) as raw_handle, io.BufferedReader(
            raw_handle, buffer_size=64 * 1024,
        ) as handle:
            def take(size: int) -> bytes:
                value = handle.read(size)
                if len(value) != size:
                    raise ValueError("truncated classfile")
                return value

            def u1() -> int:
                return take(1)[0]

            def u2() -> int:
                return int.from_bytes(take(2), "big")

            if take(4) != b"\xca\xfe\xba\xbe":
                raise ValueError("invalid classfile magic")
            take(4)  # minor_version + major_version
            constant_pool_count = u2()
            if constant_pool_count < 1:
                raise ValueError("invalid constant_pool_count")
            index = 1
            while index < constant_pool_count:
                tag = u1()
                if tag == 1:
                    take(u2())
                elif tag in {3, 4, 9, 10, 11, 12, 17, 18}:
                    take(4)
                elif tag in {5, 6}:
                    take(8)
                    index += 1
                elif tag in {7, 8, 16, 19, 20}:
                    take(2)
                elif tag == 15:
                    take(3)
                else:
                    raise ValueError(f"unknown constant-pool tag {tag}")
                index += 1
            return u2()
    except ValueError:
        return None


_INDEPENDENT_MODULE_DESCRIPTOR_ATTRIBUTES = frozenset({
    b"Module",
    b"ModulePackages",
    b"ModuleMainClass",
    b"InnerClasses",
    b"SourceFile",
    b"SourceDebugExtension",
    b"RuntimeVisibleAnnotations",
    b"RuntimeInvisibleAnnotations",
    b"RuntimeVisibleTypeAnnotations",
    b"RuntimeInvisibleTypeAnnotations",
})


def _independent_is_valid_module_descriptor(content: bytes) -> bool:
    """Independently enforce the basic JVMS 4.1 module-info shape."""
    data = memoryview(content)
    cursor = 0

    def take(size: int) -> bytes:
        nonlocal cursor
        # Callers pass constants or unsigned classfile lengths only.
        if cursor + size > len(data):
            raise ValueError("truncated classfile")
        result = bytes(data[cursor:cursor + size])
        cursor += size
        return result

    def skip(size: int) -> None:
        nonlocal cursor
        # Callers pass constants or unsigned classfile lengths only.
        if cursor + size > len(data):
            raise ValueError("truncated classfile")
        cursor += size

    def u1() -> int:
        return int.from_bytes(take(1), "big")

    def u2() -> int:
        return int.from_bytes(take(2), "big")

    def u4() -> int:
        return int.from_bytes(take(4), "big")

    try:
        if take(4) != b"\xca\xfe\xba\xbe":
            raise ValueError("invalid classfile magic")
        take(2)  # minor_version
        major_version = u2()
        constant_pool_count = u2()
        if constant_pool_count < 1:
            raise ValueError("invalid constant_pool_count")
        utf8: dict[int, bytes] = {}
        class_name_indexes: dict[int, int] = {}
        index = 1
        while index < constant_pool_count:
            tag = u1()
            if tag == 1:
                utf8[index] = take(u2())
            elif tag in {3, 4, 9, 10, 11, 12, 17, 18}:
                skip(4)
            elif tag in {5, 6}:
                skip(8)
                index += 1
            elif tag == 7:
                class_name_indexes[index] = u2()
            elif tag in {8, 16, 19, 20}:
                skip(2)
            elif tag == 15:
                skip(3)
            else:
                raise ValueError(f"unknown constant-pool tag {tag}")
            index += 1

        access_flags = u2()
        this_class = u2()
        super_class = u2()
        owner_index = class_name_indexes.get(this_class)
        owner = utf8.get(owner_index or -1)
        interface_count = u2()
        for _ in range(interface_count):
            u2()
        field_count = u2()
        if field_count:
            return False
        method_count = u2()
        if method_count:
            return False
        attributes: list[bytes] = []
        for _ in range(u2()):
            attribute_name = utf8.get(u2())
            if attribute_name is None:
                raise ValueError("invalid attribute name index")
            attributes.append(attribute_name)
            skip(u4())
        if cursor != len(data):
            raise ValueError("trailing classfile bytes")
        return bool(
            access_flags == ACC_MODULE
            and major_version >= 53
            and owner == b"module-info"
            and super_class == 0
            and interface_count == 0
            and attributes.count(b"Module") == 1
            and set(attributes) <= _INDEPENDENT_MODULE_DESCRIPTOR_ATTRIBUTES
        )
    except ValueError:
        return False


def _archive_inventory(path: Path, target_major: int) -> dict[str, Any]:
    classes: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
    valid_module_descriptors: set[str] = set()
    resource_candidates: dict[
        str, dict[int, list[dict[str, Any]]]
    ] = defaultdict(lambda: defaultdict(list))
    with zipfile.ZipFile(path) as archive:
        archive_infos = archive.infolist()
        manifest_entries = [
            info for info in archive_infos
            if not info.is_dir()
            and info.filename.upper() == "META-INF/MANIFEST.MF"
        ]
        ambiguous_manifest = bool(
            len(manifest_entries) > 1
            and any(
                not info.is_dir()
                and info.filename.startswith("META-INF/versions/")
                for info in archive_infos
            )
        )
        failures = (
            ["ambiguous_multi_release_manifest:"]
            if ambiguous_manifest
            else []
        )
        if ambiguous_manifest:
            failures[0] += ",".join(
                info.filename for info in manifest_entries
            )
        mr = _manifest_multi_release(archive)
        for ordinal, info in enumerate(archive_infos):
            if info.is_dir():
                continue
            match = re.match(
                r"META-INF/versions/([1-9][0-9]*)/(.+\.class)$",
                info.filename,
                re.ASCII,
            )
            if match and int(match.group(1)) >= MIN_MULTI_RELEASE_VERSION:
                version, logical = int(match.group(1)), match.group(2)
                if logical.startswith("META-INF/") or any(
                    part in {"", ".", ".."} for part in logical.split("/")
                ):
                    continue
                classes[logical.removesuffix(".class")][version].append(info.filename)
                access_flags = _independent_archive_class_access_flags(
                    archive, info
                )
                if (
                    access_flags is not None
                    and access_flags & ACC_MODULE
                    and _independent_is_valid_module_descriptor(
                        archive.read(info)
                    )
                ):
                    valid_module_descriptors.add(info.filename)
            elif info.filename.startswith("META-INF/versions/"):
                # Classes and resources share the canonical numeric MR path
                # rules, but JEP 238 never overlays resources below META-INF.
                resource_match = re.fullmatch(
                    r"META-INF/versions/([1-9][0-9]*)/(.+)",
                    info.filename,
                    re.ASCII,
                )
                if info.filename.endswith(".class") or not resource_match:
                    continue
                version = int(resource_match.group(1))
                logical = resource_match.group(2)
                if (
                    version < MIN_MULTI_RELEASE_VERSION
                    or logical.startswith("META-INF/")
                    or any(
                        part in {"", ".", ".."}
                        for part in logical.split("/")
                    )
                ):
                    continue
                content = archive.read(info)
                content_sha256 = hashlib.sha256(content).hexdigest()
                resource_candidates[logical][version].append({
                    "ordinal": ordinal,
                    "sha256": content_sha256,
                    "semantic_digest": _independent_resource_digest(
                        logical, content, content_sha256=content_sha256
                    ),
                    "semantic_facts": _independent_resource_facts(
                        logical, content
                    ),
                })
                # Malformed, pre-Java-8, and prohibited META-INF overlays are
                # physical evidence only, never runtime resource candidates.
                continue
            elif info.filename.endswith(".class") and not info.filename.startswith("META-INF/"):
                classes[info.filename.removesuffix(".class")][0].append(info.filename)
                access_flags = _independent_archive_class_access_flags(
                    archive, info
                )
                if (
                    access_flags is not None
                    and access_flags & ACC_MODULE
                    and _independent_is_valid_module_descriptor(
                        archive.read(info)
                    )
                ):
                    valid_module_descriptors.add(info.filename)
            elif not info.filename.endswith(".class"):
                content = archive.read(info)
                content_sha256 = hashlib.sha256(content).hexdigest()
                resource_candidates[info.filename][0].append({
                    "ordinal": ordinal,
                    "sha256": content_sha256,
                    "semantic_digest": _independent_resource_digest(
                        info.filename,
                        content,
                        content_sha256=content_sha256,
                    ),
                    "semantic_facts": _independent_resource_facts(info.filename, content),
                })
        selected = {}
        for name, versions in classes.items():
            eligible = [
                version for version in versions
                if version == 0 or (
                    mr and target_major >= 9 and version <= target_major
                )
            ]
            if not eligible:
                continue
            version = max(eligible)
            if len(versions[version]) != 1:
                failures.append(f"duplicate_class:{name}:{version}")
                continue
            selected_entry = versions[version][0]
            if selected_entry in valid_module_descriptors:
                continue
            selected[name] = selected_entry
        resources: dict[str, list[dict[str, Any]]] = {}
        for name, versions in resource_candidates.items():
            eligible = [
                version for version in versions
                if version == 0 or (
                    mr and target_major >= 9 and version <= target_major
                )
            ]
            if not eligible:
                continue
            version = max(eligible)
            if len(versions[version]) != 1:
                if is_allowed_duplicate_archive_entry(
                    name, allow_duplicate_maven_metadata=True
                ):
                    continue
                failures.append(f"duplicate_resource:{name}:{version}")
                continue
            resources[name] = [versions[version][0]]
    return {
        "classes": selected,
        "resources": resources,
        "failures": failures,
        "multi_release": mr,
    }


def _independent_resource_category(name: str) -> str:
    upper = name.upper()
    if name.lower().endswith(".xml"):
        return "runtime_topology"
    if name.startswith("META-INF/dubbo/"):
        return "runtime_topology"
    if name.startswith("META-INF/services/") or name == "META-INF/spring.factories" or (
        name.startswith("META-INF/spring/") and name.endswith(".imports")
    ):
        return "runtime_topology"
    if re.fullmatch(r"META-INF/[^/]+\.(?:SF|RSA|DSA|EC)", upper):
        return "operational_security"
    if upper == "META-INF/MANIFEST.MF":
        return "distribution_metadata"
    if re.fullmatch(r"META-INF/maven/[^/]+/[^/]+/pom\.(?:properties|xml)", name):
        return "build_metadata"
    if name.lower().endswith((".so", ".dll", ".dylib", ".jnilib")):
        return "runtime_native"
    return "unknown"


def _independent_resource_digest(
    name: str,
    content: bytes,
    *,
    content_sha256: str | None = None,
) -> str:
    category = _independent_resource_category(name)
    if category != "runtime_topology":
        return content_sha256 or hashlib.sha256(content).hexdigest()
    if name.lower().endswith(".xml"):
        normalized = content.decode("utf-8", errors="surrogateescape").replace(
            "\r\n", "\n"
        ).replace("\r", "\n")
        return hashlib.sha256(
            normalized.encode("utf-8", errors="surrogateescape")
        ).hexdigest()
    lines = []
    for raw in content.decode("utf-8", errors="replace").splitlines():
        value = raw.split("#", 1)[0].strip()
        if value:
            lines.append(value)
    return hashlib.sha256(
        json.dumps(lines, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _independent_resource_facts(name: str, content: bytes) -> list[list[str]]:
    if name.upper() == "META-INF/MANIFEST.MF":
        text = content.decode("utf-8", errors="replace").replace(
            "\r\n", "\n"
        ).replace("\r", "\n")
        unfolded = []
        for line in text.split("\n"):
            if line.startswith(" ") and unfolded:
                unfolded[-1] += line[1:]
            else:
                unfolded.append(line)
        return [
            [key.strip().lower(), value.strip()]
            for line in unfolded
            for key, separator, value in [line.partition(":")]
            if separator
        ]
    if name == "META-INF/spring.factories":
        text = content.decode("iso-8859-1").replace("\r\n", "\n").replace("\r", "\n")
        logical = []
        pending = ""
        for physical in text.split("\n"):
            combined = pending + (physical.lstrip() if pending else physical)
            trailing = len(combined) - len(combined.rstrip("\\"))
            if trailing % 2:
                pending = combined[:-1]
            else:
                logical.append(combined)
                pending = ""
        if pending:
            logical.append(pending)
        facts = []
        for raw in logical:
            stripped = raw.strip()
            if not stripped or stripped.startswith(("#", "!")):
                continue
            separator = next(
                (index for index, item in enumerate(stripped) if item in "=:"),
                -1,
            )
            if separator < 0:
                continue
            key = stripped[:separator].strip()
            for entry in stripped[separator + 1:].split(","):
                if entry.strip():
                    facts.append([f"property_entry:{key}", entry.strip()])
        return facts
    if name.lower().endswith(".xml"):
        return _independent_xml_facts(content)
    if not (
        name.startswith("META-INF/services/")
        or name.startswith("META-INF/dubbo/")
        or (name.startswith("META-INF/spring/") and name.endswith(".imports"))
    ):
        return []
    return [
        ["ordered_entry", value]
        for raw in content.decode("utf-8", errors="replace").splitlines()
        for value in [raw.split("#", 1)[0].strip()]
        if value
    ]


def _independent_artifact_security_unsupported(
    inventory: Mapping[str, Any],
) -> bool:
    """Reconstruct the release's unsupported signer/sealing boundary.

    This intentionally uses only independently inventoried archive names and
    manifest facts.  An ``.SF`` is signing metadata, but OpenJDK does not attach
    code signers unless a supported PKCS7 block is also present.
    """

    resources = inventory.get("resources") or {}
    if any(
        re.fullmatch(
            r"META-INF/[^/]+\.(?:RSA|DSA|EC)",
            str(name).upper(),
        )
        for name in resources
    ):
        return True
    manifest_rows = [
        row
        for name, selected in resources.items()
        if str(name).upper() == "META-INF/MANIFEST.MF"
        for row in selected
        if isinstance(row, Mapping)
    ]
    return any(
        len(fact) == 2
        and str(fact[0]).strip().lower() == "sealed"
        and str(fact[1]).strip().lower() == "true"
        for row in manifest_rows
        for fact in (row.get("semantic_facts") or ())
        if isinstance(fact, (list, tuple))
    )


def _independent_xml_facts(content: bytes) -> list[list[str]]:
    """Oracle-side XML registration inventory built directly from archive bytes."""
    if len(content) > 4 * 1024 * 1024:
        return [["xml_parse_gap", "resource_too_large"]]
    doctype = _ORACLE_XML_DOCTYPE.search(content)
    if b"<!ENTITY" in content.upper() or (
        doctype and b"[" in doctype.group(0)
    ):
        return [["xml_parse_gap", "doctype_or_entity_rejected"]]
    if doctype:
        declaration = doctype.group(0).lower()
        if not any(
            marker in declaration for marker in _ORACLE_ALLOWED_MYBATIS_DTDS
        ):
            return [["xml_parse_gap", "doctype_or_entity_rejected"]]
        content = content[:doctype.start()] + content[doctype.end():]
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return [["xml_parse_gap", "malformed_xml"]]

    def local(tag: Any) -> str:
        # ElementTree parsed nodes always carry a tag (a string for normal
        # elements, or a callable marker for retained comments/PIs).  The
        # former ``tag or \"\"`` therefore created an unexecutable bytecode
        # branch without representing an input state accepted by this parser.
        return str(tag).split("}")[-1].split(":")[-1]

    def nested_attribute(node: Any, child_tag: str, *names: str) -> str:
        for name in names:
            value = str(node.attrib.get(name) or "").strip()
            if value:
                return value
        for child in node:
            if local(child.tag) != child_tag:
                continue
            for name in names:
                value = str(child.attrib.get(name) or "").strip()
                if value:
                    return value
            value = str(child.text or "").strip()
            if value:
                return value
        return ""

    result = [["xml_root", local(root.tag)]]
    bean_types: dict[str, str] = {}
    bean_nodes: dict[str, Any] = {}
    for node in root.iter():
        if local(node.tag) != "bean":
            continue
        identity = str(node.attrib.get("id") or node.attrib.get("name") or "").strip()
        class_name = str(node.attrib.get("class") or "").strip()
        if identity and class_name:
            bean_types[identity] = class_name
            bean_nodes[identity] = node
            result.append(["spring_bean_class", f"{identity}|{class_name}"])
            if str(node.attrib.get("primary") or "").strip().lower() == "true":
                result.append(["spring_bean_primary", f"{identity}|{class_name}"])
            init_method = str(node.attrib.get("init-method") or "").strip()
            if init_method:
                result.append([
                    "spring_init_method",
                    f"{identity}|{class_name}|{init_method}",
                ])

    for node in root.iter():
        tag = local(node.tag)
        if tag == "class" and local(root.tag) == "persistence":
            managed_class = str(node.text or "").strip()
            if managed_class:
                result.append(["jpa_managed_class", managed_class])
        if tag == "component-scan":
            base_package = str(node.attrib.get("base-package") or "").strip()
            if base_package:
                result.append(["spring_component_scan", base_package])
        if tag == "scan":
            base_package = str(node.attrib.get("base-package") or "").strip()
            if base_package:
                result.append(["mybatis_mapper_scan", base_package])
        if tag == "plugin":
            interceptor = str(node.attrib.get("interceptor") or "").strip()
            if interceptor:
                result.append(["mybatis_plugin_registration", interceptor])
        if tag == "typeHandler":
            handler = str(node.attrib.get("handler") or "").strip()
            java_type = str(node.attrib.get("javaType") or "").strip()
            if handler:
                result.append([
                    "mybatis_type_handler_registration",
                    f"{java_type}|{handler}",
                ])
        if tag == "scheduled":
            reference = str(node.attrib.get("ref") or "").strip()
            method = str(node.attrib.get("method") or "").strip()
            target = str(node.attrib.get("target") or "").strip()
            if not reference and target:
                if "." in target and not target.startswith("&"):
                    reference, target_method = target.rsplit(".", 1)
                    method = method or target_method
                else:
                    reference = target
            if reference and method:
                result.append([
                    "spring_scheduled_method",
                    f"{reference}|{bean_types.get(reference, '')}|{method}",
                ])
        if tag == "mapper":
            namespace = str(node.attrib.get("namespace") or "").strip()
            if namespace:
                result.append(["mybatis_mapper_namespace", namespace])
        if tag in {"mapper", "select", "insert", "update", "delete"}:
            statement = str(node.attrib.get("id") or "").strip()
            if statement:
                result.append(["mybatis_statement", statement])
                statement_handler = str(
                    node.attrib.get("typeHandler") or ""
                ).strip()
                if statement_handler:
                    result.append([
                        "mybatis_statement_type_handler",
                        f"{statement}|{statement_handler}",
                    ])
    for identity, node in bean_nodes.items():
        for child in node:
            if local(child.tag) != "property":
                continue
            property_name = str(child.attrib.get("name") or "").strip()
            property_ref = nested_attribute(
                child, "ref", "ref", "bean", "local"
            )
            if property_name and property_ref:
                result.append([
                    "spring_bean_property_ref",
                    "|".join((
                        identity,
                        bean_types.get(identity, ""),
                        property_name,
                        property_ref,
                        bean_types.get(property_ref, ""),
                    )),
                ])

    quartz_factories = {
        "org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean",
        "org.springframework.scheduling.quartz.JobDetailFactoryBean",
    }
    for identity, node in bean_nodes.items():
        if bean_types.get(identity) not in quartz_factories:
            continue
        reference = ""
        method = ""
        for property_node in node:
            if local(property_node.tag) != "property":
                continue
            if property_node.attrib.get("name") == "targetObject":
                reference = nested_attribute(
                    property_node, "ref", "ref", "bean", "local"
                )
            elif property_node.attrib.get("name") == "targetMethod":
                method = nested_attribute(property_node, "value", "value")
        if reference and method:
            result.append([
                "spring_quartz_method",
                f"{reference}|{bean_types.get(reference, '')}|{method}",
            ])
    return result


_RUNTIME_PROFILE_REQUIRED_FIELDS = (
    "target_jvm",
    "runtime_platform_image_identity",
    "target_os",
    "target_arch",
    "container_and_launcher_kind",
    "ordered_runtime_path_entry_descriptors",
    "loader_topology",
    "runtime_code_source_origin_mapping_identity",
    "runtime_security_and_package_sealing_policy_identity",
    "active_profile_identities",
    "external_config_snapshot_identities",
    "agent_transformer_plugin_profile_identities",
    "business_entrypoint_profile",
    "runtime_class_closure_coverage_status",
    "resource_selection_coverage_status",
)

_RUNTIME_PROFILE_SEMANTIC_IDENTITY_FIELDS = (
    "resolved_configuration_properties",
    "runtime_configuration_coverage_status",
    "runtime_configuration_coverage_gaps",
    "entrypoint_discovery_coverage_gaps",
)

_RUNTIME_PROFILE_IDENTITY_FIELDS = (
    _RUNTIME_PROFILE_REQUIRED_FIELDS
    + _RUNTIME_PROFILE_SEMANTIC_IDENTITY_FIELDS
)


def _expected_runtime_profile_identity(
    side: Mapping[str, Any],
    artifacts: list[dict[str, Any]],
    *,
    platform_identity: str,
    jdk_home: Path,
) -> str:
    """Independently reconstruct the production RuntimeProfile identity."""
    raw = dict(side.get("runtime_profile") or {})
    release = _release_values(jdk_home)
    java_major = _release_major(jdk_home)
    raw["runtime_platform_image_identity"] = platform_identity
    raw["target_jvm"] = raw.get("target_jvm") or {
        "vendor": release.get("IMPLEMENTOR", "unknown"),
        "version": release.get("JAVA_VERSION", "unknown"),
        "major": java_major,
    }
    raw["target_os"] = raw.get("target_os") or release.get(
        "OS_NAME", "unknown"
    )
    raw["target_arch"] = raw.get("target_arch") or release.get(
        "OS_ARCH", "unknown"
    )
    path_descriptors = [
        {
            "logical_location": str(item.get("logical_location") or ""),
            "content_sha256": str(item["sha256"]),
            "path_kind": str(item.get("path_kind") or "classpath"),
            "slot": int(item["slot"]),
            "loader_realm": str(item.get("loader_realm") or ""),
        }
        for item in artifacts
    ]
    path_descriptors.sort(key=lambda item: (
        item["loader_realm"], item["slot"], item["logical_location"],
    ))
    raw["ordered_runtime_path_entry_descriptors"] = path_descriptors
    if not raw.get("runtime_code_source_origin_mapping_identity"):
        configured_artifacts = [
            item for item in (side.get("artifacts") or ())
            if isinstance(item, Mapping)
        ]
        raw["runtime_code_source_origin_mapping_identity"] = _identity(
            "runtime_code_source_origin_mapping_identity",
            {
                "origins": [
                    {
                        "logical_location": item["logical_location"],
                        "origin_identity": next(
                            str(configured.get(
                                "runtime_code_source_origin_identity"
                            ) or "")
                            for configured in configured_artifacts
                            if str(configured.get("logical_location") or "")
                            == item["logical_location"]
                        ),
                    }
                    for item in path_descriptors
                ]
            },
        )
    supplied_coverage = dict(raw.get("field_coverage") or {})
    coverage = {
        key: supplied_coverage.get(key) or (
            "known" if key in raw else "unknown"
        )
        for key in _RUNTIME_PROFILE_REQUIRED_FIELDS
    }
    raw["field_coverage"] = coverage
    policy_payload = {
        key: raw.get(key)
        for key in _RUNTIME_PROFILE_IDENTITY_FIELDS
        if key != "ordered_runtime_path_entry_descriptors"
    }
    policy_payload["ordered_runtime_path_roles"] = [
        {
            "logical_location": item.get("logical_location"),
            "path_kind": item.get("path_kind"),
            "slot": item.get("slot"),
            "loader_realm": item.get("loader_realm"),
        }
        for item in path_descriptors
    ]
    policy_payload["field_coverage"] = coverage
    policy_identity = _identity(
        "runtime_profile_policy_identity", policy_payload
    )
    snapshot_payload = {
        **{
            key: raw.get(key) for key in _RUNTIME_PROFILE_IDENTITY_FIELDS
        },
        "field_coverage": coverage,
        "runtime_profile_policy_identity": policy_identity,
    }
    return _identity("runtime_profile_identity", snapshot_payload)


def _attach_expected_artifact_instances(
    artifacts: list[dict[str, Any]], runtime_profile_identity: str,
) -> None:
    outer_sha_cache: dict[Path, str] = {}
    for artifact in artifacts:
        artifact_path = Path(str(artifact["path"])).resolve()
        outer_path = Path(str(
            artifact.get("outer_artifact_path") or artifact_path
        )).expanduser().resolve()
        if not outer_path.is_file():
            raise BinaryValidationError(
                "BINARY_ORACLE_OUTER_ARTIFACT_MISSING", str(outer_path)
            )
        # Flat classpath/module-path entries are their own outer artifact and
        # were already hashed while the runtime input was bound. Re-reading
        # every JAR here only to obtain the identical digest adds a complete
        # extra 1.4 GiB pass on the reported workload. Later inventory, javap
        # snapshot and final-stability checks still independently bind bytes.
        outer_sha = (
            str(artifact["sha256"])
            if outer_path == artifact_path
            else outer_sha_cache.get(outer_path)
        )
        if outer_sha is None:
            outer_sha = _sha256_file(outer_path)
            outer_sha_cache[outer_path] = outer_sha
        payload = {
            "outer_artifact_sha256": outer_sha,
            "container_entry": str(
                artifact.get("container_entry") or "<artifact>"
            ),
            "content_sha256": str(artifact["sha256"]),
            "runtime_profile_identity": runtime_profile_identity,
            "path_owner_loader_realm_identity": str(
                artifact.get("loader_realm") or ""
            ),
            "runtime_path_kind": str(
                artifact.get("path_kind") or "classpath"
            ),
            "runtime_classpath_index": int(artifact["slot"]),
            "container_loader_policy_version": str(
                artifact.get("container_loader_policy_version")
                or "flat-parent-first-v1"
            ),
            "runtime_code_source_origin_identity": str(
                artifact.get("runtime_code_source_origin_identity") or ""
            ),
        }
        artifact["_expected_artifact_instance_payload"] = payload
        artifact["_expected_artifact_instance_identity"] = _identity(
            "artifact_instance_identity", payload
        )


def _final_artifact_stability(
    artifacts_by_side: Iterable[
        tuple[str, Iterable[Mapping[str, Any]]]
    ],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    truth = []
    issues = []
    for side_name, artifacts in artifacts_by_side:
        for artifact in artifacts:
            path = Path(str(artifact["path"]))
            try:
                actual_sha256 = _sha256_file(path)
            except OSError:
                actual_sha256 = "MISSING_OR_UNREADABLE"
            expected_sha256 = str(artifact["sha256"])
            truth.append({
                "side": side_name,
                "loader_realm": str(artifact.get("loader_realm") or ""),
                "slot": int(artifact["slot"]),
                "expected_sha256": expected_sha256,
                "actual_sha256": actual_sha256,
            })
            if actual_sha256 != expected_sha256:
                issues.append(_validation_issue(
                    "artifact_inventory",
                    "ORACLE_ARTIFACT_CHANGED_DURING_VALIDATION",
                    side=side_name,
                    path=str(path),
                    expected_sha256=expected_sha256,
                    actual_sha256=actual_sha256,
                ))
    return issues, truth


def _artifact_configs(
    side: Mapping[str, Any],
    digest_cache: dict[Path, str] | None = None,
) -> list[dict[str, Any]]:
    result = []
    seen_slots = set()
    path_digests = digest_cache if digest_cache is not None else {}
    for raw in side.get("artifacts") or ():
        item = dict(raw)
        path = Path(str(item.get("path") or "")).expanduser().resolve()
        if not path.is_file():
            raise BinaryValidationError("BINARY_ORACLE_ARTIFACT_MISSING", str(path))
        key = (str(item.get("loader_realm") or ""), int(item.get("slot")))
        if key in seen_slots:
            raise BinaryValidationError("BINARY_ORACLE_RUNTIME_SLOT_DUPLICATE", str(key))
        seen_slots.add(key)
        item["path"] = str(path)
        digest = path_digests.get(path)
        if digest is None:
            digest = _sha256_file(path)
            path_digests[path] = digest
        item["sha256"] = digest
        result.append(item)
    return sorted(result, key=lambda item: (str(item.get("loader_realm")), int(item.get("slot"))))


def _ordered_artifacts_for_realm(
    artifacts: Iterable[Mapping[str, Any]],
    topology: Mapping[str, Any],
    entrypoint_realm: str,
    *,
    require_parent_first_unnamed: bool = False,
) -> list[dict[str, Any]]:
    """Return the exact artifact-instance search order for one loader realm."""
    items = [dict(item) for item in artifacts]
    by_realm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        by_realm[str(item.get("loader_realm") or "")].append(item)
    for values in by_realm.values():
        values.sort(key=lambda item: (int(item.get("slot") or 0), item["path"]))
    realms = {
        # The comprehension filter below already proves a non-empty identity.
        # Avoid advertising an input branch that cannot reach this expression.
        str(item.get("identity")): dict(item)
        for item in topology.get("realms") or ()
        if isinstance(item, Mapping) and item.get("identity")
    }
    platform = {
        identity for identity, item in realms.items()
        if item.get("kind") == "platform"
    }

    def effective(realm: str, stack: tuple[str, ...] = ()) -> list[dict[str, Any]]:
        current = str(realm)
        if current in platform:
            return []
        if current in stack:
            raise BinaryValidationError(
                "BINARY_ORACLE_LOADER_TOPOLOGY_CYCLE", current
            )
        config = realms.get(current)
        if not config:
            raise BinaryValidationError(
                "BINARY_ORACLE_LOADER_REALM_MISSING", current
            )
        delegation = str(config.get("delegation") or "parent_first")
        module_mode = str(config.get("module_mode") or "unnamed")
        if module_mode != "unnamed" or delegation not in {
            "parent_first", "child_first",
        }:
            raise BinaryValidationError(
                "BINARY_ORACLE_LOADER_TOPOLOGY_UNSUPPORTED", current
            )
        if require_parent_first_unnamed and delegation != "parent_first":
            raise BinaryValidationError(
                "BINARY_ORACLE_LOADER_TOPOLOGY_UNSUPPORTED", current
            )
        parent = str(config.get("parent") or "")
        if not parent:
            raise BinaryValidationError(
                "BINARY_ORACLE_PLATFORM_REALM_UNREACHABLE", str(realm)
            )
        parent_items = effective(parent, (*stack, current))
        own_items = list(by_realm.get(current, ()))
        return (
            [*parent_items, *own_items]
            if delegation == "parent_first"
            else [*own_items, *parent_items]
        )

    return effective(str(entrypoint_realm))


def _oracle_artifacts_for_entrypoint_realms(
    artifacts: Iterable[Mapping[str, Any]],
    topology: Mapping[str, Any],
    entrypoint_realms: Iterable[str],
) -> list[dict[str, Any]]:
    """Flatten an equivalent parent-first URL search order for the JVM Oracle.

    Multiple entrypoint realms are accepted only when their exact artifact
    instance order is identical. Paths alone are insufficient because the
    same file may be mounted in more than one loader realm.
    """
    items = [dict(item) for item in artifacts]

    def location(item: Mapping[str, Any]) -> tuple[str, int]:
        return (
            str(item.get("loader_realm") or ""),
            int(item.get("slot") or 0),
        )

    by_location = {location(item): item for item in items}
    if len(by_location) != len(items):
        raise BinaryValidationError(
            "BINARY_ORACLE_RUNTIME_SLOT_DUPLICATE",
            "duplicate loader realm/runtime slot",
        )
    effective_orders = {
        tuple(location(item) for item in _ordered_artifacts_for_realm(
            items,
            topology,
            str(realm),
            require_parent_first_unnamed=True,
        ))
        for realm in entrypoint_realms if str(realm)
    }
    if len(effective_orders) != 1:
        raise BinaryValidationError(
            "BINARY_ORACLE_ENTRYPOINT_REALM_ORDER_AMBIGUOUS",
            json.dumps(
                [list(map(list, order)) for order in sorted(effective_orders)],
                ensure_ascii=False,
            ),
        )
    order = next(iter(effective_orders))
    return [by_location[item] for item in order]


def _compile_oracle(
    jdk_home: Path,
    destination: Path,
    *,
    timeout_seconds: float = 300,
    max_attempts: int = 1,
    phase_deadline: float | None = None,
) -> str:
    destination.mkdir(parents=True, exist_ok=True)
    javac = jdk_tool_path(jdk_home, "javac")
    attempt_limit = max(int(max_attempts), 1)
    attempts_made = 0
    # attempt_limit is always at least one, so the loop always assigns the
    # result before it is inspected below.
    for attempt in range(1, attempt_limit + 1):
        remaining = (
            phase_deadline - time.perf_counter()
            if phase_deadline is not None else None
        )
        if remaining is not None and remaining <= 0.01:
            raise BinaryValidationError(
                "BINARY_ORACLE_RUNTIME_PHASE_TIME_BUDGET_EXCEEDED",
                "runtime Oracle phase budget exhausted during helper compilation",
            )
        attempts_made = attempt
        completed = execute_binary_tool(
            [str(javac), "-encoding", "UTF-8", "-source", "8", "-target", "8", "-d", str(destination), str(ORACLE_SOURCE)],
            stage="binary_oracle.compile",
            reason_prefix="BINARY_ORACLE_COMPILE",
            timeout_seconds=(
                min(timeout_seconds, remaining)
                if remaining is not None else timeout_seconds
            ),
        )
        if completed.succeeded:
            break
        if not tool_failure_is_retryable(completed.failure):
            break
    if not completed.succeeded:
        failure = completed.failure.to_mapping()
        failure.update({
            "attempt_count": attempts_made,
            "max_attempts": attempt_limit,
            "retryable": tool_failure_is_retryable(completed.failure),
            "retry_exhausted": bool(
                tool_failure_is_retryable(completed.failure)
                and attempts_made >= attempt_limit
            ),
        })
        raise BinaryValidationError(
            (
                "BINARY_ORACLE_COMPILE_RETRY_EXHAUSTED"
                if failure["retry_exhausted"] and attempt_limit > 1
                else "BINARY_ORACLE_COMPILE_FAILED"
            ),
            json.dumps(failure, ensure_ascii=False),
        )
    try:
        release_identity = resolve_jdk_release(jdk_home)["identity"]
    except (JdkPreflightError, OSError) as error:
        raise BinaryValidationError(
            "BINARY_ORACLE_JDK_RELEASE_MISSING", str(error)
        ) from error
    return _identity("runtime_outcome_oracle_helper_identity", {
        "source_sha256": _sha256_file(ORACLE_SOURCE),
        "target_jdk_release_sha256": release_identity,
        "policy_version": POLICY_VERSION,
    })


def _observe_classes(
    jdk_home: Path,
    artifacts: list[dict[str, Any]],
    initial_classes: Iterable[str],
    *,
    compile_timeout_seconds: float = 300,
    runtime_timeout_seconds: float = 300,
    phase_time_budget_seconds: float | None = None,
    max_attempts: int = 1,
    progress_callback: ValidationProgressCallback | None = None,
    progress_label: str = "",
    string_pool: dict[str, str] | None = None,
) -> tuple[dict[str, dict[str, Any]], str]:
    phase_deadline = (
        time.perf_counter() + float(phase_time_budget_seconds)
        if phase_time_budget_seconds is not None
        and float(phase_time_budget_seconds) > 0
        else None
    )
    with short_temporary_directory(prefix="runtime-oracle") as temp_text:
        temp = Path(temp_text)
        helper_identity = _compile_oracle(
            jdk_home,
            temp / "helper",
            timeout_seconds=compile_timeout_seconds,
            max_attempts=max_attempts,
            phase_deadline=phase_deadline,
        )
        classpath_file = temp / "classpath.txt"
        classpath_file.write_text(
            "\n".join(item["path"] for item in artifacts) + "\n", encoding="utf-8"
        )
        observations: dict[str, dict[str, Any]] = {}
        pending = {
            str(item).replace("/", ".") for item in initial_classes if item
        }
        pending_heap = list(pending)
        heapq.heapify(pending_heap)
        java = jdk_tool_path(jdk_home, "java")
        java_options = ["-Xverify:all"]
        if (jdk_home / "jre" / "lib" / "rt.jar").is_file():
            # Java 8 otherwise searches machine-global extension directories.
            # Bind Oracle observations to the selected JDK image only.
            java_options.append(
                f"-Djava.ext.dirs={jdk_home / 'jre' / 'lib' / 'ext'}"
            )

        def observe_batch(batch: tuple[str, ...], round_number: int):
            classes_file = temp / f"classes-{round_number}.txt"
            classes_file.write_text("\n".join(batch) + "\n", encoding="utf-8")
            last_problem: dict[str, Any] = {}
            attempt_limit = max(int(max_attempts), 1)
            attempts_made = 0
            retryable = False
            for attempt in range(1, attempt_limit + 1):
                remaining = (
                    phase_deadline - time.perf_counter()
                    if phase_deadline is not None else None
                )
                if remaining is not None and remaining <= 0.01:
                    raise BinaryValidationError(
                        "BINARY_ORACLE_RUNTIME_PHASE_TIME_BUDGET_EXCEEDED",
                        json.dumps({
                            "completed_observation_count": len(observations),
                            "pending_observation_count": len(pending),
                            # observe_batch is submitted only from a non-empty
                            # pending frontier, so every batch has a first row.
                            "batch_first_class": batch[0],
                            "phase_time_budget_seconds": (
                                phase_time_budget_seconds
                            ),
                        }, ensure_ascii=False),
                    )
                attempts_made = attempt
                completed = execute_binary_tool(
                    [
                        str(java), *java_options, "-cp", str(temp / "helper"),
                        "RuntimeOutcomeOracle", str(classpath_file),
                        str(classes_file),
                    ],
                    stage="binary_oracle.runtime_observation",
                    reason_prefix="BINARY_ORACLE_EXECUTION",
                    timeout_seconds=(
                        min(runtime_timeout_seconds, remaining)
                        if remaining is not None else runtime_timeout_seconds
                    ),
                    require_stdout=True,
                )
                if not completed.succeeded:
                    last_problem = completed.failure.to_mapping()
                    retryable = tool_failure_is_retryable(completed.failure)
                    if not retryable:
                        break
                    continue
                candidate_rows = []
                observed_batch = set()
                dependencies: set[str] = set()
                malformed_line = ""
                # A 12k-class batch can emit a very large JSONL string.
                # Decode directly from the immutable stdout by character
                # offset; splitlines() otherwise duplicates the full batch.
                try:
                    rows = _iter_jsonl_values(completed.stdout)
                    for row in rows:
                        name = str(row.get("class_name") or "")
                        observed_batch.add(name.replace("/", "."))
                        candidate_rows.append((name, row))
                        if row.get("status") == "definition_ready":
                            for dependency in [
                                row.get("super_name"),
                                *(row.get("interfaces") or ()),
                            ]:
                                if dependency:
                                    dependencies.add(
                                        str(dependency).replace("/", ".")
                                    )
                except json.JSONDecodeError as error:
                    line_start = completed.stdout.rfind(
                        "\n", 0, error.pos
                    ) + 1
                    malformed_line = completed.stdout[
                        line_start:line_start + 200
                    ]
                if malformed_line:
                    last_problem = {
                        "reason_code": "BINARY_ORACLE_OUTPUT_INVALID",
                        "failure_kind": "malformed_output",
                        "output_excerpt": malformed_line,
                    }
                    retryable = False
                    break
                missing = set(batch).difference(observed_batch)
                if missing:
                    last_problem = {
                        "reason_code": "BINARY_ORACLE_OUTPUT_INCOMPLETE",
                        "failure_kind": "incomplete_output",
                        "missing_classes": sorted(missing)[:20],
                    }
                    retryable = False
                    break
                return candidate_rows, dependencies
            last_problem.update({
                "attempt_count": attempts_made,
                "max_attempts": attempt_limit,
                "retryable": retryable,
                "retry_exhausted": bool(
                    retryable and attempts_made >= attempt_limit
                ),
            })
            original_reason = str(
                last_problem.get("reason_code")
                or "BINARY_ORACLE_EXECUTION_FAILED"
            )
            raise BinaryValidationError(
                (
                    "BINARY_ORACLE_EXECUTION_RETRY_EXHAUSTED"
                    if last_problem["retry_exhausted"] and attempt_limit > 1
                    else original_reason
                ),
                json.dumps(last_problem, ensure_ascii=False),
            )

        requested = set(pending)
        rounds = 0
        batch_size, workers, available_memory = (
            _runtime_oracle_execution_shape(len(pending))
        )
        if len(requested) >= MIN_CLASSES_FOR_CONCURRENT_RUNTIME_ORACLE:
            _notify_progress(
                progress_callback,
                "validation-runtime",
                f"{progress_label or '当前侧'}：目标 JVM 校验资源策略已确定",
                0,
                len(requested),
                (
                    f"batch_size={batch_size};workers={workers};"
                    f"available_memory_bytes={available_memory}"
                ),
            )

        def next_batch() -> tuple[str, ...]:
            batch = []
            while pending_heap and len(batch) < batch_size:
                class_name = heapq.heappop(pending_heap)
                # Heap and set entries are inserted together and are removed
                # only here; duplicate heap entries are never admitted.
                pending.remove(class_name)
                batch.append(class_name)
            return tuple(batch)

        def merge_batch_result(round_number, batch, result, active=()):
            candidate_rows, dependencies = result
            for name, row in candidate_rows:
                if string_pool is not None:
                    row = _compact_json_values(row, string_pool)
                observations[name] = row
            for dependency in dependencies:
                internal_name = dependency.replace(".", "/")
                if (
                    dependency not in requested
                    and internal_name not in observations
                ):
                    requested.add(dependency)
                    pending.add(dependency)
                    heapq.heappush(pending_heap, dependency)
            in_flight = sum(len(item[1]) for item in active)
            _notify_progress(
                progress_callback,
                "validation-runtime",
                f"{progress_label or '目标运行时'}：已完成 JVM 观察批次 {round_number}",
                len(observations),
                len(observations) + len(pending) + in_flight,
                f"{batch[0]} … {batch[-1]}",
            )

        if workers == 1:
            while pending:
                batch = next_batch()
                rounds += 1
                merge_batch_result(
                    rounds, batch, observe_batch(batch, rounds)
                )
        else:
            # Keep only a rolling window of isolated JVM batches. Results are
            # merged in submission order; newly discovered hierarchy classes
            # enter the same sorted queue before the next batch is submitted.
            # This preserves complete closure without retaining every child
            # result or starting redundant post-frontier JVMs.
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="binary-oracle-runtime",
            ) as executor:
                active = []
                while pending or active:
                    while pending and len(active) < workers:
                        batch = next_batch()
                        rounds += 1
                        active.append((
                            rounds,
                            batch,
                            executor.submit(observe_batch, batch, rounds),
                        ))
                    round_number, batch, future = active.pop(0)
                    merge_batch_result(
                        round_number, batch, future.result(), active
                    )
        return observations, helper_identity


@lru_cache(maxsize=8_192)
def _file_url_path(value: str) -> Path | None:
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme != "file":
        return None
    decoded = _decoded_file_url_path(parsed, windows=os.name == "nt")
    return Path(decoded).resolve() if decoded else None


def _decoded_file_url_path(parsed: Any, *, windows: bool) -> str:
    """Decode a JVM file URL without turning ``/C:/`` into ``C:\\C:``.

    JVM resource/code-source URLs use URI paths even on Windows.  A leading
    slash before a drive designator is URI syntax, not a Windows root-relative
    path.  UNC authorities remain part of the resulting path.
    """

    path = unquote(str(parsed.path or ""))
    authority = unquote(str(parsed.netloc or ""))
    remote_authority = authority if authority.lower() != "localhost" else ""
    if windows:
        if re.fullmatch(r"[A-Za-z]:", remote_authority):
            path = f"{remote_authority}{path}"
        elif remote_authority:
            path = f"//{remote_authority}{path}"
        elif re.match(r"^/[A-Za-z]:(?:/|$)", path):
            path = path[1:]
        if not path:
            return ""
        return ntpath.normpath(path.replace("/", "\\"))
    if remote_authority:
        path = f"//{remote_authority}{path}"
    return path


def _provider_resource_path(value: str) -> Path | None:
    resource = str(value or "")
    if resource.startswith("jar:"):
        resource = resource[4:].split("!/", 1)[0]
    return _file_url_path(resource)


def _oracle_provider_location(observation: Mapping[str, Any]) -> str:
    """Return independent provider evidence for classpath and named modules.

    ``ClassLoader.getResource`` is not authoritative for every resolved JDK
    module.  In particular, classes owned by ``jdk.jdi`` and ``jdk.attach``
    can load successfully while a child URLClassLoader cannot obtain their
    class resource.  Their protection-domain code source still identifies the
    exact ``jrt:`` module.  Prefer the resource URL because it identifies an
    archive entry, then use the code-source location as the JVM-supported
    fallback instead of declaring a valid platform resolution false.
    """
    resource = str(observation.get("provider_resource_url") or "")
    if resource and not resource.startswith("<resource-error:"):
        return resource
    code_source = str(observation.get("provider_url") or "")
    if code_source and not code_source.startswith("<"):
        return code_source
    return ""


def _is_bound_jdk8_platform_path(path: Path, jdk_home: Path) -> bool:
    """Recognize only platform containers inside the selected JDK 8 image."""
    resolved = path.resolve()
    runtime_root = (jdk_home / "jre").resolve()
    bootstrap_archives = {
        (runtime_root / "lib" / name).resolve()
        for name in (
            "resources.jar",
            "rt.jar",
            "sunrsasign.jar",
            "jsse.jar",
            "jce.jar",
            "charsets.jar",
            "jfr.jar",
        )
    }
    if resolved in bootstrap_archives:
        return True
    extension_root = (runtime_root / "lib" / "ext").resolve()
    if resolved.parent == extension_root and resolved.suffix.lower() == ".jar":
        return True
    try:
        resolved.relative_to((runtime_root / "classes").resolve())
    except ValueError:
        return False
    return True


def _opcode_name(value: int) -> str:
    return {
        178: "getstatic", 179: "putstatic", 180: "getfield", 181: "putfield",
        182: "invokevirtual", 183: "invokespecial", 184: "invokestatic",
        185: "invokeinterface",
    }.get(int(value), f"opcode-{value}")


def _parse_javap_structural(output: str) -> dict[str, Any]:
    """Compatibility entry point for focused parser tests/integrations."""
    return parse_structural_javap(output)


def _scan_structural_edges(
    artifact: Path, inventory: Mapping[str, Any], javap: str
) -> dict[str, Any]:
    """Run the same stable/raw-bound javap observation as the direct oracle.

    This path is a fallback only when no shared direct scan was supplied.  It
    must not silently regress to locale-dependent javap text or a header-only
    parser, because legal JVM owner/member/descriptor characters are exactly
    where that older path diverged from production facts.
    """
    combined = {
        "type_edges": set(), "class_init_edges": set(),
        "clinit_classes": set(), "semantic_instructions": set(),
        "declared_members": set(),
    }
    scanned = scan_final_artifact(
        artifact,
        javap=javap,
        max_workers=1,
        include_nested_runtime_jars=False,
        include_structural_facts=True,
        cache_result=False,
    )
    failures = [str(item) for item in scanned.get("failures") or ()]
    if not scanned.get("complete") and not failures:
        failures.append("structural_fallback_scan_incomplete")
    structural = scanned.get("structural_facts") or {}
    observed_classes = set(structural.get("class_names") or ())
    expected_classes = {
        str(name) for name in inventory.get("classes", {})
    }
    if observed_classes != expected_classes:
        failures.append(
            "structural_fallback_class_universe_mismatch:"
            f"expected={sorted(expected_classes)!r}:"
            f"observed={sorted(observed_classes)!r}"
        )
    for key in combined:
        for value in structural.get(key) or ():
            combined[key].add(
                tuple(value) if isinstance(value, list) else value
            )
    return {**combined, "failures": failures}


def _production_structural_truth_for_artifact(
    connection: sqlite3.Connection,
    artifact_instance_identity: str,
    issues: list[dict[str, Any]],
) -> tuple[set[tuple[Any, ...]], set[tuple[Any, ...]]]:
    """Project structural production facts for exactly one artifact.

    The old implementation retained projections for every edge on both sides
    at once.  At multi-million-edge scale those Python tuples cost far more
    memory than the SQLite evidence itself and force Windows into page-file
    thrashing.  The caller compares and releases one artifact at a time; the
    query remains complete and uses the caller-artifact index created with the
    fact store.
    """

    production_type: set[tuple[Any, ...]] = set()
    production_init: set[tuple[Any, ...]] = set()
    for edge in connection.execute(
        """
        SELECT e.bytecode_offset,e.symbolic_owner,e.symbolic_name,
               e.symbolic_descriptor,e.edge_kind,e.opcode,e.edge_json,
               m.class_name AS caller_class_name,
               m.member_name AS caller_member_name,
               m.descriptor AS caller_descriptor
        FROM direct_edges AS e
        JOIN members AS m ON m.member_identity=e.caller_member_identity
        WHERE e.caller_artifact_instance_identity=? AND (
            e.edge_kind IN (
                'type','class_init','method','field',
                'invokedynamic_bootstrap',
                'ldc_constant_dynamic_bootstrap','ldc_handle'
            ) OR e.edge_kind LIKE 'invokedynamic_handle_%'
              OR e.edge_kind LIKE 'ldc_bootstrap_handle_%'
        )
        """,
        (artifact_instance_identity,),
    ):
        caller = (
            edge["caller_class_name"], edge["caller_member_name"],
            edge["caller_descriptor"], int(edge["bytecode_offset"]),
        )
        payload = json.loads(edge["edge_json"])
        # direct_edges.edge_kind is NOT NULL and this query only admits
        # explicit edge kinds/prefixes, so an empty fallback cannot occur.
        edge_kind = str(edge["edge_kind"])
        if edge_kind == "type":
            production_type.add((
                *caller, edge["symbolic_owner"],
                str(payload.get("type_use_kind") or "type_instruction"),
            ))
            continue
        if edge_kind == "class_init":
            production_init.add((
                *caller, edge["symbolic_owner"],
                str(payload.get("trigger_kind") or ""),
            ))
            continue
        declared_owners = payload.get(LOADING_CONSTRAINT_TYPE_OWNERS_KEY)
        if declared_owners is None:
            continue
        if (
            not isinstance(declared_owners, list)
            or not declared_owners
            or any(
                not isinstance(item, str) or not item
                for item in declared_owners
            )
            or tuple(declared_owners)
            != tuple(sorted(set(declared_owners)))
        ):
            issues.append(_validation_issue(
                "structural_edge",
                "ORACLE_LOADING_CONSTRAINT_DECLARATION_INVALID",
                artifact_instance_identity=artifact_instance_identity,
                caller=caller,
                edge_kind=edge_kind,
            ))
            continue
        if edge_kind == "method":
            reference_kind = (
                "interface_method" if bool(payload.get("interface"))
                else "method"
            )
        elif edge_kind == "field":
            reference_kind = "field"
        else:
            handle = (
                payload.get("bootstrap") or {}
                if edge_kind == "invokedynamic_bootstrap" else payload
            )
            try:
                tag = int(handle.get("tag") or 0)
            except (AttributeError, TypeError, ValueError):
                tag = 0
            reference_kind = METHOD_HANDLE_REFERENCE_KIND_BY_TAG.get(tag) or ""
            if not reference_kind:
                issues.append(_validation_issue(
                    "structural_edge",
                    "ORACLE_LOADING_CONSTRAINT_REFERENCE_KIND_INVALID",
                    artifact_instance_identity=artifact_instance_identity,
                    caller=caller,
                    edge_kind=edge_kind,
                    tag=tag,
                ))
                continue
        for referenced_owner in declared_owners:
            production_type.add((
                *caller, referenced_owner,
                "member_reference_descriptor",
                str(edge["symbolic_owner"]),
                str(edge["symbolic_name"]),
                str(edge["symbolic_descriptor"]),
                reference_kind,
            ))
    return production_type, production_init


def _validate_structural_edges(
    connection: sqlite3.Connection,
    artifacts: list[dict[str, Any]],
    inventories: list[dict[str, Any]],
    *,
    javap: str,
    scan_cache: dict[tuple[Any, ...], _StructuralTruth] | None = None,
    direct_scan_cache: dict[
        tuple[str, str], bytes | Mapping[str, Any] | _OracleScanEvidence
    ] | None = None,
    string_pool: dict[str, str] | None = None,
    progress_callback: ValidationProgressCallback | None = None,
    progress_label: str = "",
    retain_truth_rows: bool = True,
    production_structural_cache: _ProductionStructuralSpoolCache | None = None,
    validated_projection_cache: dict[
        tuple[Any, ...], dict[str, Any]
    ] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    instance_by_location, binding_issues = _artifact_instance_bindings(
        connection, artifacts, domain="structural_edge"
    )
    issues.extend(binding_issues)
    truth_type = []
    truth_init = []
    semantic_instructions = []
    clinit_classes = set()
    declared_members = set()
    declared_members_by_artifact = []
    compact_artifact_sets = []
    compact_counts = defaultdict(int)
    artifact_count = len(artifacts)
    _notify_progress(
        progress_callback,
        "validation-structural",
        f"{progress_label or '当前侧'}：开始校验结构和指令事实",
        0,
        artifact_count,
    )
    for artifact_index, (artifact, inventory) in enumerate(
        zip(artifacts, inventories), start=1,
    ):
        instance_identity = instance_by_location.get(
            (
                str(artifact.get("loader_realm") or ""),
                int(artifact["slot"]),
            )
        )
        if not instance_identity:
            continue
        artifact_issue_start = len(issues)
        artifact_path = Path(artifact["path"])
        if (
            production_structural_cache is None
            and _sha256_file(artifact_path) != artifact["sha256"]
        ):
            issues.append(_validation_issue(
                "artifact_inventory",
                "ORACLE_ARTIFACT_CHANGED_DURING_STRUCTURAL_VALIDATION",
                artifact=artifact["path"],
            ))
            continue
        scan_key = (
            str(artifact["sha256"]),
            str(javap),
            tuple(sorted(
                (str(name), str(entry))
                for name, entry in inventory["classes"].items()
            )),
        )
        if (
            production_structural_cache is not None
            and instance_identity not in production_structural_cache
        ):
            issues.append(_validation_issue(
                "structural_edge",
                "ORACLE_PRODUCTION_STRUCTURAL_CACHE_MISSING",
                artifact_instance_identity=instance_identity,
            ))
            continue
        # Production names the trigger, not the opcode mnemonic, identically
        # for all supported active-use opcodes.
        if production_structural_cache is None:
            actual_t, actual_i = _production_structural_truth_for_artifact(
                connection, instance_identity, issues
            )
        else:
            actual_t, actual_i = production_structural_cache.get(
                instance_identity
            )
        direct_scan_key = (str(artifact["sha256"]), str(javap))
        projection_key = (
            "structural", *direct_scan_key, id(inventory)
        )
        cached_projection = (
            validated_projection_cache.get(projection_key)
            if validated_projection_cache is not None else None
        )
        if (
            cached_projection is not None
            and not retain_truth_rows
            and len(issues) == artifact_issue_start
        ):
            ordered_actual_type = sorted(actual_t)
            ordered_actual_init = sorted(actual_i)
            actual_type_identity = _artifact_truth_identity(
                "binary_oracle_type_edge_artifact_truth",
                ordered_actual_type,
            )
            actual_init_identity = _artifact_truth_identity(
                "binary_oracle_class_init_edge_artifact_truth",
                ordered_actual_init,
            )
            projection_matches = bool(
                len(ordered_actual_type)
                == cached_projection.get("type_edge_count")
                and actual_type_identity
                == cached_projection.get("type_edge_identity")
                and len(ordered_actual_init)
                == cached_projection.get("class_init_edge_count")
                and actual_init_identity
                == cached_projection.get("class_init_edge_identity")
            )
        else:
            projection_matches = False
        if projection_matches:
            compact_artifact_sets.append({
                "artifact_instance_identity": instance_identity,
                "type_edge_count": cached_projection["type_edge_count"],
                "type_edge_set_identity": cached_projection[
                    "type_edge_identity"
                ],
                "class_init_edge_count": cached_projection[
                    "class_init_edge_count"
                ],
                "class_init_edge_set_identity": cached_projection[
                    "class_init_edge_identity"
                ],
                "semantic_instruction_count": cached_projection[
                    "semantic_instruction_count"
                ],
                "semantic_instruction_set_identity": cached_projection[
                    "semantic_instruction_identity"
                ],
                "declared_member_count": cached_projection[
                    "declared_member_count"
                ],
                "declared_member_set_identity": cached_projection[
                    "declared_member_identity"
                ],
            })
            compact_counts["type_edges"] += cached_projection[
                "type_edge_count"
            ]
            compact_counts["class_init_edges"] += cached_projection[
                "class_init_edge_count"
            ]
            compact_counts["semantic_instructions"] += cached_projection[
                "semantic_instruction_count"
            ]
            compact_counts["declared_members"] += cached_projection[
                "declared_member_count"
            ]
            clinit_classes.update(
                cached_projection.get("clinit_classes") or ()
            )
            del actual_t, actual_i
            _notify_counted_progress(
                progress_callback,
                "validation-structural",
                f"{progress_label or '当前侧'}：结构和指令事实校验中",
                artifact_index,
                artifact_count,
                str(artifact.get("path") or ""),
            )
            continue
        scanned = scan_cache.get(scan_key) if scan_cache is not None else None
        if scanned is None:
            direct_scan_payload = (
                direct_scan_cache.get(direct_scan_key)
                if direct_scan_cache is not None else None
            )
            direct_scan = (
                direct_scan_cache.get_structural_evidence(
                    direct_scan_key, string_pool
                )
                if (
                    direct_scan_payload is not None
                    and isinstance(
                        direct_scan_cache, _OracleScanSpoolCache
                    )
                )
                else _normalize_oracle_scan(
                    direct_scan_payload, string_pool
                )
                if direct_scan_payload is not None
                else None
            )
            if (
                direct_scan_cache is not None
                and direct_scan is not None
                and direct_scan is not direct_scan_payload
                and not isinstance(direct_scan_cache, _OracleScanSpoolCache)
            ):
                direct_scan_cache[direct_scan_key] = direct_scan
            if direct_scan is not None and not direct_scan.complete:
                # The shared javap observation already failed closed (most
                # often because the phase-wide deadline expired). Starting an
                # unbudgeted structural fallback here would multiply Step4
                # runtime after activation is already impossible.
                scanned = _StructuralTruth(
                    type_edges=frozenset(),
                    class_init_edges=frozenset(),
                    clinit_classes=frozenset(),
                    semantic_instructions=frozenset(),
                    declared_members=frozenset(),
                    failures=direct_scan.failures or (
                        "shared_direct_oracle_scan_incomplete",
                    ),
                )
            elif (
                direct_scan is not None
                and direct_scan.structural_class_names
                == set(inventory["classes"])
            ):
                # Both validators parse the same immutable javap observation
                # with separate parsers. Reuse only when the observed class
                # universe is exactly the independent archive inventory;
                # any disagreement is itself incomplete independent truth.
                scanned = direct_scan.structural_truth
            elif direct_scan is not None:
                scanned = _StructuralTruth(
                    type_edges=frozenset(),
                    class_init_edges=frozenset(),
                    clinit_classes=frozenset(),
                    semantic_instructions=frozenset(),
                    declared_members=frozenset(),
                    failures=(
                        "shared_direct_oracle_class_universe_mismatch",
                    ),
                )
            else:
                raw_scanned = _scan_structural_edges(
                    artifact_path, inventory, javap
                )
                failures = tuple(str(item) for item in raw_scanned["failures"])
                if failures:
                    # Preserve the fail-closed behavior: partial structural
                    # output is never compared as authoritative truth.
                    scanned = _StructuralTruth(
                        type_edges=frozenset(),
                        class_init_edges=frozenset(),
                        clinit_classes=frozenset(),
                        semantic_instructions=frozenset(),
                        declared_members=frozenset(),
                        failures=failures,
                    )
                else:
                    def compact_tuple(value):
                        normalized = tuple(value)
                        return (
                            _compact_json_values(normalized, string_pool)
                            if string_pool is not None else normalized
                        )

                    scanned = _StructuralTruth(
                        type_edges=frozenset(
                            compact_tuple(
                                (
                                    *item[:5],
                                    _OPCODE_TO_TYPE_USE[item[5]],
                                    *item[6:],
                                )
                            )
                            for item in raw_scanned["type_edges"]
                        ),
                        class_init_edges=frozenset(
                            compact_tuple(item)
                            for item in raw_scanned["class_init_edges"]
                        ),
                        clinit_classes=frozenset(
                            _pooled_string(str(item), string_pool)
                            if string_pool is not None else str(item)
                            for item in raw_scanned["clinit_classes"]
                        ),
                        semantic_instructions=frozenset(
                            compact_tuple(item)
                            for item in raw_scanned["semantic_instructions"]
                        ),
                        declared_members=frozenset(
                            compact_tuple(item)
                            for item in raw_scanned["declared_members"]
                        ),
                        failures=(),
                    )
            if scan_cache is not None:
                scan_cache[scan_key] = scanned
        if scanned.failures:
            issues.append(_validation_issue(
                "type_class_init", "ORACLE_STRUCTURAL_SCAN_INCOMPLETE",
                artifact=artifact["path"], failures=list(scanned.failures),
            ))
            continue
        truth_t = scanned.type_edges
        truth_i = scanned.class_init_edges
        ordered_semantic = sorted(scanned.semantic_instructions)
        ordered_declared = sorted(scanned.declared_members)
        if retain_truth_rows:
            semantic_instructions.extend(ordered_semantic)
            declared_members.update(scanned.declared_members)
            declared_members_by_artifact.append({
                "artifact_instance_identity": instance_identity,
                "members": [list(item) for item in ordered_declared],
            })
        for missing in sorted(truth_t - actual_t):
            issues.append(_validation_issue("type_class_init", "ORACLE_TYPE_EDGE_MISSING", edge=missing))
        for extra in sorted(actual_t - truth_t):
            issues.append(_validation_issue("type_class_init", "ORACLE_TYPE_EDGE_EXTRA", edge=extra))
        for missing in sorted(truth_i - actual_i):
            issues.append(_validation_issue("type_class_init", "ORACLE_CLASS_INIT_EDGE_MISSING", edge=missing))
        for extra in sorted(actual_i - truth_i):
            issues.append(_validation_issue("type_class_init", "ORACLE_CLASS_INIT_EDGE_EXTRA", edge=extra))
        ordered_type = sorted(truth_t)
        ordered_init = sorted(truth_i)
        if retain_truth_rows:
            truth_type.extend(ordered_type)
            truth_init.extend(ordered_init)
        else:
            type_identity = _artifact_truth_identity(
                "binary_oracle_type_edge_artifact_truth",
                ordered_type,
            )
            init_identity = _artifact_truth_identity(
                "binary_oracle_class_init_edge_artifact_truth",
                ordered_init,
            )
            semantic_identity = _artifact_truth_identity(
                "binary_oracle_semantic_instruction_artifact_truth",
                ordered_semantic,
            )
            declared_identity = _artifact_truth_identity(
                "binary_oracle_declared_member_artifact_truth",
                ordered_declared,
            )
            compact_artifact_sets.append({
                "artifact_instance_identity": instance_identity,
                "type_edge_count": len(ordered_type),
                "type_edge_set_identity": type_identity,
                "class_init_edge_count": len(ordered_init),
                "class_init_edge_set_identity": init_identity,
                "semantic_instruction_count": len(ordered_semantic),
                "semantic_instruction_set_identity": semantic_identity,
                "declared_member_count": len(ordered_declared),
                "declared_member_set_identity": declared_identity,
            })
            compact_counts["type_edges"] += len(ordered_type)
            compact_counts["class_init_edges"] += len(ordered_init)
            compact_counts["semantic_instructions"] += len(ordered_semantic)
            compact_counts["declared_members"] += len(ordered_declared)
            if (
                validated_projection_cache is not None
                and len(issues) == artifact_issue_start
            ):
                validated_projection_cache[projection_key] = {
                    "type_edge_count": len(ordered_type),
                    "type_edge_identity": type_identity,
                    "class_init_edge_count": len(ordered_init),
                    "class_init_edge_identity": init_identity,
                    "semantic_instruction_count": len(ordered_semantic),
                    "semantic_instruction_identity": semantic_identity,
                    "declared_member_count": len(ordered_declared),
                    "declared_member_identity": declared_identity,
                    "clinit_classes": tuple(scanned.clinit_classes),
                }
        clinit_classes.update(scanned.clinit_classes)
        del actual_t, actual_i
        _notify_counted_progress(
            progress_callback,
            "validation-structural",
            f"{progress_label or '当前侧'}：结构和指令事实校验中",
            artifact_index,
            artifact_count,
            str(artifact.get("path") or ""),
        )
    _notify_progress(
        progress_callback,
        "validation-structural",
        f"{progress_label or '当前侧'}：结构和指令事实校验完成",
        artifact_count,
        artifact_count,
    )
    compact_structural = {
        "artifact_sets": compact_artifact_sets,
        "record_counts": dict(sorted(compact_counts.items())),
    }
    return issues, {
        "type_edges": (
            truth_type if retain_truth_rows else compact_structural
        ),
        "class_init_edges": (
            truth_init if retain_truth_rows else compact_structural
        ),
        "clinit_classes": sorted(clinit_classes),
        "semantic_instructions": (
            sorted(semantic_instructions)
            if retain_truth_rows else compact_structural
        ),
        "declared_members": (
            sorted(declared_members)
            if retain_truth_rows else compact_structural
        ),
        "declared_members_by_artifact": (
            declared_members_by_artifact
            if retain_truth_rows else compact_structural
        ),
    }


def _rows(connection: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]


def _pack_oracle_scan(result: Mapping[str, Any]) -> bytes:
    """Keep reusable javap evidence compact between independent validators."""
    return zlib.compress(
        surrogate_safe_json_dumps(
            result,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
        level=1,
    )


def _unpack_oracle_scan(result: Mapping[str, Any] | bytes) -> dict[str, Any]:
    if isinstance(result, bytes):
        return json.loads(zlib.decompress(result).decode("utf-8"))
    return dict(result)


class _OracleScanSpoolCache:
    """Disk-spooled javap evidence shared across sides and validation passes.

    A 400-artifact run can contain millions of normalized edge tuples. Keeping
    all of them in a Python dict is precisely the memory shape that caused the
    Windows validator to page for hours. Each entry remains compressed and
    only the artifact currently being compared is decoded.
    """

    _PROJECTION_NAMES = (
        "metadata",
        "direct_edges",
        "dynamic_handle_edges",
        "discovery_classes",
        "type_edges",
        "class_init_edges",
        "clinit_classes",
        "semantic_instructions",
        "declared_members",
        "structural_class_names",
    )

    def __init__(self, *, memory_limit_per_entry: int = 64 * 1024):
        self._memory_limit_per_entry = max(0, int(memory_limit_per_entry))
        self._entries: dict[
            tuple[str, str], tempfile.SpooledTemporaryFile
        ] = {}
        # Projected entries keep all fields in one spool handle.  The offset
        # directory is tiny, avoids thousands of simultaneously open files on
        # Windows, and lets later semantic/member consumers inflate only the
        # facts they actually use instead of the complete multi-million-edge
        # javap result.
        self._projection_offsets: dict[
            tuple[str, str], dict[str, tuple[int, int]]
        ] = {}

    @staticmethod
    def _encode_projection(value: Any) -> bytes:
        # These bytes are a private, same-process spool created only from
        # already-normalized Oracle objects; they are never accepted from an
        # external path. Pickle protocol 5 preserves tuple/set types and lone
        # surrogate transport strings in C, avoiding JSON's scalar-by-scalar
        # conversion and the temporary list copies previously retained for
        # every multi-million-row projection.
        return zlib.compress(
            pickle.dumps(value, protocol=5),
            level=1,
        )

    @staticmethod
    def _decode_projection(packed: bytes) -> Any:
        return pickle.loads(zlib.decompress(packed))

    @staticmethod
    def _evidence_projections(
        evidence: _OracleScanEvidence,
    ) -> tuple[tuple[str, Any], ...]:
        return (
            ("metadata", {
                "artifact_sha256": evidence.artifact_sha256,
                "complete": evidence.complete,
                "failures": evidence.failures,
            }),
            ("direct_edges", evidence.direct_truth.direct_edges),
            (
                "dynamic_handle_edges",
                evidence.direct_truth.dynamic_handle_edges,
            ),
            (
                "discovery_classes",
                evidence.direct_truth.discovery_classes,
            ),
            ("type_edges", evidence.structural_truth.type_edges),
            (
                "class_init_edges",
                evidence.structural_truth.class_init_edges,
            ),
            (
                "clinit_classes",
                evidence.structural_truth.clinit_classes,
            ),
            (
                "semantic_instructions",
                evidence.structural_truth.semantic_instructions,
            ),
            (
                "declared_members",
                evidence.structural_truth.declared_members,
            ),
            ("structural_class_names", evidence.structural_class_names),
        )

    @classmethod
    def pack_evidence(
        cls, evidence: _OracleScanEvidence,
    ) -> tuple[tuple[str, bytes], ...]:
        """Create the exact disk-spool representation without a raw graph."""

        return tuple(
            (name, cls._encode_projection(value))
            for name, value in cls._evidence_projections(evidence)
        )

    def _new_handle(self):
        return tempfile.SpooledTemporaryFile(
            max_size=self._memory_limit_per_entry,
            mode="w+b",
        )

    def _replace_entry(
        self,
        key: tuple[str, str],
        handle,
        offsets: dict[str, tuple[int, int]] | None = None,
    ) -> None:
        prior = self._entries.pop(key, None)
        if prior is not None:
            prior.close()
        self._entries[key] = handle
        if offsets is None:
            self._projection_offsets.pop(key, None)
        else:
            self._projection_offsets[key] = offsets

    def get(self, key: tuple[str, str], default=None):
        handle = self._entries.get(key)
        if handle is None:
            return default
        if key in self._projection_offsets:
            # Projected entries have no single raw representation.  Existing
            # validator paths use get_evidence()/get_projection(); returning a
            # sentinel still preserves ordinary mapping-style cache probes.
            return self
        handle.seek(0)
        return handle.read()

    def put_result(
        self, key: tuple[str, str], result: Mapping[str, Any]
    ) -> None:
        packed = _pack_oracle_scan(result)
        handle = self._new_handle()
        handle.write(packed)
        handle.flush()
        self._replace_entry(key, handle)

    def put_evidence(
        self, key: tuple[str, str], evidence: _OracleScanEvidence
    ) -> None:
        """Replace a verbose scanner object with independently readable sets."""

        self.put_packed_evidence(key, self.pack_evidence(evidence))

    def put_packed_evidence(
        self,
        key: tuple[str, str],
        projections: Iterable[tuple[str, bytes]],
    ) -> None:
        """Store a worker-produced projection only after strict framing checks."""

        packed_items = tuple(projections)
        if (
            tuple(name for name, _packed in packed_items)
            != self._PROJECTION_NAMES
            or any(type(packed) is not bytes for _name, packed in packed_items)
        ):
            raise BinaryValidationError(
                "BINARY_ORACLE_SHARED_SCAN_PROJECTION_INVALID", repr(key)
            )
        handle = self._new_handle()
        offsets: dict[str, tuple[int, int]] = {}
        try:
            for name, packed in packed_items:
                offset = handle.tell()
                handle.write(packed)
                offsets[name] = (offset, len(packed))
            handle.flush()
        except BaseException:
            handle.close()
            raise
        self._replace_entry(key, handle, offsets)

    def _projection(self, key: tuple[str, str], name: str) -> Any:
        handle = self._entries.get(key)
        offsets = self._projection_offsets.get(key)
        if handle is None or offsets is None or name not in offsets:
            raise KeyError((key, name))
        offset, length = offsets[name]
        handle.seek(offset)
        packed = handle.read(length)
        if len(packed) != length:
            raise BinaryValidationError(
                "BINARY_ORACLE_SHARED_SCAN_TRUNCATED",
                f"{key!r}:{name}",
            )
        return self._decode_projection(packed)

    @staticmethod
    def _compact_projection_rows(
        rows: Iterable[Iterable[Any]],
        string_pool: dict[str, str] | None,
    ) -> frozenset[tuple[Any, ...]]:
        if string_pool is None:
            return frozenset(tuple(row) for row in rows)
        return frozenset(
            tuple(
                _pooled_string(item, string_pool)
                if type(item) is str
                else (
                    _compact_json_values(item, string_pool)
                    if type(item) in (list, tuple, dict)
                    else item
                )
                for item in row
            )
            for row in rows
        )

    def get_projection(
        self,
        key: tuple[str, str],
        name: str,
        string_pool: dict[str, str] | None = None,
    ) -> frozenset[Any]:
        """Read one normalized set without inflating unrelated scan facts."""

        if key not in self._projection_offsets:
            self.get_evidence(key, string_pool)
        rows = self._projection(key, name)
        if name in {
            "discovery_classes", "clinit_classes", "structural_class_names",
        }:
            return frozenset(
                _pooled_string(str(item), string_pool)
                if string_pool is not None else str(item)
                for item in rows
            )
        return self._compact_projection_rows(rows, string_pool)

    def get_evidence(
        self,
        key: tuple[str, str],
        string_pool: dict[str, str] | None = None,
    ) -> _OracleScanEvidence:
        """Return complete normalized evidence, projecting a raw entry once."""

        if key not in self._entries:
            raise KeyError(key)
        if key not in self._projection_offsets:
            handle = self._entries[key]
            handle.seek(0)
            evidence = _normalize_oracle_scan(handle.read(), string_pool)
            self.put_evidence(key, evidence)
            return evidence
        metadata = self._projection(key, "metadata")
        failures = tuple(str(item) for item in metadata.get("failures") or ())
        artifact_sha256 = str(metadata.get("artifact_sha256") or "")
        complete = bool(metadata.get("complete"))
        if not complete:
            return _incomplete_oracle_scan_evidence(
                artifact_sha256, failures
            )
        direct_truth = _DirectEdgeTruth(
            artifact_sha256=artifact_sha256,
            direct_edges=self.get_projection(
                key, "direct_edges", string_pool
            ),
            dynamic_handle_edges=self.get_projection(
                key, "dynamic_handle_edges", string_pool
            ),
            discovery_classes=self.get_projection(
                key, "discovery_classes", string_pool
            ),
        )
        structural_truth = _StructuralTruth(
            type_edges=self.get_projection(key, "type_edges", string_pool),
            class_init_edges=self.get_projection(
                key, "class_init_edges", string_pool
            ),
            clinit_classes=self.get_projection(
                key, "clinit_classes", string_pool
            ),
            semantic_instructions=self.get_projection(
                key, "semantic_instructions", string_pool
            ),
            declared_members=self.get_projection(
                key, "declared_members", string_pool
            ),
            failures=(),
        )
        return _OracleScanEvidence(
            artifact_sha256=artifact_sha256,
            complete=True,
            failures=failures,
            direct_truth=direct_truth,
            structural_truth=structural_truth,
            structural_class_names=self.get_projection(
                key, "structural_class_names", string_pool
            ),
        )

    def get_direct_evidence(
        self,
        key: tuple[str, str],
        string_pool: dict[str, str] | None = None,
    ) -> _OracleScanEvidence:
        """Inflate only fields consumed by direct-edge validation."""

        if key not in self._projection_offsets:
            return self.get_evidence(key, string_pool)
        metadata = self._projection(key, "metadata")
        failures = tuple(str(item) for item in metadata.get("failures") or ())
        artifact_sha256 = str(metadata.get("artifact_sha256") or "")
        if not bool(metadata.get("complete")):
            return _incomplete_oracle_scan_evidence(
                artifact_sha256, failures
            )
        return _OracleScanEvidence(
            artifact_sha256=artifact_sha256,
            complete=True,
            failures=failures,
            direct_truth=_DirectEdgeTruth(
                artifact_sha256=artifact_sha256,
                direct_edges=self.get_projection(
                    key, "direct_edges", string_pool
                ),
                dynamic_handle_edges=self.get_projection(
                    key, "dynamic_handle_edges", string_pool
                ),
                discovery_classes=self.get_projection(
                    key, "discovery_classes", string_pool
                ),
            ),
            structural_truth=_StructuralTruth(
                type_edges=frozenset(),
                class_init_edges=frozenset(),
                clinit_classes=frozenset(),
                semantic_instructions=frozenset(),
                declared_members=frozenset(),
                failures=(),
            ),
            structural_class_names=frozenset(),
        )

    def get_structural_evidence(
        self,
        key: tuple[str, str],
        string_pool: dict[str, str] | None = None,
    ) -> _OracleScanEvidence:
        """Inflate structural fields only after the direct pass projected them."""

        if key not in self._projection_offsets:
            # The first consumer must validate and project the complete raw
            # scanner result.  This fallback keeps the cache safe for focused
            # callers that start with structural validation.
            return self.get_evidence(key, string_pool)
        metadata = self._projection(key, "metadata")
        failures = tuple(str(item) for item in metadata.get("failures") or ())
        artifact_sha256 = str(metadata.get("artifact_sha256") or "")
        if not bool(metadata.get("complete")):
            return _incomplete_oracle_scan_evidence(
                artifact_sha256, failures
            )
        return _OracleScanEvidence(
            artifact_sha256=artifact_sha256,
            complete=True,
            failures=failures,
            direct_truth=_DirectEdgeTruth(
                artifact_sha256=artifact_sha256,
                direct_edges=frozenset(),
                dynamic_handle_edges=frozenset(),
                discovery_classes=frozenset(),
            ),
            structural_truth=_StructuralTruth(
                type_edges=self.get_projection(
                    key, "type_edges", string_pool
                ),
                class_init_edges=self.get_projection(
                    key, "class_init_edges", string_pool
                ),
                clinit_classes=self.get_projection(
                    key, "clinit_classes", string_pool
                ),
                semantic_instructions=self.get_projection(
                    key, "semantic_instructions", string_pool
                ),
                declared_members=self.get_projection(
                    key, "declared_members", string_pool
                ),
                failures=(),
            ),
            structural_class_names=self.get_projection(
                key, "structural_class_names", string_pool
            ),
        )

    def clear(self) -> None:
        entries, self._entries = self._entries, {}
        self._projection_offsets.clear()
        for handle in entries.values():
            handle.close()

    def __len__(self) -> int:
        return len(self._entries)


class _SpoolStructuralInstructionSource:
    """Repeatable, per-artifact semantic instructions over a scan spool."""

    def __init__(
        self,
        cache: _OracleScanSpoolCache,
        artifacts: Iterable[Mapping[str, Any]],
        javap: str,
        string_pool: dict[str, str] | None = None,
    ):
        self._cache = cache
        self._artifacts = tuple(dict(item) for item in artifacts)
        self._javap = str(javap)
        self._string_pool = string_pool

    def iter_batches(self) -> Iterable[frozenset[tuple[Any, ...]]]:
        for artifact in self._artifacts:
            key = (str(artifact["sha256"]), self._javap)
            if self._cache.get(key) is None:
                raise BinaryValidationError(
                    "BINARY_ORACLE_SHARED_SCAN_MISSING",
                    str(artifact.get("path") or ""),
                )
            yield self._cache.get_projection(
                key, "semantic_instructions", self._string_pool
            )

    def __iter__(self):
        for batch in self.iter_batches():
            yield from batch


class _ProductionStructuralSpoolCache:
    """One-file bounded handoff from the direct DB pass to structural checks."""

    def __init__(self, *, memory_limit: int = 1024 * 1024):
        self._handle = tempfile.SpooledTemporaryFile(
            max_size=max(0, int(memory_limit)), mode="w+b"
        )
        self._offsets: dict[str, tuple[int, int]] = {}

    def put(
        self,
        artifact_instance_identity: str,
        type_edges: Iterable[tuple[Any, ...]],
        class_init_edges: Iterable[tuple[Any, ...]],
    ) -> None:
        packed = _OracleScanSpoolCache._encode_projection({
            "type_edges": tuple(type_edges),
            "class_init_edges": tuple(class_init_edges),
        })
        self._handle.seek(0, os.SEEK_END)
        offset = self._handle.tell()
        self._handle.write(packed)
        self._handle.flush()
        self._offsets[str(artifact_instance_identity)] = (
            offset, len(packed)
        )

    def get(
        self, artifact_instance_identity: str,
    ) -> tuple[set[tuple[Any, ...]], set[tuple[Any, ...]]]:
        location = self._offsets.get(str(artifact_instance_identity))
        if location is None:
            raise BinaryValidationError(
                "BINARY_ORACLE_PRODUCTION_STRUCTURAL_CACHE_MISSING",
                str(artifact_instance_identity),
            )
        offset, length = location
        self._handle.seek(offset)
        packed = self._handle.read(length)
        if len(packed) != length:
            raise BinaryValidationError(
                "BINARY_ORACLE_PRODUCTION_STRUCTURAL_CACHE_TRUNCATED",
                str(artifact_instance_identity),
            )
        payload = _OracleScanSpoolCache._decode_projection(packed)
        return (
            {tuple(item) for item in payload.get("type_edges") or ()},
            {
                tuple(item)
                for item in payload.get("class_init_edges") or ()
            },
        )

    def __contains__(self, artifact_instance_identity: str) -> bool:
        return str(artifact_instance_identity) in self._offsets

    def clear(self) -> None:
        handle, self._handle = self._handle, None
        self._offsets.clear()
        if handle is not None:
            handle.close()

    def __del__(self):
        try:
            self.clear()
        except Exception:
            pass


_OPCODE_TO_TYPE_USE = {
    "new": "new",
    "anewarray": "anewarray",
    "checkcast": "checkcast",
    "instanceof": "instanceof",
    "multianewarray": "multianewarray",
    "class_literal": "class_literal",
    "method_type_descriptor": "method_type_descriptor",
    "bootstrap_class_constant": "bootstrap_class_constant",
    "invokedynamic_callsite_descriptor": "invokedynamic_callsite_descriptor",
    "constant_dynamic_descriptor": "constant_dynamic_descriptor",
    "method_handle_descriptor": "method_handle_descriptor",
    "member_reference_descriptor": "member_reference_descriptor",
}

_ORACLE_LINKAGE_EDGE_FAMILIES = frozenset({
    "invokedynamic",
    "ldc_constant_dynamic_bootstrap",
    "ldc_bootstrap_handle",
    "ldc_handle",
})
_ORACLE_DIRECT_REFERENCE_KINDS_BY_OPCODE = {
    "getstatic": frozenset({"field"}),
    "putstatic": frozenset({"field"}),
    "getfield": frozenset({"field"}),
    "putfield": frozenset({"field"}),
    "invokevirtual": frozenset({"method"}),
    "invokespecial": frozenset({"method", "interface_method"}),
    "invokestatic": frozenset({"method", "interface_method"}),
    "invokeinterface": frozenset({"interface_method"}),
}
_ORACLE_DIRECT_METHOD_REFERENCE_KINDS = frozenset({
    "method", "interface_method",
})
_ORACLE_DIRECT_EDGE_TUPLE_SIZE = 9


def _incomplete_oracle_scan_evidence(
    artifact_sha256: str,
    failures: Iterable[str],
) -> _OracleScanEvidence:
    normalized_failures = tuple(str(item) for item in failures)
    return _OracleScanEvidence(
        artifact_sha256=artifact_sha256,
        complete=False,
        failures=normalized_failures,
        direct_truth=_DirectEdgeTruth(
            artifact_sha256=artifact_sha256,
            direct_edges=frozenset(),
            dynamic_handle_edges=frozenset(),
            discovery_classes=frozenset(),
        ),
        structural_truth=_StructuralTruth(
            type_edges=frozenset(),
            class_init_edges=frozenset(),
            clinit_classes=frozenset(),
            semantic_instructions=frozenset(),
            declared_members=frozenset(),
            failures=normalized_failures,
        ),
        structural_class_names=frozenset(),
    )


def _normalize_oracle_scan(
    result: Mapping[str, Any] | bytes | _OracleScanEvidence,
    string_pool: dict[str, str] | None = None,
) -> _OracleScanEvidence:
    """Project a scanner result once into all facts consumed by validation."""
    if isinstance(result, _OracleScanEvidence):
        return result
    unpacked = _unpack_oracle_scan(result)
    transported_text: dict[str, str] = {}

    def compact_text(value: str) -> str:
        try:
            return transported_text[value]
        except KeyError:
            normalized = transport_jvm_text(value)
            if string_pool is not None:
                normalized = _pooled_string(normalized, string_pool)
            transported_text[value] = normalized
            return normalized

    def compact_value(value: Any) -> Any:
        value_type = type(value)
        if value_type is str:
            return compact_text(value)
        if value_type in (list, tuple):
            return tuple(compact_value(item) for item in value)
        if value_type is dict:
            return {
                compact_text(key) if type(key) is str else key:
                compact_value(item)
                for key, item in value.items()
            }
        return value

    artifact_sha256 = compact_text(str(
        unpacked.get("artifact_sha256") or ""
    ))
    complete = bool(unpacked.get("complete"))
    failures = tuple(
        compact_text(str(item))
        for item in (unpacked.get("failures") or ())
    )
    if not complete:
        # Partial rows are not authoritative and historically were rejected
        # before normalization. Keep that fail-closed order, and do not spend
        # time or memory projecting evidence that no validator may consume.
        return _incomplete_oracle_scan_evidence(artifact_sha256, failures)
    rows = unpacked.get("edges") or ()
    invalid_linkage_rows = [
        row
        for row in rows
        if row.get("opcode_family") in _ORACLE_LINKAGE_EDGE_FAMILIES
        and (
            row.get("reference_kind") not in METHOD_HANDLE_REFERENCE_KINDS
            or type(row.get("reference_interface")) is not bool
        )
    ]
    if invalid_linkage_rows:
        return _incomplete_oracle_scan_evidence(
            artifact_sha256,
            (*failures, "oracle_dynamic_reference_kind_missing_or_invalid"),
        )
    invalid_direct_rows = []
    for row in rows:
        opcode = row.get("opcode_family")
        if opcode in _ORACLE_LINKAGE_EDGE_FAMILIES:
            continue
        reference_kind = row.get("reference_kind")
        allowed_kinds = _ORACLE_DIRECT_REFERENCE_KINDS_BY_OPCODE.get(opcode)
        invalid = allowed_kinds is None or reference_kind not in allowed_kinds
        if allowed_kinds and "field" not in allowed_kinds:
            invalid = invalid or (
                type(row.get("reference_interface")) is not bool
                or row.get("reference_interface")
                is not (reference_kind == "interface_method")
            )
        if invalid:
            invalid_direct_rows.append(row)
    if invalid_direct_rows:
        return _incomplete_oracle_scan_evidence(
            artifact_sha256,
            (*failures, "oracle_direct_reference_kind_missing_or_invalid"),
        )

    def compact_tuple(value: Iterable[Any]) -> tuple[Any, ...]:
        # Fuse JVM text transport, string pooling and tuple freezing into the
        # projection pass. The former whole-tree preflight walked all facts and
        # then walked them again when even one lone surrogate was present.
        return tuple(compact_value(item) for item in value)

    direct_truth = _DirectEdgeTruth(
        artifact_sha256=artifact_sha256,
        direct_edges=frozenset(
            compact_tuple((
                row["caller_owner"], row["caller_member"],
                row["caller_descriptor"], row["callee_owner"],
                row["callee_member"], row["callee_descriptor"],
                row["opcode_family"], int(row["instruction_offset"]),
                row["reference_kind"],
            ))
            for row in rows
            if row.get("opcode_family") not in _ORACLE_LINKAGE_EDGE_FAMILIES
        ),
        dynamic_handle_edges=frozenset(
            compact_tuple((
                row["caller_owner"], row["caller_member"],
                row["caller_descriptor"], row["callee_owner"],
                row["callee_member"], row["callee_descriptor"],
                row["reference_kind"],
                row["reference_interface"],
                row["opcode_family"],
                int(row["instruction_offset"]),
            ))
            for row in rows
            if row.get("opcode_family") in _ORACLE_LINKAGE_EDGE_FAMILIES
        ),
        discovery_classes=frozenset(
            (
                _pooled_string(
                    compact_text(
                        # The generator filter below guarantees this value is
                        # truthy before either projection branch executes.
                        str(row.get("callee_owner"))
                    ).replace(".", "/"),
                    string_pool,
                )
                if string_pool is not None
                else compact_text(
                    str(row.get("callee_owner"))
                ).replace(".", "/")
            )
            for row in rows if row.get("callee_owner")
        ),
    )
    structural = unpacked.get("structural_facts") or {}
    structural_truth = _StructuralTruth(
        type_edges=frozenset(
            compact_tuple((
                *item[:5], _OPCODE_TO_TYPE_USE[item[5]], *item[6:],
            ))
            for item in (structural.get("type_edges") or ())
        ),
        class_init_edges=frozenset(
            compact_tuple(item)
            for item in (structural.get("class_init_edges") or ())
        ),
        clinit_classes=frozenset(
            compact_text(str(item))
            for item in (structural.get("clinit_classes") or ())
        ),
        semantic_instructions=frozenset(
            compact_tuple(item)
            for item in (structural.get("semantic_instructions") or ())
        ),
        declared_members=frozenset(
            compact_tuple(item)
            for item in (structural.get("declared_members") or ())
        ),
        failures=(),
    )
    return _OracleScanEvidence(
        artifact_sha256=direct_truth.artifact_sha256,
        complete=True,
        failures=failures,
        direct_truth=direct_truth,
        structural_truth=structural_truth,
        structural_class_names=frozenset(
            compact_text(str(item))
            for item in (structural.get("class_names") or ())
        ),
    )


def _scan_final_artifact_process(
    request: tuple[
        tuple[str, str], str, str, float | None,
        CompiledJavapSessionBinding | None,
    ],
) -> tuple[tuple[str, str], tuple[tuple[str, bytes], ...]]:
    """Build one complete compressed Oracle projection in an isolated worker.

    Javap text parsing, normalization and projection compression are all CPU
    heavy Python work.  Returning only bounded compressed projections avoids
    both the GIL bottleneck of the former thread pool and a second giant graph
    serialization in the parent.  The parent still validates projection names,
    later decodes every set, and compares every fact against production.
    """

    key, path_text, javap, time_budget_seconds, compiled_binding = request
    if compiled_binding is not None:
        try:
            install_compiled_javap_session_binding(compiled_binding)
        except (JavapSessionError, OSError, ValueError):
            # The binding is an optional transport optimization. A changed or
            # inaccessible parent temporary directory falls back to compiling
            # the same pinned helper locally; no scan may be skipped.
            pass
    result = scan_final_artifact(
        Path(path_text),
        javap=javap,
        max_workers=1,
        time_budget_seconds=time_budget_seconds,
        include_nested_runtime_jars=False,
        include_structural_facts=True,
        cache_result=False,
        persistent_javap_sessions=True,
    )
    evidence = _normalize_oracle_scan(result, None)
    return key, _OracleScanSpoolCache.pack_evidence(evidence)


def _same_json_value(left: Any, right: Any) -> bool:
    """Compare JSON-like values without conflating bool/int or int/float."""
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return (
            left.keys() == right.keys()
            and all(_same_json_value(value, right[key]) for key, value in left.items())
        )
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(
            _same_json_value(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    if type(left) is not type(right):
        return False
    return left == right


def _pooled_string(value: str, pool: dict[str, str]) -> str:
    pooled = pool.get(value)
    if pooled is not None:
        return pooled
    # Object sharing is only a memory optimization; it is not validation
    # evidence. A high-cardinality edge/member corpus can otherwise make this
    # dictionary retain every unique transient string after its artifact has
    # already been compressed to the disk spool. Stop admitting new values at
    # a fixed bound and never retain unusually large diagnostic text.
    if (
        len(pool) >= MAX_VALIDATION_STRING_POOL_ENTRIES
        or len(value) > MAX_VALIDATION_POOLED_STRING_CHARS
    ):
        return value
    pool[value] = value
    return value


class _BoundedProjectionCache:
    """Cache repeated immutable identity projections without unbounded RSS."""

    _MISSING = object()

    def __init__(self, limit: int):
        self.limit = max(0, int(limit))
        self.values: dict[str, Any] = {}

    def resolve(
        self,
        identities: Iterable[str],
        loader: Callable[[tuple[str, ...]], Mapping[str, Any]],
    ) -> dict[str, Any]:
        normalized = tuple(dict.fromkeys(
            str(item) for item in identities if item
        ))
        result: dict[str, Any] = {}
        misses = []
        for identity in normalized:
            value = self.values.get(identity, self._MISSING)
            if value is self._MISSING:
                misses.append(identity)
            elif value is not None:
                result[identity] = value
        if misses:
            loaded = dict(loader(tuple(misses)))
            for identity in misses:
                value = loaded.get(identity)
                if len(self.values) < self.limit:
                    # Negative entries are safe: the validated immutable
                    # SQLite attachment cannot gain a member during the run.
                    self.values[identity] = value
                if value is not None:
                    result[identity] = value
        return result


def _compact_json_values(value: Any, string_pool: dict[str, str]) -> Any:
    """Deduplicate strings and freeze JSON arrays without changing encoding."""
    value_type = type(value)
    if value_type is str:
        return _pooled_string(value, string_pool)
    if value_type in (list, tuple):
        return tuple(
            _compact_json_values(item, string_pool) for item in value
        )
    if value_type is dict:
        return {
            _pooled_string(key, string_pool): _compact_json_values(
                item, string_pool
            )
            for key, item in value.items()
        }
    return value


def _compact_observations(
    observations: Mapping[str, Mapping[str, Any]],
    string_pool: dict[str, str],
    *,
    values_compacted: bool = False,
) -> dict[str, Mapping[str, Any]]:
    compacted = {}
    for class_name, row in observations.items():
        pooled_name = _pooled_string(str(class_name), string_pool)
        if isinstance(row, _CompactObservation):
            compacted[pooled_name] = row
        else:
            payload = dict(row)
            if not values_compacted:
                payload = _compact_json_values(payload, string_pool)
            compacted[pooled_name] = _CompactObservation(
                payload
            )
    return compacted


def _runtime_observation_set_identity(
    observations: Mapping[str, Mapping[str, Any]],
) -> str:
    """Hash all observations through bounded, exact canonical row chunks.

    The generic streaming identity is the byte-contract authority, but writing
    every scalar through Python is unnecessarily expensive for this unusually
    wide and flat mapping. Encoding one class record at a time with the same
    frozen JSON options preserves that exact byte stream while bounding
    transient memory by the largest observation rather than the full graph.

    Generated observations contain string keys and JSON-native values. Fall
    back to the generic contract for independently authored boundary objects,
    so this optimization can neither admit a wider value domain nor weaken a
    validation failure.
    """

    if any(type(class_name) is not str for class_name in observations):
        return canonical_identity_streaming(
            "binary_runtime_observation_set_identity",
            observations,
            schema_version="1",
        )
    digest = hashlib.sha256()
    digest.update(
        b'{"namespace":"binary_runtime_observation_set_identity",'
        b'"payload":{'
    )
    for index, class_name in enumerate(sorted(observations)):
        row = observations[class_name]
        if not isinstance(row, Mapping) or any(
            type(key) is not str for key in row
        ):
            return canonical_identity_streaming(
                "binary_runtime_observation_set_identity",
                observations,
                schema_version="1",
            )
        if index:
            digest.update(b",")
        digest.update(surrogate_safe_json_bytes(
            class_name,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ))
        digest.update(b":")
        digest.update(surrogate_safe_json_bytes(
            dict(row),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ))
    digest.update(b'},"schema_version":"1"}')
    return digest.hexdigest()


def _observation_needs_javap_members(
    observation: Mapping[str, Any],
) -> bool:
    status = observation.get("status")
    if status is None:
        # Compatibility for focused fixtures predating runtime status rows.
        return True
    if status == "definition_ready":
        # The pinned helper always emits this field for a ready class. Keep a
        # defensive exact fallback for independently authored/legacy rows that
        # claim readiness without the declaration projection.
        return not isinstance(observation.get("members"), (list, tuple))
    return bool(
        status == "definition_failed"
        and observation.get("failure_phase") == "member_linkage"
    )


def _attach_provider_declared_members(
    artifacts: Iterable[Mapping[str, Any]],
    edge_truth: Mapping[str, Any],
    observations: Mapping[str, dict[str, Any]],
    string_pool: dict[str, str],
) -> None:
    """Attach javap fallback members only from the JVM-selected provider."""
    artifact_path_by_identity = {
        str(item.get("_expected_artifact_instance_identity") or ""):
        Path(str(item["path"])).resolve()
        for item in artifacts
    }
    javap_members_by_path: dict[
        Path, dict[str, list[str]]
    ] = defaultdict(lambda: defaultdict(list))
    for artifact_members in (
        edge_truth.get("declared_members_by_artifact") or ()
    ):
        artifact_path = artifact_path_by_identity.get(str(
            artifact_members.get("artifact_instance_identity") or ""
        ))
        if artifact_path is None:
            continue
        for owner, kind, member_name, descriptor, flags in (
            artifact_members.get("members") or ()
        ):
            javap_members_by_path[artifact_path][str(owner)].append(
                f"{kind}|{member_name}|{descriptor}|{int(flags)}"
            )
    if not javap_members_by_path:
        # Compatibility for isolated unit fixtures that construct pre-v3
        # truth directly. Production validation always carries exact
        # artifact-instance provenance from the structural pass.
        fallback_members: dict[str, list[str]] = defaultdict(list)
        for owner, kind, member_name, descriptor, flags in (
            edge_truth.get("declared_members") or ()
        ):
            fallback_members[str(owner)].append(
                f"{kind}|{member_name}|{descriptor}|{int(flags)}"
            )
        for class_name, values in fallback_members.items():
            observation = observations.get(class_name)
            if (
                observation is not None
                and _observation_needs_javap_members(observation)
            ):
                observation["javap_declared_members"] = tuple(
                    _pooled_string(value, string_pool)
                    for value in sorted(set(values))
                )
        return
    for class_name, observation in observations.items():
        if not _observation_needs_javap_members(observation):
            continue
        provider_path = _provider_resource_path(
            _oracle_provider_location(observation)
        )
        if provider_path is None:
            continue
        values = javap_members_by_path.get(
            provider_path.resolve(), {}
        ).get(class_name, ())
        if values:
            observation["javap_declared_members"] = tuple(
                _pooled_string(value, string_pool)
                for value in sorted(set(values))
            )


def _attach_provider_declared_members_from_scan_cache(
    artifacts: Iterable[Mapping[str, Any]],
    javap: str,
    scan_cache: _OracleScanSpoolCache,
    observations: Mapping[str, dict[str, Any]],
    string_pool: dict[str, str],
) -> None:
    """Attach provider members without retaining every artifact's member set."""

    classes_by_provider: dict[Path, set[str]] = defaultdict(set)
    for class_name, observation in observations.items():
        # Reflection emits the complete declared-member set before reporting
        # ``definition_ready``. Javap is an exact fallback only when class
        # definition succeeded but enumerating members failed because an
        # unrelated signature type could not link. Decoding every artifact's
        # independently scanned member projection for ready classes repeated
        # millions of rows that could never participate in the fallback.
        if not _observation_needs_javap_members(observation):
            continue
        provider_path = _provider_resource_path(
            _oracle_provider_location(observation)
        )
        if provider_path is not None:
            classes_by_provider[provider_path.resolve()].add(str(class_name))
    if not classes_by_provider:
        return
    members_by_class: dict[str, list[str]] = defaultdict(list)
    for artifact in artifacts:
        artifact_path = Path(str(artifact["path"])).resolve()
        selected_classes = classes_by_provider.get(artifact_path)
        if not selected_classes:
            continue
        scan_key = (str(artifact["sha256"]), str(javap))
        if scan_cache.get(scan_key) is None:
            raise BinaryValidationError(
                "BINARY_ORACLE_SHARED_SCAN_MISSING", str(artifact_path)
            )
        for owner, kind, member_name, descriptor, flags in (
            scan_cache.get_projection(
                scan_key, "declared_members", string_pool
            )
        ):
            owner_text = str(owner)
            if owner_text in selected_classes:
                members_by_class[owner_text].append(
                    f"{kind}|{member_name}|{descriptor}|{int(flags)}"
                )
    for class_name, values in members_by_class.items():
        # A class enters members_by_class only after membership in the
        # observation-derived selected_classes set, and only via append().
        observation = observations[class_name]
        observation["javap_declared_members"] = tuple(
            _pooled_string(value, string_pool)
            for value in sorted(set(values))
        )


def _share_equal_observation_values(
    reference: Mapping[str, Mapping[str, Any]],
    candidate: dict[str, Mapping[str, Any]],
) -> tuple[int, int]:
    """Share only type-exact, equal, immutable post-observation values.

    Runtime observations are no longer mutated after javap-declared members
    have been attached.  Sharing equal rows (or equal values in a row whose
    provider URL differs) therefore changes neither side's evidence nor the
    canonical validation identity, while avoiding a second retained copy.
    """
    shared_rows = 0
    shared_values = 0
    for class_name, row in tuple(candidate.items()):
        reference_row = reference.get(class_name)
        if not isinstance(reference_row, Mapping):
            continue
        same_row = row.keys() == reference_row.keys()
        for key, value in tuple(row.items()):
            if key not in reference_row:
                same_row = False
                continue
            reference_value = reference_row[key]
            if _same_json_value(value, reference_value):
                if value is not reference_value:
                    # Candidate rows are mutable until this sharing pass. A
                    # compact row can only arrive after whole-row reuse.
                    if isinstance(row, dict):
                        row[key] = reference_value
                    shared_values += 1
            else:
                same_row = False
        if same_row:
            candidate[class_name] = reference_row
            shared_rows += 1
    return shared_rows, shared_values


def _has_complete_reconciliation_chunk_order(
    connection: sqlite3.Connection,
    kind: str,
) -> bool:
    """Return true only when every chunk has one v9 locality record."""

    kind_code = _ORACLE_RECONCILIATION_KIND_CODES[kind]
    try:
        total, ordered = connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM reconciliation_records
               WHERE record_kind=?),
              (SELECT COUNT(*)
               FROM reconciliation_records AS records
               JOIN reconciliation_chunk_order AS ordering
                 ON ordering.chunk_identity=records.chunk_identity
                AND ordering.record_kind=records.record_kind
               WHERE records.record_kind=?)
            """,
            (kind_code, kind_code),
        ).fetchone()
        return int(total) == int(ordered)
    except (IndexError, TypeError, ValueError, sqlite3.Error):
        return False


def _iter_reconciliation(
    connection: sqlite3.Connection,
    kind: str,
) -> Iterable[dict[str, Any]]:
    kind_code = _ORACLE_RECONCILIATION_KIND_CODES[kind]
    if not isinstance(connection, sqlite3.Connection):
        # Boundary adapters predating v9 expose only the original one-query
        # protocol. They have no physical locality table to consult.
        chunks = connection.execute(
            "SELECT record_count,payload_zlib FROM reconciliation_records "
            "WHERE record_kind=? ORDER BY chunk_identity",
            (kind_code,),
        )
    else:
        try:
            ordered_chunks = connection.execute(
                """
                SELECT records.record_count,records.payload_zlib
                FROM reconciliation_chunk_order AS ordering
                JOIN reconciliation_records AS records
                  ON records.chunk_identity=ordering.chunk_identity
                 AND records.record_kind=ordering.record_kind
                WHERE ordering.record_kind=?
                ORDER BY ordering.chunk_ordinal
                """,
                (kind_code,),
            )
            unordered_chunks = connection.execute(
                """
                SELECT records.record_count,records.payload_zlib
                FROM reconciliation_records AS records
                LEFT JOIN reconciliation_chunk_order AS ordering
                  ON ordering.chunk_identity=records.chunk_identity
                 AND ordering.record_kind=records.record_kind
                WHERE records.record_kind=?
                  AND ordering.chunk_identity IS NULL
                ORDER BY records.chunk_identity
                """,
                (kind_code,),
            )
            chunks = chain(ordered_chunks, unordered_chunks)
        except sqlite3.Error:
            # Immutable v8 fixtures do not carry the performance-only
            # insertion-order index. Every chunk is still read and validated;
            # only their traversal locality is unavailable.
            chunks = connection.execute(
                "SELECT record_count,payload_zlib "
                "FROM reconciliation_records WHERE record_kind=? "
                "ORDER BY chunk_identity",
                (kind_code,),
            )
    for row in chunks:
        decoded = json.loads(
            zlib.decompress(row["payload_zlib"]).decode("utf-8")
        )
        if isinstance(decoded, dict):
            payload_format = decoded.get("format")
            if payload_format == "binary-reconciliation-columnar-payload-v1":
                if (
                    set(decoded) != {"format", "records", "shapes"}
                    or not isinstance(decoded.get("records"), list)
                    or not isinstance(decoded.get("shapes"), list)
                ):
                    raise BinaryValidationError(
                        "BINARY_ORACLE_RECONCILIATION_CHUNK_FORMAT_INVALID",
                        kind,
                    )
                shapes: list[tuple[str, ...]] = []
                seen_shapes: set[tuple[str, ...]] = set()
                for raw_shape in decoded["shapes"]:
                    if (
                        not isinstance(raw_shape, list)
                        or any(type(field) is not str for field in raw_shape)
                    ):
                        raise BinaryValidationError(
                            "BINARY_ORACLE_RECONCILIATION_CHUNK_FORMAT_INVALID",
                            kind,
                        )
                    shape = tuple(raw_shape)
                    if (
                        shape != tuple(sorted(set(shape)))
                        or shape in seen_shapes
                    ):
                        raise BinaryValidationError(
                            "BINARY_ORACLE_RECONCILIATION_CHUNK_FORMAT_INVALID",
                            kind,
                        )
                    seen_shapes.add(shape)
                    shapes.append(shape)
                records = []
                for raw_record in decoded["records"]:
                    if (
                        not isinstance(raw_record, list)
                        or not raw_record
                        or type(raw_record[0]) is not int
                        or not 0 <= raw_record[0] < len(shapes)
                    ):
                        raise BinaryValidationError(
                            "BINARY_ORACLE_RECONCILIATION_RECORD_INVALID",
                            kind,
                        )
                    shape = shapes[raw_record[0]]
                    if len(raw_record) != len(shape) + 1:
                        raise BinaryValidationError(
                            "BINARY_ORACLE_RECONCILIATION_RECORD_INVALID",
                            kind,
                        )
                    records.append(dict(zip(shape, raw_record[1:])))
                payload_only = True
            elif (
                payload_format == "binary-reconciliation-payload-array-v1"
                and set(decoded) == {"format", "records"}
                and isinstance(decoded.get("records"), list)
            ):
                # Immutable v10 chunks retain the former payload-only array.
                records = decoded["records"]
                payload_only = True
            else:
                raise BinaryValidationError(
                    "BINARY_ORACLE_RECONCILIATION_CHUNK_FORMAT_INVALID",
                    kind,
                )
        elif isinstance(decoded, list):
            # Immutable v9 fixtures retain the former redundant envelope.
            # The independent Oracle accepts all formats and still reads every
            # exact payload; newer schemas remove only redundant encoding.
            records = decoded
            payload_only = False
        else:
            raise BinaryValidationError(
                "BINARY_ORACLE_RECONCILIATION_CHUNK_FORMAT_INVALID", kind
            )
        if len(records) != int(row["record_count"]):
            raise BinaryValidationError(
                "BINARY_ORACLE_RECONCILIATION_CHUNK_COUNT_INVALID", kind
            )
        for item in records:
            if not isinstance(item, dict):
                raise BinaryValidationError(
                    "BINARY_ORACLE_RECONCILIATION_RECORD_INVALID", kind
                )
            yield item if payload_only else item["payload"]


def _reconciliation(connection: sqlite3.Connection, kind: str) -> list[dict[str, Any]]:
    return list(_iter_reconciliation(connection, kind))


def _member_tuple(value: str) -> tuple[str, str, str, int]:
    kind, name, descriptor, flags = value.split("|", 3)
    return kind, name, descriptor, int(flags)


def _descriptor_parameters(descriptor: str) -> tuple[str, ...] | None:
    value = str(descriptor or "")
    if not value.startswith("("):
        return None
    result = []
    index = 1
    while index < len(value) and value[index] != ")":
        start = index
        while index < len(value) and value[index] == "[":
            index += 1
        if index >= len(value):
            return None
        if value[index] == "L":
            end = value.find(";", index)
            if end < 0:
                return None
            index = end + 1
        else:
            index += 1
        result.append(value[start:index])
    # The loop stops before the end only when it encounters ``)``.
    return tuple(result) if index < len(value) else None


def _descriptor_return_class(descriptor: str) -> str:
    value = str(descriptor or "")
    marker = value.find(")")
    returned = value[marker + 1:] if marker >= 0 else ""
    return returned[1:-1] if returned.startswith("L") and returned.endswith(";") else ""


def _oracle_type_provider_owner(symbolic_owner: str) -> str:
    """Independently map an array class to the classfile its JVM type needs."""
    value = str(symbolic_owner or "")
    if not value.startswith("["):
        return value
    while value.startswith("["):
        value = value[1:]
    if value.startswith("L") and value.endswith(";"):
        return value[1:-1]
    return ""


def _declared_members(observation: Mapping[str, Any]) -> list[tuple[str, str, str, int]]:
    # Reflection is authoritative when it could enumerate the declaration.
    # javap is only a fallback for classes whose unrelated optional member
    # types prevented exhaustive reflection.  Access-flag renderings can
    # legitimately differ (for example reflection retains ACC_VARARGS while
    # the compact javap parser only records ``public``).  Treating those two
    # rows as distinct creates duplicate logical methods and incorrectly turns
    # a unique framework callback/bean implementation into a possible set.
    result: dict[tuple[str, str, str], tuple[str, str, str, int]] = {}
    for source in ("members", "javap_declared_members"):
        for value in observation.get(source) or ():
            member = _member_tuple(value)
            result.setdefault(member[:3], member)
    return list(result.values())


def _cached_declared_members(
    observations: Mapping[str, Mapping[str, Any]],
    owner: str,
    cache: dict[str, tuple[tuple[str, str, str, int], ...]],
    observation: Mapping[str, Any] | None = None,
) -> tuple[tuple[str, str, str, int], ...]:
    """Return one exact declaration projection shared by semantic passes."""

    normalized_owner = str(owner)
    source = (
        observation
        if observation is not None
        else observations.get(normalized_owner) or {}
    )
    if isinstance(source, _CompactObservation):
        cached = source._declared_members_cache
        if cached is None:
            cached = tuple(_declared_members(source))
            source._declared_members_cache = cached
        return cached
    cached = cache.get(normalized_owner)
    if cached is not None:
        return cached
    projected = tuple(_declared_members(source))
    cache[normalized_owner] = projected
    return projected


def _oracle_class_load_ready(observation: Mapping[str, Any] | None) -> bool:
    if not observation:
        return False
    return bool(
        observation.get("status") == "definition_ready"
        or (
            observation.get("status") == "definition_failed"
            and observation.get("failure_phase") == "member_linkage"
        )
    )


def _oracle_aop_pointcut_constraints(expression: str) -> dict[str, Any] | None:
    value = str(expression or "")
    executions = re.findall(
        r"execution\([^)]*?([\w.$*]+)\.([\w$*]+)\s*\(", value
    )
    if not executions:
        return None
    unsupported = bool(
        "||" in value
        or re.search(
            r"(?<!@)\b(?:within|this|target|args|bean|call|get|set|cflow)\s*\(",
            value,
        )
        or re.search(r"@(?:target|args|this)\s*\(", value)
        or re.search(r"!\s*@within\s*\(", value)
    )
    descriptor_set = lambda items: frozenset(
        "L" + item.replace(".", "/") + ";" for item in items
    )
    return {
        "executions": tuple(executions),
        "class_annotations": descriptor_set(
            re.findall(r"(?<!!)@within\(([\w.$]+)\)", value)
        ),
        "method_annotations": descriptor_set(
            re.findall(r"(?<!!)@annotation\(([\w.$]+)\)", value)
        ),
        "excluded_method_annotations": descriptor_set(
            re.findall(r"!\s*@annotation\(([\w.$]+)\)", value)
        ),
        "complete": not unsupported,
    }


def _resolve_member(
    observations: Mapping[str, Mapping[str, Any]],
    owner: str,
    kind: str,
    name: str,
    descriptor: str,
    visited: frozenset[str] = frozenset(),
    declared_members_cache: dict[
        str, tuple[tuple[str, str, str, int], ...]
    ] | None = None,
) -> tuple[str, tuple[str, str, str, int]] | None:
    if owner in visited:
        return None
    observation = observations.get(owner)
    if not _oracle_class_load_ready(observation):
        return None
    if declared_members_cache is None:
        declared_members = _declared_members(observation)
    else:
        declared_members = declared_members_cache.get(owner)
        if declared_members is None:
            declared_members = tuple(_declared_members(observation))
            declared_members_cache[owner] = declared_members
    for member in declared_members:
        if member[:3] == (kind, name, descriptor):
            return owner, member
    if name == "<init>":
        return None
    is_interface_method = bool(
        kind == "method" and int(observation.get("modifiers") or 0) & 0x0200
    )
    if is_interface_method:
        # JVM interface method resolution may select a matching public
        # instance method declared by Object before searching superinterfaces.
        object_member = _resolve_member(
            observations, "java/lang/Object", kind, name, descriptor,
            visited | {owner}, declared_members_cache,
        )
        if object_member:
            flags = int(object_member[1][3])
            if flags & 0x0001 and not flags & 0x0008:
                return object_member
    parents = (
        [*(observation.get("interfaces") or ()), observation.get("super_name")]
        if kind == "field"
        else (
            [*(observation.get("interfaces") or ())]
            if is_interface_method
            else [
                observation.get("super_name"),
                *(observation.get("interfaces") or ()),
            ]
        )
    )
    for parent in parents:
        if not parent:
            continue
        result = _resolve_member(
            observations, str(parent), kind, name, descriptor,
            visited | {owner}, declared_members_cache,
        )
        if result:
            return result
    return None


def _is_subtype(
    observations: Mapping[str, Mapping[str, Any]], child: str, parent: str,
    visited: frozenset[str] = frozenset(),
) -> bool:
    if child == parent:
        return True
    if child in visited:
        return False
    row = observations.get(child) or {}
    return any(
        _is_subtype(observations, str(candidate), parent, visited | {child})
        for candidate in [row.get("super_name"), *(row.get("interfaces") or ())]
        if candidate
    )


def _oracle_annotation_closure(
    observations: Mapping[str, Mapping[str, Any]], descriptors: Iterable[str],
) -> set[str]:
    result = {
        normalized for value in descriptors if (normalized := str(value))
    }
    pending = list(result)
    while pending:
        descriptor = pending.pop()
        if not descriptor.startswith("L") or not descriptor.endswith(";"):
            continue
        annotation_type = descriptor[1:-1]
        for nested in (observations.get(annotation_type) or {}).get(
            "class_annotations"
        ) or ():
            if nested not in result:
                result.add(str(nested))
                pending.append(str(nested))
    return result


def _oracle_member_annotations(
    observation: Mapping[str, Any],
) -> dict[tuple[str, str], set[str]]:
    result: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in observation.get("member_annotations") or ():
        name, descriptor, annotation = str(row).split("|", 2)
        result[(name, descriptor)].add(annotation)
    return result


def _oracle_annotation_values(
    rows: Iterable[str], *, member_rows: bool = False,
) -> dict[Any, dict[str, set[str]]]:
    result: dict[Any, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for raw in rows or ():
        parts = str(raw).split("|", 4 if member_rows else 2)
        if member_rows:
            if len(parts) != 5:
                continue
            name, member_descriptor, annotation, attribute, value = parts
            key = (name, member_descriptor, annotation)
        else:
            if len(parts) != 3:
                continue
            annotation, attribute, value = parts
            key = annotation
        result[key][attribute].add(value)
    return result


def _oracle_condition_status(
    descriptors: Iterable[str],
    values: Mapping[str, Mapping[str, set[str]]],
    *,
    active_profiles: set[str],
    resolved_properties: Mapping[str, str],
    configuration_complete: bool,
    observations: Mapping[str, Mapping[str, Any]],
) -> str:
    unresolved = False
    for descriptor in descriptors:
        attributes = values.get(str(descriptor)) or {}
        flattened = {
            value for items in attributes.values() for value in items
            if value and not value.startswith("<unresolved:")
        }
        if descriptor == "Lorg/springframework/context/annotation/Profile;":
            if flattened and not flattened.intersection(active_profiles):
                return "inactive"
        elif str(descriptor).endswith("/ConditionalOnClass;"):
            classes = {
                value.replace(".", "/") for value in flattened if "." in value or "/" in value
            }
            if classes and not all(name in observations for name in classes):
                return "inactive"
            if not classes:
                unresolved = True
        elif str(descriptor).endswith("/ConditionalOnMissingClass;"):
            classes = {
                value.replace(".", "/") for value in flattened if "." in value or "/" in value
            }
            if classes and not all(name not in observations for name in classes):
                return "inactive"
            if not classes:
                unresolved = True
        elif str(descriptor).endswith("/ConditionalOnProperty;"):
            prefix = str(next(iter(attributes.get("prefix") or ("",)), "") or "").strip()
            if prefix and not prefix.endswith("."):
                prefix += "."
            declared_names = (
                set(attributes.get("name") or ())
                or set(attributes.get("value") or ())
            )
            names = {prefix + str(value) for value in declared_names if str(value)}
            having = str(
                next(iter(attributes.get("havingValue") or ("",)), "") or ""
            )
            match_missing = str(
                next(iter(attributes.get("matchIfMissing") or ("false",)), "false")
            ).lower() == "true"
            if not names:
                unresolved = True
                continue
            for name in names:
                if name not in resolved_properties:
                    if not match_missing:
                        if configuration_complete:
                            return "inactive"
                        unresolved = True
                    continue
                actual = str(resolved_properties[name])
                if not (actual == having if having else actual.lower() != "false"):
                    return "inactive"
        elif str(descriptor).startswith(
            "Lorg/springframework/boot/autoconfigure/condition/Conditional"
        ) or descriptor == "Lorg/springframework/context/annotation/Conditional;":
            unresolved = True
    return "unproven" if unresolved else "active"


def _oracle_selected_auto_configurations(
    resource_truth: Iterable[Mapping[str, Any]],
) -> tuple[set[str], dict[str, set[tuple[str, str]]]]:
    result = set()
    callbacks: dict[str, set[tuple[str, str]]] = defaultdict(set)
    boot_imports = (
        "META-INF/spring/"
        "org.springframework.boot.autoconfigure.AutoConfiguration.imports"
    )
    factory_keys = {
        "org.springframework.boot.autoconfigure.EnableAutoConfiguration",
        "org.springframework.boot.autoconfigure.AutoConfiguration",
    }
    for selection in resource_truth:
        name = str(selection.get("name") or "")
        for selected in selection.get("selected") or ():
            for key, value in selected.get("semantic_facts") or ():
                if name == boot_imports and key == "ordered_entry":
                    result.add(str(value).replace(".", "/"))
                elif str(key).startswith("property_entry:") and str(key).split(
                    ":", 1
                )[1] in factory_keys:
                    result.add(str(value).replace(".", "/"))
                elif str(key).startswith("property_entry:"):
                    registration = str(key).split(":", 1)[1]
                    callback = _ORACLE_SPRING_FACTORIES_CALLBACKS.get(registration)
                    if callback:
                        callbacks[str(value).replace(".", "/")].add(callback)
    return result, dict(callbacks)


def _validate_entrypoint_discovery(
    generation: Path,
    current_side: Mapping[str, Any],
    current_artifacts: list[dict[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
    resource_truth: Iterable[Mapping[str, Any]],
    direct_edge_truth: Iterable[Iterable[Any]],
    semantic_instructions: Iterable[Iterable[Any]],
    *,
    inventories: list[dict[str, Any]] | None = None,
    declared_members_cache: dict[
        str, tuple[tuple[str, str, str, int], ...]
    ] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Independently reconstruct automatic callback roots using target-JVM reflection."""

    issues = []
    shared_declared_members = (
        declared_members_cache
        if declared_members_cache is not None else {}
    )
    candidate_activation_gaps = set()
    runtime_profile = current_side.get("runtime_profile") or {}
    profile = runtime_profile.get("business_entrypoint_profile")
    if profile is None:
        profile = {}
    declared_coverage_gaps: set[str] = set()

    def import_declared_gaps(raw: Any, *, invalid_gap: str) -> None:
        if raw is None:
            return
        if not isinstance(raw, (list, tuple)):
            declared_coverage_gaps.add(invalid_gap)
            return
        declared_coverage_gaps.update(
            str(value).strip()
            for value in raw
            if str(value or "").strip()
        )

    import_declared_gaps(
        runtime_profile.get("entrypoint_discovery_coverage_gaps"),
        invalid_gap="entrypoint_discovery_coverage_gaps_invalid",
    )
    if isinstance(profile, Mapping):
        import_declared_gaps(
            profile.get("coverage_gaps"),
            invalid_gap="declared_entrypoint_coverage_gaps_invalid",
        )
        if profile.get("coverage_status") not in {None, "complete"}:
            declared_coverage_gaps.add(
                "declared_entrypoint_coverage_incomplete"
            )
    else:
        profile = {}
        declared_coverage_gaps.add("entrypoint_profile_invalid")
    topology = runtime_profile.get("loader_topology") or {}
    non_platform_realms = sorted({
        str(item["identity"])
        for item in topology.get("realms") or ()
        if item.get("kind") != "platform" and item.get("identity")
    })
    realms = tuple(topology.get("entrypoint_realms") or non_platform_realms)
    path_kinds_by_path = {
        Path(str(item["path"])).resolve(): str(item.get("path_kind") or "").lower()
        for item in current_artifacts
    }
    business_path_kinds = {
        "application", "application_classes", "business", "business_classes",
    }

    def artifact_path(observation: Mapping[str, Any]) -> Path | None:
        return _file_url_path(str(observation.get("provider_url") or ""))

    security_policy_supported = str(
        runtime_profile.get(
            "runtime_security_and_package_sealing_policy_identity"
        )
        or "standard-unsealed-unsigned-v1"
    ) == "standard-unsealed-unsigned-v1"
    security_unsupported_artifact_paths = {
        Path(str(artifact["path"])).resolve()
        for artifact, inventory in zip(
            current_artifacts, inventories or (), strict=False
        )
        if _independent_artifact_security_unsupported(inventory)
    }

    def security_prevents_definition(
        observation: Mapping[str, Any],
    ) -> bool:
        path = artifact_path(observation)
        return bool(
            path is not None
            and path in path_kinds_by_path
            and (
                not security_policy_supported
                or path in security_unsupported_artifact_paths
            )
        )

    def business_owned(observation: Mapping[str, Any]) -> bool:
        path = artifact_path(observation)
        return path is not None and path_kinds_by_path.get(path) in business_path_kinds

    # Resolve all framework callback-interface subtypes in one reverse
    # hierarchy walk. The former method/member loop recursively walked the
    # same superclass graph once per (class, callback interface), producing
    # millions of equivalent subtype checks on large dependency closures.
    children_by_parent: dict[str, list[str]] = defaultdict(list)
    for child_name, child_observation in observations.items():
        for parent_name in (
            child_observation.get("super_name"),
            *(child_observation.get("interfaces") or ()),
        ):
            normalized_parent = str(parent_name or "")
            if normalized_parent:
                children_by_parent[normalized_parent].append(child_name)
    callback_kinds_by_class: dict[
        str, dict[str, set[str]]
    ] = defaultdict(lambda: defaultdict(set))
    for interface_name, callbacks in _ORACLE_INTERFACE_CALLBACKS.items():
        pending_subtypes = [interface_name]
        visited_subtypes = set()
        while pending_subtypes:
            subtype = pending_subtypes.pop()
            if subtype in visited_subtypes:
                continue
            visited_subtypes.add(subtype)
            if subtype in observations:
                for callback_name, entry_kind in callbacks.items():
                    callback_kinds_by_class[subtype][callback_name].add(
                        entry_kind
                    )
            pending_subtypes.extend(children_by_parent.get(subtype, ()))

    annotation_closure_cache: dict[tuple[str, ...], frozenset[str]] = {}

    def annotation_closure(values: Iterable[str]) -> frozenset[str]:
        key = tuple(values)
        result = annotation_closure_cache.get(key)
        if result is None:
            result = frozenset(_oracle_annotation_closure(observations, key))
            annotation_closure_cache[key] = result
        return result

    exact_main_classes = {
        str(profile.get("main_class") or "").strip().replace(".", "/")
    } - {""}
    launcher_kind = str(
        (current_side.get("runtime_profile") or {}).get(
            "container_and_launcher_kind"
        ) or ""
    ).lower()
    if launcher_kind in {
        "java-jar", "executable-jar", "spring-boot", "spring_boot",
        "spring-boot-launcher", "spring-boot-executable-jar",
    }:
        for artifact in current_artifacts:
            artifact_path_value = Path(str(artifact["path"])).resolve()
            if path_kinds_by_path.get(artifact_path_value) not in business_path_kinds:
                continue
            with zipfile.ZipFile(artifact_path_value) as archive:
                manifests = [
                    info for info in archive.infolist()
                    if not info.is_dir()
                    and info.filename.upper() == "META-INF/MANIFEST.MF"
                ]
                for manifest in manifests:
                    for key, value in _independent_resource_facts(
                        manifest.filename, archive.read(manifest)
                    ):
                        if str(key).lower() in {"main-class", "start-class"}:
                            exact_main_classes.add(
                                str(value).strip().replace(".", "/")
                            )

    registered_auto_configurations, spring_factories_callbacks = (
        _oracle_selected_auto_configurations(resource_truth)
    )
    explicitly_activated_frameworks = {
        str(value or "").strip().lower()
        for value in profile.get("activated_frameworks") or ()
    }
    launcher = str(
        (current_side.get("runtime_profile") or {}).get(
            "container_and_launcher_kind"
        ) or ""
    ).lower()
    declared_method_keys = {
        (
            str(item.get("class_name") or "").replace("/", "."),
            str(item.get("member_name") or ""),
            str(item.get("descriptor") or ""),
        )
        for item in profile.get("methods") or ()
        if isinstance(item, Mapping)
    }
    spring_boot_active = (
        "spring_boot" in explicitly_activated_frameworks
        or launcher in {
            "spring-boot", "spring_boot", "spring-boot-launcher",
            "spring-boot-executable-jar",
        }
        or any(
            len(edge) == _ORACLE_DIRECT_EDGE_TUPLE_SIZE
            and str(edge[8]) in _ORACLE_DIRECT_METHOD_REFERENCE_KINDS
            and str(edge[3]).replace("/", ".")
            == "org.springframework.boot.SpringApplication"
            and str(edge[4]) == "run"
            and business_owned(observations.get(str(edge[0]).replace(".", "/")) or {})
            and (
                (str(edge[0]), str(edge[1]), str(edge[2]))
                in declared_method_keys
                or (
                    str(edge[0]).replace(".", "/") in exact_main_classes
                    and str(edge[1]) == "main"
                    and str(edge[2]) == "([Ljava/lang/String;)V"
                )
            )
            for edge in direct_edge_truth
        )
    )
    resource_activated = (
        set(registered_auto_configurations) | set(spring_factories_callbacks)
        if spring_boot_active else set()
    )
    activated = set(resource_activated)
    activated.update(
        str(value).replace(".", "/")
        for value in profile.get("activated_classes") or ()
        if str(value).strip()
    )
    jpa_entity_annotations = {
        "Ljavax/persistence/Entity;", "Ljakarta/persistence/Entity;",
        "Ljavax/persistence/MappedSuperclass;",
        "Ljakarta/persistence/MappedSuperclass;",
    }
    activated_entity_classes = {
        str(value).replace(".", "/")
        for value in profile.get("activated_entity_classes") or ()
        if str(value or "").strip()
    }
    for selection in resource_truth:
        for selected in selection.get("selected") or ():
            for key, value in selected.get("semantic_facts") or ():
                if key == "jpa_managed_class" and str(value or "").strip():
                    activated_entity_classes.add(str(value).replace(".", "/"))
    if spring_boot_active:
        for class_name, observation in observations.items():
            if (
                business_owned(observation)
                and set(observation.get("class_annotations") or ()).intersection(
                    jpa_entity_annotations
                )
            ):
                activated_entity_classes.add(class_name)
    active_profiles = {
        str(value or "").strip()
        for value in (current_side.get("runtime_profile") or {}).get(
            "active_profile_identities"
        ) or ()
    }
    resolved_properties = {
        str(key): str(value) for key, value in (
            (current_side.get("runtime_profile") or {}).get(
                "resolved_configuration_properties"
            ) or {}
        ).items()
    }
    configuration_complete = str(
        (current_side.get("runtime_profile") or {}).get(
            "runtime_configuration_coverage_status"
        ) or ""
    ) == "complete"
    component_scan_prefixes = {
        class_name.rsplit("/", 1)[0]
        for class_name in exact_main_classes
        if "/" in class_name and spring_boot_active
    }
    for class_name, observation in observations.items():
        if not business_owned(observation):
            continue
        annotation_values = _oracle_annotation_values(
            observation.get("class_annotation_values") or ()
        )
        component_values = annotation_values.get(
            "Lorg/springframework/context/annotation/ComponentScan;"
        ) or {}
        component_scan_prefixes.update(
            value.replace(".", "/")
            for items in component_values.values() for value in items
            if value and not value.lower().endswith(".class")
        )
    component_annotations = {
        "Lorg/springframework/stereotype/Component;",
        "Lorg/springframework/stereotype/Service;",
        "Lorg/springframework/stereotype/Repository;",
        "Lorg/springframework/stereotype/Controller;",
        "Lorg/springframework/web/bind/annotation/RestController;",
        "Lorg/springframework/context/annotation/Configuration;",
    }
    for class_name, observation in observations.items():
        if (
            set(observation.get("class_annotations") or ()).intersection(
                component_annotations
            )
            and any(
                class_name == prefix or class_name.startswith(prefix + "/")
                for prefix in component_scan_prefixes
            )
        ):
            activated.add(class_name)
    imported_activated = set()
    changed = True
    while changed:
        changed = False
        for class_name, observation in observations.items():
            if class_name not in activated and not business_owned(observation):
                continue
            annotations = annotation_closure(
                observation.get("class_annotations") or ()
            )
            annotated_types = [class_name]
            annotated_types.extend(
                descriptor[1:-1]
                for descriptor in annotations
                if descriptor.startswith("L") and descriptor.endswith(";")
            )
            for annotated_type in annotated_types:
                for imported in (observations.get(annotated_type) or {}).get(
                    "class_annotation_imports"
                ) or ():
                    if str(imported).startswith("<unresolved:"):
                        candidate_activation_gaps.add(
                            f"annotation_import:{class_name}:{imported}"
                        )
                    elif imported not in activated:
                        activated.add(str(imported))
                        imported_activated.add(str(imported))
                        changed = True

    declared = {
        (
            str(item.get("class_name") or "").replace(".", "/"),
            str(item.get("member_name") or ""),
            str(item.get("descriptor") or ""),
        )
        for item in profile.get("methods") or ()
        if isinstance(item, Mapping)
    }
    expected = set()
    for realm in realms:
        for class_name, observation in observations.items():
            if not _oracle_class_load_ready(observation):
                continue
            if security_prevents_definition(observation):
                continue
            if int(observation.get("modifiers") or 0) & (0x0200 | 0x0400):
                continue
            owned = business_owned(observation)
            active = owned or class_name in activated
            class_annotations = annotation_closure(
                observation.get("class_annotations") or ()
            )
            conditional_class = any(
                value.startswith(
                    "Lorg/springframework/boot/autoconfigure/condition/Conditional"
                ) or value == "Lorg/springframework/context/annotation/Conditional;"
                for value in class_annotations
            )
            annotation_by_member = _oracle_member_annotations(observation)
            class_annotation_values = _oracle_annotation_values(
                observation.get("class_annotation_values") or ()
            )
            member_annotation_values = _oracle_annotation_values(
                observation.get("member_annotation_values") or (),
                member_rows=True,
            )
            class_condition_status = _oracle_condition_status(
                observation.get("class_annotations") or (),
                class_annotation_values,
                active_profiles=active_profiles,
                resolved_properties=resolved_properties,
                configuration_complete=configuration_complete,
                observations=observations,
            )
            for kind, member_name, descriptor, flags in _cached_declared_members(
                observations, class_name, shared_declared_members, observation
            ):
                if kind != "method":
                    continue
                if flags & 0x0400:
                    continue
                member_key = (class_name, member_name, descriptor)
                if member_key in declared:
                    expected.add((
                        realm, class_name, member_name, descriptor,
                        "declared_runtime_entry", "exact",
                        "runtime_profile_declaration",
                    ))
                    continue
                annotations = annotation_closure(
                    annotation_by_member.get((member_name, descriptor), ())
                )
                candidate_kinds = {
                    _ORACLE_METHOD_ENTRY_KINDS[value]
                    for value in annotations
                    if value in _ORACLE_METHOD_ENTRY_KINDS
                }
                for annotation, (entry_kind, names) in _ORACLE_CLASS_TRIGGER_KINDS.items():
                    if annotation in class_annotations and member_name in names:
                        candidate_kinds.add(entry_kind)
                candidate_kinds.update(
                    callback_kinds_by_class.get(class_name, {}).get(
                        member_name, ()
                    )
                )
                for callback_name, entry_kind in spring_factories_callbacks.get(
                    class_name, ()
                ):
                    if member_name == callback_name:
                        candidate_kinds.add(entry_kind)
                if (
                    member_name == "main"
                    and descriptor == "([Ljava/lang/String;)V"
                    and flags & 0x0001 and flags & 0x0008 and owned
                ):
                    candidate_kinds.add("java_main")
                for entry_kind in candidate_kinds:
                    conditional = conditional_class or any(
                        value.startswith(
                            "Lorg/springframework/boot/autoconfigure/condition/Conditional"
                        ) or value == "Lorg/springframework/context/annotation/Conditional;"
                        for value in annotations
                    )
                    values_for_member = {
                        annotation: attributes
                        for (value_name, value_descriptor, annotation), attributes
                        in member_annotation_values.items()
                        if value_name == member_name and value_descriptor == descriptor
                    }
                    member_condition_status = _oracle_condition_status(
                        annotation_by_member.get((member_name, descriptor), ()),
                        values_for_member,
                        active_profiles=active_profiles,
                        resolved_properties=resolved_properties,
                        configuration_complete=configuration_complete,
                        observations=observations,
                    )
                    if "inactive" in {
                        class_condition_status, member_condition_status
                    }:
                        continue
                    if conditional and "unproven" in {
                        class_condition_status, member_condition_status
                    }:
                        certainty = "possible"
                        reason = "framework_condition_not_evaluated"
                    elif (
                        entry_kind == "jpa_lifecycle_callback"
                        and class_name not in activated_entity_classes
                    ):
                        certainty = "possible"
                        reason = "entity_lifecycle_activation_unproven"
                    elif entry_kind == "jpa_lifecycle_callback":
                        certainty = "exact"
                        reason = "jpa_entity_registration_proved"
                    elif entry_kind == "java_main" and class_name not in exact_main_classes:
                        certainty = "possible"
                        reason = "business_main_activation_unproven"
                    elif active:
                        certainty = "exact"
                        if owned:
                            reason = "business_final_artifact_runtime_trigger"
                        elif class_name in resource_activated:
                            reason = (
                                "spring_factories_runtime_registration"
                                if class_name in spring_factories_callbacks
                                else "spring_boot_auto_configuration_import"
                            )
                        elif class_name in imported_activated:
                            reason = "spring_import_from_active_configuration"
                        else:
                            reason = "runtime_profile_activation_declaration"
                    else:
                        certainty = "possible"
                        reason = "dependency_framework_activation_unproven"
                    expected.add((
                        realm, class_name, member_name, descriptor,
                        entry_kind, certainty, reason,
                    ))

    # Reconstruct Spring AMQP's string-named MessageListenerAdapter callback
    # directly from javap output. This intentionally does not consume the ASM
    # instruction facts used by production discovery.
    adapter_owner = (
        "org/springframework/amqp/rabbit/listener/adapter/MessageListenerAdapter"
    )
    instruction_batches = getattr(
        semantic_instructions, "iter_batches", None
    )
    batches = (
        instruction_batches()
        if callable(instruction_batches) else (semantic_instructions,)
    )
    for instruction_batch in batches:
        instructions_by_member: dict[
            tuple[str, str, str], list[tuple[int, str, str]]
        ] = defaultdict(list)
        for owner, member_name, descriptor, bci, opcode, comment in (
            instruction_batch
        ):
            instructions_by_member[(
                str(owner), str(member_name), str(descriptor)
            )].append((int(bci), str(opcode), str(comment)))
        for factory_key, instructions in instructions_by_member.items():
            factory_class, _factory_member, factory_descriptor = factory_key
            factory_observation = observations.get(factory_class) or {}
            if (
                not _oracle_class_load_ready(factory_observation)
                or security_prevents_definition(factory_observation)
            ):
                continue
            instructions.sort()
            callback_names = set()
            for constructor_index, (_bci, opcode, comment) in enumerate(
                instructions
            ):
                referenced_owner, referenced_name, referenced_descriptor = (
                    _javap_reference(comment)
                )
                if not (
                    opcode == "invokespecial"
                    and referenced_owner == adapter_owner
                    and referenced_name == "<init>"
                    and "Ljava/lang/String;" in referenced_descriptor
                ):
                    continue
                preceding_literals = [
                    value.removeprefix("String ")
                    for _offset, literal_opcode, value in instructions[
                        max(0, constructor_index - 16):constructor_index
                    ]
                    if literal_opcode in {"ldc", "ldc_w"}
                    and value.startswith("String ")
                ]
                if preceding_literals:
                    callback_names.add(preceding_literals[-1])
            if not callback_names:
                continue
            receiver_owners = {
                parameter[1:-1]
                for parameter in (
                    _descriptor_parameters(factory_descriptor) or ()
                )
                if parameter.startswith("L") and parameter.endswith(";")
            }
            factory_active = spring_boot_active and (
                business_owned(factory_observation)
                or factory_class in activated
            )
            for realm in realms:
                for receiver_owner in receiver_owners:
                    receiver_observation = observations.get(receiver_owner) or {}
                    if security_prevents_definition(receiver_observation):
                        continue
                    callback_candidates = [
                        (name, descriptor)
                        for kind, name, descriptor, _flags in (
                            _cached_declared_members(
                                observations,
                                receiver_owner,
                                shared_declared_members,
                                receiver_observation,
                            )
                        )
                        if kind == "method" and name in callback_names
                    ]
                    certainty = (
                        "exact"
                        if factory_active and len(callback_candidates) == 1
                        else "possible"
                    )
                    reason = (
                        "spring_message_listener_adapter_registration"
                        if certainty == "exact"
                        else (
                            "spring_message_listener_adapter_activation_"
                            "unproven"
                        )
                    )
                    for callback_name, callback_descriptor in (
                        callback_candidates
                    ):
                        expected.add((
                            realm, receiver_owner, callback_name,
                            callback_descriptor, "spring_message_listener",
                            certainty, reason,
                        ))
        del instructions_by_member

    activated_resource_names = {
        str(value).removeprefix("classpath:").lstrip("/")
        for value in profile.get("activated_resource_names") or ()
        if str(value or "").strip()
    }
    for observation in observations.values():
        if not business_owned(observation):
            continue
        for value in observation.get("class_annotation_resources") or ():
            value = str(value or "")
            if value.startswith("<unresolved:"):
                candidate_activation_gaps.add(f"resource_import:{value}")
            elif value.lower().endswith(".xml"):
                activated_resource_names.add(
                    value.removeprefix("classpath:").lstrip("/")
                )

    for selection in resource_truth:
        resource_name = str(selection.get("name") or "")
        if not resource_name.lower().endswith(".xml"):
            continue
        realm = str(selection.get("realm") or "")
        resource_exact = resource_name in activated_resource_names
        for selected in selection.get("selected") or ():
            for fact_key, raw_value in selected.get("semantic_facts") or ():
                mybatis_callback = {
                    "mybatis_plugin_registration": (
                        "mybatis_plugin_callback", ("intercept",)
                    ),
                    "mybatis_type_handler_registration": (
                        "mybatis_type_handler_callback",
                        ("setParameter", "getResult"),
                    ),
                    "mybatis_statement_type_handler": (
                        "mybatis_type_handler_callback",
                        ("setParameter", "getResult"),
                    ),
                }.get(str(fact_key or ""))
                if mybatis_callback:
                    entry_kind, callback_names = mybatis_callback
                    class_name = str(raw_value or "").rsplit("|", 1)[-1].replace(
                        ".", "/"
                    )
                    class_observation = observations.get(class_name) or {}
                    if security_prevents_definition(class_observation):
                        continue
                    candidates = [
                        (name, descriptor)
                        for kind, name, descriptor, _flags in _cached_declared_members(
                            observations,
                            class_name,
                            shared_declared_members,
                            class_observation,
                        )
                        if kind == "method" and name in callback_names
                    ]
                    certainty = "exact" if resource_exact else "possible"
                    reason = (
                        "mybatis_resource_registration"
                        if resource_exact
                        else "mybatis_resource_activation_unproven"
                    )
                    for name, descriptor in candidates:
                        expected.add((
                            realm, class_name, name, descriptor, entry_kind,
                            certainty, reason,
                        ))
                    continue
                entry_kind = {
                    "spring_init_method": "spring_xml_init_method",
                    "spring_scheduled_method": "spring_xml_scheduled",
                    "spring_quartz_method": "spring_xml_quartz",
                }.get(str(fact_key or ""))
                if not entry_kind:
                    continue
                parts = str(raw_value or "").split("|", 2)
                if len(parts) != 3 or not parts[1] or not parts[2]:
                    continue
                class_name = parts[1].replace(".", "/")
                method_name = parts[2]
                class_observation = observations.get(class_name) or {}
                if security_prevents_definition(class_observation):
                    continue
                candidates = [
                    (name, descriptor)
                    for kind, name, descriptor, _flags in _cached_declared_members(
                        observations,
                        class_name,
                        shared_declared_members,
                        class_observation,
                    )
                    if kind == "method" and name == method_name
                ]
                certainty = "exact" if resource_exact and len(candidates) == 1 else "possible"
                reason = (
                    "spring_import_resource_activation"
                    if resource_exact else "spring_xml_activation_unproven"
                )
                for name, descriptor in candidates:
                    expected.add((
                        realm, class_name, name, descriptor,
                        entry_kind, certainty, reason,
                    ))

    actual = {
        (
            str(item.get("initiating_loader_realm_identity") or ""),
            str(item.get("class_name") or ""),
            str(item.get("member_name") or ""),
            str(item.get("descriptor") or ""),
            str(item.get("entry_kind") or ""),
            str(item.get("path_certainty") or ""),
            str(item.get("activation_reason") or ""),
        )
        for item in _iter_sidecar_object_rows(
            generation, "binary_entrypoints.json", "records"
        )
    }
    # Candidate roots intentionally retain incomplete activation evidence and
    # therefore need not be reconstructed as an identical set by an
    # independent mechanism. Only exact roots can create authoritative
    # reachability; those must match byte-for-byte. Candidate consistency is
    # checked later by the closed-world uncertainty reconstruction.
    actual_exact = {item for item in actual if item[5] == "exact"}
    expected_exact = {item for item in expected if item[5] == "exact"}
    if actual_exact != expected_exact:
        issues.append(_validation_issue(
            "entrypoint_discovery", "ORACLE_ENTRYPOINT_SET_MISMATCH",
            missing=sorted(expected_exact - actual_exact),
            extra=sorted(actual_exact - expected_exact),
        ))
    attested_coverage_gaps = {
        str(value).strip()
        for value in (
            _sidecar_top_level_value(
                generation, "binary_entrypoints.json", "coverage_gaps"
            )
            or ()
        )
        if str(value or "").strip()
    }
    missing_declared_gaps = sorted(
        declared_coverage_gaps - attested_coverage_gaps
    )
    if missing_declared_gaps:
        issues.append(_validation_issue(
            "entrypoint_discovery",
            "ORACLE_ENTRYPOINT_DECLARED_COVERAGE_GAP_MISSING",
            missing=missing_declared_gaps,
        ))
    attested_coverage_status = str(
        _sidecar_top_level_value(
            generation, "binary_entrypoints.json", "coverage_status"
        )
        or ("partial" if attested_coverage_gaps else "complete")
    )
    expected_attested_status = (
        "partial" if attested_coverage_gaps else "complete"
    )
    if attested_coverage_status != expected_attested_status:
        issues.append(_validation_issue(
            "entrypoint_discovery",
            "ORACLE_ENTRYPOINT_COVERAGE_ATTESTATION_INVALID",
            expected=expected_attested_status,
            actual=attested_coverage_status,
        ))
    return issues, {
        "exact_entrypoints": [list(item) for item in sorted(expected_exact)],
        "exact_entrypoint_count": len(expected_exact),
        "oracle_candidate_entrypoint_count": len(expected - expected_exact),
        "production_candidate_entrypoint_count": len(actual - actual_exact),
        "candidate_activation_gaps": sorted(candidate_activation_gaps),
    }


def _oracle_runtime_contexts(
    observations: Mapping[str, Mapping[str, Any]],
    initial_classes: Iterable[str],
    entrypoint_realms: Iterable[str],
    platform_realm: str,
) -> tuple[tuple[str, str], ...]:
    """Mirror JVM initiating-to-defining-loader hierarchy traversal.

    Initial application classes and symbolic targets are requested through an
    entrypoint realm.  Their superclasses and interfaces are then requested by
    the selected class's defining loader.  Applying every transitive platform
    type back to every application realm invents provider obligations that do
    not exist in the production reconciliation universe.
    """
    contexts = set()
    pending = [
        (str(realm), provider_owner)
        for realm in entrypoint_realms
        for name in initial_classes
        for provider_owner in (
            _oracle_type_provider_owner(str(name).replace(".", "/")),
        )
        if str(realm) and provider_owner
    ]
    while pending:
        realm, name = pending.pop()
        if (realm, name) in contexts:
            continue
        contexts.add((realm, name))
        observation = observations.get(name) or {}
        if observation.get("status") != "definition_ready":
            continue
        defining_realm = (
            platform_realm
            if _file_url_path(str(observation.get("provider_url") or "")) is None
            else realm
        )
        for dependency in [
            observation.get("super_name"), *(observation.get("interfaces") or ())
        ]:
            normalized = _oracle_type_provider_owner(
                str(dependency or "").replace(".", "/")
            )
            if normalized and (defining_realm, normalized) not in contexts:
                pending.append((defining_realm, normalized))
    return tuple(sorted(contexts))


def _validation_issue(domain: str, code: str, **evidence: Any) -> dict[str, Any]:
    return {"domain": domain, "reason_code": code, "evidence": evidence}


def _artifact_instance_bindings(
    connection: sqlite3.Connection,
    artifacts: Iterable[Mapping[str, Any]],
    *,
    domain: str,
) -> tuple[dict[tuple[str, int], str], list[dict[str, Any]]]:
    """Bind config artifacts to exact runtime locations, not content aliases."""
    artifact_rows = list(artifacts)
    strict_identity_binding = any(
        "_expected_artifact_instance_payload" in artifact
        for artifact in artifact_rows
    )
    rows_by_location: dict[tuple[str, int], sqlite3.Row] = {}
    ambiguous_locations: set[tuple[str, int]] = set()
    issues = []
    selected_columns = (
        "artifact_instance_identity,coord,outer_artifact_sha256,"
        "container_entry,content_sha256,runtime_profile_identity,"
        "loader_realm_identity,runtime_path_kind,"
        "runtime_classpath_index,container_loader_policy_version,"
        "runtime_code_source_origin_identity"
        if strict_identity_binding
        else "artifact_instance_identity,content_sha256,"
        "loader_realm_identity,runtime_classpath_index"
    )
    for row in connection.execute(
        f"SELECT {selected_columns} FROM artifact_instances"
    ):
        location = (
            str(row["loader_realm_identity"] or ""),
            int(row["runtime_classpath_index"]),
        )
        if location in rows_by_location:
            ambiguous_locations.add(location)
        else:
            rows_by_location[location] = row

    bindings: dict[tuple[str, int], str] = {}
    expected_locations: set[tuple[str, int]] = set()
    for artifact in artifact_rows:
        location = (
            str(artifact.get("loader_realm") or ""),
            int(artifact.get("slot")),
        )
        if location in expected_locations:
            issues.append(_validation_issue(
                domain,
                "ORACLE_ARTIFACT_CONFIG_LOCATION_DUPLICATE",
                loader_realm=location[0],
                slot=location[1],
                path=str(artifact.get("path") or ""),
            ))
            continue
        expected_locations.add(location)
        if location in ambiguous_locations:
            issues.append(_validation_issue(
                domain,
                "ORACLE_ARTIFACT_INSTANCE_AMBIGUOUS",
                loader_realm=location[0],
                slot=location[1],
                path=str(artifact.get("path") or ""),
            ))
            continue
        row = rows_by_location.get(location)
        if row is None:
            issues.append(_validation_issue(
                domain,
                "ORACLE_ARTIFACT_INSTANCE_UNBOUND",
                loader_realm=location[0],
                slot=location[1],
                path=str(artifact.get("path") or ""),
            ))
            continue
        expected_sha = str(artifact.get("sha256") or "")
        actual_sha = str(row["content_sha256"] or "")
        if actual_sha != expected_sha:
            issues.append(_validation_issue(
                domain,
                "ORACLE_ARTIFACT_INSTANCE_CONTENT_MISMATCH",
                loader_realm=location[0],
                slot=location[1],
                path=str(artifact.get("path") or ""),
                expected_sha256=expected_sha,
                actual_sha256=actual_sha,
            ))
            continue
        instance_identity = str(row["artifact_instance_identity"] or "")
        if not instance_identity:
            issues.append(_validation_issue(
                domain,
                "ORACLE_ARTIFACT_INSTANCE_IDENTITY_MISSING",
                loader_realm=location[0],
                slot=location[1],
                path=str(artifact.get("path") or ""),
            ))
            continue
        expected_payload = artifact.get(
            "_expected_artifact_instance_payload"
        )
        expected_identity = str(artifact.get(
            "_expected_artifact_instance_identity"
        ) or "")
        if strict_identity_binding:
            if not isinstance(expected_payload, Mapping) or not expected_identity:
                issues.append(_validation_issue(
                    domain,
                    "ORACLE_ARTIFACT_INSTANCE_EXPECTATION_MISSING",
                    loader_realm=location[0],
                    slot=location[1],
                    path=str(artifact.get("path") or ""),
                ))
                continue
            actual_payload = {
                "outer_artifact_sha256": str(
                    row["outer_artifact_sha256"] or ""
                ),
                "container_entry": str(row["container_entry"] or ""),
                "content_sha256": actual_sha,
                "runtime_profile_identity": str(
                    row["runtime_profile_identity"] or ""
                ),
                "path_owner_loader_realm_identity": str(
                    row["loader_realm_identity"] or ""
                ),
                "runtime_path_kind": str(
                    row["runtime_path_kind"] or ""
                ),
                "runtime_classpath_index": int(
                    row["runtime_classpath_index"]
                ),
                "container_loader_policy_version": str(
                    row["container_loader_policy_version"] or ""
                ),
                "runtime_code_source_origin_identity": str(
                    row["runtime_code_source_origin_identity"] or ""
                ),
            }
            actual_recomputed_identity = _identity(
                "artifact_instance_identity", actual_payload
            )
            field_mismatches = {
                key: {
                    "expected": expected_payload.get(key),
                    "actual": actual_payload.get(key),
                }
                for key in expected_payload
                if actual_payload.get(key) != expected_payload.get(key)
            }
            expected_coord = str(artifact.get("coord") or "")
            actual_coord = str(row["coord"] or "")
            if actual_coord != expected_coord:
                field_mismatches["coord"] = {
                    "expected": expected_coord,
                    "actual": actual_coord,
                }
            if (
                actual_recomputed_identity != instance_identity
                or expected_identity != instance_identity
                or field_mismatches
            ):
                issues.append(_validation_issue(
                    domain,
                    "ORACLE_ARTIFACT_INSTANCE_IDENTITY_MISMATCH",
                    loader_realm=location[0],
                    slot=location[1],
                    path=str(artifact.get("path") or ""),
                    expected_artifact_instance_identity=expected_identity,
                    actual_artifact_instance_identity=instance_identity,
                    recomputed_artifact_instance_identity=(
                        actual_recomputed_identity
                    ),
                    field_mismatches=field_mismatches,
                ))
                continue
        bindings[location] = instance_identity
    for loader_realm, slot in sorted(set(rows_by_location) - expected_locations):
        row = rows_by_location[(loader_realm, slot)]
        issues.append(_validation_issue(
            domain,
            "ORACLE_ARTIFACT_INSTANCE_UNEXPECTED",
            loader_realm=loader_realm,
            slot=slot,
            artifact_instance_identity=str(
                row["artifact_instance_identity"] or ""
            ),
            content_sha256=str(row["content_sha256"] or ""),
        ))
    return bindings, issues


def _sequential_member_rowid_ranges(
    connection: sqlite3.Connection,
) -> dict[str, tuple[int, int, int]] | None:
    """Index contiguous per-artifact member ranges with one sequential pass.

    Fact-store insertion writes one complete artifact before the next one, so
    members belonging to an artifact occupy one rowid interval.  Recording
    only those intervals lets the edge validator load a small, covering
    caller projection for the active artifact instead of asking SQLite to do
    one hashed ``members`` lookup for every direct edge.  Older/focused stores
    without the production column, or any non-contiguous layout, return
    ``None`` and retain the exact legacy join.
    """

    try:
        rows = connection.execute(
            "SELECT rowid,artifact_instance_identity "
            "FROM members ORDER BY rowid"
        )
    except sqlite3.Error:
        return None
    mutable: dict[str, list[int]] = {}
    previous_identity: str | None = None
    try:
        for raw in rows:
            rowid = int(raw[0])
            identity = str(raw[1])
            observed = mutable.get(identity)
            if observed is None:
                mutable[identity] = [rowid, rowid, 1]
            elif previous_identity != identity:
                # Reappearing after another artifact would make one rowid
                # interval include unrelated members. Fall back rather than
                # relying on an insertion-layout assumption for correctness.
                return None
            else:
                observed[1] = rowid
                observed[2] += 1
            previous_identity = identity
    except (IndexError, TypeError, ValueError, sqlite3.Error):
        return None
    return {
        identity: (values[0], values[1], values[2])
        for identity, values in mutable.items()
    }


def _artifact_member_projection(
    connection: sqlite3.Connection,
    artifact_instance_identity: str,
    rowid_range: tuple[int, int, int],
) -> dict[str, tuple[str, str, str]] | None:
    """Load caller symbols for one artifact through its sequential row range."""

    first_rowid, last_rowid, expected_count = rowid_range
    if expected_count == 0:
        return {}
    try:
        projection = {
            str(row[0]): (str(row[1]), str(row[2]), str(row[3]))
            for row in connection.execute(
                """
                SELECT member_identity,class_name,member_name,descriptor
                FROM members
                WHERE rowid BETWEEN ? AND ?
                  AND artifact_instance_identity=?
                ORDER BY rowid
                """,
                (first_rowid, last_rowid, artifact_instance_identity),
            )
        }
    except (IndexError, TypeError, ValueError, sqlite3.Error):
        return None
    if len(projection) != expected_count:
        return None
    return projection


def _identity_rows_with_table_locality(
    connection: sqlite3.Connection,
    *,
    table: str,
    identity_column: str,
    selected_columns: tuple[str, ...],
    identities: Iterable[str],
    prefer_table_locality: bool = True,
) -> tuple[sqlite3.Row, ...]:
    """Resolve hashed identities before reading large table rows in rowid order.

    A direct ``WHERE sha_identity IN (...)`` alternates between the compact
    identity index and random main-table pages.  First resolving only
    ``(identity,rowid)`` keeps that phase index-covering; the payload columns
    are then read through a dense rowid range or sorted integer keys.  Tables
    without rowid retain the original identity lookup exactly.
    """

    names = (table, identity_column, *selected_columns)
    if any(re.fullmatch(r"[a-z_][a-z0-9_]*", name) is None for name in names):
        raise ValueError("unsafe SQLite identifier")
    normalized = tuple(dict.fromkeys(str(item) for item in identities))
    if not normalized:
        return ()
    placeholders = ",".join("?" for _item in normalized)
    selected = ",".join(selected_columns)
    legacy_query = (
        f"SELECT {selected} FROM {table} "
        f"WHERE {identity_column} IN ({placeholders})"
    )
    if not prefer_table_locality:
        return tuple(connection.execute(legacy_query, normalized))
    try:
        locations = sorted(
            (
                int(row[0]), str(row[1])
            )
            for row in connection.execute(
                f"SELECT rowid,{identity_column} FROM {table} "
                f"WHERE {identity_column} IN ({placeholders})",
                normalized,
            )
        )
    except (IndexError, TypeError, ValueError, sqlite3.Error):
        return tuple(connection.execute(legacy_query, normalized))
    if not locations:
        return ()
    expected = {identity for _rowid, identity in locations}
    first_rowid = locations[0][0]
    last_rowid = locations[-1][0]
    span = last_rowid - first_rowid + 1
    try:
        if span <= max(64, len(locations) * 4):
            rows = connection.execute(
                f"SELECT {selected} FROM {table} "
                "WHERE rowid BETWEEN ? AND ? ORDER BY rowid",
                (first_rowid, last_rowid),
            )
        else:
            rowid_placeholders = ",".join("?" for _item in locations)
            rows = connection.execute(
                f"SELECT {selected} FROM {table} "
                f"WHERE rowid IN ({rowid_placeholders}) ORDER BY rowid",
                tuple(rowid for rowid, _identity in locations),
            )
        return tuple(
            row for row in rows
            if str(row[identity_column]) in expected
        )
    except (IndexError, TypeError, ValueError, sqlite3.Error):
        return tuple(connection.execute(legacy_query, normalized))


class _SequentialIdentityProjection:
    """Merge ordered identities with one forward SQLite table scan.

    Reconciliation v9 records preserve the reconciler's direct-edge rowid
    order. Resolving each SHA identity through the primary-key B-tree still
    performs millions of random index probes even when the requested payload
    rows are adjacent. This cursor consumes the table once in rowid order.
    Any missing or out-of-order identity falls back to the exact indexed
    lookup, so the locality hint can never omit or relabel evidence.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        table: str,
        identity_column: str,
        selected_columns: tuple[str, ...],
        prefer_table_locality: bool,
    ):
        names = (table, identity_column, *selected_columns)
        if any(
            re.fullmatch(r"[a-z_][a-z0-9_]*", name) is None
            for name in names
        ):
            raise ValueError("unsafe SQLite identifier")
        self.connection = connection
        self.table = table
        self.identity_column = identity_column
        self.selected_columns = selected_columns
        self.prefer_table_locality = prefer_table_locality
        selected = ",".join(selected_columns)
        self.cursor = connection.execute(
            f"SELECT {selected} FROM {table} ORDER BY rowid"
        )
        self.current = self.cursor.fetchone()
        self.closed = False

    def resolve(self, identities: Iterable[str]) -> tuple[sqlite3.Row, ...]:
        normalized = tuple(dict.fromkeys(str(item) for item in identities))
        if not normalized:
            return ()
        resolved = []
        fallback = []
        for identity in normalized:
            while (
                self.current is not None
                and str(self.current[self.identity_column]) != identity
            ):
                self.current = self.cursor.fetchone()
            if self.current is None:
                fallback.append(identity)
                continue
            resolved.append(self.current)
            self.current = self.cursor.fetchone()
        if fallback:
            resolved.extend(_identity_rows_with_table_locality(
                self.connection,
                table=self.table,
                identity_column=self.identity_column,
                selected_columns=self.selected_columns,
                identities=fallback,
                prefer_table_locality=self.prefer_table_locality,
            ))
        return tuple(resolved)

    def close(self) -> None:
        if not self.closed:
            self.cursor.close()
            self.closed = True


def _prefer_identity_table_locality(
    connection: sqlite3.Connection,
) -> bool:
    """Use two-phase row reads only when the fact store risks OS paging."""

    try:
        database_path = next(
            str(row[2])
            for row in connection.execute("PRAGMA database_list")
            if str(row[1]) == "main" and str(row[2])
        )
        database_size = Path(database_path).stat().st_size
    except (OSError, StopIteration, IndexError, TypeError, sqlite3.Error):
        return False
    gib = 1024 * 1024 * 1024
    if database_size < gib:
        return False
    try:
        available = system_available_memory_bytes()
    except Exception:
        available = None
    if available is None:
        return database_size >= 8 * gib
    return database_size * 2 >= max(1, int(available))


def _production_direct_truth_for_artifact(
    connection: sqlite3.Connection,
    artifact_instance_identity: str,
    issues: list[dict[str, Any]],
    *,
    include_structural: bool = False,
    member_rowid_range: tuple[int, int, int] | None = None,
) -> (
    tuple[set[tuple[Any, ...]], set[tuple[Any, ...]]]
    | tuple[
        set[tuple[Any, ...]], set[tuple[Any, ...]],
        set[tuple[Any, ...]], set[tuple[Any, ...]],
    ]
):
    """Project production edges for one artifact into bounded comparison sets."""

    direct: set[tuple[Any, ...]] = set()
    dynamic: set[tuple[Any, ...]] = set()
    structural_type: set[tuple[Any, ...]] = set()
    structural_init: set[tuple[Any, ...]] = set()
    edge_kinds = (
        "'type','class_init',"
        if include_structural else ""
    ) + (
        "'method','field','invokedynamic_bootstrap',"
        "'invokedynamic_handle_method','invokedynamic_handle_field',"
        "'ldc_constant_dynamic_bootstrap','ldc_handle'"
    )
    member_projection = (
        _artifact_member_projection(
            connection, artifact_instance_identity, member_rowid_range
        )
        if member_rowid_range is not None else None
    )
    if member_projection is None:
        edge_query = f"""
            SELECT e.edge_kind,e.symbolic_owner,e.symbolic_name,
                   e.symbolic_descriptor,e.opcode,e.bytecode_offset,
                   e.edge_json,
                   m.class_name AS caller_class_name,
                   m.member_name AS caller_member_name,
                   m.descriptor AS caller_descriptor
            FROM direct_edges AS e
            JOIN members AS m
              ON m.member_identity=e.caller_member_identity
            WHERE e.caller_artifact_instance_identity=? AND (
                e.edge_kind IN ({edge_kinds})
                  OR e.edge_kind LIKE 'invokedynamic_handle_%'
                  OR e.edge_kind LIKE 'ldc_bootstrap_handle_%'
            )
        """
    else:
        edge_query = f"""
            SELECT e.caller_member_identity,e.edge_kind,e.symbolic_owner,
                   e.symbolic_name,e.symbolic_descriptor,e.opcode,
                   e.bytecode_offset,e.edge_json
            FROM direct_edges AS e
            WHERE e.caller_artifact_instance_identity=? AND (
                e.edge_kind IN ({edge_kinds})
                  OR e.edge_kind LIKE 'invokedynamic_handle_%'
                  OR e.edge_kind LIKE 'ldc_bootstrap_handle_%'
            )
        """
    for edge in connection.execute(edge_query, (artifact_instance_identity,)):
        if member_projection is None:
            caller_class_name = str(edge["caller_class_name"])
            caller_member_name = str(edge["caller_member_name"])
            caller_descriptor = str(edge["caller_descriptor"])
        else:
            caller_identity = str(edge["caller_member_identity"])
            caller = member_projection.get(caller_identity)
            if caller is None:
                # A valid fact store keeps caller/member artifact identities
                # aligned. Preserve the legacy INNER JOIN semantics even for
                # an independently authored or malformed store by resolving
                # the exceptional cross-artifact caller exactly once.
                caller_row = connection.execute(
                    """
                    SELECT class_name,member_name,descriptor
                    FROM members WHERE member_identity=?
                    """,
                    (caller_identity,),
                ).fetchone()
                if caller_row is None:
                    continue
                caller = (
                    str(caller_row[0]), str(caller_row[1]),
                    str(caller_row[2]),
                )
                member_projection[caller_identity] = caller
            caller_class_name, caller_member_name, caller_descriptor = caller
        # direct_edges.edge_kind is NOT NULL and this query only admits
        # explicit edge kinds/prefixes, so an empty fallback cannot occur.
        edge_kind = str(edge["edge_kind"])
        edge_payload: Any = None
        edge_payload_loaded = False
        if include_structural:
            try:
                # direct_edges.edge_json is NOT NULL in the fact-store schema.
                edge_payload = json.loads(str(edge["edge_json"]))
            except (TypeError, ValueError, json.JSONDecodeError):
                edge_payload = None
            edge_payload_loaded = True
            caller = (
                caller_class_name, caller_member_name, caller_descriptor,
                int(edge["bytecode_offset"]),
            )
            if edge_kind == "type":
                structural_type.add((
                    *caller, edge["symbolic_owner"],
                    str(
                        (
                            edge_payload.get("type_use_kind")
                            if isinstance(edge_payload, Mapping) else None
                        )
                        or "type_instruction"
                    ),
                ))
            elif edge_kind == "class_init":
                structural_init.add((
                    *caller, edge["symbolic_owner"],
                    str(
                        (
                            edge_payload.get("trigger_kind")
                            if isinstance(edge_payload, Mapping) else None
                        )
                        or ""
                    ),
                ))
            else:
                declared_owners = (
                    edge_payload.get(LOADING_CONSTRAINT_TYPE_OWNERS_KEY)
                    if isinstance(edge_payload, Mapping) else None
                )
                if declared_owners is not None:
                    if (
                        not isinstance(declared_owners, list)
                        or not declared_owners
                        or any(
                            not isinstance(item, str) or not item
                            for item in declared_owners
                        )
                        or tuple(declared_owners)
                        != tuple(sorted(set(declared_owners)))
                    ):
                        issues.append(_validation_issue(
                            "structural_edge",
                            "ORACLE_LOADING_CONSTRAINT_DECLARATION_INVALID",
                            artifact_instance_identity=(
                                artifact_instance_identity
                            ),
                            caller=caller,
                            edge_kind=edge_kind,
                        ))
                    else:
                        if edge_kind == "method":
                            reference_kind = (
                                "interface_method"
                                if bool(edge_payload.get("interface"))
                                else "method"
                            )
                        elif edge_kind == "field":
                            reference_kind = "field"
                        else:
                            handle = (
                                edge_payload.get("bootstrap") or {}
                                if edge_kind == "invokedynamic_bootstrap"
                                else edge_payload
                            )
                            try:
                                tag = int(handle.get("tag") or 0)
                            except (AttributeError, TypeError, ValueError):
                                tag = 0
                            reference_kind = (
                                METHOD_HANDLE_REFERENCE_KIND_BY_TAG.get(tag)
                                or ""
                            )
                            if not reference_kind:
                                issues.append(_validation_issue(
                                    "structural_edge",
                                    "ORACLE_LOADING_CONSTRAINT_REFERENCE_KIND_INVALID",
                                    artifact_instance_identity=(
                                        artifact_instance_identity
                                    ),
                                    caller=caller,
                                    edge_kind=edge_kind,
                                    tag=tag,
                                ))
                        if reference_kind:
                            for referenced_owner in declared_owners:
                                structural_type.add((
                                    *caller, referenced_owner,
                                    "member_reference_descriptor",
                                    str(edge["symbolic_owner"]),
                                    str(edge["symbolic_name"]),
                                    str(edge["symbolic_descriptor"]),
                                    reference_kind,
                                ))
        dynamic_bootstrap = (
            edge_kind == "invokedynamic_bootstrap"
            and str(edge["symbolic_owner"] or "").replace("/", ".")
            not in LINKER_BOOTSTRAP_OWNERS
        )
        ldc_linkage = (
            edge_kind == "ldc_constant_dynamic_bootstrap"
            or edge_kind == "ldc_handle"
            or edge_kind.startswith("ldc_bootstrap_handle_")
        )
        if (
            edge_kind.startswith("invokedynamic_handle_")
            or dynamic_bootstrap
            or ldc_linkage
        ):
            if not edge_payload_loaded:
                try:
                    edge_payload = json.loads(str(edge["edge_json"]))
                except (TypeError, ValueError, json.JSONDecodeError):
                    edge_payload = None
            handle_payload = edge_payload
            if (
                edge_kind == "invokedynamic_bootstrap"
                and isinstance(edge_payload, Mapping)
            ):
                handle_payload = edge_payload.get("bootstrap")
            reference_tag = (
                handle_payload.get("tag")
                if isinstance(handle_payload, Mapping) else None
            )
            reference_kind = (
                METHOD_HANDLE_REFERENCE_KIND_BY_TAG.get(reference_tag)
                if type(reference_tag) is int else None
            )
            reference_interface = (
                handle_payload.get("interface")
                if isinstance(handle_payload, Mapping) else None
            )
            if reference_kind is None or type(reference_interface) is not bool:
                issues.append(_validation_issue(
                    "dynamic_bootstrap",
                    "ORACLE_PRODUCTION_DYNAMIC_REFERENCE_KIND_INVALID",
                    edge_kind=edge_kind,
                    caller_class=caller_class_name,
                    caller_member=caller_member_name,
                    caller_descriptor=caller_descriptor,
                    bytecode_offset=int(edge["bytecode_offset"]),
                ))
                continue
            linkage_family = (
                "invokedynamic"
                if edge_kind.startswith("invokedynamic_handle_")
                or dynamic_bootstrap
                else "ldc_bootstrap_handle"
                if edge_kind.startswith("ldc_bootstrap_handle_")
                else edge_kind
            )
            dynamic.add((
                caller_class_name.replace("/", "."),
                caller_member_name, caller_descriptor,
                edge["symbolic_owner"].replace("/", "."),
                edge["symbolic_name"], edge["symbolic_descriptor"],
                reference_kind, reference_interface, linkage_family,
                int(edge["bytecode_offset"]),
            ))
            continue
        if edge_kind not in {"method", "field"}:
            continue
        if edge_kind == "method":
            if not edge_payload_loaded:
                try:
                    edge_payload = json.loads(str(edge["edge_json"]))
                except (TypeError, ValueError, json.JSONDecodeError):
                    edge_payload = None
            reference_interface = (
                edge_payload.get("interface")
                if isinstance(edge_payload, Mapping) else None
            )
            if type(reference_interface) is not bool:
                issues.append(_validation_issue(
                    "direct_edge",
                    "ORACLE_PRODUCTION_DIRECT_REFERENCE_KIND_INVALID",
                    edge_kind=edge_kind,
                    caller_class=caller_class_name,
                    caller_member=caller_member_name,
                    caller_descriptor=caller_descriptor,
                    bytecode_offset=int(edge["bytecode_offset"]),
                ))
                continue
            reference_kind = (
                "interface_method" if reference_interface else "method"
            )
        else:
            reference_kind = "field"
        direct.add((
            caller_class_name.replace("/", "."),
            caller_member_name, caller_descriptor,
            edge["symbolic_owner"].replace("/", "."),
            edge["symbolic_name"], edge["symbolic_descriptor"],
            _opcode_name(edge["opcode"]), int(edge["bytecode_offset"]),
            reference_kind,
        ))
    if include_structural:
        return direct, dynamic, structural_type, structural_init
    return direct, dynamic


def _validate_direct_edges(
    connection: sqlite3.Connection,
    artifacts: list[dict[str, Any]],
    *,
    javap: str,
    scan_cache: dict[
        tuple[str, str], bytes | Mapping[str, Any] | _OracleScanEvidence
    ] | None = None,
    truth_cache: dict[tuple[str, str], _DirectEdgeTruth] | None = None,
    string_pool: dict[str, str] | None = None,
    progress_callback: ValidationProgressCallback | None = None,
    progress_label: str = "",
    time_budget_seconds: float | None = None,
    retain_truth_rows: bool = True,
    production_structural_cache: _ProductionStructuralSpoolCache | None = None,
    validated_projection_cache: dict[
        tuple[Any, ...], dict[str, Any]
    ] | None = None,
    member_rowid_ranges_output: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    truth_rows = []
    dynamic_rows = []
    direct_artifact_sets = []
    dynamic_artifact_sets = []
    direct_record_count = 0
    dynamic_record_count = 0
    discovery_classes = set()
    instance_by_location, binding_issues = _artifact_instance_bindings(
        connection, artifacts, domain="direct_edge"
    )
    issues.extend(binding_issues)
    # Scan independent artifacts concurrently, but keep one javap worker per
    # artifact so the global process count remains bounded. The previous nested
    # shape scanned JARs serially while starting up to eight JVMs for tiny
    # 32-class groups inside each JAR; at 400+ dependencies JVM startup became
    # the dominant validation cost.
    spooled_scan_results = isinstance(scan_cache, _OracleScanSpoolCache)
    scan_results: dict[tuple[str, str], _OracleScanEvidence] = {}
    available_scan_keys: set[tuple[str, str]] = set()
    scan_requests: dict[tuple[str, str], Path] = {}
    for artifact in artifacts:
        scan_key = (str(artifact["sha256"]), str(javap))
        cached = scan_cache.get(scan_key) if scan_cache is not None else None
        if cached is not None:
            available_scan_keys.add(scan_key)
            if not spooled_scan_results:
                normalized = _normalize_oracle_scan(cached, string_pool)
                scan_results[scan_key] = normalized
                # cached can be non-None only after reading scan_cache above.
                if normalized is not cached:
                    scan_cache[scan_key] = normalized
        else:
            scan_requests.setdefault(scan_key, Path(artifact["path"]))

    scan_total = len(available_scan_keys) + len(scan_requests)
    _notify_progress(
        progress_callback,
        "validation-direct-edges",
        f"{progress_label or '当前侧'}：开始独立 javap 制品扫描",
        len(available_scan_keys),
        scan_total,
    )
    phase_deadline = (
        time.perf_counter() + float(time_budget_seconds)
        if time_budget_seconds is not None and float(time_budget_seconds) > 0
        else None
    )

    def scan_request(item: tuple[tuple[str, str], Path]):
        key, path = item
        remaining_budget = (
            phase_deadline - time.perf_counter()
            if phase_deadline is not None else None
        )
        if remaining_budget is not None and remaining_budget <= 0:
            return key, {
                "artifact_sha256": key[0],
                "complete": False,
                "edges": [],
                "failures": ["oracle_javap_phase_time_budget_exceeded"],
            }
        return key, scan_final_artifact(
            path,
            javap=javap,
            max_workers=1,
            # Every request receives only the time remaining on the shared
            # per-side phase deadline. A large dependency set therefore
            # cannot multiply the configured budget by its artifact count.
            time_budget_seconds=remaining_budget,
            # Each config entry is already one materialized runtime
            # classpath artifact. Recursing into BOOT-INF/lib here would add
            # classes that production did not snapshot for this instance.
            include_nested_runtime_jars=False,
            include_structural_facts=True,
            # This validator immediately stores one compact zlib copy for the
            # base/current and structural passes. Avoid building the oracle's
            # separate JSON-string cache for the same result first.
            cache_result=False,
            # Reuse the exact target JDK's standard javap ToolProvider across
            # artifacts. Transport failure falls back to the ordinary javap
            # executable inside the scanner; no class or edge can be skipped.
            persistent_javap_sessions=True,
        )

    worker_count, scan_available_memory = _artifact_scan_worker_count(
        len(scan_requests)
    )
    process_scan = bool(
        spooled_scan_results
        and worker_count > 1
        and len(scan_requests) >= MIN_ARTIFACTS_FOR_PROCESS_ORACLE_SCAN
    )
    scan_executor_workers = (
        min(worker_count, MAX_PROCESS_ORACLE_SCAN_WORKERS)
        if process_scan else worker_count
    )
    if scan_requests:
        _notify_progress(
            progress_callback,
            "validation-direct-edges",
            (
                f"{progress_label or '当前侧'}：独立 javap 并发度 "
                f"{scan_executor_workers}，按可用内存抑制换页"
            ),
            len(available_scan_keys),
            scan_total,
            (
                "available_memory=unknown"
                if scan_available_memory is None
                else f"available_memory={scan_available_memory}"
            ),
        )

    compiled_javap_binding: CompiledJavapSessionBinding | None = None
    if process_scan:
        try:
            # Spawned workers do not inherit the parent's in-memory helper
            # cache. Compile the content-pinned ToolProvider bridge once and
            # let every worker verify those exact bytes before reuse. Any
            # setup or verification failure remains an optimization miss:
            # workers compile the same helper locally and still scan all
            # requested classes.
            compiled_javap_binding = (
                capture_compiled_javap_session_binding(javap)
            )
        except (JavapSessionError, OSError, ValueError):
            compiled_javap_binding = None

    def execute_scans(use_process: bool) -> None:
        pending_requests = [
            item for item in scan_requests.items()
            if item[0] not in available_scan_keys
        ]
        if not pending_requests:
            return
        requests = iter(pending_requests)
        executor_workers = (
            min(worker_count, MAX_PROCESS_ORACLE_SCAN_WORKERS)
            if use_process else worker_count
        )

        def submit_scan(executor, request):
            if not use_process:
                return executor.submit(scan_request, request)
            key, path = request
            remaining_budget = (
                phase_deadline - time.perf_counter()
                if phase_deadline is not None else None
            )
            return executor.submit(
                _scan_final_artifact_process,
                (
                    key,
                    str(path),
                    javap,
                    remaining_budget,
                    compiled_javap_binding,
                ),
            )

        executor_type = (
            ProcessPoolExecutor if use_process else ThreadPoolExecutor
        )
        executor_options = (
            {"mp_context": multiprocessing.get_context("spawn")}
            if use_process
            else {"thread_name_prefix": "binary-oracle-artifact"}
        )
        with executor_type(
            max_workers=executor_workers, **executor_options
        ) as executor:
            active = {}
            for _ in range(executor_workers):
                if (
                    phase_deadline is not None
                    and time.perf_counter() >= phase_deadline
                ):
                    break
                try:
                    request = next(requests)
                except StopIteration:
                    break
                active[submit_scan(executor, request)] = request[0]
            while active:
                remaining_wait = (
                    phase_deadline - time.perf_counter()
                    if phase_deadline is not None else None
                )
                wait_timeout = (
                    None
                    if remaining_wait is None
                    else remaining_wait
                    if remaining_wait > 0
                    else 0.1
                )
                completed, _pending = wait(
                    active,
                    timeout=wait_timeout,
                    return_when=FIRST_COMPLETED,
                )
                if not completed:
                    # Running scans own the same absolute phase deadline and
                    # cooperatively stop snapshot copying, archive CRC reads,
                    # and javap. Poll only those active tasks; never enqueue a
                    # fresh artifact after the shared phase budget expires.
                    continue
                for future in completed:
                    active.pop(future)
                    scan_key, result = future.result()
                    # Refill the just-freed worker slot before normalizing and
                    # compressing this result. Projection encoding is CPU and
                    # disk work; starting the next independent javap process
                    # first overlaps both without exceeding the existing JVM
                    # or memory-worker bound. At most the one result already
                    # owned by this completed Future is retained here.
                    if (
                        phase_deadline is None
                        or time.perf_counter() < phase_deadline
                    ):
                        try:
                            request = next(requests)
                        except StopIteration:
                            request = None
                        if request is not None:
                            active[submit_scan(executor, request)] = request[0]
                    available_scan_keys.add(scan_key)
                    if spooled_scan_results:
                        if use_process:
                            scan_cache.put_packed_evidence(scan_key, result)
                        else:
                            scan_cache.put_evidence(
                                scan_key,
                                _normalize_oracle_scan(result, string_pool),
                            )
                    else:
                        normalized = _normalize_oracle_scan(
                            result, string_pool
                        )
                        scan_results[scan_key] = normalized
                        if scan_cache is not None and result.get("complete"):
                            scan_cache[scan_key] = normalized
                    _notify_counted_progress(
                        progress_callback,
                        "validation-direct-edges",
                        f"{progress_label or '当前侧'}：独立 javap 制品扫描中",
                        len(available_scan_keys),
                        scan_total,
                        # Every completed key was submitted from this map.
                        str(scan_requests[scan_key]),
                    )
                    del result

    if worker_count:
        if process_scan:
            process_attempt_started = time.perf_counter()
            try:
                execute_scans(True)
            except (OSError, BrokenProcessPool) as error:
                # Process creation may be prohibited by a container/desktop
                # policy. Preserve the configured semantic time budget by not
                # charging failed transport setup, then execute every missing
                # artifact through the original exact thread/JVM path.
                if phase_deadline is not None:
                    phase_deadline += (
                        time.perf_counter() - process_attempt_started
                    )
                _notify_progress(
                    progress_callback,
                    "validation-direct-edges",
                    (
                        f"{progress_label or '当前侧'}：进程扫描不可用，"
                        "切回完整线程扫描"
                    ),
                    len(available_scan_keys),
                    scan_total,
                    f"{type(error).__name__}: {error}",
                )
                execute_scans(False)
        else:
            execute_scans(False)
    for scan_key in scan_requests:
        if scan_key in available_scan_keys:
            continue
        result = {
            "artifact_sha256": scan_key[0],
            "complete": False,
            "edges": [],
            "failures": ["oracle_javap_phase_time_budget_exceeded"],
        }
        available_scan_keys.add(scan_key)
        if spooled_scan_results:
            scan_cache.put_evidence(
                scan_key,
                _normalize_oracle_scan(result, string_pool),
            )
        else:
            scan_results[scan_key] = _normalize_oracle_scan(
                result, string_pool
            )
    # scan_final_artifact keeps immutable serialized results for reuse by
    # callers.  This validator now owns compact copies, so retaining both
    # representations would only inflate its validation peak.
    clear_immutable_oracle_cache()
    _notify_progress(
        progress_callback,
        "validation-direct-edges",
        f"{progress_label or '当前侧'}：独立 javap 制品扫描完成",
        scan_total,
        scan_total,
    )

    _notify_progress(
        progress_callback,
        "validation-direct-edge-production",
        f"{progress_label or '当前侧'}：开始建立成员顺序区间",
        0,
        1,
    )
    member_rowid_ranges = _sequential_member_rowid_ranges(connection)
    if member_rowid_ranges_output is not None:
        # This map contains only three integers per artifact. Its lifetime is
        # the current validate_generation call, so later semantic replays can
        # avoid rescanning the complete members table without any stale-file
        # cache across validation runs.
        member_rowid_ranges_output["ranges"] = member_rowid_ranges
    if member_rowid_ranges is None:
        _notify_progress(
            progress_callback,
            "validation-direct-edge-production",
            (
                f"{progress_label or '当前侧'}：成员布局不连续，"
                "使用兼容 JOIN 校验"
            ),
            1,
            1,
        )
    else:
        _notify_progress(
            progress_callback,
            "validation-direct-edge-production",
            f"{progress_label or '当前侧'}：成员顺序区间已建立",
            1,
            1,
            f"artifact_ranges={len(member_rowid_ranges)}",
        )

    projection_total = sum(
        bool(instance_by_location.get((
            str(artifact.get("loader_realm") or ""),
            int(artifact["slot"]),
        )))
        for artifact in artifacts
    )
    projection_current = 0
    _notify_progress(
        progress_callback,
        "validation-direct-edge-production",
        f"{progress_label or '当前侧'}：开始校验生产调用边",
        0,
        projection_total,
    )

    for artifact in artifacts:
        instance_identity = instance_by_location.get(
            (
                str(artifact.get("loader_realm") or ""),
                int(artifact["slot"]),
            )
        )
        if not instance_identity:
            continue
        artifact_issue_start = len(issues)
        scan_key = (str(artifact["sha256"]), str(javap))
        member_rowid_range = (
            member_rowid_ranges.get(instance_identity, (0, -1, 0))
            if member_rowid_ranges is not None else None
        )
        if production_structural_cache is None:
            actual, actual_dynamic = _production_direct_truth_for_artifact(
                connection,
                instance_identity,
                issues,
                member_rowid_range=member_rowid_range,
            )
        else:
            (
                actual, actual_dynamic,
                actual_type, actual_init,
            ) = _production_direct_truth_for_artifact(
                connection,
                instance_identity,
                issues,
                include_structural=True,
                member_rowid_range=member_rowid_range,
            )
            production_structural_cache.put(
                instance_identity, actual_type, actual_init
            )
            del actual_type, actual_init
        projection_current += 1
        _notify_counted_progress(
            progress_callback,
            "validation-direct-edge-production",
            f"{progress_label or '当前侧'}：生产调用边校验中",
            projection_current,
            projection_total,
            str(artifact.get("path") or instance_identity),
        )
        projection_key = ("direct", *scan_key)
        cached_projection = (
            validated_projection_cache.get(projection_key)
            if validated_projection_cache is not None else None
        )
        ordered_actual = None
        ordered_actual_dynamic = None
        if cached_projection is not None and len(issues) == artifact_issue_start:
            ordered_actual = sorted(actual)
            ordered_actual_dynamic = sorted(actual_dynamic)
            actual_identity = _artifact_truth_identity(
                "binary_oracle_direct_edge_artifact_truth",
                ordered_actual,
            )
            actual_dynamic_identity = _artifact_truth_identity(
                "binary_oracle_dynamic_edge_artifact_truth",
                ordered_actual_dynamic,
            )
            projection_matches = bool(
                len(ordered_actual)
                == cached_projection.get("direct_record_count")
                and actual_identity
                == cached_projection.get("direct_record_identity")
                and len(ordered_actual_dynamic)
                == cached_projection.get("dynamic_record_count")
                and actual_dynamic_identity
                == cached_projection.get("dynamic_record_identity")
            )
        else:
            projection_matches = False

        if projection_matches:
            ordered_truth = ordered_actual
            ordered_dynamic_truth = ordered_actual_dynamic
            direct_identity = str(
                cached_projection["direct_record_identity"]
            )
            dynamic_identity = str(
                cached_projection["dynamic_record_identity"]
            )
            # Direct and dynamic tuple equality has already been proven for
            # this SHA/JDK. Rebuild the small target-owner set from the live
            # production tuples instead of retaining per-artifact duplicate
            # class-name references across both sides.
            discovery_classes.update(
                str(edge[3]).replace(".", "/")
                for edge in chain(actual, actual_dynamic)
                if len(edge) > 3 and edge[3]
            )
        else:
            normalized_truth = (
                truth_cache.get(scan_key) if truth_cache is not None else None
            )
            if spooled_scan_results:
                scan_evidence = scan_cache.get_direct_evidence(
                    scan_key, string_pool
                )
            else:
                scan_evidence = scan_results[scan_key]
            if (
                normalized_truth is None
                and scan_evidence.artifact_sha256
                and scan_evidence.artifact_sha256 != artifact["sha256"]
            ):
                issues.append(_validation_issue(
                    "direct_edge",
                    "ORACLE_ARTIFACT_CHANGED_DURING_DIRECT_EDGE_VALIDATION",
                    artifact=artifact["path"],
                    expected_sha256=artifact["sha256"],
                    actual_sha256=scan_evidence.artifact_sha256,
                ))
                continue
            if normalized_truth is None and not scan_evidence.complete:
                issues.append(_validation_issue(
                    "direct_edge", "ORACLE_JAVAP_INVENTORY_INCOMPLETE",
                    artifact=artifact["path"], failures=scan_evidence.failures,
                ))
                continue
            if normalized_truth is None:
                normalized_truth = scan_evidence.direct_truth
                if truth_cache is not None:
                    truth_cache[scan_key] = normalized_truth
            if (
                normalized_truth.artifact_sha256
                and normalized_truth.artifact_sha256 != artifact["sha256"]
            ):
                issues.append(_validation_issue(
                    "direct_edge",
                    "ORACLE_ARTIFACT_CHANGED_DURING_DIRECT_EDGE_VALIDATION",
                    artifact=artifact["path"],
                    expected_sha256=artifact["sha256"],
                    actual_sha256=normalized_truth.artifact_sha256,
                ))
                continue
            truth = normalized_truth.direct_edges
            dynamic_truth = normalized_truth.dynamic_handle_edges
            artifact_discovery_classes = tuple(
                normalized_truth.discovery_classes
            )
            discovery_classes.update(artifact_discovery_classes)
            for missing in sorted(truth - actual):
                issues.append(_validation_issue(
                    "direct_edge", "ORACLE_DIRECT_EDGE_MISSING", edge=missing
                ))
            for extra in sorted(actual - truth):
                issues.append(_validation_issue(
                    "direct_edge", "ORACLE_DIRECT_EDGE_EXTRA", edge=extra
                ))
            for missing in sorted(dynamic_truth - actual_dynamic):
                issues.append(_validation_issue(
                    "dynamic_bootstrap", "ORACLE_DYNAMIC_HANDLE_MISSING",
                    edge=missing,
                ))
            for extra in sorted(actual_dynamic - dynamic_truth):
                issues.append(_validation_issue(
                    "dynamic_bootstrap", "ORACLE_DYNAMIC_HANDLE_EXTRA",
                    edge=extra,
                ))
            ordered_truth = sorted(truth)
            ordered_dynamic_truth = sorted(dynamic_truth)
            direct_identity = _artifact_truth_identity(
                "binary_oracle_direct_edge_artifact_truth",
                ordered_truth,
            )
            dynamic_identity = _artifact_truth_identity(
                "binary_oracle_dynamic_edge_artifact_truth",
                ordered_dynamic_truth,
            )
            if (
                validated_projection_cache is not None
                and len(issues) == artifact_issue_start
            ):
                validated_projection_cache[projection_key] = {
                    "direct_record_count": len(ordered_truth),
                    "direct_record_identity": direct_identity,
                    "dynamic_record_count": len(ordered_dynamic_truth),
                    "dynamic_record_identity": dynamic_identity,
                }
        direct_record_count += len(ordered_truth)
        dynamic_record_count += len(ordered_dynamic_truth)
        if retain_truth_rows:
            truth_rows.extend(ordered_truth)
            dynamic_rows.extend(ordered_dynamic_truth)
        else:
            direct_artifact_sets.append({
                "artifact_instance_identity": instance_identity,
                "record_count": len(ordered_truth),
                "record_set_identity": direct_identity,
            })
            dynamic_artifact_sets.append({
                "artifact_instance_identity": instance_identity,
                "record_count": len(ordered_dynamic_truth),
                "record_set_identity": dynamic_identity,
            })
        del actual, actual_dynamic
    return issues, {
        "direct_edges": (
            truth_rows if retain_truth_rows else {
                "record_count": direct_record_count,
                "artifact_sets": direct_artifact_sets,
            }
        ),
        "dynamic_handle_edges": (
            dynamic_rows if retain_truth_rows else {
                "record_count": dynamic_record_count,
                "artifact_sets": dynamic_artifact_sets,
            }
        ),
        "discovery_classes": sorted(discovery_classes),
    }


def _validate_runtime_outcomes(
    connection: sqlite3.Connection,
    artifacts: list[dict[str, Any]],
    oracle_artifacts: list[dict[str, Any]],
    inventories: list[dict[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
    entrypoint_realms: Iterable[str],
    initial_classes: Iterable[str],
    platform_realm: str,
    jdk_home: Path,
    *,
    runtime_security_policy_identity: str = "standard-unsealed-unsigned-v1",
    proven_equal_observation_set_identity: str = "",
    progress_callback: ValidationProgressCallback | None = None,
    progress_label: str = "",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    instance_by_location, binding_issues = _artifact_instance_bindings(
        connection, artifacts, domain="provider"
    )
    issues.extend(binding_issues)
    target_jdk_major = _release_major(jdk_home)
    application_classes = {
        class_name
        for inventory in inventories
        for class_name in inventory["classes"]
    }
    declared_members_cache: dict[
        str, tuple[tuple[str, str, str, int], ...]
    ] = {}

    @lru_cache(maxsize=200_000)
    def resolve_member_cached(
        owner: str, kind: str, name: str, descriptor: str,
    ) -> tuple[str, tuple[str, str, str, int]] | None:
        return _resolve_member(
            observations, owner, kind, name, descriptor,
            declared_members_cache=declared_members_cache,
        )

    def dispatch_symbol(
        target: tuple[str, tuple[str, str, str, int]],
    ) -> tuple[str, str, str]:
        declaring, member = target
        _kind, member_name, descriptor, flags = member
        if (
            int(flags) & 0x1000
            and member_name in {
                "begin", "commit", "end", "isEnabled", "shouldCommit",
            }
            and _is_subtype(
                observations, declaring, "jdk/jfr/Event"
            )
        ):
            # The target JVM injects these synthetic methods into Event
            # subclasses at definition time. Their behavior is platform-owned,
            # so dependency impact normalizes them to the JFR base API rather
            # than publishing a nonexistent dependency classfile member.
            return "jdk/jfr/Event", member_name, descriptor
        return declaring, member_name, descriptor

    # Index direct children once, then close only the virtual owners that are
    # actually queried below. Building a transitive ancestor frozenset and a
    # one-element subtype list for every leaf class retained hundreds of
    # thousands of containers even when a class had no descendants.
    direct_children: dict[str, list[str]] = defaultdict(list)
    concrete_classes = set()
    for class_name, observation in observations.items():
        if not _oracle_class_load_ready(observation):
            continue
        modifiers = int(observation.get("modifiers") or 0)
        if not modifiers & (0x0200 | 0x0400):
            concrete_classes.add(class_name)
        for parent in [
            observation.get("super_name"),
            *(observation.get("interfaces") or ()),
        ]:
            if parent:
                direct_children[str(parent)].append(class_name)
    for values in direct_children.values():
        values.sort()
    nontrivial_concrete_subtypes: dict[str, tuple[str, ...]] = {}

    def concrete_subtypes(owner: str) -> tuple[str, ...]:
        children = direct_children.get(owner)
        if not children:
            return (owner,) if owner in concrete_classes else ()
        cached = nontrivial_concrete_subtypes.get(owner)
        if cached is not None:
            return cached
        pending = [owner]
        visited = set()
        result = []
        while pending:
            candidate = pending.pop()
            if candidate in visited:
                continue
            visited.add(candidate)
            if candidate in concrete_classes:
                result.append(candidate)
            pending.extend(direct_children.get(candidate, ()))
        cached = tuple(sorted(result))
        nontrivial_concrete_subtypes[owner] = cached
        return cached
    # URLClassLoader exposes the physical provider URL, not the loader realm.
    # Resolve that URL through the exact parent-first Oracle classpath order;
    # the first mount of a byte-identical path is the selected instance.
    expected_instance_by_path: dict[Path, str] = {}
    for artifact in oracle_artifacts:
        location = (
            str(artifact.get("loader_realm") or ""),
            int(artifact.get("slot") or 0),
        )
        instance_identity = instance_by_location.get(location)
        if instance_identity:
            expected_instance_by_path.setdefault(
                Path(str(artifact["path"])).resolve(), instance_identity
            )
    security_policy_supported = (
        str(runtime_security_policy_identity)
        == "standard-unsealed-unsigned-v1"
    )
    security_unsupported_artifact_paths = {
        Path(str(artifact["path"])).resolve()
        for artifact, inventory in zip(artifacts, inventories)
        if _independent_artifact_security_unsupported(inventory)
    }
    # These indexes are consulted only for four scalar values. Retaining the
    # full decoded reconciliation payloads (especially definition evidence)
    # made the Oracle keep a second copy of a large part of the graph alive.
    # Compact tuples preserve every value used by the checks below while the
    # authoritative records remain intact in SQLite.
    definitions = {
        (row["initiating_loader_realm_identity"], row["class_name"]): (
            row["class_definition_status"], row["class_load_status"],
        )
        for row in _iter_reconciliation(connection, "class_definition")
    }
    provider_by_key = {
        (row["initiating_loader_realm_identity"], row["class_name"]): (
            row["class_provider_status"],
            row.get("selected_artifact_instance_identity"),
        )
        for row in _iter_reconciliation(connection, "provider_binding")
    }
    oracle_contexts = _oracle_runtime_contexts(
        observations, initial_classes, entrypoint_realms, platform_realm
    )
    for realm, name in oracle_contexts:
        oracle = observations.get(name) or {}
        provider = provider_by_key.get((realm, name))
        if not provider:
            issues.append(_validation_issue(
                "provider", "ORACLE_PROVIDER_BINDING_MISSING", realm=realm, class_name=name,
            ))
            continue
        actual_status = provider[0]
        provider_location = _oracle_provider_location(oracle)
        if not provider_location:
            if actual_status == "resolved":
                issues.append(_validation_issue(
                    "provider", "ORACLE_PROVIDER_FALSE_RESOLUTION", realm=realm, class_name=name,
                ))
            continue
        provider_path = _provider_resource_path(provider_location)
        if provider_path is None or (
            target_jdk_major == 8
            and _is_bound_jdk8_platform_path(provider_path, jdk_home)
        ):
            expected_kind = "platform"
        else:
            expected_kind = "artifact"
        if actual_status != "resolved":
            issues.append(_validation_issue(
                "provider", "ORACLE_PROVIDER_MISSED", realm=realm, class_name=name,
                oracle_provider_url=provider_location,
            ))
            continue
        selected = provider[1]
        if expected_kind == "platform":
            if not str(selected).startswith("platform-image:"):
                issues.append(_validation_issue(
                    "provider", "ORACLE_PLATFORM_PROVIDER_MISMATCH",
                    realm=realm, class_name=name, selected=selected,
                ))
        else:
            expected_instance = expected_instance_by_path.get(provider_path)
            if not expected_instance or str(selected) != expected_instance:
                issues.append(_validation_issue(
                    "provider", "ORACLE_ARTIFACT_PROVIDER_MISMATCH",
                    realm=realm, class_name=name, oracle_provider_url=provider_location,
                    selected=selected,
                    expected_artifact_instance_identity=expected_instance,
                ))
        definition = definitions.get((realm, name))
        production_definition_status = definition[0] if definition else None
        production_class_load_status = definition[1] if definition else None
        production_class_load_ready = production_class_load_status == "ready"
        security_prevents_definition = bool(
            expected_kind == "artifact"
            and (
                not security_policy_supported
                or provider_path in security_unsupported_artifact_paths
            )
        )
        oracle_definition_ready = bool(
            oracle.get("status") == "definition_ready"
            and not security_prevents_definition
        )
        if (
            not definition
            or oracle_definition_ready
            != (production_definition_status == "definition_ready")
        ):
            issues.append(_validation_issue(
                "class_definition", "ORACLE_DEFINITION_READY_MISMATCH",
                realm=realm, class_name=name,
                oracle_status=oracle.get("status"),
                production_status=production_definition_status,
            ))
        oracle_class_load_ready = bool(
            _oracle_class_load_ready(oracle)
            and not security_prevents_definition
        )
        if definition and production_class_load_ready != oracle_class_load_ready:
            issues.append(_validation_issue(
                "class_definition", "ORACLE_CLASS_LOAD_READY_MISMATCH",
                realm=realm, class_name=name,
                oracle_status=oracle.get("status"),
                oracle_failure_phase=oracle.get("failure_phase"),
                production_class_load_status=production_class_load_status,
            ))

    provider_count = len(provider_by_key)
    selected_caller_artifact_classes = frozenset(
        (str(selected), str(class_name))
        for (_realm, class_name), (status, selected) in provider_by_key.items()
        if status == "resolved"
        and selected
        and not str(selected).startswith("platform-image:")
    )
    # A runtime reconciliation intentionally excludes bytecode owned by a
    # physically present but shadowed class variant.  Completeness therefore
    # has to be measured over selected caller definitions, not every row in
    # the physical fact store.  Older/in-memory boundary harnesses may expose
    # only the columns used by the individual check; full production fact
    # stores always expose the caller artifact binding and use this filter.
    direct_edge_columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(direct_edges)")
    }
    can_filter_selected_callers = (
        "caller_artifact_instance_identity" in direct_edge_columns
        and "caller_member_identity" in direct_edge_columns
    )
    # Provider/definition validation is complete. Release those decoded
    # reconciliation graphs before constructing member/edge indexes so the two
    # largest Oracle views do not overlap at peak RSS.
    del (
        definitions,
        provider_by_key,
        expected_instance_by_path,
        instance_by_location,
    )

    try:
        variable_limit = connection.getlimit(
            sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER
        )
    except (AttributeError, sqlite3.Error):
        variable_limit = 999
    lookup_batch_size = max(1, min(5_000, variable_limit - 8))
    prefer_identity_table_locality = _prefer_identity_table_locality(
        connection
    )

    def batches(values: Iterable[Any]):
        batch = []
        for value in values:
            batch.append(value)
            if len(batch) >= lookup_batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    direct_edge_selected_columns = (
        "direct_edge_identity", "edge_kind", "symbolic_owner",
        "symbolic_name", "symbolic_descriptor", "opcode",
    )

    def open_direct_projection(
        reconciliation_kind: str,
    ) -> _SequentialIdentityProjection | None:
        if not (
            prefer_identity_table_locality
            and _has_complete_reconciliation_chunk_order(
                connection, reconciliation_kind
            )
        ):
            return None
        return _SequentialIdentityProjection(
            connection,
            table="direct_edges",
            identity_column="direct_edge_identity",
            selected_columns=direct_edge_selected_columns,
            prefer_table_locality=prefer_identity_table_locality,
        )

    def direct_edge_batch(
        edge_ids: Iterable[str],
        projection: _SequentialIdentityProjection | None = None,
    ):
        identities = tuple(dict.fromkeys(str(item) for item in edge_ids))
        # Every caller passes one non-empty reconciliation batch.  The queried
        # identity/kind/symbol columns are NOT NULL in BinaryFactStore; only
        # opcode is nullable for non-bytecode semantic edges.
        return {
            str(row["direct_edge_identity"]): (
                str(row["edge_kind"]),
                str(row["symbolic_owner"]),
                str(row["symbolic_name"]),
                str(row["symbolic_descriptor"]),
                int(row["opcode"]) if row["opcode"] is not None else 0,
            )
            for row in (
                projection.resolve(identities)
                if projection is not None
                else _identity_rows_with_table_locality(
                    connection,
                    table="direct_edges",
                    identity_column="direct_edge_identity",
                    selected_columns=direct_edge_selected_columns,
                    identities=identities,
                    prefer_table_locality=prefer_identity_table_locality,
                )
            )
        }

    member_symbol_cache = _BoundedProjectionCache(
        _runtime_member_projection_cache_limit()
    )

    def load_member_symbols(identities: tuple[str, ...]):
        return {
            str(row["member_identity"]): (
                str(row["class_name"]),
                str(row["member_name"]),
                str(row["descriptor"]),
            )
            for row in _identity_rows_with_table_locality(
                connection,
                table="members",
                identity_column="member_identity",
                selected_columns=(
                    "member_identity", "class_name", "member_name",
                    "descriptor",
                ),
                identities=identities,
                prefer_table_locality=prefer_identity_table_locality,
            )
        }

    def member_symbol_batch(member_ids: Iterable[str]):
        return member_symbol_cache.resolve(member_ids, load_member_symbols)

    def reconciliation_total(kind: str) -> int | None:
        try:
            return int(connection.execute(
                "SELECT COALESCE(SUM(record_count),0) "
                "FROM reconciliation_records WHERE record_kind=?",
                (_ORACLE_RECONCILIATION_KIND_CODES[kind],),
            ).fetchone()[0])
        except (IndexError, TypeError, ValueError, sqlite3.Error):
            # Focused/legacy integrations may expose reconciliation through a
            # compatibility connection without the physical chunk table.
            return None

    member_resolution_total = reconciliation_total("member_resolution")
    member_resolution_count = 0
    member_progress_interval = max(
        lookup_batch_size,
        (
            (member_resolution_total + 19) // 20
            if member_resolution_total is not None else 100_000
        ),
    )
    next_member_progress = member_progress_interval
    _notify_progress(
        progress_callback,
        "validation-runtime-reconciliation",
        f"{progress_label or '当前侧'}：开始校验成员解析记录",
        0,
        member_resolution_total,
    )
    member_direct_projection = open_direct_projection("member_resolution")
    try:
        for resolution_batch in batches(
            _iter_reconciliation(connection, "member_resolution")
        ):
            member_resolution_count += len(resolution_batch)
            edge_by_id = direct_edge_batch(
                (
                    row["direct_edge_identity"]
                    for row in resolution_batch
                ),
                member_direct_projection,
            )
            selected_members = member_symbol_batch(
                row.get("resolved_member_identity")
                for row in resolution_batch
            )
            for resolution in resolution_batch:
                edge_identity = str(resolution["direct_edge_identity"])
                edge = edge_by_id.get(edge_identity)
                if not edge or edge[0] not in {"method", "field"}:
                    continue
                kind = "field" if edge[0] == "field" else "method"
                oracle_member = resolve_member_cached(
                    edge[1], kind, edge[2], edge[3],
                )
                status = resolution["member_resolution_status"]
                if oracle_member is None:
                    if status == "resolved":
                        issues.append(_validation_issue(
                            "member_resolution",
                            "ORACLE_MEMBER_FALSE_RESOLUTION",
                            direct_edge_identity=edge_identity,
                        ))
                    continue
                declaring, _member = oracle_member
                if status != "resolved":
                    issues.append(_validation_issue(
                        "member_resolution", "ORACLE_MEMBER_MISSED",
                        direct_edge_identity=edge_identity,
                        declaring_owner=declaring,
                    ))
                    continue
                selected_member = selected_members.get(str(
                    resolution.get("resolved_member_identity") or ""
                ))
                if selected_member and selected_member[0] != declaring:
                    issues.append(_validation_issue(
                        "member_resolution",
                        "ORACLE_MEMBER_OWNER_MISMATCH",
                        direct_edge_identity=edge_identity,
                        expected_owner=declaring,
                        actual_owner=selected_member[0],
                    ))
            if (
                member_resolution_count >= next_member_progress
                or (
                    member_resolution_total is not None
                    and member_resolution_count == member_resolution_total
                )
            ):
                _notify_progress(
                    progress_callback,
                    "validation-runtime-reconciliation",
                    f"{progress_label or '当前侧'}：成员解析记录校验中",
                    member_resolution_count,
                    member_resolution_total,
                )
                next_member_progress = (
                    member_resolution_count + member_progress_interval
                )
    finally:
        if member_direct_projection is not None:
            member_direct_projection.close()
    _notify_progress(
        progress_callback,
        "validation-runtime-reconciliation",
        f"{progress_label or '当前侧'}：成员解析记录校验完成",
        member_resolution_count,
        (
            member_resolution_total
            if member_resolution_total is not None
            else member_resolution_count
        ),
    )

    @lru_cache(maxsize=100_000)
    def oracle_dispatch_targets(
        owner: str, name: str, descriptor: str
    ) -> frozenset[tuple[str, str, str]]:
        result = set()
        declaration = resolve_member_cached(
            owner, "method", name, descriptor,
        )
        declaration_fixed = bool(
            declaration
            and (
                int(declaration[1][3]) & 0x0010
                or int(
                    (observations.get(declaration[0]) or {}).get("modifiers")
                    or 0
                ) & 0x0010
            )
        )
        if declaration_fixed:
            result.add(dispatch_symbol(declaration))
        elif declaration:
            for class_name in concrete_subtypes(owner):
                target = resolve_member_cached(
                    class_name, "method", name, descriptor,
                )
                if target:
                    result.add(dispatch_symbol(target))
        return frozenset(result)

    def validate_dispatch(
        edge_id: str,
        edge: tuple[str, str, str, str, int],
        production_status: str,
        target_symbols: set[tuple[str, str, str]],
    ) -> None:
        oracle_targets = oracle_dispatch_targets(edge[1], edge[2], edge[3])
        application_oracle_targets = {
            item for item in oracle_targets if item[0] in application_classes
        }
        if target_symbols != application_oracle_targets:
            issues.append(_validation_issue(
                "dispatch", "ORACLE_DISPATCH_TARGET_MISMATCH",
                direct_edge_identity=edge_id,
                expected=sorted(application_oracle_targets), actual=sorted(target_symbols),
            ))
        if application_oracle_targets and production_status not in {
            "possible", "partial_possible_set", "proven_receiver", "exact"
        }:
            issues.append(_validation_issue(
                "dispatch", "ORACLE_DISPATCH_STATUS_MISMATCH",
                direct_edge_identity=edge_id, status=production_status,
            ))

    dispatch_total = reconciliation_total("dispatch_resolution")
    dispatch_count = 0
    dispatch_progress_interval = max(
        lookup_batch_size,
        (
            (dispatch_total + 19) // 20
            if dispatch_total is not None else 100_000
        ),
    )
    next_dispatch_progress = dispatch_progress_interval
    _notify_progress(
        progress_callback,
        "validation-runtime-reconciliation",
        f"{progress_label or '当前侧'}：开始校验分派解析记录",
        0,
        dispatch_total,
    )
    with short_temporary_directory(
        prefix="binary-validation-dispatch"
    ) as dispatch_temp:
        seen_connection = sqlite3.connect(
            Path(dispatch_temp) / "seen.sqlite", uri=True
        )
        seen_connection.row_factory = sqlite3.Row
        seen_connection.execute(
            "CREATE TABLE seen (evidence TEXT PRIMARY KEY) WITHOUT ROWID"
        )
        dispatch_direct_projection = None
        try:
            dispatch_direct_projection = open_direct_projection(
                "dispatch_resolution"
            )
            for dispatch_batch in batches(
                _iter_reconciliation(connection, "dispatch_resolution")
            ):
                dispatch_count += len(dispatch_batch)
                edge_by_id = direct_edge_batch(
                    (
                        row["direct_edge_identity"]
                        for row in dispatch_batch
                    ),
                    dispatch_direct_projection,
                )
                target_ids = [
                    target
                    for row in dispatch_batch
                    for target in (
                        row.get("implementation_target_identities") or ()
                    )
                ]
                target_members = member_symbol_batch(target_ids)
                seen_rows = []
                for row in dispatch_batch:
                    edge_id = str(row["direct_edge_identity"])
                    edge = edge_by_id.get(edge_id)
                    if not edge or edge[0] != "method" or edge[4] not in {
                        182, 185,
                    }:
                        continue
                    seen_rows.append((edge_id,))
                    target_symbols = {
                        target_members[target_id]
                        for target_id in (
                            row.get("implementation_target_identities") or ()
                        )
                        if target_id in target_members
                    }
                    validate_dispatch(
                        edge_id,
                        edge,
                        str(row.get("dispatch_status") or ""),
                        target_symbols,
                    )
                if seen_rows:
                    seen_connection.executemany(
                        "INSERT OR IGNORE INTO seen VALUES (?)", seen_rows
                    )
                if (
                    dispatch_count >= next_dispatch_progress
                    or (
                        dispatch_total is not None
                        and dispatch_count == dispatch_total
                    )
                ):
                    _notify_progress(
                        progress_callback,
                        "validation-runtime-reconciliation",
                        f"{progress_label or '当前侧'}：分派解析记录校验中",
                        dispatch_count,
                        dispatch_total,
                    )
                    next_dispatch_progress = (
                        dispatch_count + dispatch_progress_interval
                    )
            _notify_progress(
                progress_callback,
                "validation-runtime-reconciliation",
                f"{progress_label or '当前侧'}：分派解析记录校验完成",
                dispatch_count,
                dispatch_total if dispatch_total is not None else dispatch_count,
            )
            seen_connection.commit()
            _notify_progress(
                progress_callback,
                "validation-runtime-reconciliation",
                f"{progress_label or '当前侧'}：开始复核缺失分派记录",
                0,
                None,
            )
            database_path_text = str(
                connection.execute("PRAGMA database_list").fetchone()[2]
                or ""
            )
            missing_query = """
                SELECT e.direct_edge_identity,e.edge_kind,e.symbolic_owner,
                       e.symbolic_name,e.symbolic_descriptor,e.opcode
                       {caller_columns}
                FROM {schema}.direct_edges AS e
                {seen_join}
                WHERE e.edge_kind='method' AND e.opcode IN (182,185)
                {missing_predicate}
            """
            if database_path_text:
                facts_path = Path(database_path_text).resolve()
                facts_uri = f"{facts_path.as_uri()}?mode=ro&immutable=1"
                seen_connection.execute(
                    "ATTACH DATABASE ? AS facts", (facts_uri,)
                )
                missing_rows = seen_connection.execute(missing_query.format(
                    schema="facts",
                    caller_columns=(
                        ",e.caller_artifact_instance_identity,"
                        "e.caller_member_identity"
                        if can_filter_selected_callers else ""
                    ),
                    seen_join=(
                        "LEFT JOIN seen AS s "
                        "ON s.evidence=e.direct_edge_identity"
                    ),
                    missing_predicate="AND s.evidence IS NULL",
                ))
            else:
                seen_ids = {
                    str(row[0])
                    for row in seen_connection.execute(
                        "SELECT evidence FROM seen"
                    )
                }
                missing_rows = (
                    row for row in connection.execute(missing_query.format(
                        schema="main",
                        caller_columns=(
                            ",e.caller_artifact_instance_identity,"
                            "e.caller_member_identity"
                            if can_filter_selected_callers else ""
                        ),
                        seen_join="", missing_predicate="",
                    ))
                    if str(row["direct_edge_identity"]) not in seen_ids
                )

            @lru_cache(maxsize=20_000)
            def missing_caller_class(member_identity: str) -> str | None:
                source = seen_connection if database_path_text else connection
                schema = "facts" if database_path_text else "main"
                row = source.execute(
                    f"SELECT class_name FROM {schema}.members "
                    "WHERE member_identity=?",
                    (member_identity,),
                ).fetchone()
                return str(row[0]) if row is not None else None

            for row in missing_rows:
                if can_filter_selected_callers:
                    caller_class = missing_caller_class(str(
                        row["caller_member_identity"]
                    ))
                    # Preserve the former INNER JOIN behavior for a dangling
                    # member in an independently authored fact store.
                    if caller_class is None or (
                        str(row["caller_artifact_instance_identity"]),
                        caller_class,
                    ) not in selected_caller_artifact_classes:
                        continue
                edge_id = str(row["direct_edge_identity"])
                edge = (
                    str(row["edge_kind"]),
                    str(row["symbolic_owner"]),
                    str(row["symbolic_name"]),
                    str(row["symbolic_descriptor"]),
                    # The missing-row query restricts this column to 182/185.
                    int(row["opcode"]),
                )
                validate_dispatch(edge_id, edge, "", set())
            _notify_progress(
                progress_callback,
                "validation-runtime-reconciliation",
                f"{progress_label or '当前侧'}：缺失分派记录复核完成",
                1,
                1,
            )
        finally:
            if dispatch_direct_projection is not None:
                dispatch_direct_projection.close()
            seen_connection.close()

    if proven_equal_observation_set_identity:
        if re.fullmatch(
            r"[0-9a-f]{64}", proven_equal_observation_set_identity
        ) is None:
            raise BinaryValidationError(
                "BINARY_RUNTIME_OBSERVATION_IDENTITY_INVALID",
                proven_equal_observation_set_identity,
            )
        observation_set_identity = proven_equal_observation_set_identity
    else:
        observation_set_identity = _runtime_observation_set_identity(
            observations
        )
    return issues, {
        "runtime_observation_set_identity": observation_set_identity,
        "runtime_observation_count": len(observations),
        "provider_count": provider_count,
        "member_resolution_count": member_resolution_count,
        "dispatch_count": dispatch_count,
        "runtime_security_policy_supported": security_policy_supported,
        "security_unsupported_artifact_count": len(
            security_unsupported_artifact_paths
        ),
    }


def _validate_resource_selections(
    connection: sqlite3.Connection,
    artifacts: list[dict[str, Any]],
    inventories: list[dict[str, Any]],
    entrypoint_realms: Iterable[str],
    topology: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    production = {
        (row["initiating_loader_realm_identity"], row["resource_name"], row["resource_mechanism"]): row
        for row in _reconciliation(connection, "resource_selection")
    }
    truth = {}
    inventory_by_location = {
        (
            str(artifact.get("loader_realm") or ""),
            int(artifact.get("slot") or 0),
        ): inventory
        for artifact, inventory in zip(artifacts, inventories)
    }
    all_names = sorted({name for inventory in inventories for name in inventory["resources"]})
    for realm in entrypoint_realms:
        ordered_artifacts = _ordered_artifacts_for_realm(
            artifacts, topology, str(realm)
        )
        for name in all_names:
            category = _independent_resource_category(name)
            mechanism = (
                "ordered_all"
                if category == "runtime_topology"
                else "classloader_first"
            )
            candidates = []
            for artifact in ordered_artifacts:
                location = (
                    str(artifact.get("loader_realm") or ""),
                    int(artifact.get("slot") or 0),
                )
                inventory = inventory_by_location.get(location) or {
                    "resources": {}
                }
                for item in inventory["resources"].get(name, ()):
                    candidates.append({
                        "slot": int(artifact["slot"]),
                        "origin": str(artifact.get("runtime_code_source_origin_identity") or ""),
                        "digest": item["semantic_digest"] if category == "runtime_topology" else item["sha256"],
                        "semantic_facts": item["semantic_facts"],
                    })
            selected = candidates if mechanism == "ordered_all" else candidates[:1]
            key = (realm, name, mechanism)
            truth[key] = selected
            actual_record = production.get(key)
            actual = []
            for item in (actual_record or {}).get("selected_resources") or ():
                actual.append({
                    "slot": int(item["runtime_classpath_index"]),
                    "origin": item["runtime_code_source_origin_identity"],
                    "digest": (
                        item["normalized_resource_digest"]
                        if category == "runtime_topology" else item["content_sha256"]
                    ),
                    "semantic_facts": item.get("resource_semantic_facts") or [],
                })
            def comparable(item):
                semantic = item.get("semantic_facts") or []
                return {
                    "slot": item["slot"], "origin": item["origin"],
                    "value": semantic if semantic else item["digest"],
                }
            expected_comparable = [comparable(item) for item in selected]
            actual_comparable = [comparable(item) for item in actual]
            if actual_comparable != expected_comparable:
                issues.append(_validation_issue(
                    "resource_selection", "ORACLE_RESOURCE_SELECTION_MISMATCH",
                    realm=realm, resource_name=name,
                    expected=expected_comparable, actual=actual_comparable,
                ))
    # Compare the full key universe as well as values.  Without this check a
    # production regression that leaks an inactive physical MR resource into
    # reconciliation would be invisible because independent truth correctly
    # omits that logical resource name.
    unexpected_keys = sorted(set(production) - set(truth))
    for realm, name, mechanism in unexpected_keys:
        issues.append(_validation_issue(
            "resource_selection",
            "ORACLE_RESOURCE_SELECTION_UNEXPECTED",
            realm=realm,
            resource_name=name,
            resource_mechanism=mechanism,
        ))
    return issues, {
        "resource_selections": [
            {"realm": key[0], "name": key[1], "mechanism": key[2], "selected": value}
            for key, value in sorted(truth.items())
        ]
    }


def _validate_pairings(
    generation: Path, base_artifacts: list[dict[str, Any]], current_artifacts: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    payload = _load_json(generation / "binary_pairings.json")
    actual = {
        row["logical_dependency_lineage"]: row["status"]
        for row in payload.get("pairings") or ()
    }
    base = defaultdict(int)
    current = defaultdict(int)
    for item in base_artifacts:
        base[str(item.get("lineage") or item.get("coord") or item.get("logical_location"))] += 1
    for item in current_artifacts:
        current[str(item.get("lineage") or item.get("coord") or item.get("logical_location"))] += 1
    expected = {}
    issues = []
    for lineage in sorted(set(base) | set(current)):
        if base[lineage] > 1 or current[lineage] > 1:
            status = "ambiguous"
        elif base[lineage] and current[lineage]:
            status = "exact"
        elif base[lineage]:
            status = "base_only"
        else:
            status = "current_only"
        expected[lineage] = status
        if actual.get(lineage) != status:
            issues.append(_validation_issue(
                "pairing", "ORACLE_PAIRING_MISMATCH", lineage=lineage,
                expected=status, actual=actual.get(lineage),
            ))
    return issues, {"pairings": expected}


def _edge_scan_artifact_identities(
    connection: sqlite3.Connection,
) -> tuple[str, ...]:
    """Return the small authoritative artifact order for local edge scans."""

    try:
        return tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT artifact_instance_identity FROM artifact_instances "
                "ORDER BY runtime_classpath_index,rowid"
            )
        )
    except sqlite3.Error:
        # Focused/legacy stores may omit artifact_instances. Preserve their
        # complete edge universe through the covering caller-artifact index.
        return tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT DISTINCT caller_artifact_instance_identity "
                "FROM direct_edges "
                "ORDER BY caller_artifact_instance_identity"
            )
        )


def _iter_edge_rows_with_local_callers(
    connection: sqlite3.Connection,
    *,
    selected_columns: str,
    edge_predicate: str,
    edge_parameters: tuple[Any, ...] = (),
    member_rowid_ranges: Mapping[
        str, tuple[int, int, int]
    ] | None = None,
    progress_callback: ValidationProgressCallback | None = None,
    progress_label: str = "",
):
    """Stream edge rows with bounded, sequential caller-symbol projections.

    The production schema keeps members for each artifact contiguous.  One
    per-artifact projection replaces a hashed members-table lookup for every
    edge while preserving INNER JOIN behavior for dangling/cross-artifact
    callers.  A legacy or non-contiguous member layout retains the original
    global JOIN exactly.
    """

    if member_rowid_ranges is None:
        member_rowid_ranges = _sequential_member_rowid_ranges(connection)
    if member_rowid_ranges is None:
        for edge in connection.execute(
            f"""
            SELECT {selected_columns},
                   m.class_name AS caller_class_name,
                   m.member_name AS caller_member_name,
                   m.descriptor AS caller_descriptor
            FROM direct_edges AS e
            JOIN members AS m
              ON m.member_identity=e.caller_member_identity
            WHERE {edge_predicate}
            """,
            edge_parameters,
        ):
            yield edge, (
                str(edge["caller_class_name"]),
                str(edge["caller_member_name"]),
                str(edge["caller_descriptor"]),
            )
        return

    artifact_identities = _edge_scan_artifact_identities(connection)
    _notify_progress(
        progress_callback,
        "validation-edge-replay",
        progress_label or "开始顺序重放已校验调用边",
        0,
        len(artifact_identities),
    )
    for artifact_index, artifact_identity in enumerate(
        artifact_identities, start=1,
    ):
        member_projection = _artifact_member_projection(
            connection,
            artifact_identity,
            member_rowid_ranges.get(artifact_identity, (0, -1, 0)),
        )
        if member_projection is None:
            # This artifact has not yielded any rows yet, so a local fallback
            # can reproduce the old INNER JOIN without duplication.
            for edge in connection.execute(
                f"""
                SELECT {selected_columns},
                       m.class_name AS caller_class_name,
                       m.member_name AS caller_member_name,
                       m.descriptor AS caller_descriptor
                FROM direct_edges AS e
                JOIN members AS m
                  ON m.member_identity=e.caller_member_identity
                WHERE e.caller_artifact_instance_identity=?
                  AND ({edge_predicate})
                ORDER BY e.rowid
                """,
                (artifact_identity, *edge_parameters),
            ):
                yield edge, (
                    str(edge["caller_class_name"]),
                    str(edge["caller_member_name"]),
                    str(edge["caller_descriptor"]),
                )
        else:
            for edge in connection.execute(
                f"""
                SELECT e.caller_member_identity,{selected_columns}
                FROM direct_edges AS e
                WHERE e.caller_artifact_instance_identity=?
                  AND ({edge_predicate})
                ORDER BY e.rowid
                """,
                (artifact_identity, *edge_parameters),
            ):
                caller_identity = str(edge["caller_member_identity"])
                caller = member_projection.get(caller_identity)
                if caller is None:
                    caller_row = connection.execute(
                        "SELECT class_name,member_name,descriptor "
                        "FROM members WHERE member_identity=?",
                        (caller_identity,),
                    ).fetchone()
                    if caller_row is None:
                        # Match the legacy INNER JOIN for a dangling caller.
                        continue
                    caller = (
                        str(caller_row[0]), str(caller_row[1]),
                        str(caller_row[2]),
                    )
                    member_projection[caller_identity] = caller
                yield edge, caller
        _notify_counted_progress(
            progress_callback,
            "validation-edge-replay",
            progress_label or "顺序重放已校验调用边",
            artifact_index,
            len(artifact_identities),
            artifact_identity,
        )


def _iter_validated_direct_edges(
    database: Path,
    *,
    symbolic_method_target: tuple[str, str] | None = None,
    member_rowid_ranges: Mapping[
        str, tuple[int, int, int]
    ] | None = None,
    progress_callback: ValidationProgressCallback | None = None,
    progress_label: str = "",
) -> Iterable[tuple[Any, ...]]:
    """Replay already validated method/field truth from the immutable store.

    The independent javap pass has just proved exact set equality per artifact.
    Replaying the SQLite side avoids retaining a second multi-million-row
    Python graph while preserving the same normalized tuples consumed by the
    semantic validators.
    """

    if symbolic_method_target is None:
        edge_predicate = "e.edge_kind IN ('method','field')"
        edge_parameters: tuple[Any, ...] = ()
    else:
        if (
            type(symbolic_method_target) is not tuple
            or len(symbolic_method_target) != 2
            or any(type(value) is not str or not value for value in symbolic_method_target)
        ):
            raise BinaryValidationError(
                "BINARY_VALIDATED_DIRECT_EDGE_FILTER_INVALID",
                repr(symbolic_method_target),
            )
        edge_predicate = (
            "e.edge_kind='method' AND e.symbolic_owner=? "
            "AND e.symbolic_name=?"
        )
        edge_parameters = symbolic_method_target

    connection = _open_immutable_sqlite(database)
    connection.row_factory = sqlite3.Row
    try:
        for edge, caller in _iter_edge_rows_with_local_callers(
            connection,
            selected_columns=(
                "e.edge_kind,e.symbolic_owner,e.symbolic_name,"
                "e.symbolic_descriptor,e.opcode,e.bytecode_offset,e.edge_json"
            ),
            edge_predicate=edge_predicate,
            edge_parameters=edge_parameters,
            member_rowid_ranges=member_rowid_ranges,
            progress_callback=progress_callback,
            progress_label=progress_label,
        ):
            # All selected text columns are NOT NULL in the validated fact
            # store. Empty strings remain observable; SQL NULL is impossible.
            edge_kind = str(edge["edge_kind"])
            if edge_kind == "method":
                try:
                    payload = json.loads(str(edge["edge_json"]))
                except (TypeError, ValueError, json.JSONDecodeError) as error:
                    raise BinaryValidationError(
                        "BINARY_VALIDATED_DIRECT_EDGE_REPLAY_INVALID",
                        str(error),
                    ) from error
                reference_interface = (
                    payload.get("interface")
                    if isinstance(payload, Mapping) else None
                )
                if type(reference_interface) is not bool:
                    raise BinaryValidationError(
                        "BINARY_VALIDATED_DIRECT_EDGE_REPLAY_INVALID",
                        str(edge["bytecode_offset"]),
                    )
                reference_kind = (
                    "interface_method" if reference_interface else "method"
                )
            else:
                reference_kind = "field"
            yield (
                caller[0].replace("/", "."),
                caller[1],
                caller[2],
                str(edge["symbolic_owner"]).replace("/", "."),
                str(edge["symbolic_name"]),
                str(edge["symbolic_descriptor"]),
                _opcode_name(edge["opcode"]),
                int(edge["bytecode_offset"]),
                reference_kind,
            )
    finally:
        connection.close()


def _iter_validated_type_edges(
    database: Path,
    *,
    member_rowid_ranges: Mapping[
        str, tuple[int, int, int]
    ] | None = None,
    progress_callback: ValidationProgressCallback | None = None,
    progress_label: str = "",
) -> Iterable[tuple[Any, ...]]:
    connection = _open_immutable_sqlite(database)
    connection.row_factory = sqlite3.Row
    try:
        for edge, caller in _iter_edge_rows_with_local_callers(
            connection,
            selected_columns=(
                "e.bytecode_offset,e.symbolic_owner,e.edge_json"
            ),
            edge_predicate="e.edge_kind='type'",
            member_rowid_ranges=member_rowid_ranges,
            progress_callback=progress_callback,
            progress_label=progress_label,
        ):
            payload = json.loads(str(edge["edge_json"]))
            yield (
                caller[0], caller[1], caller[2],
                int(edge["bytecode_offset"]),
                str(edge["symbolic_owner"]),
                str(payload.get("type_use_kind") or "type_instruction"),
            )
    finally:
        connection.close()


def _iter_common_validated_direct_edges(
    base_database: Path,
    current_database: Path,
    target_owners: Iterable[str] | None = None,
) -> Iterable[tuple[Any, ...]]:
    """Stream the distinct cross-side edge intersection through SQLite.

    SQLite's temporary B-tree may spill to disk. This replaces two globally
    sorted Python arrays whose object expansion alone can exceed physical RAM.
    Both input edge sets have already passed the independent javap equality
    check before this helper is used.
    """

    normalized_target_owners = (
        None
        if target_owners is None
        else {
            # The trailing filter proves owner is non-empty before projection.
            str(owner).replace(".", "/")
            for owner in target_owners
            if str(owner or "")
        }
    )
    if normalized_target_owners == set():
        return
    connection = sqlite3.connect(":memory:", uri=True)
    try:
        connection.execute("PRAGMA temp_store = FILE")
        owner_join = ""
        edge_source = "{schema}.direct_edges AS e"
        if normalized_target_owners is not None:
            connection.execute(
                "CREATE TABLE affected_owner(owner TEXT PRIMARY KEY) WITHOUT ROWID"
            )
            connection.executemany(
                "INSERT INTO affected_owner(owner) VALUES(?)",
                ((owner,) for owner in sorted(normalized_target_owners)),
            )
            owner_join = (
                " JOIN affected_owner AS affected"
                " ON affected.owner=e.symbolic_owner"
            )
        connection.execute(
            "ATTACH DATABASE ? AS base_side",
            (f"{base_database.resolve().as_uri()}?mode=ro&immutable=1",),
        )
        connection.execute(
            "ATTACH DATABASE ? AS current_side",
            (f"{current_database.resolve().as_uri()}?mode=ro&immutable=1",),
        )
        if normalized_target_owners is not None:
            has_symbolic_target_indexes = all(
                connection.execute(
                    f"SELECT 1 FROM {schema}.sqlite_master "
                    "WHERE type='index' "
                    "AND name='direct_edges_symbolic_target'"
                ).fetchone() is not None
                for schema in ("base_side", "current_side")
            )
            if has_symbolic_target_indexes:
                # Without a fixed join order SQLite chooses a full direct-edge
                # scan and probes the tiny affected_owner table for every row.
                # CROSS JOIN deliberately drives the existing symbolic-target
                # index once per affected owner instead. The relational input
                # to the exact INTERSECT is unchanged.
                edge_source = (
                    "affected_owner AS affected CROSS JOIN "
                    "{schema}.direct_edges AS e "
                    "INDEXED BY direct_edges_symbolic_target "
                    "ON e.symbolic_owner=affected.owner"
                )
                owner_join = ""
        projection = """
            SELECT replace(m.class_name,'/','.'),m.member_name,m.descriptor,
                   replace(e.symbolic_owner,'/','.'),e.symbolic_name,
                   e.symbolic_descriptor,
                   CASE e.opcode
                     WHEN 178 THEN 'getstatic' WHEN 179 THEN 'putstatic'
                     WHEN 180 THEN 'getfield' WHEN 181 THEN 'putfield'
                     WHEN 182 THEN 'invokevirtual'
                     WHEN 183 THEN 'invokespecial'
                     WHEN 184 THEN 'invokestatic'
                     WHEN 185 THEN 'invokeinterface'
                     ELSE 'opcode-' || CAST(e.opcode AS TEXT)
                   END,
                   e.bytecode_offset,
                   CASE
                     WHEN e.edge_kind='field' THEN 'field'
                     WHEN json_extract(e.edge_json,'$.interface')=1
                       THEN 'interface_method'
                     ELSE 'method'
                   END
            FROM {edge_source}
            JOIN {schema}.members AS m
              ON m.member_identity=e.caller_member_identity
            {owner_join}
            WHERE e.edge_kind IN ('method','field')
        """
        query = (
            projection.format(
                schema="base_side",
                edge_source=edge_source.format(schema="base_side"),
                owner_join=owner_join,
            )
            + " INTERSECT "
            + projection.format(
                schema="current_side",
                edge_source=edge_source.format(schema="current_side"),
                owner_join=owner_join,
            )
        )
        for row in connection.execute(query):
            yield tuple(row)
    finally:
        connection.close()


def _resolution_affected_owners(
    observations_by_side: Mapping[
        str, Mapping[str, Mapping[str, Any]]
    ],
) -> set[str]:
    """Return a conservative owner closure whose JVM lookup can differ.

    Member resolution depends only on definition readiness, interface/class
    shape, parents and declared members. If those inputs are identical for an
    owner and every node reachable from it, resolving a common symbolic edge
    is necessarily identical. Reverse-closing every changed node across both
    hierarchies therefore removes unrelated millions of edges without sampling
    or weakening the Oracle.
    """

    base = observations_by_side.get("base") or {}
    current = observations_by_side.get("current") or {}

    def signature(observation: Mapping[str, Any] | None) -> tuple[Any, ...]:
        if observation is None:
            return ("missing",)
        return (
            _oracle_class_load_ready(observation),
            int(observation.get("modifiers") or 0),
            str(observation.get("super_name") or ""),
            tuple(observation.get("interfaces") or ()),
            tuple(observation.get("members") or ()),
            tuple(observation.get("javap_declared_members") or ()),
        )

    owners = set(base) | set(current)
    affected = {
        str(owner)
        for owner in owners
        if signature(base.get(owner)) != signature(current.get(owner))
    }
    reverse_children: dict[str, set[str]] = defaultdict(set)
    for observations in (base, current):
        for owner, observation in observations.items():
            for parent in (
                observation.get("super_name"),
                *(observation.get("interfaces") or ()),
            ):
                if parent:
                    reverse_children[str(parent)].add(str(owner))
    pending = list(affected)
    while pending:
        parent = pending.pop()
        for child in reverse_children.get(parent, ()):
            if child not in affected:
                affected.add(child)
                pending.append(child)
    return affected


def _reachable_validated_current_methods(
    database: Path,
    entrypoints: set[tuple[str, str, str]],
    observations: Mapping[str, Mapping[str, Any]],
    declared_members_cache: dict[
        str, tuple[tuple[str, str, str, int], ...]
    ],
) -> set[tuple[str, str, str]]:
    """Traverse only callers reached from declared roots via indexed SQL."""

    reached = set(entrypoints)
    pending = list(entrypoints)
    connection = _open_immutable_sqlite(database)
    connection.row_factory = sqlite3.Row
    try:
        while pending:
            caller = pending.pop()
            caller_owner, caller_name, caller_descriptor = caller
            for edge in connection.execute(
                """
                SELECT e.symbolic_owner,e.symbolic_name,
                       e.symbolic_descriptor
                FROM members AS m
                JOIN direct_edges AS e
                  ON e.caller_member_identity=m.member_identity
                WHERE m.class_name=? AND m.member_kind='method'
                  AND m.member_name=? AND m.descriptor=?
                  AND e.edge_kind='method'
                """,
                (
                    str(caller_owner).replace(".", "/"),
                    caller_name,
                    caller_descriptor,
                ),
            ):
                target = _resolve_member(
                    observations,
                    str(edge["symbolic_owner"]).replace(".", "/"),
                    "method",
                    str(edge["symbolic_name"]),
                    str(edge["symbolic_descriptor"]),
                    declared_members_cache=declared_members_cache,
                )
                if not target:
                    continue
                resolved = (
                    target[0].replace("/", "."),
                    str(target[1][1]),
                    str(target[1][2]),
                )
                if resolved not in reached:
                    reached.add(resolved)
                    pending.append(resolved)
    finally:
        connection.close()
    return reached


def _validate_cross_version_semantics(
    generation: Path,
    config: Mapping[str, Any],
    truth_parts: Mapping[str, Any],
    observations_by_side: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    base_edges = truth_parts["base"]["direct_edges"]
    current_edges = truth_parts["current"]["direct_edges"]
    compact_edge_truth = isinstance(base_edges, Mapping) or isinstance(
        current_edges, Mapping
    )
    base_database = generation / "base_binary_facts.sqlite"
    current_database = generation / "current_binary_facts.sqlite"
    if compact_edge_truth:
        resolution_affected_owners = _resolution_affected_owners(
            observations_by_side
        )
        common_edges: Iterable[tuple[Any, ...]] = (
            _iter_common_validated_direct_edges(
                base_database,
                current_database,
                resolution_affected_owners,
            )
        )
        current_edge_factory = lambda: _iter_validated_direct_edges(
            current_database
        )
        current_type_edge_factory = lambda: _iter_validated_type_edges(
            current_database
        )
    else:
        common_edges = sorted(
            set(map(tuple, base_edges)).intersection(
                set(map(tuple, current_edges))
            )
        )
        current_edge_factory = lambda: iter(current_edges)
        current_type_edges = truth_parts["current"]["type_edges"]
        current_type_edge_factory = lambda: iter(current_type_edges)
    expected_resolution_changes = set()
    declared_members_caches = {"base": {}, "current": {}}

    @lru_cache(maxsize=200_000)
    def resolve_cross_member(
        side_name: str,
        owner: str,
        member_kind: str,
        member_name: str,
        member_descriptor: str,
    ):
        return _resolve_member(
            observations_by_side[side_name],
            owner,
            member_kind,
            member_name,
            member_descriptor,
            declared_members_cache=declared_members_caches[side_name],
        )

    @lru_cache(maxsize=100_000)
    def cross_owner_ready(side_name: str, owner: str) -> bool:
        return _oracle_class_load_ready(
            observations_by_side[side_name].get(owner)
        )

    for raw_edge in common_edges:
        edge = tuple(raw_edge)
        (
            caller_owner, caller_name, caller_descriptor,
            target_owner, target_name, target_descriptor,
            opcode, bytecode_offset, reference_kind,
        ) = edge
        opcode_text = str(opcode)
        if (
            str(reference_kind) in _ORACLE_DIRECT_METHOD_REFERENCE_KINDS
            and opcode_text.startswith("invoke")
        ):
            member_kind = "method"
        elif (
            str(reference_kind) == "field"
            and opcode_text in {
                "getfield", "putfield", "getstatic", "putstatic",
            }
        ):
            member_kind = "field"
        else:
            continue
        normalized_owner = str(target_owner).replace(".", "/")
        # A missing/failed owner is a class-definition outcome, not a
        # no-such-member outcome.  The production decision engine deliberately
        # keeps those cases out of its authoritative member-resolution delta
        # set, so the independent Oracle must make the same JVM distinction.
        if not all(
            cross_owner_ready(side_name, normalized_owner)
            for side_name in ("base", "current")
        ):
            continue
        base_target = resolve_cross_member(
            "base", normalized_owner,
            member_kind, str(target_name), str(target_descriptor),
        )
        current_target = resolve_cross_member(
            "current", normalized_owner,
            member_kind, str(target_name), str(target_descriptor),
        )
        if (
            not base_target and not current_target
        ) or (
            base_target and current_target and base_target[0] == current_target[0]
        ):
            continue
        reported_owner = (
            base_target[0].replace("/", ".")
            if (
                base_target
                and not current_target
                and _is_subtype(
                    observations_by_side["current"],
                    normalized_owner,
                    base_target[0],
                )
            )
            else str(target_owner)
        )
        expected_resolution_changes.add((
            str(caller_owner), str(caller_name), str(caller_descriptor),
            int(bytecode_offset), reported_owner, str(target_name),
            str(target_descriptor),
            base_target[0].replace("/", ".") if base_target else "",
            current_target[0].replace("/", ".") if current_target else "",
        ))
    del common_edges

    actual_resolution_changes = set()
    for decision in _iter_sidecar_object_rows(
        generation,
        "binary_decisions.json",
        "authoritative_change_facts",
        progress_phase="validation-decision-sidecar",
    ):
        if decision.get("reason_code") != "RUNTIME_MEMBER_RESOLUTION_CHANGED":
            continue
        scope = decision.get("fact_scope") or {}
        evidence = decision.get("evidence") or {}
        caller = evidence.get("semantic_caller_edge") or {}
        actual_resolution_changes.add((
            str(caller.get("caller_class") or "").replace("/", "."),
            str(caller.get("caller_member") or ""),
            str(caller.get("caller_descriptor") or ""),
            int(caller.get("bytecode_offset") or 0),
            str(scope.get("class_name") or "").replace("/", "."),
            str(scope.get("member_name") or ""),
            str(scope.get("descriptor") or ""),
            str((evidence.get("base_resolution") or {}).get("resolved_owner") or "").replace("/", "."),
            str((evidence.get("current_resolution") or {}).get("resolved_owner") or "").replace("/", "."),
        ))
    for missing in sorted(expected_resolution_changes - actual_resolution_changes):
        issues.append(_validation_issue(
            "cross_version_member_resolution",
            "ORACLE_MEMBER_RESOLUTION_CHANGE_MISSING",
            change=missing,
        ))
    for extra in sorted(actual_resolution_changes - expected_resolution_changes):
        issues.append(_validation_issue(
            "cross_version_member_resolution",
            "ORACLE_MEMBER_RESOLUTION_CHANGE_EXTRA",
            change=extra,
        ))

    entrypoints = {
        (
            str(item.get("class_name") or "").replace("/", "."),
            str(item.get("member_name") or ""),
            str(item.get("descriptor") or ""),
        )
        for item in (
            ((config.get("current") or {}).get("runtime_profile") or {})
            .get("business_entrypoint_profile", {}).get("methods") or ()
        )
    }
    reached = set(entrypoints)
    if entrypoints:
        if compact_edge_truth:
            reached = _reachable_validated_current_methods(
                current_database,
                entrypoints,
                observations_by_side["current"],
                declared_members_caches["current"],
            )
        else:
            current_graph = defaultdict(set)
            for raw_edge in current_edge_factory():
                edge = tuple(raw_edge)
                caller = (str(edge[0]), str(edge[1]), str(edge[2]))
                if (
                    len(edge) != _ORACLE_DIRECT_EDGE_TUPLE_SIZE
                    or str(edge[8])
                    not in _ORACLE_DIRECT_METHOD_REFERENCE_KINDS
                    or not str(edge[5]).startswith("(")
                ):
                    continue
                target = _resolve_member(
                    observations_by_side["current"],
                    str(edge[3]).replace(".", "/"),
                    "method", edge[4], edge[5],
                    declared_members_cache=(
                        declared_members_caches["current"]
                    ),
                )
                if target:
                    current_graph[caller].add((
                        target[0].replace("/", "."),
                        str(target[1][1]),
                        str(target[1][2]),
                    ))
            pending = list(entrypoints)
            while pending:
                caller = pending.pop()
                for target in current_graph.get(caller, ()):
                    if target not in reached:
                        reached.add(target)
                        pending.append(target)

    base_resources = {
        (item["realm"], item["name"], item["mechanism"]): item["selected"]
        for item in truth_parts["base"]["resource_selections"]
    }
    current_resources = {
        (item["realm"], item["name"], item["mechanism"]): item["selected"]
        for item in truth_parts["current"]["resource_selections"]
    }
    changed_services: dict[str, str] = {}
    for key in sorted(set(base_resources).intersection(current_resources)):
        _realm, name, _mechanism = key
        if not name.startswith("META-INF/services/"):
            continue
        if base_resources[key] == current_resources[key]:
            continue
        changed_services[name] = name.removeprefix("META-INF/services/")
    load_callers: dict[tuple[str, str, str], set[int]] = defaultdict(set)
    if changed_services:
        for edge in current_edge_factory():
            if (
                len(edge) == _ORACLE_DIRECT_EDGE_TUPLE_SIZE
                and str(edge[8]) in _ORACLE_DIRECT_METHOD_REFERENCE_KINDS
                and str(edge[3]) == "java.util.ServiceLoader"
                and str(edge[4]) == "load"
                and str(edge[5]).startswith("(Ljava/lang/Class;")
            ):
                load_callers[(
                    str(edge[0]), str(edge[1]), str(edge[2]),
                )].add(int(edge[7]))
    resources_by_service: dict[str, set[str]] = defaultdict(set)
    for resource_name, service in changed_services.items():
        resources_by_service[service].add(resource_name)
    activated_resources: set[str] = set()
    if load_callers:
        for raw_literal in current_type_edge_factory():
            literal = tuple(raw_literal)
            caller = (
                str(literal[0]).replace("/", "."),
                str(literal[1]), str(literal[2]),
            )
            literal_owner = str(literal[4]).replace("/", ".")
            if (
                literal[5] == "class_literal"
                and literal_owner in resources_by_service
                and caller in load_callers
                and any(
                    0 <= load_offset - int(literal[3]) <= 4
                    for load_offset in load_callers[caller]
                )
                and caller in reached
            ):
                activated_resources.update(
                    resources_by_service[literal_owner]
                )
    expected_resource_status = {
        resource_name: (
            "reachable"
            if resource_name in activated_resources
            else "not_found_in_static_analysis"
        )
        for resource_name in sorted(changed_services)
    }
    actual_resource_status = {
        str(item.get("resource_name") or ""): str(item.get("activation_status") or "")
        for item in _iter_sidecar_object_rows(
            generation,
            "binary_formal_results.json",
            "resource_activation_results",
            progress_phase="validation-formal-sidecar",
        )
    }
    if actual_resource_status != expected_resource_status:
        issues.append(_validation_issue(
            "resource_activation",
            "ORACLE_RESOURCE_ACTIVATION_MISMATCH",
            expected=expected_resource_status,
            actual=actual_resource_status,
        ))
    return issues, {
        "member_resolution_changes": sorted(expected_resolution_changes),
        "resource_activation_status": dict(sorted(expected_resource_status.items())),
    }


def _javap_reference(comment: str) -> tuple[str, str, str]:
    match = re.match(
        r"(?:InterfaceMethod|Method)\s+(?:(?P<owner>[\w/$]+)\.)?"
        r'"?(?P<name>[^":]+)"?:(?P<descriptor>\(.*)$',
        str(comment or ""),
    )
    if not match:
        return "", "", ""
    return (
        str(match.group("owner") or ""),
        # Both groups are mandatory and non-empty in the successful regex.
        str(match.group("name")),
        str(match.group("descriptor")),
    )


def _oracle_runtime_semantic_rows(
    observations: Mapping[str, Mapping[str, Any]],
    instructions: Iterable[Iterable[Any]],
    declared_members_cache: dict[
        str, tuple[tuple[str, str, str, int], ...]
    ] | None = None,
) -> set[tuple[str, str, str, str, str, str, str, str]]:
    """Rebuild literal reflection and JDK proxy edges from javap output."""
    shared_declared_members = (
        declared_members_cache
        if declared_members_cache is not None else {}
    )
    grouped: dict[tuple[str, str, str], list[tuple[int, str, str]]] = defaultdict(list)
    for owner, member, descriptor, bci, opcode, comment in instructions:
        grouped[(str(owner), str(member), str(descriptor))].append(
            (int(bci), str(opcode), str(comment))
        )
    result = set()
    reflection_terminals = {
        ("java/lang/reflect/Method", "invoke"),
        ("java/lang/reflect/Constructor", "newInstance"),
        ("java/lang/reflect/Field", "get"),
        ("java/lang/reflect/Field", "set"),
        ("java/lang/invoke/MethodHandle", "invoke"),
        ("java/lang/invoke/MethodHandle", "invokeExact"),
    }
    lookup_kinds = {
        "getMethod": ("method", "reflection_method_invocation"),
        "getDeclaredMethod": ("method", "reflection_method_invocation"),
        "getConstructor": ("method", "reflection_constructor_invocation"),
        "getDeclaredConstructor": ("method", "reflection_constructor_invocation"),
        "getField": ("field", "reflection_field_access"),
        "getDeclaredField": ("field", "reflection_field_access"),
        "findStatic": ("method", "method_handle_invocation"),
        "findVirtual": ("method", "method_handle_invocation"),
        "findSpecial": ("method", "method_handle_invocation"),
        "findConstructor": ("method", "method_handle_invocation"),
        "findGetter": ("field", "method_handle_field_access"),
        "findSetter": ("field", "method_handle_field_access"),
    }
    for caller, rows in grouped.items():
        rows.sort()
        calls = [(*_javap_reference(comment), index) for index, (_bci, _op, comment) in enumerate(rows)]
        terminal_indexes = {
            index for ref_owner, ref_name, _descriptor, index in calls
            if (ref_owner, ref_name) in reflection_terminals
        }
        for ref_owner, ref_name, _ref_descriptor, index in calls:
            if ref_name not in lookup_kinds or not any(
                index < terminal <= index + 48 for terminal in terminal_indexes
            ):
                continue
            member_kind, semantic_kind = lookup_kinds[ref_name]
            window = rows[max(0, index - 32):index]
            strings = [
                (offset, comment.removeprefix("String "))
                for offset, (_bci, opcode, comment) in enumerate(window)
                if opcode in {"ldc", "ldc_w"} and comment.startswith("String ")
            ]
            type_literals = [
                (offset, comment.removeprefix("class ").strip('"'))
                for offset, (_bci, opcode, comment) in enumerate(window)
                if opcode in {"ldc", "ldc_w"} and comment.startswith("class ")
            ]
            for_name_indexes = [
                offset for offset, (_bci, _opcode, comment) in enumerate(window)
                if _javap_reference(comment)[:2] == ("java/lang/Class", "forName")
            ]
            target_owner = ""
            if for_name_indexes:
                preceding = [value for offset, value in strings if offset < for_name_indexes[-1]]
                if preceding:
                    target_owner = preceding[-1].replace(".", "/")
            if not target_owner and strings:
                preceding_types = [
                    value for offset, value in type_literals if offset < strings[-1][0]
                ]
                if preceding_types:
                    target_owner = preceding_types[-1]
            if not target_owner and type_literals:
                target_owner = type_literals[0][1]
            target_name = "<init>" if "Constructor" in ref_name else (
                strings[-1][1] if strings else ""
            )
            candidates = [
                (name, descriptor)
                for kind, name, descriptor, _flags in _cached_declared_members(
                    observations,
                    target_owner,
                    shared_declared_members,
                )
                if kind == member_kind and name == target_name
            ]
            certainty = "exact" if len(candidates) == 1 else "possible"
            for name, descriptor in candidates:
                result.add((semantic_kind, *caller, target_owner, name, descriptor, certainty))

        proxy_calls = [
            index for ref_owner, ref_name, _descriptor, index in calls
            if (ref_owner, ref_name) == ("java/lang/reflect/Proxy", "newProxyInstance")
        ]
        for proxy_index in proxy_calls:
            before = rows[max(0, proxy_index - 32):proxy_index]
            after = rows[proxy_index + 1:proxy_index + 49]
            handler_classes = {
                comment.removeprefix("class ").strip('"')
                for _bci, opcode, comment in before
                if opcode == "new" and comment.startswith("class ")
                and _is_subtype(
                    observations,
                    comment.removeprefix("class ").strip('"'),
                    "java/lang/reflect/InvocationHandler",
                )
            }
            interface_literals = {
                comment.removeprefix("class ").strip('"')
                for _bci, opcode, comment in before
                if opcode in {"ldc", "ldc_w"} and comment.startswith("class ")
            }
            invoked_interfaces = {
                _javap_reference(comment)[0]
                for _bci, opcode, comment in after if opcode == "invokeinterface"
            }
            exact_invocation = bool(interface_literals.intersection(invoked_interfaces))
            candidates = [
                (handler, name, descriptor)
                for handler in handler_classes
                for kind, name, descriptor, _flags in _cached_declared_members(
                    observations,
                    handler,
                    shared_declared_members,
                )
                if kind == "method" and name == "invoke"
            ]
            certainty = "exact" if len(candidates) == 1 and exact_invocation else "possible"
            for handler, name, descriptor in candidates:
                result.add(("dynamic_proxy_callback", *caller, handler, name, descriptor, certainty))
    return result


def _validate_runtime_semantic_overlay(
    generation: Path,
    current_side: Mapping[str, Any],
    current_artifacts: Iterable[Mapping[str, Any]],
    base_observations: Mapping[str, Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
    semantic_instructions: Iterable[Iterable[Any]],
    direct_edges: Iterable[Iterable[Any]],
    resource_truth: Iterable[Mapping[str, Any]],
    *,
    current_declared_members_cache: dict[
        str, tuple[tuple[str, str, str, int], ...]
    ] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    supported_kinds = {
        "reflection_method_invocation", "reflection_constructor_invocation",
        "reflection_field_access", "method_handle_invocation",
        "method_handle_field_access", "dynamic_proxy_callback",
        "mybatis_mapper_proxy_dispatch",
        "spring_transaction_proxy_dispatch",
        "spring_bean_wiring_dispatch", "spring_data_repository_proxy_dispatch",
        "spring_aop_dispatch", "spring_security_filter_dispatch",
        "declarative_http_client_dispatch", "dubbo_spi_dispatch",
        "implicit_data_contract_dispatch",
    }
    artifact_paths = {
        Path(str(item["path"])).resolve()
        for item in current_artifacts
        if item.get("path")
    }
    expected = set()

    shared_current_declared_members = (
        current_declared_members_cache
        if current_declared_members_cache is not None else {}
    )
    base_declared_members_cache: dict[
        str, tuple[tuple[str, str, str, int], ...]
    ] = {}

    def current_declared_members(
        owner: str,
    ) -> tuple[tuple[str, str, str, int], ...]:
        return _cached_declared_members(
            observations, owner, shared_current_declared_members
        )

    def base_declared_members(
        owner: str,
    ) -> tuple[tuple[str, str, str, int], ...]:
        return _cached_declared_members(
            base_observations, owner, base_declared_members_cache
        )

    @lru_cache(maxsize=20_000)
    def runtime_type_closure(child: str) -> frozenset[str]:
        reached = {str(child)}
        pending = [str(child)]
        while pending:
            current = pending.pop()
            row = observations.get(current) or {}
            for parent in (
                row.get("super_name"), *(row.get("interfaces") or ())
            ):
                parent_text = str(parent or "")
                if parent_text and parent_text not in reached:
                    reached.add(parent_text)
                    pending.append(parent_text)
        return frozenset(reached)

    def runtime_is_subtype(child: str, parent: str) -> bool:
        return str(parent) in runtime_type_closure(str(child))

    new_types_by_factory: dict[
        tuple[str, str, str], set[str]
    ] = defaultdict(set)
    filter_registration_callers: set[tuple[str, str, str]] = set()
    instruction_batches = getattr(
        semantic_instructions, "iter_batches", None
    )
    batches = (
        instruction_batches()
        if callable(instruction_batches) else (semantic_instructions,)
    )
    for instruction_batch in batches:
        if not isinstance(
            instruction_batch, (list, tuple, set, frozenset)
        ):
            instruction_batch = tuple(instruction_batch)
        expected.update(
            row for row in _oracle_runtime_semantic_rows(
                observations,
                instruction_batch,
                shared_current_declared_members,
            )
            if _file_url_path(
                str(
                    (observations.get(row[4]) or {}).get("provider_url")
                    or ""
                )
            ) in artifact_paths
        )
        for owner, member_name, descriptor, _bci, opcode, comment in (
            instruction_batch
        ):
            caller = (str(owner), str(member_name), str(descriptor))
            opcode_text = str(opcode)
            comment_text = str(comment)
            if opcode_text == "new" and comment_text.startswith("class "):
                new_types_by_factory[caller].add(
                    comment_text.removeprefix("class ").strip('"')
                )
            if _javap_reference(comment_text)[1] in {
                "addFilter", "addFilterBefore", "addFilterAfter",
                "addFilterAt",
            }:
                filter_registration_callers.add(caller)
    namespaces = {
        str(value).replace(".", "/")
        for selection in resource_truth
        for selected in selection.get("selected") or ()
        for key, value in selected.get("semantic_facts") or ()
        if key == "mybatis_mapper_namespace"
    }
    runtime_targets = []
    for owner, name, count in (
        ("org/apache/ibatis/binding/MapperProxy", "invoke", 3),
        ("org/apache/ibatis/binding/MapperMethod", "execute", 2),
    ):
        candidates = [
            (member_name, descriptor)
            for kind, member_name, descriptor, _flags in (
                current_declared_members(owner)
            )
            if kind == "method" and member_name == name
            and len(_descriptor_parameters(descriptor) or ()) == count
        ]
        if len(candidates) == 1:
            runtime_targets.append((owner, *candidates[0]))
    mapper_annotation = "Lorg/apache/ibatis/annotations/Mapper;"

    path_kinds = {
        Path(str(item.get("path") or "")).resolve(): str(item.get("path_kind") or "").lower()
        for item in current_artifacts
    }

    def business_owned(observation):
        path = _file_url_path(str(observation.get("provider_url") or ""))
        return path is not None and path_kinds.get(path) in {
            "application", "application_classes", "business", "business_classes",
        }

    runtime_profile = current_side.get("runtime_profile") or {}
    activated_frameworks = {
        str(value or "").lower()
        for value in (runtime_profile.get("business_entrypoint_profile") or {}).get(
            "activated_frameworks"
        ) or ()
    }
    launcher = str(runtime_profile.get("container_and_launcher_kind") or "").lower()
    spring_active = "spring_boot" in activated_frameworks or launcher in {
        "spring-boot", "spring_boot", "spring-boot-launcher",
        "spring-boot-executable-jar",
    }
    active_profiles = {
        str(value or "") for value in runtime_profile.get("active_profile_identities") or ()
    }
    resolved_properties = {
        str(key): str(value)
        for key, value in (runtime_profile.get("resolved_configuration_properties") or {}).items()
    }
    configuration_complete = str(
        runtime_profile.get("runtime_configuration_coverage_status") or ""
    ) == "complete"
    entry_profile = runtime_profile.get("business_entrypoint_profile") or {}
    scan_prefixes = {
        str(value or "").replace(".", "/")
        for value in entry_profile.get("activated_component_scan_packages") or ()
    }
    main_class = str(entry_profile.get("main_class") or "").replace(".", "/")
    if spring_active and "/" in main_class:
        scan_prefixes.add(main_class.rsplit("/", 1)[0])
    component_scan = "Lorg/springframework/context/annotation/ComponentScan;"
    for class_name, observation in observations.items():
        if not business_owned(observation):
            continue
        values = _oracle_annotation_values(
            observation.get("class_annotation_values") or ()
        ).get(component_scan) or {}
        scan_prefixes.update(
            value.replace(".", "/")
            for items in values.values() for value in items
            if value and not value.lower().endswith(".class")
        )
    active_resources = {
        str(value or "").removeprefix("classpath:").lstrip("/")
        for value in entry_profile.get("activated_resource_names") or ()
    }
    bean_types: dict[str, str] = {}
    primary_bean_types: set[str] = set()
    custom_repository_configuration = False
    for selection in resource_truth:
        resource_name = str(selection.get("name") or "")
        for selected in selection.get("selected") or ():
            for key, value in selected.get("semantic_facts") or ():
                if key == "spring_bean_class":
                    parts = str(value).split("|", 1)
                    if len(parts) == 2:
                        bean_types[parts[1].replace(".", "/")] = (
                            "exact" if resource_name in active_resources else "possible"
                        )
                elif key == "spring_bean_primary":
                    parts = str(value).split("|", 1)
                    if len(parts) == 2:
                        primary_bean_types.add(parts[1].replace(".", "/"))
    component_annotations = {
        "Lorg/springframework/stereotype/Component;",
        "Lorg/springframework/stereotype/Service;",
        "Lorg/springframework/stereotype/Repository;",
        "Lorg/springframework/stereotype/Controller;",
        "Lorg/springframework/web/bind/annotation/RestController;",
        "Lorg/springframework/context/annotation/Configuration;",
    }
    for class_name, observation in observations.items():
        descriptors = set(observation.get("class_annotations") or ())
        repository_attributes = _oracle_annotation_values(
            observation.get("class_annotation_values") or ()
        ).get(
            "Lorg/springframework/data/jpa/repository/config/EnableJpaRepositories;"
        ) or {}
        if {"repositoryBaseClass", "repositoryFactoryBeanClass"}.intersection(
            repository_attributes
        ):
            custom_repository_configuration = True
        if not descriptors.intersection(component_annotations):
            continue
        condition = _oracle_condition_status(
            descriptors,
            _oracle_annotation_values(observation.get("class_annotation_values") or ()),
            active_profiles=active_profiles,
            resolved_properties=resolved_properties,
            configuration_complete=configuration_complete,
            observations=observations,
        )
        if condition == "inactive":
            continue
        discovered = business_owned(observation) or any(
            class_name == prefix or class_name.startswith(prefix + "/")
            for prefix in scan_prefixes
        )
        bean_types[class_name] = (
            "exact" if condition == "active" and discovered else "possible"
        )
        if "Lorg/springframework/context/annotation/Primary;" in descriptors:
            primary_bean_types.add(class_name)
    bean_annotation = "Lorg/springframework/context/annotation/Bean;"
    for class_name, observation in observations.items():
        member_annotations = _oracle_member_annotations(observation)
        for kind, member_name, descriptor, _flags in (
            current_declared_members(class_name)
        ):
            annotations = set(member_annotations.get((member_name, descriptor), ()))
            if kind != "method" or bean_annotation not in annotations:
                continue
            returned = _descriptor_return_class(descriptor)
            if returned:
                compatible_constructions = {
                    candidate
                    for candidate in new_types_by_factory.get(
                        (class_name, member_name, descriptor), ()
                    )
                    if candidate == returned
                    or runtime_is_subtype(candidate, returned)
                }
                registered_type = (
                    next(iter(compatible_constructions))
                    if len(compatible_constructions) == 1 else returned
                )
                if (
                    len(compatible_constructions) != 1
                    and int((observations.get(returned) or {}).get("modifiers") or 0)
                    & 0x0200
                ):
                    continue
                bean_types[registered_type] = (
                    "exact" if business_owned(observation) else "possible"
                )
                if "Lorg/springframework/context/annotation/Primary;" in annotations:
                    primary_bean_types.add(registered_type)

    bean_types_by_target: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for implementation, activation in bean_types.items():
        for target in runtime_type_closure(implementation):
            bean_types_by_target[target].append((implementation, activation))

    @lru_cache(maxsize=10_000)
    def spring_dispatch_candidates(
        target_interface: str,
        target_name: str,
        target_descriptor: str,
    ) -> tuple[tuple[tuple[str, str, str, str, bool], ...], dict[str, Any]]:
        implementations = []
        for implementation, activation in bean_types_by_target.get(
            target_interface, ()
        ):
            implementations.extend(
                (
                    implementation, name, descriptor, activation,
                    implementation in primary_bean_types,
                )
                for kind, name, descriptor, _flags in (
                    current_declared_members(implementation)
                )
                if kind == "method" and name == target_name
                and descriptor == target_descriptor
            )
        primary_implementations = tuple(
            item for item in implementations if item[4]
        )
        selected = (
            primary_implementations
            if len(primary_implementations) == 1
            else tuple(implementations)
        )
        evidence = {
            "interface": target_interface,
            "spring_active": spring_active,
            "candidates": [
                {
                    "implementation": candidate[0],
                    "member_name": candidate[1],
                    "descriptor": candidate[2],
                    "activation": candidate[3],
                    "primary": candidate[4],
                }
                for candidate in implementations
            ],
            "selected_candidate_count": len(selected),
        }
        return selected, evidence

    @lru_cache(maxsize=10_000)
    def repository_dispatch_candidates(
        target_name: str, parameter_count: int,
    ) -> tuple[tuple[str, str], ...]:
        return tuple(
            (name, descriptor)
            for kind, name, descriptor, _flags in current_declared_members(
                "org/springframework/data/jpa/repository/support/"
                "SimpleJpaRepository"
            )
            if kind == "method" and name == target_name
            and len(_descriptor_parameters(descriptor) or ())
            == parameter_count
        )

    bean_wiring_candidate_evidence: dict[tuple[str, ...], dict[str, Any]] = {}
    invoked_owners: set[str] = set()
    extension_loader_calls: set[tuple[str, str, str]] = set()
    for edge in direct_edges:
        if (
            len(edge) != _ORACLE_DIRECT_EDGE_TUPLE_SIZE
            or str(edge[8]) not in _ORACLE_DIRECT_METHOD_REFERENCE_KINDS
            or not str(edge[5]).startswith("(")
        ):
            continue
        caller_class = str(edge[0]).replace(".", "/")
        caller_name, caller_descriptor = str(edge[1]), str(edge[2])
        target_interface = str(edge[3]).replace(".", "/")
        target_name, target_descriptor = str(edge[4]), str(edge[5])
        invoked_owners.add(target_interface)
        if (
            target_interface
            == "org/apache/dubbo/common/extension/ExtensionLoader"
            and target_name in {
                "getExtension", "getAdaptiveExtension",
                "getActivateExtension",
            }
        ):
            extension_loader_calls.add((
                caller_class, caller_name, caller_descriptor,
            ))
        interface_observation = observations.get(target_interface) or {}
        if int(interface_observation.get("modifiers") or 0) & 0x0200:
            selected_implementations, candidate_evidence = (
                spring_dispatch_candidates(
                    target_interface, target_name, target_descriptor
                )
            )
            for implementation, name, descriptor, activation, _primary in (
                selected_implementations
            ):
                expected_row = (
                    "spring_bean_wiring_dispatch",
                    caller_class, caller_name, caller_descriptor,
                    implementation, name, descriptor,
                    (
                        "exact"
                        if len(selected_implementations) == 1
                        and spring_active and activation == "exact"
                        else "possible"
                    ),
                )
                expected.add(expected_row)
                bean_wiring_candidate_evidence[
                    expected_row[:7]
                ] = candidate_evidence

        if runtime_is_subtype(
            target_interface,
            "org/springframework/data/repository/Repository",
        ) and not custom_repository_configuration:
            parameter_count = len(_descriptor_parameters(target_descriptor) or ())
            candidates = repository_dispatch_candidates(
                target_name, parameter_count
            )
            for name, descriptor in candidates:
                expected.add((
                    "spring_data_repository_proxy_dispatch",
                    caller_class, caller_name, caller_descriptor,
                    "org/springframework/data/jpa/repository/support/SimpleJpaRepository",
                    name, descriptor,
                    "exact" if spring_active and len(candidates) == 1 else "possible",
                ))

    for class_name, observation in observations.items():
        annotated = mapper_annotation in set(
            observation.get("class_annotations") or ()
        )
        if (
            not (annotated or class_name in namespaces)
            or class_name not in invoked_owners
            or not (int(observation.get("modifiers") or 0) & 0x0200)
        ):
            continue
        certainty = "exact" if annotated else "possible"
        for kind, mapper_name, mapper_descriptor, _flags in (
            current_declared_members(class_name)
        ):
            if kind != "method":
                continue
            for target_owner, target_name, target_descriptor in runtime_targets:
                expected.add((
                    "mybatis_mapper_proxy_dispatch",
                    class_name, mapper_name, mapper_descriptor,
                    target_owner, target_name, target_descriptor, certainty,
                ))

    aspect_annotation = "Lorg/aspectj/lang/annotation/Aspect;"
    advice_annotations = {
        "Lorg/aspectj/lang/annotation/Before;",
        "Lorg/aspectj/lang/annotation/After;",
        "Lorg/aspectj/lang/annotation/Around;",
        "Lorg/aspectj/lang/annotation/AfterReturning;",
        "Lorg/aspectj/lang/annotation/AfterThrowing;",
    }
    for aspect_name, observation in observations.items():
        if aspect_annotation not in set(observation.get("class_annotations") or ()):
            continue
        annotation_values = _oracle_annotation_values(
            observation.get("member_annotation_values") or (), member_rows=True
        )
        for kind, advice_name, advice_descriptor, _flags in (
            current_declared_members(aspect_name)
        ):
            if kind != "method":
                continue
            values = {
                value
                for (name, descriptor, annotation), attributes in annotation_values.items()
                if name == advice_name and descriptor == advice_descriptor
                and annotation in advice_annotations
                for items in attributes.values() for value in items
            }
            pointcuts = [
                parsed for value in values
                if (parsed := _oracle_aop_pointcut_constraints(value))
            ]
            for pointcut in pointcuts:
                for owner_pattern, method_pattern in pointcut["executions"]:
                    owner_re = re.compile(
                        "^" + re.escape(owner_pattern.replace(".", "/")).replace(r"\*", ".*") + "$"
                    )
                    method_re = re.compile(
                        "^" + re.escape(method_pattern).replace(r"\*", ".*") + "$"
                    )
                    for join_owner, join_observation in observations.items():
                        if not owner_re.match(join_owner):
                            continue
                        class_annotations = set(
                            join_observation.get("class_annotations") or ()
                        )
                        if not pointcut["class_annotations"].issubset(
                            class_annotations
                        ):
                            continue
                        annotations_by_member = _oracle_member_annotations(
                            join_observation
                        )
                        for (
                            join_kind, join_name, join_descriptor, _join_flags
                        ) in current_declared_members(join_owner):
                            member_annotations = set(
                                annotations_by_member.get(
                                    (join_name, join_descriptor), ()
                                )
                            )
                            if (
                                join_kind != "method"
                                or join_name in {"<init>", "<clinit>"}
                                or not method_re.match(join_name)
                                or not pointcut["method_annotations"].issubset(
                                    member_annotations
                                )
                                or pointcut["excluded_method_annotations"].intersection(
                                    member_annotations
                                )
                            ):
                                continue
                            expected.add((
                                "spring_aop_dispatch",
                                join_owner, join_name, join_descriptor,
                                aspect_name, advice_name, advice_descriptor,
                                (
                                    "exact"
                                    if pointcut["complete"] and spring_active
                                    and business_owned(observation)
                                    else "possible"
                                ),
                            ))

    bean_methods = {
        (class_name, member_name, descriptor)
        for class_name, observation in observations.items()
        for (member_name, descriptor), annotations in _oracle_member_annotations(observation).items()
        if bean_annotation in annotations
        and _descriptor_return_class(descriptor) in {
            "org/springframework/security/web/SecurityFilterChain",
            "javax/servlet/Filter", "jakarta/servlet/Filter",
        }
    }
    for bean_method in bean_methods:
        if bean_method not in filter_registration_callers:
            continue
        filter_types = {
            candidate
            for candidate in new_types_by_factory.get(bean_method, ())
            if (
                runtime_is_subtype(
                    candidate,
                    "javax/servlet/Filter",
                )
                or runtime_is_subtype(
                    candidate,
                    "jakarta/servlet/Filter",
                )
            )
        }
        # bean_methods is derived from observations.items(), so its owner is
        # guaranteed to exist and carry the annotation evidence used above.
        bean_observation = observations[bean_method[0]]
        for filter_type in filter_types:
            for kind, callback_name, callback_descriptor, _flags in (
                current_declared_members(filter_type)
            ):
                if kind == "method" and callback_name == "doFilter":
                    expected.add((
                        "spring_security_filter_dispatch",
                        *bean_method,
                        filter_type, callback_name, callback_descriptor,
                        "exact" if spring_active and business_owned(bean_observation) else "possible",
                    ))

    feign_annotations = {
        "Lorg/springframework/cloud/openfeign/FeignClient;",
        "Lfeign/RequestLine;",
    }
    feign_targets = []
    for owner in (
        "feign/SynchronousMethodHandler",
        "feign/InvocationHandlerFactory$Default",
    ):
        feign_targets.extend(
            (owner, name, descriptor)
            for kind, name, descriptor, _flags in (
                current_declared_members(owner)
            )
            if kind == "method" and name == "invoke"
        )
    for client_name, observation in observations.items():
        class_declares_client = bool(feign_annotations.intersection(
            set(observation.get("class_annotations") or ())
        ))
        member_annotations = _oracle_member_annotations(observation)
        certainty = "exact" if spring_active and feign_targets else "possible"
        for kind, client_method, client_descriptor, _flags in (
            current_declared_members(client_name)
        ):
            if kind != "method":
                continue
            method_declares_client = bool(feign_annotations.intersection(
                member_annotations.get((client_method, client_descriptor), ())
            ))
            if not class_declares_client and not method_declares_client:
                continue
            for target_owner, target_name, target_descriptor in feign_targets:
                expected.add((
                    "declarative_http_client_dispatch",
                    client_name, client_method, client_descriptor,
                    target_owner, target_name, target_descriptor, certainty,
                ))

    dubbo_providers: dict[tuple[str, str], set[str]] = defaultdict(set)
    dubbo_prefixes = (
        "META-INF/dubbo/internal/",
        "META-INF/dubbo/external/",
        "META-INF/dubbo/",
    )
    for selection in resource_truth:
        resource_name = str(selection.get("name") or "")
        prefix = next(
            (value for value in dubbo_prefixes if resource_name.startswith(value)),
            "",
        )
        if not prefix:
            continue
        service = resource_name[len(prefix):].replace(".", "/")
        realm = str(selection.get("realm") or "")
        for selected in selection.get("selected") or ():
            for key, value in selected.get("semantic_facts") or ():
                if key != "ordered_entry":
                    continue
                implementation = str(value).split("=", 1)[-1].strip().replace(
                    ".", "/"
                )
                if implementation:
                    dubbo_providers[(realm, service)].add(implementation)
    dubbo_certainty = "exact" if len(dubbo_providers) == 1 else "possible"
    for caller in extension_loader_calls:
        for (_realm, _service), implementations in dubbo_providers.items():
            for implementation in implementations:
                for kind, target_name, target_descriptor, _flags in (
                    current_declared_members(implementation)
                ):
                    if kind == "method" and target_name not in {"<init>", "<clinit>"}:
                        expected.add((
                            "dubbo_spi_dispatch", *caller,
                            implementation, target_name, target_descriptor,
                            dubbo_certainty,
                        ))

    data_binding_annotations = {
        "Lorg/springframework/web/bind/annotation/RequestMapping;",
        "Lorg/springframework/web/bind/annotation/GetMapping;",
        "Lorg/springframework/web/bind/annotation/PostMapping;",
        "Lorg/springframework/web/bind/annotation/PutMapping;",
        "Lorg/springframework/web/bind/annotation/PatchMapping;",
        "Lorg/springframework/web/bind/annotation/DeleteMapping;",
    }

    def descriptor_owner(descriptor: str) -> str:
        value = str(descriptor or "")
        return value[1:-1] if value.startswith("L") and value.endswith(";") else ""

    binding_callers: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for class_name, observation in observations.items():
        member_annotations = _oracle_member_annotations(observation)
        for kind, member_name, member_descriptor, _flags in (
            current_declared_members(class_name)
        ):
            if kind != "method" or not data_binding_annotations.intersection(
                member_annotations.get((member_name, member_descriptor), ())
            ):
                continue
            descriptors = list(_descriptor_parameters(member_descriptor) or ())
            marker = member_descriptor.find(")")
            if marker >= 0:
                descriptors.append(member_descriptor[marker + 1:])
            for descriptor in descriptors:
                owner = descriptor_owner(descriptor)
                if owner:
                    binding_callers[owner].add(
                        (class_name, member_name, member_descriptor)
                    )

    for decision_field in (
        "authoritative_change_facts", "diagnostic_candidate_facts",
    ):
        for decision in _iter_sidecar_object_rows(
            generation,
            "binary_decisions.json",
            decision_field,
            progress_phase="validation-decision-sidecar",
        ):
            scope = decision.get("fact_scope") or {}
            if scope.get("member_kind") != "field":
                continue
            owner = str(scope.get("class_name") or "").replace(".", "/")
            target_name = str(scope.get("member_name") or "")
            target_descriptor = str(scope.get("descriptor") or "")
            if not owner or not target_name:
                continue
            current_targets = [
                (name, descriptor)
                for kind, name, descriptor, _flags in (
                    current_declared_members(owner)
                )
                if kind == "field" and name == target_name
            ]
            if not current_targets:
                base_targets = [
                    (name, descriptor)
                    for kind, name, descriptor, _flags in (
                        base_declared_members(owner)
                    )
                    if kind == "field" and name == target_name
                ]
                current_targets = base_targets or [
                    (target_name, target_descriptor)
                ]
            for caller in binding_callers.get(owner, ()):
                for name, descriptor in current_targets:
                    expected.add((
                        "implicit_data_contract_dispatch", *caller,
                        owner, name, descriptor, "exact",
                    ))

    transaction_targets = []
    for owner, name, count in (
        ("org/springframework/transaction/interceptor/TransactionInterceptor", "invoke", 1),
        ("org/springframework/transaction/interceptor/TransactionAspectSupport", "invokeWithinTransaction", 3),
        ("org/springframework/aop/framework/ReflectiveMethodInvocation", "proceed", 0),
    ):
        candidates = [
            (member_name, descriptor)
            for kind, member_name, descriptor, _flags in (
                current_declared_members(owner)
            )
            if kind == "method" and member_name == name
            and len(_descriptor_parameters(descriptor) or ()) == count
        ]
        if len(candidates) == 1:
            transaction_targets.append((owner, *candidates[0]))
    transactional = "Lorg/springframework/transaction/annotation/Transactional;"
    for class_name, observation in observations.items():
        if not business_owned(observation):
            continue
        class_tx = transactional in set(observation.get("class_annotations") or ())
        member_annotations = _oracle_member_annotations(observation)
        for kind, member_name, member_descriptor, _flags in (
            current_declared_members(class_name)
        ):
            if kind != "method" or not (
                class_tx or transactional in member_annotations.get(
                    (member_name, member_descriptor), ()
            )):
                continue
            certainty = (
                "exact" if spring_active and len(transaction_targets) == 3 else "possible"
            )
            for target_owner, target_name, target_descriptor in transaction_targets:
                expected.add((
                    "spring_transaction_proxy_dispatch",
                    class_name, member_name, member_descriptor,
                    target_owner, target_name, target_descriptor, certainty,
                ))
    # Release construction-only indexes before the production semantic rows
    # are decoded. The two complete edge sets must overlap briefly for exact
    # equality, but their unrelated hierarchy/factory caches do not.
    if current_declared_members_cache is None:
        shared_current_declared_members.clear()
    base_declared_members_cache.clear()
    runtime_type_closure.cache_clear()
    spring_dispatch_candidates.cache_clear()
    repository_dispatch_candidates.cache_clear()
    new_types_by_factory.clear()
    bean_types.clear()
    bean_types_by_target.clear()
    primary_bean_types.clear()
    invoked_owners.clear()
    binding_callers.clear()

    actual = set()
    for row in _iter_sidecar_object_rows(
        generation,
        "binary_runtime_semantic_overlay.json",
        "rows",
        progress_phase="validation-runtime-semantic-sidecar",
    ):
        if row.get("semantic_edge_kind") not in supported_kinds:
            continue
        actual.add((
            # The membership guard admits only non-empty supported strings.
            str(row.get("semantic_edge_kind")),
            str(row.get("caller_class_name") or ""),
            str(row.get("caller_member_name") or ""),
            str(row.get("caller_descriptor") or ""),
            str(row.get("target_class_name") or ""),
            str(row.get("target_member_name") or ""),
            str(row.get("target_descriptor") or ""),
            str(row.get("path_certainty") or ""),
        ))
    issues = []
    actual_exact = {item for item in actual if item[7] == "exact"}
    expected_exact = {item for item in expected if item[7] == "exact"}
    if actual_exact != expected_exact:
        expected_by_edge = {item[:7]: item[7] for item in expected}
        actual_by_edge = {item[:7]: item[7] for item in actual}
        certainty_conflicts = [
            {
                "edge": list(edge),
                "oracle_certainty": expected_by_edge[edge],
                "production_certainty": actual_by_edge[edge],
                "oracle_candidate_evidence": bean_wiring_candidate_evidence.get(edge),
            }
            for edge in sorted(set(expected_by_edge).intersection(actual_by_edge))
            if expected_by_edge[edge] != actual_by_edge[edge]
        ]
        issues.append(_validation_issue(
            "runtime_semantic_overlay",
            "ORACLE_RUNTIME_SEMANTIC_EDGE_SET_MISMATCH",
            missing=sorted(expected_exact - actual_exact),
            extra=sorted(actual_exact - expected_exact),
            certainty_conflicts=certainty_conflicts,
        ))
    return issues, {
        "validated_kinds": sorted(supported_kinds),
        "validated_exact_edges": [list(item) for item in sorted(expected_exact)],
        "observed_production_exact_edges": [
            list(item) for item in sorted(actual_exact)
        ],
        "oracle_candidate_edge_count": len(expected - expected_exact),
        "production_candidate_edge_count": len(actual - actual_exact),
        "exact_edge_set_matches": actual_exact == expected_exact,
    }


def _validated_empty_entrypoint_set(
    entrypoint_payload: Mapping[str, Any],
    entrypoint_validation_issues: Iterable[Mapping[str, Any]],
    entrypoint_truth: Mapping[str, Any] | None,
) -> bool:
    """Return true only when two independent views prove that no root exists.

    Candidate roots are deliberately not compared as an exact set by the
    entrypoint Oracle because their activation evidence can be incomplete.  A
    graph-free closed-world pass is therefore allowed only when both candidate
    counts are zero as well as the independently reconstructed exact set.  Any
    validation issue, discovery gap, unexpected record or missing truth input
    fails closed to the ordinary full-graph reconstruction.
    """

    truth = dict(entrypoint_truth or {})
    records_empty = (
        int(entrypoint_payload.get("record_count") or 0) == 0
        if "record_count" in entrypoint_payload
        else not tuple(entrypoint_payload.get("records") or ())
    )
    return bool(
        entrypoint_truth is not None
        and not tuple(entrypoint_validation_issues)
        and records_empty
        and not tuple(entrypoint_payload.get("coverage_gaps") or ())
        and int(truth.get("exact_entrypoint_count") or 0) == 0
        and int(truth.get("oracle_candidate_entrypoint_count") or 0) == 0
        and int(truth.get("production_candidate_entrypoint_count") or 0) == 0
        and not tuple(truth.get("candidate_activation_gaps") or ())
    )


class _ClosedWorldGraphIndex:
    """Disk-backed reconciliation index with caller/evidence lookups.

    Reconciliation chunks are compressed JSON in the production store. The
    previous validator expanded all five domains and every direct edge into
    Python dictionaries. This index decodes each chunk once, stores only the
    scalar fields the Oracle consumes, and derives transitions only for
    reached callers or reported path evidence.
    """

    def __init__(
        self,
        generation: Path,
        index_path: Path,
        *,
        paired_artifact_missing_targets: set[str],
        unresolved_edge_alias_targets: Mapping[str, set[str]],
        progress_callback: ValidationProgressCallback | None = None,
    ):
        self._generation = generation
        self._paired_missing = paired_artifact_missing_targets
        self._aliases = unresolved_edge_alias_targets
        self._progress_callback = progress_callback
        self._closed = False
        self._compact_resolution_index = True
        self._evidence_cache: OrderedDict[
            str, tuple[list[tuple[str, str, str, str]], str, str]
        ] = OrderedDict()
        self.connection = sqlite3.connect(index_path, uri=True)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            PRAGMA locking_mode=EXCLUSIVE;
            PRAGMA temp_store=FILE;
            CREATE TABLE member_resolution (
                edge_rowid INTEGER PRIMARY KEY,
                status TEXT NOT NULL,
                resolved_member TEXT NOT NULL
            );
            CREATE TABLE dispatch_resolution (
                edge_rowid INTEGER PRIMARY KEY,
                status TEXT NOT NULL,
                targets_json TEXT NOT NULL
            );
            CREATE TABLE type_resolution (
                edge_rowid INTEGER PRIMARY KEY,
                status TEXT NOT NULL
            );
            CREATE TABLE initialization_resolution (
                edge_rowid INTEGER PRIMARY KEY,
                status TEXT NOT NULL,
                targets_json TEXT NOT NULL
            );
            CREATE TABLE linkage_resolution (
                edge_rowid INTEGER PRIMARY KEY,
                status TEXT NOT NULL
            );
            CREATE TABLE orphan_member_resolution (
                evidence TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                resolved_member TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE orphan_dispatch_resolution (
                evidence TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                targets_json TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE orphan_type_resolution (
                evidence TEXT PRIMARY KEY,
                status TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE orphan_initialization_resolution (
                evidence TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                targets_json TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE orphan_linkage_resolution (
                evidence TEXT PRIMARY KEY,
                status TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE semantic_transition (
                caller TEXT NOT NULL,
                target TEXT NOT NULL,
                certainty TEXT NOT NULL,
                evidence TEXT NOT NULL
            );
            """
        )
        facts_uri = (
            f"{(generation / 'current_binary_facts.sqlite').resolve().as_uri()}"
            "?mode=ro&immutable=1"
        )
        try:
            self.connection.execute("ATTACH DATABASE ? AS facts", (facts_uri,))
            self._build_reconciliation_indexes()
            self._build_semantic_index()
        except BaseException:
            self.connection.close()
            raise

    @staticmethod
    def _insert_batches(
        connection: sqlite3.Connection,
        statement: str,
        rows: Iterable[tuple[Any, ...]],
        *,
        batch_size: int = 10_000,
        progress: Callable[[int], None] | None = None,
    ) -> int:
        batch: list[tuple[Any, ...]] = []
        inserted = 0
        for row in rows:
            batch.append(row)
            if len(batch) >= batch_size:
                connection.executemany(statement, batch)
                inserted += len(batch)
                batch.clear()
                if progress is not None:
                    progress(inserted)
        if batch:
            connection.executemany(statement, batch)
            inserted += len(batch)
            if progress is not None:
                progress(inserted)
        return inserted

    def _build_reconciliation_indexes(self) -> None:
        source = _open_immutable_sqlite(
            self._generation / "current_binary_facts.sqlite"
        )
        source.row_factory = sqlite3.Row
        specs = (
            (
                "member_resolution",
                "INSERT INTO member_resolution VALUES (?,?,?)",
                "INSERT INTO orphan_member_resolution VALUES (?,?,?)",
                lambda row: (
                    str(row.get("member_resolution_status") or ""),
                    str(row.get("resolved_member_identity") or ""),
                ),
            ),
            (
                "dispatch_resolution",
                "INSERT INTO dispatch_resolution VALUES (?,?,?)",
                "INSERT INTO orphan_dispatch_resolution VALUES (?,?,?)",
                lambda row: (
                    str(row.get("dispatch_status") or ""),
                    surrogate_safe_json_dumps(
                        list(row.get("implementation_target_identities") or ()),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                ),
            ),
            (
                "type_resolution",
                "INSERT INTO type_resolution VALUES (?,?)",
                "INSERT INTO orphan_type_resolution VALUES (?,?)",
                lambda row: (
                    str(row.get("type_resolution_status") or ""),
                ),
            ),
            (
                "class_initialization_resolution",
                "INSERT INTO initialization_resolution VALUES (?,?,?)",
                "INSERT INTO orphan_initialization_resolution VALUES (?,?,?)",
                lambda row: (
                    str(row.get("class_initialization_status") or ""),
                    surrogate_safe_json_dumps(
                        list(row.get("initializer_target_identities") or ()),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                ),
            ),
            (
                "linkage_resolution",
                "INSERT INTO linkage_resolution VALUES (?,?)",
                "INSERT INTO orphan_linkage_resolution VALUES (?,?)",
                lambda row: (
                    str(row.get("linkage_status") or ""),
                ),
            ),
        )
        try:
            states: list[dict[str, Any]] = []
            for domain_index, (
                kind, statement, orphan_statement, project,
            ) in enumerate(specs, start=1):
                total = int(source.execute(
                    "SELECT COALESCE(SUM(record_count),0) "
                    "FROM reconciliation_records WHERE record_kind=?",
                    (_ORACLE_RECONCILIATION_KIND_CODES[kind],),
                ).fetchone()[0])
                iterator = iter(_iter_reconciliation(source, kind))
                states.append({
                    "domain_index": domain_index,
                    "kind": kind,
                    "statement": statement,
                    "orphan_statement": orphan_statement,
                    "project": project,
                    "iterator": iterator,
                    "current": next(iterator, None),
                    "main_batch": [],
                    "orphan_batch": [],
                    "processed": 0,
                    "total": total,
                    "progress_interval": max(
                        10_000,
                        (total + 19) // 20 if total else 10_000,
                    ),
                    "next_progress": max(
                        10_000,
                        (total + 19) // 20 if total else 10_000,
                    ),
                })
                _notify_progress(
                    self._progress_callback,
                    "validation-closed-world-index",
                    f"闭世界索引：{kind}",
                    0,
                    total,
                )

            def flush_state(state: dict[str, Any]) -> None:
                main_batch = state["main_batch"]
                if main_batch:
                    self.connection.executemany(
                        state["statement"], main_batch
                    )
                    main_batch.clear()
                orphan_batch = state["orphan_batch"]
                if orphan_batch:
                    self.connection.executemany(
                        state["orphan_statement"], orphan_batch
                    )
                    orphan_batch.clear()

            def stage_record(
                state: dict[str, Any],
                reconciliation: Mapping[str, Any],
                edge_rowid: int | None,
            ) -> None:
                projected = state["project"](reconciliation)
                if edge_rowid is None:
                    state["orphan_batch"].append((
                        str(reconciliation.get("direct_edge_identity") or ""),
                        *projected,
                    ))
                else:
                    state["main_batch"].append((edge_rowid, *projected))
                state["processed"] += 1
                if (
                    len(state["main_batch"])
                    + len(state["orphan_batch"])
                    >= 10_000
                ):
                    flush_state(state)
                if (
                    state["processed"] >= state["next_progress"]
                    or state["processed"] == state["total"]
                ):
                    _notify_progress(
                        self._progress_callback,
                        "validation-closed-world-index",
                        f"闭世界索引：{state['kind']}",
                        state["processed"],
                        state["total"],
                    )
                    state["next_progress"] = (
                        state["processed"] + state["progress_interval"]
                    )

            direct_edge_total = int(self.connection.execute(
                "SELECT COUNT(*) FROM facts.direct_edges"
            ).fetchone()[0])
            direct_edge_progress_interval = max(
                10_000,
                (direct_edge_total + 19) // 20
                if direct_edge_total else 10_000,
            )
            _notify_progress(
                self._progress_callback,
                "validation-closed-world-index",
                "闭世界索引：单次顺序合并全部解析域",
                0,
                direct_edge_total,
            )
            # Every reconciliation family is a monotonic subset of the
            # reconciler's direct-edge rowid scan. Advance all five iterators
            # together while reading the wide facts table exactly once. This
            # avoids both a second SHA-keyed database and five repeated scans
            # of the multi-GiB direct-edge table.
            edge_cursor = self.connection.execute(
                """
                SELECT edge.rowid AS edge_rowid,
                       edge.direct_edge_identity AS evidence
                FROM facts.direct_edges AS edge NOT INDEXED
                ORDER BY edge.rowid
                """
            )
            try:
                for current_edge, edge_row in enumerate(edge_cursor, start=1):
                    evidence = str(edge_row["evidence"])
                    edge_rowid = int(edge_row["edge_rowid"])
                    for state in states:
                        reconciliation = state["current"]
                        while (
                            reconciliation is not None
                            and str(reconciliation.get(
                                "direct_edge_identity"
                            ) or "") == evidence
                        ):
                            stage_record(state, reconciliation, edge_rowid)
                            reconciliation = next(
                                state["iterator"], None
                            )
                            state["current"] = reconciliation
                    if (
                        current_edge == direct_edge_total
                        or current_edge % direct_edge_progress_interval == 0
                    ):
                        _notify_progress(
                            self._progress_callback,
                            "validation-closed-world-index",
                            "闭世界索引：单次顺序合并全部解析域",
                            current_edge,
                            direct_edge_total,
                        )
            finally:
                edge_cursor.close()

            # A missing order hint, legacy hash-ordered chunk, or malformed
            # evidence can leave records behind the forward scan. Resolve all
            # such records through the exact primary-key lookup. Locality is
            # optional; validation completeness never is.
            for state in states:
                reconciliation = state["current"]
                while reconciliation is not None:
                    evidence = str(
                        reconciliation.get("direct_edge_identity") or ""
                    )
                    matched = self.connection.execute(
                        "SELECT rowid FROM facts.direct_edges "
                        "WHERE direct_edge_identity=?",
                        (evidence,),
                    ).fetchone()
                    stage_record(
                        state,
                        reconciliation,
                        int(matched[0]) if matched is not None else None,
                    )
                    reconciliation = next(state["iterator"], None)
                    state["current"] = reconciliation
                flush_state(state)
                _notify_progress(
                    self._progress_callback,
                    "validation-closed-world-index",
                    f"闭世界索引完成：{state['kind']}",
                    state["domain_index"],
                    len(specs),
                )
            self.connection.commit()
        finally:
            source.close()

    def _build_semantic_index(self) -> None:
        def semantic_rows():
            for row in _iter_sidecar_object_rows(
                self._generation,
                "binary_runtime_semantic_overlay.json",
                "rows",
                progress_callback=self._progress_callback,
                progress_phase="validation-closed-world-semantic-index",
            ):
                caller = str(row.get("caller_member_identity") or "")
                target = str(row.get("target_member_identity") or "")
                if caller and target:
                    yield (
                        caller,
                        target,
                        "exact"
                        if row.get("path_certainty") == "exact"
                        else "possible",
                        str(row.get("semantic_edge_identity") or ""),
                    )
            inline_path = self._generation / "binary_inline_overlay.json"
            if inline_path.is_file():
                for row in _iter_sidecar_object_rows(
                    self._generation,
                    "binary_inline_overlay.json",
                    "rows",
                    progress_callback=self._progress_callback,
                    progress_phase="validation-closed-world-inline-index",
                ):
                    if (
                        row.get("consumption_state") != "changed_with_source"
                        or row.get("binding_certainty")
                        not in {"proven", "possible"}
                    ):
                        continue
                    caller = str(row.get("consumer_member_identity") or "")
                    target = str(
                        row.get("changed_field_member_identity") or ""
                    )
                    if caller and target:
                        yield (
                            caller,
                            target,
                            "exact"
                            if row.get("binding_certainty") == "proven"
                            else "possible",
                            str(row.get("inline_overlay_identity") or ""),
                        )

        self._insert_batches(
            self.connection,
            "INSERT INTO semantic_transition VALUES (?,?,?,?)",
            semantic_rows(),
        )
        # Building both lookup indexes after the append-only load lets SQLite
        # sort once. Maintaining two B-trees for every streamed semantic edge
        # caused avoidable random writes on virtualized Windows disks.
        self.connection.executescript(
            """
            CREATE INDEX semantic_transition_caller
                ON semantic_transition(caller);
            CREATE INDEX semantic_transition_evidence
                ON semantic_transition(evidence);
            """
        )
        self.connection.commit()

    def close(self) -> None:
        if not self._closed:
            self.connection.close()
            self._closed = True

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


    def _unresolved_certainty(self, status: str, symbolic: str) -> str:
        return (
            "exact"
            if status == "no_such_member"
            or (
                symbolic in self._paired_missing
                and status in {
                    "no_class_definition", "class_definition_failed",
                }
            )
            else "possible"
        )

    def _direct_relations(
        self,
        *,
        caller: str | None = None,
        evidence: str | None = None,
    ) -> list[tuple[str, str, str, str]]:
        evidence_cache = getattr(self, "_evidence_cache", None)
        if evidence_cache is None:
            # Boundary tests and legacy adapters may construct this index via
            # __new__ and populate only the old fields.
            evidence_cache = OrderedDict()
            self._evidence_cache = evidence_cache
        if evidence is not None:
            cached = evidence_cache.get(str(evidence))
            if cached is not None:
                evidence_cache.move_to_end(str(evidence))
                return cached[0]
        predicate = (
            "e.caller_member_identity=?" if caller is not None
            else "e.direct_edge_identity=?"
        )
        parameter = caller if caller is not None else evidence
        compact_index = bool(getattr(
            self, "_compact_resolution_index", False
        ))
        member_join = (
            "mr.edge_rowid=e.rowid"
            if compact_index else "mr.evidence=e.direct_edge_identity"
        )
        dispatch_join = (
            "dr.edge_rowid=e.rowid"
            if compact_index else "dr.evidence=e.direct_edge_identity"
        )
        type_join = (
            "tr.edge_rowid=e.rowid"
            if compact_index else "tr.evidence=e.direct_edge_identity"
        )
        initialization_join = (
            "ir.edge_rowid=e.rowid"
            if compact_index else "ir.evidence=e.direct_edge_identity"
        )
        rows = self.connection.execute(
            f"""
            SELECT e.direct_edge_identity,e.caller_member_identity,e.edge_kind,
                   e.symbolic_owner,e.symbolic_name,e.symbolic_descriptor,
                   mr.status AS member_status,
                   mr.resolved_member AS resolved_member,
                   dr.status AS dispatch_status,
                   dr.targets_json AS dispatch_targets,
                   tr.status AS type_status,
                   ir.status AS initialization_status,
                   ir.targets_json AS initialization_targets,
                   lr.status AS linkage_status
            FROM facts.direct_edges AS e
            LEFT JOIN member_resolution AS mr
              ON {member_join}
            LEFT JOIN dispatch_resolution AS dr
              ON {dispatch_join}
            LEFT JOIN type_resolution AS tr
              ON {type_join}
            LEFT JOIN initialization_resolution AS ir
              ON {initialization_join}
            LEFT JOIN linkage_resolution AS lr
              ON {(
                  "lr.edge_rowid=e.rowid"
                  if compact_index else "lr.evidence=e.direct_edge_identity"
              )}
            WHERE {predicate}
            """,
            (parameter,),
        )
        relations: list[tuple[str, str, str, str]] = []
        member_status = ""
        linkage_status = ""
        for row in rows:
            member_status = str(row["member_status"] or "")
            linkage_status = str(row["linkage_status"] or "")
            edge_id = str(row["direct_edge_identity"] or "")
            edge_caller = str(row["caller_member_identity"] or "")
            edge_kind = str(row["edge_kind"] or "")
            dynamic_handle = edge_kind.startswith("invokedynamic_handle_")
            executable_linkage = edge_kind in {
                "invokedynamic_bootstrap",
                "ldc_constant_dynamic_bootstrap",
            } or dynamic_handle
            if row["member_status"] is not None and (
                edge_kind in {"method", "field"} or executable_linkage
            ):
                targets = json.loads(str(row["dispatch_targets"] or "[]"))
                if (
                    not targets
                    and row["member_status"] == "resolved"
                    and row["resolved_member"]
                ):
                    targets = [str(row["resolved_member"])]
                certainty = (
                    "possible"
                    if row["dispatch_status"] in {
                        "possible", "partial_possible_set",
                    }
                    or executable_linkage
                    else "exact"
                )
                relations.extend(
                    (edge_caller, str(target), certainty, edge_id)
                    for target in targets
                    if target
                )
                if row["member_status"] != "resolved":
                    symbolic = _identity("binary_symbolic_trace_target", {
                        "owner": row["symbolic_owner"],
                        "name": row["symbolic_name"],
                        "descriptor": row["symbolic_descriptor"],
                        "member_kind": (
                            "field" if edge_kind == "field" else "method"
                        ),
                    })
                    aliases = self._aliases.get(edge_id, set())
                    for symbolic_target in sorted(aliases or {symbolic}):
                        relations.append((
                            edge_caller,
                            symbolic_target,
                            self._unresolved_certainty(
                                str(row["member_status"] or ""),
                                symbolic_target,
                            ),
                            edge_id,
                        ))
            if row["type_status"] in {
                "resolved", "primitive_or_array_type",
            }:
                symbolic = _identity("binary_symbolic_trace_target", {
                    "owner": row["symbolic_owner"],
                    "name": "<class>",
                    "descriptor": row["symbolic_descriptor"],
                    "member_kind": "class",
                })
                relations.append((edge_caller, symbolic, "exact", edge_id))
            if row["initialization_status"] == "resolved":
                relations.extend(
                    (edge_caller, str(target), "exact", edge_id)
                    for target in json.loads(
                        str(row["initialization_targets"] or "[]")
                    )
                    if target
                )
        if evidence is not None:
            evidence_key = str(evidence)
            if not member_status:
                try:
                    orphan_member = self.connection.execute(
                        "SELECT status FROM orphan_member_resolution "
                        "WHERE evidence=?",
                        (evidence_key,),
                    ).fetchone()
                except sqlite3.Error:
                    orphan_member = None
                member_status = (
                    str(orphan_member[0] or "") if orphan_member else ""
                )
            if not linkage_status:
                try:
                    orphan_linkage = self.connection.execute(
                        "SELECT status FROM orphan_linkage_resolution "
                        "WHERE evidence=?",
                        (evidence_key,),
                    ).fetchone()
                except sqlite3.Error:
                    orphan_linkage = None
                linkage_status = (
                    str(orphan_linkage[0] or "") if orphan_linkage else ""
                )
            evidence_cache[evidence_key] = (
                list(relations), member_status, linkage_status,
            )
            evidence_cache.move_to_end(evidence_key)
            while len(evidence_cache) > MAX_CLOSED_WORLD_EVIDENCE_CACHE_ENTRIES:
                evidence_cache.popitem(last=False)
        return relations

    def transitions(self, caller: str) -> list[tuple[str, str, str]]:
        result = [
            (target, certainty, evidence)
            for edge_caller, target, certainty, evidence
            in self._direct_relations(caller=caller)
            if edge_caller == caller
        ]
        result.extend(
            (
                str(row["target"]),
                str(row["certainty"]),
                str(row["evidence"]),
            )
            for row in self.connection.execute(
                "SELECT target,certainty,evidence "
                "FROM semantic_transition WHERE caller=?",
                (caller,),
            )
        )
        return result

    def relations_for_evidence(
        self, evidence: str
    ) -> list[tuple[str, str, str]]:
        result = [
            (caller, target, certainty)
            for caller, target, certainty, _edge_id
            in self._direct_relations(evidence=evidence)
        ]
        result.extend(
            (
                str(row["caller"]),
                str(row["target"]),
                str(row["certainty"]),
            )
            for row in self.connection.execute(
                "SELECT caller,target,certainty "
                "FROM semantic_transition WHERE evidence=?",
                (evidence,),
            )
        )
        return result

    def resolution_status(self, evidence: str) -> str:
        evidence_cache = getattr(self, "_evidence_cache", None)
        cached = (
            evidence_cache.get(str(evidence))
            if evidence_cache is not None else None
        )
        if cached is not None:
            evidence_cache.move_to_end(str(evidence))
            return cached[1]
        if bool(getattr(self, "_compact_resolution_index", False)):
            edge = self.connection.execute(
                "SELECT rowid FROM facts.direct_edges "
                "WHERE direct_edge_identity=?",
                (evidence,),
            ).fetchone()
            row = self.connection.execute(
                "SELECT status FROM member_resolution WHERE edge_rowid=?",
                (int(edge[0]),),
            ).fetchone() if edge is not None else self.connection.execute(
                "SELECT status FROM orphan_member_resolution "
                "WHERE evidence=?",
                (evidence,),
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT status FROM member_resolution WHERE evidence=?",
                (evidence,),
            ).fetchone()
        return str(row[0] or "") if row else ""

    def linkage_status(self, evidence: str) -> str:
        evidence_cache = getattr(self, "_evidence_cache", None)
        cached = (
            evidence_cache.get(str(evidence))
            if evidence_cache is not None else None
        )
        if cached is not None:
            evidence_cache.move_to_end(str(evidence))
            return cached[2]
        if bool(getattr(self, "_compact_resolution_index", False)):
            edge = self.connection.execute(
                "SELECT rowid FROM facts.direct_edges "
                "WHERE direct_edge_identity=?",
                (evidence,),
            ).fetchone()
            row = self.connection.execute(
                "SELECT status FROM linkage_resolution WHERE edge_rowid=?",
                (int(edge[0]),),
            ).fetchone() if edge is not None else self.connection.execute(
                "SELECT status FROM orphan_linkage_resolution "
                "WHERE evidence=?",
                (evidence,),
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT status FROM linkage_resolution WHERE evidence=?",
                (evidence,),
            ).fetchone()
        return str(row[0] or "") if row else ""


def _closed_world_decision_aliases(
    generation: Path,
) -> tuple[set[str], dict[str, set[str]]]:
    paired_artifact_missing_targets = set()
    unresolved_edge_alias_targets: dict[str, set[str]] = defaultdict(set)
    for decision in _iter_sidecar_object_rows(
        generation,
        "binary_decisions.json",
        "authoritative_change_facts",
        progress_phase="validation-closed-world-decisions",
    ):
        scope = decision.get("fact_scope") or {}
        kind = str(scope.get("member_kind") or decision.get("fact_kind") or "")
        artifact_sides = {
            str(artifact.get("side") or "")
            for artifact in decision.get("dependency_artifacts") or ()
        }
        if (
            scope.get("member_change_kind") == "removed"
            and kind in {"method", "field"}
            and {"base", "current"}.issubset(artifact_sides)
        ):
            paired_artifact_missing_targets.add(_identity(
                "binary_symbolic_trace_target", {
                    "owner": str(scope.get("class_name") or "").replace(
                        ".", "/"
                    ),
                    "name": str(scope.get("member_name") or ""),
                    "descriptor": str(scope.get("descriptor") or ""),
                    "member_kind": kind,
                },
            ))
        if kind in {"method", "field"}:
            target = _identity("binary_symbolic_trace_target", {
                "owner": str(scope.get("class_name") or "").replace(".", "/"),
                "name": str(scope.get("member_name") or ""),
                "descriptor": str(scope.get("descriptor") or ""),
                "member_kind": kind,
            })
            for edge_id in (
                (decision.get("evidence") or {}).get(
                    "current_unresolved_direct_edge_identities"
                ) or ()
            ):
                unresolved_edge_alias_targets[str(edge_id)].add(target)
    return paired_artifact_missing_targets, unresolved_edge_alias_targets


def _load_closed_world_graph(
    generation: Path,
    semantic_payload: Mapping[str, Any],
) -> tuple[
    dict[str, list[tuple[str, str, str]]],
    dict[str, list[tuple[str, str, str]]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    """Materialize the independently validated graph for reachable roots."""

    database = generation / "current_binary_facts.sqlite"
    connection = _open_immutable_sqlite(database)
    connection.row_factory = sqlite3.Row
    try:
        edges = {
            row["direct_edge_identity"]: row
            for row in _rows(connection, "direct_edges")
        }
        resolutions = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(connection, "member_resolution")
        }
        dispatches = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(connection, "dispatch_resolution")
        }
        type_resolutions = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(connection, "type_resolution")
        }
        initializations = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(
                connection, "class_initialization_resolution"
            )
        }
        linkages = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(connection, "linkage_resolution")
        }
    finally:
        connection.close()

    # caller -> (target, certainty, evidence identity)
    transitions: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    relation_by_evidence: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

    def admit(caller: str, target: str, certainty: str, evidence: str) -> None:
        # Every call site below constructs certainty from a closed exact /
        # possible choice; only missing relation endpoints can reject a row.
        if not caller or not target:
            return
        record = (target, certainty, evidence)
        transitions[caller].append(record)
        relation_by_evidence[evidence].append((caller, target, certainty))

    (
        paired_artifact_missing_targets,
        unresolved_edge_alias_targets,
    ) = _closed_world_decision_aliases(generation)

    def unresolved_certainty(status: str, symbolic: str) -> str:
        # A direct bytecode reference to a definitively missing member/class is
        # an exact failing edge when the changed dependency exists on both
        # sides. A whole unmatched dependency remains an attribution limit.
        return (
            "exact"
            if status == "no_such_member"
            or (
                symbolic in paired_artifact_missing_targets
                and status in {"no_class_definition", "class_definition_failed"}
            )
            else "possible"
        )

    for edge_id, resolution in resolutions.items():
        edge = edges.get(edge_id)
        if edge is None:
            continue
        # direct_edges.edge_kind is NOT NULL in the fact-store schema.
        edge_kind = str(edge["edge_kind"])
        dynamic_handle = edge_kind.startswith("invokedynamic_handle_")
        executable_linkage = edge_kind in {
            "invokedynamic_bootstrap", "ldc_constant_dynamic_bootstrap",
        } or dynamic_handle
        if edge_kind not in {"method", "field"} and not executable_linkage:
            continue
        dispatch = dispatches.get(edge_id) or {}
        targets = list(dispatch.get("implementation_target_identities") or ())
        if (
            not targets
            and resolution.get("member_resolution_status") == "resolved"
            and resolution.get("resolved_member_identity")
        ):
            targets = [resolution["resolved_member_identity"]]
        certainty = (
            "possible"
            if dispatch.get("dispatch_status") in {
                "possible", "partial_possible_set",
            }
            or executable_linkage
            else "exact"
        )
        for target in targets:
            admit(str(edge["caller_member_identity"]), str(target), certainty, edge_id)
        if resolution.get("member_resolution_status") != "resolved":
            symbolic = _identity("binary_symbolic_trace_target", {
                "owner": edge["symbolic_owner"],
                "name": edge["symbolic_name"],
                "descriptor": edge["symbolic_descriptor"],
                "member_kind": "field" if edge_kind == "field" else "method",
            })
            alias_targets = unresolved_edge_alias_targets.get(edge_id, set())
            # If the base-side resolver proved that a symbolic Child.m edge
            # selected Parent.m, the changed API is Parent.m.  Reporting both
            # the symbolic child alias and the declaration invents an API
            # change on Child and duplicates the public result.
            for symbolic_target in sorted(alias_targets or {symbolic}):
                admit(
                    str(edge["caller_member_identity"]), symbolic_target,
                    unresolved_certainty(
                        str(resolution.get("member_resolution_status") or ""),
                        symbolic_target,
                    ),
                    edge_id,
                )

    for edge_id, resolution in type_resolutions.items():
        if resolution.get("type_resolution_status") not in {
            "resolved", "primitive_or_array_type",
        }:
            continue
        edge = edges.get(edge_id)
        if edge is None:
            continue
        symbolic = _identity("binary_symbolic_trace_target", {
            "owner": edge["symbolic_owner"], "name": "<class>",
            "descriptor": edge["symbolic_descriptor"], "member_kind": "class",
        })
        admit(str(edge["caller_member_identity"]), symbolic, "exact", edge_id)

    for edge_id, resolution in initializations.items():
        if resolution.get("class_initialization_status") != "resolved":
            continue
        edge = edges.get(edge_id)
        if edge is None:
            continue
        for target in resolution.get("initializer_target_identities") or ():
            admit(str(edge["caller_member_identity"]), str(target), "exact", edge_id)

    for row in semantic_payload.get("rows") or ():
        admit(
            str(row.get("caller_member_identity") or ""),
            str(row.get("target_member_identity") or ""),
            "exact" if row.get("path_certainty") == "exact" else "possible",
            str(row.get("semantic_edge_identity") or ""),
        )
    inline_path = generation / "binary_inline_overlay.json"
    if inline_path.is_file():
        for row in _load_json(inline_path).get("rows") or ():
            if row.get("consumption_state") != "changed_with_source" or row.get(
                "binding_certainty"
            ) not in {"proven", "possible"}:
                continue
            admit(
                str(row.get("consumer_member_identity") or ""),
                str(row.get("changed_field_member_identity") or ""),
                "exact" if row.get("binding_certainty") == "proven" else "possible",
                str(row.get("inline_overlay_identity") or ""),
            )

    return (
        dict(transitions),
        dict(relation_by_evidence),
        resolutions,
        linkages,
    )


def _validate_closed_world_results(
    generation: Path,
    *,
    entrypoint_validation_issues: Iterable[Mapping[str, Any]] = (),
    entrypoint_truth: Mapping[str, Any] | None = None,
    progress_callback: ValidationProgressCallback | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate closed-world outputs in one bounded short-path workspace."""

    # The on-disk graph can contain millions of keys and expands its path with
    # SQLite sidecars. Keep its complete lifetime inside the shared short-path
    # runtime so Windows never falls back to an unbounded user temp path.
    with short_temporary_directory(
        prefix="binary-validation-graph"
    ) as graph_temporary:
        return _validate_closed_world_results_in_workspace(
            generation,
            graph_directory=Path(graph_temporary),
            entrypoint_validation_issues=entrypoint_validation_issues,
            entrypoint_truth=entrypoint_truth,
            progress_callback=progress_callback,
        )


def _validate_closed_world_results_in_workspace(
    generation: Path,
    *,
    graph_directory: Path,
    entrypoint_validation_issues: Iterable[Mapping[str, Any]] = (),
    entrypoint_truth: Mapping[str, Any] | None = None,
    progress_callback: ValidationProgressCallback | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Rebuild formal reachability from already independently validated facts.

    Direct/reconciliation records are admitted here only after their preceding
    Oracle validators have compared them with raw artifacts and target-JVM
    observations. Semantic edges and entrypoints have likewise already been
    independently rebuilt. This final pass closes those domains over the
    formal result, API projection, CSV and summary surfaces.
    """
    issues: list[dict[str, Any]] = []
    projections = {
        str(row.get("projection_identity") or ""): row
        for row in _iter_sidecar_object_rows(
            generation,
            "binary_projections.json",
            "formal_projections",
            progress_callback=progress_callback,
            progress_phase="validation-closed-world-projections",
        )
    }
    if not projections:
        formal_result_ids = [
            str(row.get("projection_identity") or "")
            for row in _iter_sidecar_object_rows(
                generation,
                "binary_formal_results.json",
                "results",
                progress_callback=progress_callback,
                progress_phase="validation-closed-world-results",
            )
        ]
        reported_api_ids = [
            str(row.get("reported_api_identity") or "")
            for row in _iter_sidecar_object_rows(
                generation,
                "binary_formal_results.json",
                "by_api",
                progress_callback=progress_callback,
                progress_phase="validation-closed-world-api",
            )
        ]
        if formal_result_ids:
            issues.append(_validation_issue(
                "closed_world_results",
                "ORACLE_FORMAL_PROJECTION_RESULT_SET_MISMATCH",
                missing=[],
                extra=sorted(formal_result_ids),
            ))
        if reported_api_ids:
            issues.append(_validation_issue(
                "closed_world_results",
                "ORACLE_API_AGGREGATION_MISMATCH",
                mismatches=[{
                    "field": "identity_set",
                    "missing": [],
                    "extra": sorted(reported_api_ids),
                }],
            ))
        csv_path = generation / "binary_formal_results.csv"
        with csv_path.open(encoding="utf-8-sig", newline="") as handle:
            if list(csv.DictReader(handle)):
                issues.append(_validation_issue(
                    "closed_world_results",
                    "ORACLE_FORMAL_CSV_PROJECTION_MISMATCH",
                ))
        authoritative_count = sum(
            1 for _row in _iter_sidecar_object_rows(
                generation,
                "binary_decisions.json",
                "authoritative_change_facts",
                progress_callback=progress_callback,
                progress_phase="validation-closed-world-decisions",
            )
        )
        summary = _load_json(generation / "binary_summary.json")
        summary_expected = {
            "authoritative_change_fact_count": authoritative_count,
            "formal_projection_count": 0,
            "formal_trace_result_count": 0,
            "unique_reported_api_total": 0,
            "reachable_total": 0,
            "uncertain_total": 0,
            "not_found_in_static_analysis_total": 0,
            "not_analyzed_total": 0,
            "probable_impact_total": 0,
        }
        summary_mismatches = {
            key: {"expected": value, "actual": summary.get(key)}
            for key, value in summary_expected.items()
            if summary.get(key) != value
        }
        if summary_mismatches:
            issues.append(_validation_issue(
                "closed_world_results",
                "ORACLE_SUMMARY_AGGREGATION_MISMATCH",
                mismatches=summary_mismatches,
            ))
        return issues, {
            "reachability_rebuild_status": (
                "not_required_no_formal_projections"
            ),
            "exact_reachable_node_count": 0,
            "possible_reachable_node_count": 0,
            "formal_result_count": len(formal_result_ids),
            "reported_api_count": len(reported_api_ids),
            "formal_identity_set_closed": not issues,
        }

    exact_entrypoints: set[str] = set()
    possible_entrypoints: set[str] = set()
    entrypoint_record_count = 0
    for row in _iter_sidecar_object_rows(
        generation,
        "binary_entrypoints.json",
        "records",
        progress_callback=progress_callback,
        progress_phase="validation-closed-world-entrypoints",
    ):
        entrypoint_record_count += 1
        member_identity = str(row.get("member_identity") or "")
        if row.get("path_certainty") == "exact":
            exact_entrypoints.add(member_identity)
        elif row.get("path_certainty") == "possible":
            possible_entrypoints.add(member_identity)
    possible_entrypoints.difference_update(exact_entrypoints)
    entrypoint_coverage_gaps = _sidecar_top_level_value(
        generation, "binary_entrypoints.json", "coverage_gaps"
    )
    if not isinstance(entrypoint_coverage_gaps, list):
        raise BinaryValidationError(
            "BINARY_VALIDATION_JSON_INVALID",
            "binary_entrypoints.json:coverage_gaps",
        )
    entrypoint_payload = {
        "record_count": entrypoint_record_count,
        "coverage_gaps": entrypoint_coverage_gaps,
    }
    graph_not_required = _validated_empty_entrypoint_set(
        entrypoint_payload,
        entrypoint_validation_issues,
        entrypoint_truth,
    )
    graph_index: _ClosedWorldGraphIndex | None = None
    legacy_transitions: Mapping[
        str, Iterable[tuple[str, str, str]]
    ] = {}
    legacy_relations: Mapping[
        str, Iterable[tuple[str, str, str]]
    ] = {}
    legacy_resolutions: Mapping[str, Mapping[str, Any]] = {}
    legacy_linkages: Mapping[str, Mapping[str, Any]] = {}
    if not graph_not_required:
        if (generation / "current_binary_facts.sqlite").is_file():
            paired_missing, unresolved_aliases = (
                _closed_world_decision_aliases(generation)
            )
            graph_index = _ClosedWorldGraphIndex(
                generation,
                graph_directory / "closed-world-index.sqlite",
                paired_artifact_missing_targets=paired_missing,
                unresolved_edge_alias_targets=unresolved_aliases,
                progress_callback=progress_callback,
            )
        else:
            semantic_payload = _load_json(
                generation / "binary_runtime_semantic_overlay.json"
            )
            (
                legacy_transitions,
                legacy_relations,
                legacy_resolutions,
                legacy_linkages,
            ) = _load_closed_world_graph(generation, semantic_payload)
    def closure(roots: set[str], *, include_possible: bool) -> set[str]:
        reached = set(roots)
        pending = list(sorted(roots))
        while pending:
            caller = pending.pop()
            transitions = (
                graph_index.transitions(caller)
                if graph_index is not None
                else legacy_transitions.get(caller, ())
            )
            for target, certainty, _evidence in transitions:
                if certainty == "possible" and not include_possible:
                    continue
                if target not in reached:
                    reached.add(target)
                    pending.append(target)
        return reached

    exact_reached = closure(exact_entrypoints, include_possible=False)
    possible_reached = closure(
        exact_entrypoints | possible_entrypoints, include_possible=True
    )

    decisions = {
        str(row.get("decision_identity") or ""): row
        for row in _iter_sidecar_object_rows(
            generation,
            "binary_decisions.json",
            "authoritative_change_facts",
            progress_callback=progress_callback,
            progress_phase="validation-closed-world-decisions",
        )
    }
    decisions_by_change = {
        str(row.get("change_fact_identity") or ""): row
        for row in decisions.values()
    }
    assessments = {
        str(row.get("projection_assessment_identity") or ""): row
        for row in _iter_sidecar_object_rows(
            generation,
            "binary_projections.json",
            "authoritative_projection_assessments",
            progress_callback=progress_callback,
            progress_phase="validation-closed-world-assessments",
        )
    }
    coverage = _load_json(generation / "binary_coverage.json")
    # Semantic-adapter gaps are global diagnostics; they must not turn an
    # unrelated, otherwise complete target into not_analyzed. Per-result trace
    # construction intentionally applies only entrypoint/runtime/decision and
    # target-specific enumeration gaps.
    decision_gap_union = {
        str(gap)
        for row in decisions.values()
        for gap in row.get("coverage_gaps") or ()
    }
    for row in _iter_sidecar_object_rows(
        generation,
        "binary_decisions.json",
        "diagnostic_candidate_facts",
        progress_callback=progress_callback,
        progress_phase="validation-closed-world-diagnostics",
    ):
        decision_gap_union.update(
            str(gap) for gap in row.get("coverage_gaps") or ()
        )
    semantic_coverage_gaps = _sidecar_top_level_value(
        generation,
        "binary_runtime_semantic_overlay.json",
        "coverage_gaps",
    )
    if not isinstance(semantic_coverage_gaps, list):
        raise BinaryValidationError(
            "BINARY_VALIDATION_JSON_INVALID",
            "binary_runtime_semantic_overlay.json:coverage_gaps",
        )
    global_trace_gaps = (
        set(coverage.get("trace_coverage_gaps") or ())
        - set(semantic_coverage_gaps)
        - decision_gap_union
        - {
            "trace_path_enumeration_limit_exceeded",
            "trace_node_limit_exceeded",
        }
    )
    priority = {
        "reachable": 3, "uncertain": 2,
        "not_found_in_static_analysis": 1, "not_analyzed": 0,
    }
    grouped: dict[tuple[Any, Any, Any, Any], dict[str, Any]] = {}
    result_projection_ids: set[str] = set()
    formal_result_count = 0
    runtime_profile_identity: Any = None

    def accumulate_result(result: Mapping[str, Any]) -> None:
        nonlocal runtime_profile_identity
        if runtime_profile_identity is None:
            runtime_profile_identity = result.get("runtime_profile_identity")
        change_identity = str(result.get("change_fact_identity") or "")
        decision_for_change = decisions_by_change.get(change_identity)
        if decision_for_change is None:
            return
        scope = decision_for_change.get("fact_scope") or {}
        key = (
            scope.get("class_name"),
            scope.get("member_kind") or decision_for_change.get("fact_kind"),
            scope.get("member_name"),
            scope.get("descriptor"),
        )
        aggregate = grouped.get(key)
        if aggregate is None:
            aggregate = {
                "reachability_status": str(
                    result.get("reachability_status") or ""
                ),
                "is_reachable": False,
                "probable_impact": False,
                "path_set_complete": True,
                "exact_path_exists": False,
                "possible_path_exists": False,
                "projection_ids": [],
                "change_ids": [],
                "base_coords": set(),
                "current_coords": set(),
                "loader_realms": set(),
            }
            grouped[key] = aggregate
        realm = str(scope.get("initiating_loader_realm_identity") or "")
        if realm:
            aggregate["loader_realms"].add(realm)
        status = str(result.get("reachability_status") or "")
        if priority.get(status, -1) > priority.get(
            str(aggregate["reachability_status"]), -1
        ):
            aggregate["reachability_status"] = status
        aggregate["is_reachable"] = bool(
            aggregate["is_reachable"] or result.get("is_reachable")
        )
        aggregate["probable_impact"] = bool(
            aggregate["probable_impact"]
            or result.get("impact_conclusion") == "probable_impact"
        )
        aggregate["path_set_complete"] = bool(
            aggregate["path_set_complete"]
            and result.get("path_set_complete")
        )
        aggregate["exact_path_exists"] = bool(
            aggregate["exact_path_exists"]
            or result.get("exact_path_exists")
        )
        aggregate["possible_path_exists"] = bool(
            aggregate["possible_path_exists"]
            or result.get("possible_path_exists")
        )
        aggregate["projection_ids"].append(
            str(result.get("projection_identity") or "")
        )
        aggregate["change_ids"].append(change_identity)
        for artifact in decision_for_change.get("dependency_artifacts") or ():
            coord = str(artifact.get("coord") or "")
            side = str(artifact.get("side") or "")
            if coord and side == "base":
                aggregate["base_coords"].add(coord)
            elif coord and side == "current":
                aggregate["current_coords"].add(coord)

    for result in _iter_sidecar_object_rows(
        generation,
        "binary_formal_results.json",
        "results",
        progress_callback=progress_callback,
        progress_phase="validation-closed-world-results",
    ):
        formal_result_count += 1
        projection_id = str(result.get("projection_identity") or "")
        result_projection_ids.add(projection_id)
        accumulate_result(result)
        projection = projections.get(projection_id) or {}
        assessment_id = str(projection.get("projection_assessment_identity") or "")
        assessment = assessments.get(assessment_id) or {}
        decision = decisions.get(str(assessment.get("decision_identity") or ""))
        if decision is None or result.get("change_fact_identity") != decision.get(
            "change_fact_identity"
        ):
            issues.append(_validation_issue(
                "closed_world_results", "ORACLE_FORMAL_RESULT_DECISION_BINDING_MISMATCH",
                projection_identity=projection_id,
            ))
            continue
        targets = {str(value) for value in result.get("target_nodes") or () if value}
        exact = bool(targets.intersection(exact_reached))
        possible = bool(targets.intersection(possible_reached))
        complete = not global_trace_gaps and not set(
            decision.get("coverage_gaps") or ()
        )
        expected_status = (
            "reachable" if exact else
            "uncertain" if possible else
            "not_found_in_static_analysis" if complete else
            "not_analyzed"
        )
        expected_state = {
            "reachability_status": expected_status,
            "analysis_status": expected_status,
            "is_reachable": exact,
            "impact_conclusion": "probable_impact" if exact else "inconclusive",
            "decision_bucket": "probable_impact" if exact else "inconclusive",
            "runtime_verification_status": (
                "required_not_executed" if exact else "undetermined"
            ),
            "runtime_verification_executed_by_system": False,
            "exact_path_exists": exact,
        }
        if graph_not_required:
            # With a complete, independently proven empty root set no path can
            # exist, and result completeness is determined solely by the same
            # global/per-decision gaps used by the production tracer.
            expected_state.update({
                "possible_path_exists": False,
                "path_set_complete": complete,
            })
        mismatches = {
            key: {"expected": value, "actual": result.get(key)}
            for key, value in expected_state.items()
            if result.get(key) != value
        }

        path_resolution_statuses = set()
        path_linkage_statuses = set()
        for path in result.get("paths") or ():
            entrypoint = str(path.get("entrypoint_member_identity") or "")
            valid_entrypoint = entrypoint in (
                exact_entrypoints | possible_entrypoints
            )
            if not valid_entrypoint:
                issues.append(_validation_issue(
                    "closed_world_results",
                    "ORACLE_TRACE_PATH_ENTRYPOINT_MISMATCH",
                    projection_identity=projection_id,
                    path_identity=path.get("path_identity"),
                    entrypoint_member_identity=entrypoint,
                ))
            current_nodes = {entrypoint} if valid_entrypoint else set()
            path_certainty = (
                "possible" if entrypoint in possible_entrypoints else "exact"
            )
            for path_edge in path.get("edges") or ():
                evidence = str(path_edge.get("direct_edge_identity") or "")
                next_nodes = set()
                relations = (
                    graph_index.relations_for_evidence(evidence)
                    if graph_index is not None
                    else legacy_relations.get(evidence, ())
                )
                for caller, target, certainty in relations:
                    if caller in current_nodes:
                        next_nodes.add(target)
                        if certainty == "possible":
                            path_certainty = "possible"
                current_nodes = next_nodes
                if graph_index is not None:
                    path_resolution_statuses.add(
                        graph_index.resolution_status(evidence)
                    )
                    path_linkage_statuses.add(
                        graph_index.linkage_status(evidence)
                    )
                else:
                    if evidence in legacy_resolutions:
                        path_resolution_statuses.add(str(
                            legacy_resolutions[evidence].get(
                                "member_resolution_status"
                            ) or ""
                        ))
                    if evidence in legacy_linkages:
                        path_linkage_statuses.add(str(
                            legacy_linkages[evidence].get(
                                "linkage_status"
                            ) or ""
                        ))
            if not current_nodes.intersection(targets):
                issues.append(_validation_issue(
                    "closed_world_results", "ORACLE_TRACE_PATH_CONTINUITY_MISMATCH",
                    projection_identity=projection_id,
                    path_identity=path.get("path_identity"),
                ))
            if path.get("path_certainty") != path_certainty:
                issues.append(_validation_issue(
                    "closed_world_results", "ORACLE_TRACE_PATH_CERTAINTY_MISMATCH",
                    projection_identity=projection_id,
                    path_identity=path.get("path_identity"),
                    expected=path_certainty, actual=path.get("path_certainty"),
                ))
            expected_path_identity = _identity("binary_trace_path_identity", {
                "entrypoint_member_identity": entrypoint,
                "entrypoint_record_identities": [
                    row.get("entrypoint_record_identity")
                    for row in path.get("entrypoint_records") or ()
                ],
                "target_nodes": list(result.get("target_nodes") or ()),
                "edge_identities": [
                    row.get("direct_edge_identity")
                    for row in path.get("edges") or ()
                ],
                "path_certainty": path.get("path_certainty"),
            })
            if path.get("path_identity") != expected_path_identity:
                issues.append(_validation_issue(
                    "closed_world_results", "ORACLE_TRACE_PATH_IDENTITY_MISMATCH",
                    projection_identity=projection_id,
                    path_identity=path.get("path_identity"),
                ))
        path_resolution_statuses.discard("")
        path_linkage_statuses.discard("")
        if sorted(path_resolution_statuses) != list(
            result.get("member_resolution_statuses") or ()
        ):
            mismatches["member_resolution_statuses"] = {
                "expected": sorted(path_resolution_statuses),
                "actual": result.get("member_resolution_statuses"),
            }
        if sorted(path_linkage_statuses) != list(
            result.get("linkage_resolution_statuses") or ()
        ):
            mismatches["linkage_resolution_statuses"] = {
                "expected": sorted(path_linkage_statuses),
                "actual": result.get("linkage_resolution_statuses"),
            }
        if mismatches:
            issues.append(_validation_issue(
                "closed_world_results", "ORACLE_FORMAL_STATE_MISMATCH",
                projection_identity=projection_id, mismatches=mismatches,
            ))
        expected_result_identity = _identity(
            "binary_trace_result_identity",
            {
                key: value for key, value in result.items()
                if key != "trace_result_identity"
            },
        )
        if result.get("trace_result_identity") != expected_result_identity:
            issues.append(_validation_issue(
                "closed_world_results", "ORACLE_FORMAL_RESULT_IDENTITY_MISMATCH",
                projection_identity=projection_id,
            ))

    if result_projection_ids != set(projections):
        issues.append(_validation_issue(
            "closed_world_results",
            "ORACLE_FORMAL_PROJECTION_RESULT_SET_MISMATCH",
            missing=sorted(set(projections) - result_projection_ids),
            extra=sorted(result_projection_ids - set(projections)),
        ))

    expected_api: dict[str, dict[str, Any]] = {}
    analysis_context = str(_sidecar_top_level_value(
        generation,
        "binary_decisions.json",
        "analysis_context_identity",
    ) or "")
    runtime_profile_identity = (
        runtime_profile_identity
        if formal_result_count else
        (_load_json(generation / "binary_summary.json")).get(
            "current_runtime_profile_identity"
        )
    )
    for key, aggregate in grouped.items():
        owner, kind, name, descriptor = key
        identity = _identity("reported_api_identity", {
            "analysis_context_identity": analysis_context,
            "current_runtime_profile_identity": runtime_profile_identity,
            "class_name": owner,
            "member_kind": kind,
            "member_name": name,
            "descriptor": descriptor,
            "grouping_rule_version": "binary-reported-api-v2",
        })
        status = str(aggregate["reachability_status"])
        expected_api[identity] = {
            "reported_api_identity": identity,
            "display_owner": owner,
            "display_member": name,
            "display_descriptor": descriptor,
            "display_member_kind": kind,
            "initiating_loader_realms": sorted(aggregate["loader_realms"]),
            "reachability_status": status,
            "is_reachable": bool(aggregate["is_reachable"]),
            "impact_conclusion": (
                "probable_impact"
                if aggregate["probable_impact"]
                else "inconclusive"
            ),
            "runtime_verification_status": (
                "required_not_executed"
                if status == "reachable"
                else "undetermined"
            ),
            "runtime_verification_executed_by_system": False,
            "path_set_complete": bool(aggregate["path_set_complete"]),
            "exact_path_exists": bool(aggregate["exact_path_exists"]),
            "possible_path_exists": bool(
                aggregate["possible_path_exists"]
            ),
            "contributing_projection_ids": sorted(
                aggregate["projection_ids"]
            ),
            "contributing_change_fact_ids": sorted(
                aggregate["change_ids"]
            ),
            "base_dependency_coords": sorted(aggregate["base_coords"]),
            "current_dependency_coords": sorted(
                aggregate["current_coords"]
            ),
        }
    csv_fields = {
        "display_owner", "display_member", "display_descriptor",
        "reachability_status", "impact_conclusion",
        "runtime_verification_status",
    }
    actual_api_ids: set[str] = set()
    actual_api_csv: dict[str, tuple[str, ...]] = {}
    api_field_mismatches = []
    ordered_csv_fields = tuple(sorted(csv_fields))
    for row in _iter_sidecar_object_rows(
        generation,
        "binary_formal_results.json",
        "by_api",
        progress_callback=progress_callback,
        progress_phase="validation-closed-world-api",
    ):
        identity = str(row.get("reported_api_identity") or "")
        actual_api_ids.add(identity)
        actual_api_csv[identity] = tuple(
            str(row.get(field) or "") for field in ordered_csv_fields
        )
        expected_row = expected_api.get(identity)
        if expected_row is None:
            continue
        for field, expected in expected_row.items():
            if row.get(field) != expected:
                api_field_mismatches.append({
                    "reported_api_identity": identity,
                    "field": field,
                    "expected": expected,
                    "actual": row.get(field),
                })
    api_mismatches = []
    if actual_api_ids != set(expected_api):
        api_mismatches.append({
            "field": "identity_set",
            "missing": sorted(set(expected_api) - actual_api_ids),
            "extra": sorted(actual_api_ids - set(expected_api)),
        })
    api_mismatches.extend(api_field_mismatches)
    if api_mismatches:
        issues.append(_validation_issue(
            "closed_world_results", "ORACLE_API_AGGREGATION_MISMATCH",
            mismatches=api_mismatches[:100],
        ))

    csv_path = generation / "binary_formal_results.csv"
    csv_by_identity: dict[str, tuple[str, ...]] = {}
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            csv_by_identity[
                str(row.get("reported_api_identity") or "")
            ] = tuple(
                str(row.get(field) or "") for field in ordered_csv_fields
            )
    csv_mismatch = set(csv_by_identity) != actual_api_ids
    if not csv_mismatch:
        for identity, expected_csv in actual_api_csv.items():
            if csv_by_identity.get(identity) != expected_csv:
                csv_mismatch = True
                break
    if csv_mismatch:
        issues.append(_validation_issue(
            "closed_world_results", "ORACLE_FORMAL_CSV_PROJECTION_MISMATCH",
        ))

    summary = _load_json(generation / "binary_summary.json")
    summary_expected = {
        "authoritative_change_fact_count": len(decisions),
        "formal_projection_count": len(projections),
        "formal_trace_result_count": formal_result_count,
        "unique_reported_api_total": len(expected_api),
        "reachable_total": sum(
            row["reachability_status"] == "reachable" for row in expected_api.values()
        ),
        "uncertain_total": sum(
            row["reachability_status"] == "uncertain" for row in expected_api.values()
        ),
        "not_found_in_static_analysis_total": sum(
            row["reachability_status"] == "not_found_in_static_analysis"
            for row in expected_api.values()
        ),
        "not_analyzed_total": sum(
            row["reachability_status"] == "not_analyzed" for row in expected_api.values()
        ),
        "probable_impact_total": sum(
            row["impact_conclusion"] == "probable_impact"
            for row in expected_api.values()
        ),
    }
    summary_mismatches = {
        key: {"expected": value, "actual": summary.get(key)}
        for key, value in summary_expected.items()
        if summary.get(key) != value
    }
    if summary_mismatches:
        issues.append(_validation_issue(
            "closed_world_results", "ORACLE_SUMMARY_AGGREGATION_MISMATCH",
            mismatches=summary_mismatches,
        ))
    closed_world_truth = {
        "reachability_rebuild_status": (
            "not_required_validated_empty_entrypoint_set"
            if graph_not_required else "completed_full_graph"
        ),
        "exact_reachable_node_count": len(exact_reached),
        "possible_reachable_node_count": len(possible_reached),
        "formal_result_count": formal_result_count,
        "reported_api_count": len(expected_api),
        "formal_identity_set_closed": not issues,
    }
    if graph_index is not None:
        graph_index.close()
    return issues, closed_world_truth


def _validate_source_attestation(
    generation: Path, config: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Re-hash every supplied source file without using the source parser."""
    overlay = dict(config.get("source_overlay") or {})
    path = generation / "binary_source_attestation.json"
    if not overlay:
        issues = []
        if path.exists():
            issues.append(_validation_issue(
                "source_attestation", "ORACLE_UNEXPECTED_SOURCE_ATTESTATION_PRESENT",
                attestation_present=True,
            ))
        return issues, {"source_input_status": "not_provided", "source_file_count": 0}
    if not path.is_file():
        return [_validation_issue(
            "source_attestation", "ORACLE_SOURCE_ATTESTATION_MISSING",
            attestation_present=False,
        )], {"source_input_status": "provided", "source_file_count": 0}

    payload = _load_json(path)
    actual_files = []
    actual_sets = []
    expected_coverage_gaps = []
    language_file_counts: dict[str, int] = defaultdict(int)
    issues = []
    for raw_set in overlay.get("source_sets") or ():
        source_set = dict(raw_set or {})
        roots = [
            Path(str(item)).expanduser().resolve()
            for item in source_set.get("source_dirs") or ()
        ]
        common_value = source_set.get("source_root") or (
            roots[0] if len(roots) == 1 else None
        )
        if common_value is None:
            issues.append(_validation_issue(
                "source_attestation", "ORACLE_SOURCE_COMMON_ROOT_MISSING",
                owner_coord=str(source_set.get("owner_coord") or ""),
            ))
            continue
        common = Path(str(common_value)).expanduser().resolve()
        set_files = []
        for root in roots:
            if not root.is_dir():
                issues.append(_validation_issue(
                    "source_attestation", "ORACLE_SOURCE_ROOT_MISSING",
                    source_root=str(root),
                ))
                continue
            source_files = sorted(
                file_path for file_path in root.rglob("*")
                if file_path.is_file()
                and file_path.suffix.lower() in _ORACLE_SOURCE_FILE_LANGUAGES
            )
            for file_path in source_files:
                try:
                    logical = file_path.relative_to(common).as_posix()
                except ValueError:
                    issues.append(_validation_issue(
                        "source_attestation", "ORACLE_SOURCE_FILE_OUTSIDE_SNAPSHOT",
                        source_file=str(file_path), source_root=str(common),
                    ))
                    continue
                row = {
                    "owner_type": str(source_set.get("owner_type") or ""),
                    "owner_coord": str(source_set.get("owner_coord") or ""),
                    "module": str(source_set.get("module") or "root"),
                    "logical_path": logical,
                    "sha256": _sha256_file(file_path),
                }
                actual_files.append(row)
                set_files.append(row)
                language = _ORACLE_SOURCE_FILE_LANGUAGES[
                    file_path.suffix.lower()
                ]
                language_file_counts[language] += 1
                if language != "java":
                    expected_coverage_gaps.append({
                        "reason_code": "BINARY_SOURCE_LANGUAGE_NOT_MAPPED",
                        "language": language,
                        "owner_coord": row["owner_coord"],
                        "module": row["module"],
                        "logical_path": logical,
                    })
        actual_sets.append({
            "owner_type": str(source_set.get("owner_type") or ""),
            "owner_coord": str(source_set.get("owner_coord") or ""),
            "module": str(source_set.get("module") or "root"),
            "snapshot_revision": str(
                source_set.get("snapshot_revision") or "content-addressed-only"
            ),
            "file_count": len(set_files),
        })

    attested_core = [{
        key: row.get(key) for key in (
            "owner_type", "owner_coord", "module", "logical_path", "sha256"
        )
    } for row in payload.get("files") or ()]
    if attested_core != actual_files:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_FILE_MANIFEST_MISMATCH",
            expected=actual_files, actual=attested_core,
        ))
    attested_sets = [{
        key: row.get(key) for key in (
            "owner_type", "owner_coord", "module", "snapshot_revision", "file_count"
        )
    } for row in payload.get("source_sets") or ()]
    if attested_sets != actual_sets:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_SET_ATTESTATION_MISMATCH",
            expected=actual_sets, actual=attested_sets,
        ))
    snapshot_identity = _identity(
        "source_snapshot_identity", {"files": list(payload.get("files") or ())}
    )
    if payload.get("source_snapshot_identity") != snapshot_identity:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_SNAPSHOT_IDENTITY_MISMATCH",
            expected=snapshot_identity,
            actual=payload.get("source_snapshot_identity"),
        ))
    if payload.get("file_count") != len(actual_files):
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_FILE_COUNT_MISMATCH",
            expected=len(actual_files), actual=payload.get("file_count"),
        ))
    if payload.get("language_file_counts") != dict(sorted(language_file_counts.items())):
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_LANGUAGE_COUNTS_MISMATCH",
            expected=dict(sorted(language_file_counts.items())),
            actual=payload.get("language_file_counts"),
        ))
    attested_gaps = list(payload.get("coverage_gaps") or ())
    actual_source_keys = {
        (row["owner_coord"], row["module"], row["logical_path"])
        for row in actual_files
    }
    seen_gap_identities = set()
    for gap in attested_gaps:
        identity = (
            str(gap.get("reason_code") or ""),
            str(gap.get("owner_coord") or ""),
            str(gap.get("module") or ""),
            str(gap.get("logical_path") or ""),
        )
        valid_reason = identity[0] in {
            "BINARY_SOURCE_LANGUAGE_NOT_MAPPED",
            "BINARY_SOURCE_PARSE_PARTIAL",
        }
        if (
            identity in seen_gap_identities
            or not valid_reason
            or identity[1:] not in actual_source_keys
        ):
            issues.append(_validation_issue(
                "source_attestation", "ORACLE_SOURCE_COVERAGE_GAP_INVALID",
                gap=gap,
            ))
        seen_gap_identities.add(identity)
    missing_language_gaps = [
        gap for gap in expected_coverage_gaps if gap not in attested_gaps
    ]
    if missing_language_gaps:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_COVERAGE_GAPS_MISMATCH",
            missing=missing_language_gaps,
            actual=attested_gaps,
        ))
    expected_coverage_status = "partial" if attested_gaps else "complete"
    if payload.get("coverage_status") != expected_coverage_status:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_COVERAGE_STATUS_MISMATCH",
            expected=expected_coverage_status,
            actual=payload.get("coverage_status"),
        ))
    return issues, {
        "source_input_status": "provided",
        "source_file_count": len(actual_files),
        "source_snapshot_identity": snapshot_identity,
        "source_coverage_status": expected_coverage_status,
        "source_coverage_gap_count": len(expected_coverage_gaps),
        "source_manifest_exact": not issues,
    }


def _oracle_tool_execution_policy(config: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(config.get("tool_execution_policy") or {})
    allowed = {
        "oracle_compile_timeout_seconds",
        "oracle_runtime_timeout_seconds",
        "oracle_runtime_phase_time_budget_seconds",
        "oracle_max_attempts",
        "oracle_javap_time_budget_seconds",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise BinaryValidationError(
            "BINARY_ORACLE_TOOL_POLICY_INVALID",
            f"unknown fields: {unknown}",
        )
    try:
        compile_timeout = float(raw.get("oracle_compile_timeout_seconds", 300))
        runtime_timeout = float(raw.get("oracle_runtime_timeout_seconds", 300))
        runtime_phase_time_budget = float(
            raw.get("oracle_runtime_phase_time_budget_seconds", 1800)
        )
        javap_time_budget = float(
            raw.get("oracle_javap_time_budget_seconds", 3600)
        )
        max_attempts = int(raw.get("oracle_max_attempts", 2))
    except (TypeError, ValueError) as error:
        raise BinaryValidationError(
            "BINARY_ORACLE_TOOL_POLICY_INVALID", str(error)
        ) from error
    if (
        any(
            isinstance(raw.get(field), bool)
            for field in (
                "oracle_compile_timeout_seconds",
                "oracle_runtime_timeout_seconds",
                "oracle_runtime_phase_time_budget_seconds",
                "oracle_javap_time_budget_seconds",
                "oracle_max_attempts",
            )
        )
        or isinstance(raw.get("oracle_max_attempts"), float)
        or not 0.01 <= compile_timeout <= 300
        or not 0.01 <= runtime_timeout <= 300
        or not 1 <= runtime_phase_time_budget <= 7200
        or not 0.01 <= javap_time_budget <= 7200
        or not 1 <= max_attempts <= 3
    ):
        raise BinaryValidationError(
            "BINARY_ORACLE_TOOL_POLICY_INVALID",
            "compile/runtime timeouts must be within 0.01..300 seconds, "
            "runtime phase budget within 1..7200 seconds, javap budget "
            "within 0.01..7200 seconds, and attempts within 1..3",
        )
    return {
        "compile_timeout_seconds": compile_timeout,
        "runtime_timeout_seconds": runtime_timeout,
        "runtime_phase_time_budget_seconds": runtime_phase_time_budget,
        "javap_time_budget_seconds": javap_time_budget,
        "max_attempts": max_attempts,
    }


def validate_oracle_tool_execution_policy(
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate Oracle limits without starting generation or Oracle work.

    The production pipeline calls this during its static preflight.  Keeping
    the parser here gives the early check and the independent validator one
    exact contract instead of two copies that can drift.
    """
    return _oracle_tool_execution_policy(config)


_DIRECTORY_FSYNC_UNSUPPORTED_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, "EINVAL", None),
        getattr(errno, "ENOSYS", None),
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
)


def _add_validation_cleanup_note(primary: BaseException, note: str) -> None:
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


@contextmanager
def _owned_descriptor(descriptor: int, label: str):
    try:
        yield descriptor
    finally:
        primary = sys.exc_info()[1]
        try:
            os.close(descriptor)
        except BaseException as error:
            if primary is None:
                raise
            _add_validation_cleanup_note(
                primary,
                f"cleanup failed (close {label}): "
                f"{type(error).__name__}: {error}",
            )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | int(getattr(os, "O_DIRECTORY", 0) or 0)
        | int(getattr(os, "O_NOFOLLOW", 0) or 0)
        | int(getattr(os, "O_BINARY", 0) or 0)
    )


@contextmanager
def _open_bound_directory(
    path: str | Path,
    *,
    dir_fd: int | None = None,
):
    if dir_fd is None:
        descriptor = os.open(path, _directory_open_flags())
    else:
        descriptor = os.open(path, _directory_open_flags(), dir_fd=dir_fd)
    with _owned_descriptor(descriptor, f"directory {path}") as opened:
        observed = os.fstat(opened)
        if not stat.S_ISDIR(observed.st_mode):
            raise OSError(errno.ENOTDIR, f"not a directory: {path}")
        yield opened


def _descriptor_identity(value: os.stat_result) -> tuple[int, int]:
    return int(value.st_dev), int(value.st_ino)


def _fsync_bound_directory(descriptor: int) -> bool:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno in _DIRECTORY_FSYNC_UNSUPPORTED_ERRNOS:
            return False
        raise
    return True


def _write_json_descriptor(descriptor: int, value: Any) -> None:
    for payload in iter_json_bytes(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        newline=True,
    ):
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError(
                    errno.EIO,
                    "validation attachment write made no progress",
                )
            remaining = remaining[written:]
    os.fsync(descriptor)


@contextmanager
def _open_bound_regular_file(directory_fd: int, name: str):
    descriptor = os.open(
        name,
        os.O_RDONLY
        | int(getattr(os, "O_NOFOLLOW", 0) or 0)
        | int(getattr(os, "O_BINARY", 0) or 0),
        dir_fd=directory_fd,
    )
    with _owned_descriptor(
        descriptor, f"validation attachment {name}"
    ) as opened_descriptor:
        opened = os.fstat(opened_descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(errno.EINVAL, f"not a regular file: {name}")
        yield opened_descriptor


def _bound_files_equal(directory_fd: int, first: str, second: str) -> bool:
    try:
        with _open_bound_regular_file(directory_fd, first) as left, \
                _open_bound_regular_file(directory_fd, second) as right:
            if os.fstat(left).st_size != os.fstat(right).st_size:
                return False
            while True:
                left_block = os.read(left, 1024 * 1024)
                right_block = os.read(right, 1024 * 1024)
                if left_block != right_block:
                    return False
                if not left_block:
                    return True
    except OSError:
        return False


_SECURE_VALIDATION_DIRFD_SUPPORTED = bool(
    os.name != "nt"
    and int(getattr(os, "O_DIRECTORY", 0) or 0)
    and int(getattr(os, "O_NOFOLLOW", 0) or 0)
    and all(
        operation in os.supports_dir_fd
        for operation in (os.open, os.mkdir, os.stat, os.unlink, os.link)
    )
    and os.stat in os.supports_follow_symlinks
    and os.link in os.supports_follow_symlinks
)


def _secure_validation_dirfd_supported() -> bool:
    return _SECURE_VALIDATION_DIRFD_SUPPORTED


def _validation_attachment_path_error(
    destination: Path,
    error: BaseException | str,
) -> BinaryValidationError:
    return BinaryValidationError(
        "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
        f"{destination}: {error}",
    )


def _write_validation_attachment_dirfd(
    generation: Path,
    destination_name: str,
    result: Mapping[str, Any],
) -> Path:
    requested_generation = Path(os.path.abspath(generation))
    destination = requested_generation / "validation" / destination_name
    try:
        generation_parent = requested_generation.parent.resolve(strict=True)
        generation = generation_parent / requested_generation.name
        destination = generation / "validation" / destination_name
        with _open_bound_directory(generation_parent) as generation_parent_fd:
            parent_identity = _descriptor_identity(
                os.fstat(generation_parent_fd)
            )
            with _open_bound_directory(
                requested_generation.name,
                dir_fd=generation_parent_fd,
            ) as generation_fd:
                generation_identity = _descriptor_identity(
                    os.fstat(generation_fd)
                )
                try:
                    os.mkdir("validation", mode=0o700, dir_fd=generation_fd)
                except FileExistsError:
                    pass
                with _open_bound_directory(
                    "validation", dir_fd=generation_fd
                ) as validation_fd:
                    validation_identity = _descriptor_identity(
                        os.fstat(validation_fd)
                    )
                    # Commit the validation directory entry in the generation
                    # before publishing an attachment within that directory.
                    _fsync_bound_directory(generation_fd)
                    temporary_name = (
                        f".{destination_name}.{os.getpid()}."
                        f"{secrets.token_hex(12)}.tmp"
                    )
                    temporary_fd = os.open(
                        temporary_name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | int(getattr(os, "O_NOFOLLOW", 0) or 0)
                        | int(getattr(os, "O_BINARY", 0) or 0),
                        0o600,
                        dir_fd=validation_fd,
                    )
                    try:
                        with _owned_descriptor(
                            temporary_fd,
                            f"temporary validation attachment {temporary_name}",
                        ) as opened_temporary:
                            _write_json_descriptor(opened_temporary, result)
                        try:
                            # A hard link is the portable POSIX no-replace
                            # publish primitive exposed by Python. EEXIST is
                            # atomic, unlike exists() followed by os.replace().
                            os.link(
                                temporary_name,
                                destination_name,
                                src_dir_fd=validation_fd,
                                dst_dir_fd=validation_fd,
                                follow_symlinks=False,
                            )
                        except FileExistsError:
                            if not _bound_files_equal(
                                validation_fd,
                                destination_name,
                                temporary_name,
                            ):
                                raise BinaryValidationError(
                                    "BINARY_VALIDATION_IDENTITY_COLLISION",
                                    str(destination),
                                ) from None
                    finally:
                        primary = sys.exc_info()[1]
                        try:
                            os.unlink(temporary_name, dir_fd=validation_fd)
                        except FileNotFoundError:
                            pass
                        except BaseException as error:
                            if primary is None:
                                raise
                            _add_validation_cleanup_note(
                                primary,
                                "cleanup failed (unlink temporary validation "
                                f"attachment {temporary_name}): "
                                f"{type(error).__name__}: {error}",
                            )
                    _fsync_bound_directory(validation_fd)

                    current_parent = os.stat(
                        generation_parent, follow_symlinks=False
                    )
                    current_generation = os.stat(
                        requested_generation.name,
                        dir_fd=generation_parent_fd,
                        follow_symlinks=False,
                    )
                    current_validation = os.stat(
                        "validation",
                        dir_fd=generation_fd,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISDIR(current_parent.st_mode)
                        or _descriptor_identity(current_parent)
                        != parent_identity
                        or not stat.S_ISDIR(current_generation.st_mode)
                        or _descriptor_identity(current_generation)
                        != generation_identity
                        or not stat.S_ISDIR(current_validation.st_mode)
                        or _descriptor_identity(current_validation)
                        != validation_identity
                    ):
                        raise _validation_attachment_path_error(
                            destination,
                            "generation or validation directory changed during publication",
                        )
        return destination
    except BinaryValidationError:
        raise
    except (OSError, RuntimeError) as error:
        raise _validation_attachment_path_error(destination, error) from error


def _write_validation_attachment_portable(
    generation: Path,
    destination_name: str,
    result: Mapping[str, Any],
) -> Path:
    """Strict fallback where Python cannot bind filesystem operations by dirfd.

    The pre/post checks reject pre-existing links. They cannot close a hostile
    same-privilege rename race on platforms without no-follow dirfd support;
    activation therefore still re-reads and byte-compares the attachment.
    """

    requested_generation = Path(os.path.abspath(generation))
    destination = requested_generation / "validation" / destination_name
    try:
        if requested_generation.is_symlink():
            raise _validation_attachment_path_error(
                destination, "generation path is a symbolic link"
            )
        # Canonicalize ancestor aliases before publication.  Rejecting every
        # lexical ancestor link would falsely block standard platform aliases
        # such as macOS /var -> /private/var; the generation entry itself was
        # checked above and all subsequent checks bind to this physical path.
        generation = requested_generation.resolve(strict=True)
        validation_dir = generation / "validation"
        destination = validation_dir / destination_name
        validation_dir.mkdir(exist_ok=True)
        if (
            validation_dir.is_symlink()
            or validation_dir.resolve(strict=True) != validation_dir
        ):
            raise _validation_attachment_path_error(
                destination, "validation directory is not bound to generation"
            )
        fsync_directory(generation)
        temporary = validation_dir / (
            f".{destination_name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | int(getattr(os, "O_NOFOLLOW", 0) or 0)
            | int(getattr(os, "O_BINARY", 0) or 0),
            0o600,
        )
        try:
            with _owned_descriptor(
                descriptor, f"temporary validation attachment {temporary}"
            ) as opened_temporary:
                _write_json_descriptor(opened_temporary, result)
            try:
                link_kwargs = (
                    {"follow_symlinks": False}
                    if os.link in os.supports_follow_symlinks
                    else {}
                )
                os.link(temporary, destination, **link_kwargs)
            except FileExistsError:
                if not files_equal(destination, temporary):
                    raise BinaryValidationError(
                        "BINARY_VALIDATION_IDENTITY_COLLISION",
                        str(destination),
                    ) from None
        finally:
            primary = sys.exc_info()[1]
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except BaseException as error:
                if primary is None:
                    raise
                _add_validation_cleanup_note(
                    primary,
                    "cleanup failed (unlink temporary validation attachment "
                    f"{temporary}): {type(error).__name__}: {error}",
                )
        fsync_directory(validation_dir)
        if (
            validation_dir.is_symlink()
            or validation_dir.resolve(strict=True).parent != generation
            or destination.is_symlink()
            or not destination.is_file()
        ):
            raise _validation_attachment_path_error(
                destination, "validation attachment path changed during publication"
            )
        return destination
    except BinaryValidationError:
        raise
    except (OSError, RuntimeError) as error:
        raise _validation_attachment_path_error(destination, error) from error


def _write_validation_attachment(
    generation: Path,
    validation_run_identity: str,
    result: Mapping[str, Any],
) -> Path:
    destination_name = f"{validation_run_identity}.json"
    if _secure_validation_dirfd_supported():
        return _write_validation_attachment_dirfd(
            generation, destination_name, result
        )
    return _write_validation_attachment_portable(
        generation, destination_name, result
    )


def _finalize_validation_result(
    generation: Path,
    manifest: Mapping[str, Any],
    truth_parts: Mapping[str, Any],
    helper_identities: Mapping[str, Any],
    issues: list[dict[str, Any]],
    progress_callback: ValidationProgressCallback | None,
) -> dict[str, Any]:
    """Bind and persist one complete pass/fail validation attachment."""
    result_generation_identity = str(
        manifest.get("result_generation_identity") or ""
    )
    active_snapshot_identities = manifest.get("active_snapshot_identities")
    if not isinstance(active_snapshot_identities, Mapping):
        active_snapshot_identities = {}
    skipped_domains = []
    for domain, truth in truth_parts.items():
        if isinstance(truth, Mapping) and truth.get("status") == "not_run":
            skipped_domains.append({
                "domain": str(domain),
                "reason_code": str(truth.get("reason_code") or ""),
            })
        if domain in {"base", "current"} and isinstance(truth, Mapping):
            for nested_domain, nested_truth in truth.items():
                if (
                    isinstance(nested_truth, Mapping)
                    and nested_truth.get("status") == "not_run"
                ):
                    skipped_domains.append({
                        "domain": f"{domain}.{nested_domain}",
                        "reason_code": str(
                            nested_truth.get("reason_code") or ""
                        ),
                    })
    truth_set_identity = canonical_identity_streaming(
        "binary_oracle_truth_set_identity",
        truth_parts,
        schema_version="1",
    )
    oracle_manifest_identity = oracle_support_manifest_identity()
    implementation_identity = validator_implementation_identity()
    issue_set_identity = canonical_identity_streaming(
        "binary_validation_issue_set_identity",
        issues,
        schema_version="1",
    )
    validation_run_identity = _identity("binary_validation_run_identity", {
        "result_generation_identity": result_generation_identity,
        "active_snapshot_identities": dict(active_snapshot_identities),
        "oracle_support_manifest_identity": oracle_manifest_identity,
        "truth_set_identity": truth_set_identity,
        "issue_set_identity": issue_set_identity,
        "validation_policy_version": POLICY_VERSION,
        "validator_implementation_identity": implementation_identity,
        "helper_identities": dict(helper_identities),
    })
    domain_counts = defaultdict(lambda: {"issues": 0})
    for issue in issues:
        domain_counts[issue["domain"]]["issues"] += 1
    result = {
        "schema": "java-upgrade-analyzer.binary-validation-result.v1",
        "validation_run_identity": validation_run_identity,
        "result_generation_identity": result_generation_identity,
        "oracle_support_manifest_identity": oracle_manifest_identity,
        "truth_set_identity": truth_set_identity,
        "issue_set_identity": issue_set_identity,
        "validation_policy_version": POLICY_VERSION,
        "validator_implementation_identity": implementation_identity,
        "status": "passed" if not issues else "failed",
        "issue_count": len(issues),
        "issues": issues,
        "domain_summary": dict(domain_counts),
        "helper_identities": dict(helper_identities),
        "skipped_domains": sorted(
            skipped_domains,
            key=lambda item: (item["domain"], item["reason_code"]),
        ),
        "production_identity_influence": "none_validation_attachment_only",
    }
    destination = generation / "validation" / f"{validation_run_identity}.json"
    _notify_progress(
        progress_callback,
        "validation-write",
        "开始流式写入独立验证结果",
        0,
        1,
        str(destination),
    )
    destination = _write_validation_attachment(
        generation,
        validation_run_identity,
        result,
    )
    _notify_progress(
        progress_callback,
        "validation-write",
        "独立验证结果已写入",
        1,
        1,
        str(destination),
    )
    return {**result, "validation_result_path": str(destination)}


def validate_generation(
    config: Mapping[str, Any],
    generation_directory: str | Path,
    *,
    progress_callback: ValidationProgressCallback | None = None,
) -> dict[str, Any]:
    # URL resolution is repeated for every observed provider but normally has
    # only one value per artifact. Scope the memo to this validation run so a
    # later run cannot inherit stale filesystem/symlink state.
    _file_url_path.cache_clear()
    progress_callback = progress_callback or _environment_progress_callback()
    try:
        available_memory = system_available_memory_bytes()
    # This is an advisory preflight only.  Platform probes may fail in ways
    # other than OSError (for example a missing ctypes symbol on an unusual
    # Windows runtime); validation itself must remain authoritative.
    except Exception:
        available_memory = None
    if (
        available_memory is not None
        and available_memory < LOW_AVAILABLE_MEMORY_WARNING_BYTES
    ):
        _notify_progress(
            progress_callback,
            "validation-memory-preflight",
            "可用内存低于 4 GiB；将继续使用分批校验，系统可能出现换页",
            available_memory,
            LOW_AVAILABLE_MEMORY_WARNING_BYTES,
            f"available_memory_bytes={available_memory}",
        )
    tool_policy = validate_oracle_tool_execution_policy(config)
    requested_generation = Path(generation_directory).expanduser()
    if requested_generation.is_symlink():
        raise BinaryValidationError(
            "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
            f"generation path is a symbolic link: {requested_generation}",
        )
    generation = requested_generation.resolve()
    base_side = dict(config.get("base") or {})
    current_side = dict(config.get("current") or {})
    _notify_progress(
        progress_callback,
        "validation-preflight",
        "复核 Step0 已验证的 JDK 工具链",
        0,
        2,
    )
    checked_jdks: dict[str, dict[str, Any]] = {}
    observed_jdk_identities: dict[str, str] = {}
    for side_index, (side_name, side) in enumerate(
        (("base", base_side), ("current", current_side)), start=1,
    ):
        jdk_home = Path(str(side.get("jdk_home") or "")).expanduser().resolve()
        try:
            observed = checked_jdks.get(str(jdk_home))
            if observed is None:
                observed = preflight_jdk_home(jdk_home)
                checked_jdks[str(jdk_home)] = observed
        except JdkPreflightError as error:
            raise BinaryValidationError(
                "BINARY_VALIDATION_JDK_PREFLIGHT_FAILED",
                json.dumps(
                    {
                        "side": side_name,
                        "jdk_home": str(jdk_home),
                        "reason_code": error.reason_code,
                        "detail": str(error),
                        "diagnostic": error.diagnostic,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            ) from error
        expected_identity = str(side.get("jdk_preflight_identity") or "")
        if (
            expected_identity
            and expected_identity != observed["jdk_preflight_identity"]
        ):
            raise BinaryValidationError(
                "BINARY_VALIDATION_JDK_CHANGED_SINCE_STEP0",
                json.dumps(
                    {
                        "side": side_name,
                        "jdk_home": str(jdk_home),
                        "expected_jdk_preflight_identity": expected_identity,
                        "actual_jdk_preflight_identity": observed[
                            "jdk_preflight_identity"
                        ],
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
        observed_jdk_identities[side_name] = str(
            observed["jdk_preflight_identity"]
        )
        _notify_progress(
            progress_callback,
            "validation-preflight",
            f"{side_name} JDK 工具链复核通过",
            side_index,
            2,
            str(jdk_home),
        )
    loaded_manifest = _load_json(generation / "result_generation.json")
    integrity_issues = []
    if not isinstance(loaded_manifest, Mapping):
        integrity_issues.append(_validation_issue(
            "generation_integrity",
            "ORACLE_GENERATION_MANIFEST_SCHEMA_INVALID",
            actual_type=type(loaded_manifest).__name__,
        ))
        manifest: Mapping[str, Any] = {}
    else:
        manifest = loaded_manifest
    policy_identities = manifest.get("policy_identities")
    if not isinstance(policy_identities, Mapping):
        policy_identities = {}
    for side_name in ("base", "current"):
        policy_field = f"{side_name}_jdk_preflight_identity"
        expected_identity = str(policy_identities.get(policy_field) or "")
        actual_identity = observed_jdk_identities.get(side_name, "")
        if (
            re.fullmatch(r"[0-9a-f]{64}", expected_identity) is None
            or expected_identity != actual_identity
        ):
            integrity_issues.append(_validation_issue(
                "generation_integrity",
                "ORACLE_GENERATION_JDK_PREFLIGHT_IDENTITY_MISMATCH",
                side=side_name,
                expected_jdk_preflight_identity=expected_identity,
                actual_jdk_preflight_identity=actual_identity,
            ))
    generation_identity = str(manifest.get("result_generation_identity") or "")
    expected_generation_identity = _expected_result_generation_identity(manifest)
    if (
        expected_generation_identity is None
        or expected_generation_identity != generation_identity
    ):
        integrity_issues.append(_validation_issue(
            "generation_integrity",
            "ORACLE_GENERATION_IDENTITY_MISMATCH",
            declared_result_generation_identity=generation_identity,
            expected_result_generation_identity=expected_generation_identity,
        ))
    if generation.name != generation_identity:
        integrity_issues.append(_validation_issue(
            "generation_integrity",
            "ORACLE_GENERATION_DIRECTORY_IDENTITY_MISMATCH",
            generation_directory=str(generation),
            declared_result_generation_identity=generation_identity,
        ))
    sidecar_identities = manifest.get("sidecar_content_identities")
    if not isinstance(sidecar_identities, Mapping):
        integrity_issues.append(_validation_issue(
            "generation_integrity",
            "ORACLE_GENERATION_SIDECAR_MANIFEST_INVALID",
            actual_type=type(sidecar_identities).__name__,
        ))
        sidecar_identities = {}
    integrity_issues.extend(_generation_sidecar_declaration_issues(
        config, generation, sidecar_identities
    ))
    for name, expected in sidecar_identities.items():
        if (
            not _safe_generation_sidecar_name(name)
            or not isinstance(expected, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        ):
            integrity_issues.append(_validation_issue(
                "generation_integrity",
                "ORACLE_GENERATION_SIDECAR_DECLARATION_INVALID",
                sidecar=str(name),
                expected_sha256=expected,
            ))
            continue
        sidecar = generation / str(name)
        actual = "MISSING_OR_SYMLINK"
        if not sidecar.is_symlink() and sidecar.is_file():
            indexed_digest: list[str] = []
            indexed_fields = _LARGE_SIDECAR_FIELDS.get(str(name))
            if indexed_fields is not None:
                try:
                    prime_canonical_json_fields(
                        sidecar,
                        indexed_fields,
                        digest_output=indexed_digest,
                        progress_callback=lambda completed, total: _notify_progress(
                            progress_callback,
                            "validation-generation-integrity",
                            "逐字节校验生成侧车完整性并建立字段索引",
                            completed,
                            total,
                            str(name),
                        ),
                    )
                except StreamingJsonReadError:
                    # Non-canonical or malformed input must use the exact
                    # byte scanner and will still fail semantic validation at
                    # the normal streaming reader boundary.
                    indexed_digest.clear()
            if indexed_digest:
                actual = indexed_digest[0]
            else:
                actual = _sha256_file(
                    sidecar,
                    progress_callback=progress_callback,
                    progress_phase="validation-generation-integrity",
                    progress_message="逐字节校验生成侧车完整性",
                    progress_item=str(name),
                )
        if actual != expected:
            integrity_issues.append(_validation_issue(
                "generation_integrity", "ORACLE_GENERATION_SIDECAR_TAMPERED",
                sidecar=name, expected_sha256=expected, actual_sha256=actual,
            ))
    if integrity_issues:
        not_run = {
            "status": "not_run",
            "reason_code": "GENERATION_INTEGRITY_VALIDATION_FAILED",
        }
        truth_parts = {
            "generation_integrity": [
                issue["evidence"] for issue in integrity_issues
            ],
            "pairings": dict(not_run),
            "source_attestation": dict(not_run),
            "base": dict(not_run),
            "current": dict(not_run),
            "cross_version_semantics": dict(not_run),
            "entrypoint_discovery": dict(not_run),
            "runtime_semantic_overlay": dict(not_run),
            "closed_world_results": dict(not_run),
        }
        return _finalize_validation_result(
            generation,
            manifest,
            truth_parts,
            {},
            integrity_issues,
            progress_callback,
        )
    artifact_digest_cache: dict[Path, str] = {}
    base_artifacts = _artifact_configs(base_side, artifact_digest_cache)
    current_artifacts = _artifact_configs(
        current_side, artifact_digest_cache
    )
    artifact_digest_cache.clear()
    base_jdk = Path(str(base_side.get("jdk_home") or "")).expanduser().resolve()
    current_jdk = Path(str(current_side.get("jdk_home") or "")).expanduser().resolve()
    policy_identities = manifest.get("policy_identities")
    profile_binding_issues = []
    if not isinstance(policy_identities, Mapping):
        policy_identities = {}
    for side_name, side, artifacts, jdk_home in (
        ("base", base_side, base_artifacts, base_jdk),
        ("current", current_side, current_artifacts, current_jdk),
    ):
        platform_identity = str(
            policy_identities.get(f"{side_name}_platform_image") or ""
        )
        if re.fullmatch(r"[0-9a-f]{64}", platform_identity) is None:
            profile_binding_issues.append(_validation_issue(
                "artifact_instance",
                "ORACLE_RUNTIME_PLATFORM_IDENTITY_MISSING",
                side=side_name,
                actual_runtime_platform_identity=platform_identity,
            ))
            continue
        try:
            runtime_profile_identity = _expected_runtime_profile_identity(
                side,
                artifacts,
                platform_identity=platform_identity,
                jdk_home=jdk_home,
            )
            _attach_expected_artifact_instances(
                artifacts, runtime_profile_identity
            )
        except (
            BinaryFirstContractError,
            KeyError,
            OSError,
            StopIteration,
            TypeError,
            ValueError,
        ) as error:
            profile_binding_issues.append(_validation_issue(
                "artifact_instance",
                "ORACLE_ARTIFACT_INSTANCE_EXPECTATION_FAILED",
                side=side_name,
                error_type=type(error).__name__,
                detail=str(error),
            ))
    if profile_binding_issues:
        not_run = {
            "status": "not_run",
            "reason_code": "ARTIFACT_INSTANCE_EXPECTATION_FAILED",
        }
        truth_parts = {
            "generation_integrity": [{"status": "intact"}],
            "pairings": dict(not_run),
            "source_attestation": dict(not_run),
            "base": dict(not_run),
            "current": dict(not_run),
            "cross_version_semantics": dict(not_run),
            "entrypoint_discovery": dict(not_run),
            "runtime_semantic_overlay": dict(not_run),
            "closed_world_results": dict(not_run),
        }
        return _finalize_validation_result(
            generation,
            manifest,
            truth_parts,
            {},
            profile_binding_issues,
            progress_callback,
        )
    inventory_cache: dict[tuple[str, int], dict[str, Any]] = {}

    def inventories_for(
        artifacts: Iterable[Mapping[str, Any]],
        jdk_home: Path,
        *,
        side_name: str,
    ) -> list[dict[str, Any]]:
        artifact_rows = list(artifacts)
        target_major = _release_major(jdk_home)
        _notify_progress(
            progress_callback,
            "validation-inventory",
            f"{side_name}：开始校验制品清单与摘要",
            0,
            len(artifact_rows),
        )
        worker_count, available_memory = _artifact_scan_worker_count(
            len(artifact_rows)
        )
        if worker_count > 1:
            _notify_progress(
                progress_callback,
                "validation-inventory",
                f"{side_name}：制品校验并发度 {worker_count}",
                0,
                len(artifact_rows),
                (
                    "available_memory=unknown"
                    if available_memory is None
                    else f"available_memory={available_memory}"
                ),
            )

        if worker_count <= 1:
            result = []
            for index, item in enumerate(artifact_rows, start=1):
                key = (str(item["sha256"]), target_major)
                path = Path(item["path"])
                actual_sha256 = _sha256_file(path)
                if actual_sha256 != key[0]:
                    raise BinaryValidationError(
                        "BINARY_ORACLE_ARTIFACT_CHANGED_DURING_INVENTORY",
                        f"{path}: expected={key[0]};actual={actual_sha256}",
                    )
                inventory = inventory_cache.get(key)
                if inventory is None:
                    inventory = _archive_inventory(path, target_major)
                    inventory_cache[key] = inventory
                result.append(inventory)
                _notify_counted_progress(
                    progress_callback,
                    "validation-inventory",
                    f"{side_name}：制品清单校验中",
                    index,
                    len(artifact_rows),
                    str(path),
                )
            return result

        # One representative per content/target pair performs ZIP, resource
        # and XML inventory. Every physical path still receives its own full
        # SHA check. The representative hashes and then immediately opens the
        # archive in the same worker, preserving the original mutation window
        # instead of separating verification and inventory into two phases.
        representative_indexes: dict[tuple[str, int], int] = {}
        for request_index, item in enumerate(artifact_rows):
            key = (str(item["sha256"]), target_major)
            if (
                key not in inventory_cache
                and key not in representative_indexes
            ):
                representative_indexes[key] = request_index

        def scan_request(request: tuple[int, Mapping[str, Any]]):
            request_index, item = request
            key = (str(item["sha256"]), target_major)
            path = Path(item["path"])
            actual_sha256 = _sha256_file(path)
            if actual_sha256 != key[0]:
                raise BinaryValidationError(
                    "BINARY_ORACLE_ARTIFACT_CHANGED_DURING_INVENTORY",
                    f"{path}: expected={key[0]};actual={actual_sha256}",
                )
            inventory = (
                _archive_inventory(path, target_major)
                if representative_indexes.get(key) == request_index
                else None
            )
            return key, path, inventory

        # A rolling window prevents I/O concurrency from becoming paging when
        # the validator shares a 32 GiB Windows host with other processes.
        completed_count = 0
        requests = iter(enumerate(artifact_rows))
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="binary-oracle-inventory",
        ) as executor:
            active = {}
            for _ in range(worker_count):
                try:
                    request = next(requests)
                except StopIteration:
                    break
                active[executor.submit(scan_request, request)] = None
            while active:
                completed, _pending = wait(
                    active, return_when=FIRST_COMPLETED
                )
                for future in completed:
                    active.pop(future)
                    key, path, inventory = future.result()
                    if inventory is not None:
                        inventory_cache[key] = inventory
                    completed_count += 1
                    _notify_counted_progress(
                        progress_callback,
                        "validation-inventory",
                        f"{side_name}：制品清单校验中",
                        completed_count,
                        len(artifact_rows),
                        str(path),
                    )
                    try:
                        next_request = next(requests)
                    except StopIteration:
                        continue
                    active[executor.submit(
                        scan_request, next_request
                    )] = None

        result = [
            inventory_cache[(str(item["sha256"]), target_major)]
            for item in artifact_rows
        ]
        if artifact_rows:
            _notify_counted_progress(
                progress_callback,
                "validation-inventory",
                f"{side_name}：制品清单校验完成",
                len(artifact_rows),
                len(artifact_rows),
                side_name,
            )
        return result

    base_inventories = inventories_for(
        base_artifacts, base_jdk, side_name="base",
    )
    current_inventories = inventories_for(
        current_artifacts, current_jdk, side_name="current",
    )
    issues = []
    for side, inventories in (("base", base_inventories), ("current", current_inventories)):
        for inventory in inventories:
            for failure in inventory["failures"]:
                issues.append(_validation_issue("artifact_inventory", "ORACLE_INVENTORY_FAILURE", side=side, failure=failure))
    truth_parts = {
        "generation_integrity": [{"status": "intact"}],
    }
    pairing_issues, pairing_truth = _validate_pairings(
        generation, base_artifacts, current_artifacts
    )
    issues.extend(pairing_issues)
    truth_parts.update(pairing_truth)
    source_issues, source_truth = _validate_source_attestation(generation, config)
    issues.extend(source_issues)
    truth_parts["source_attestation"] = source_truth

    if issues:
        not_run = {
            "status": "not_run",
            "reason_code": "PREREQUISITE_VALIDATION_FAILED",
        }
        truth_parts.update({
            "base": dict(not_run),
            "current": dict(not_run),
            "cross_version_semantics": dict(not_run),
            "entrypoint_discovery": dict(not_run),
            "runtime_semantic_overlay": dict(not_run),
            "closed_world_results": dict(not_run),
        })
        inventory_cache.clear()
        gc.collect()
        return _finalize_validation_result(
            generation,
            manifest,
            truth_parts,
            {},
            issues,
            progress_callback,
        )

    helper_identities = {}
    observations_by_side = {}
    validation_string_pool: dict[str, str] = {}
    # A full 400-JAR javap truth set contains millions of tuples. Keep the
    # reusable observation compressed and disk-spooled; each validator decodes
    # only the artifact it is actively comparing. Focused callers can still
    # pass ordinary dict caches to the helpers for compatibility.
    direct_scan_cache = _OracleScanSpoolCache()
    validated_projection_cache: dict[
        tuple[Any, ...], dict[str, Any]
    ] = {}
    side_validation_cache: dict[
        tuple[str, str, str, str],
        tuple[dict[str, Any], str, dict[str, Any]],
    ] = {}
    side_specs = (
        ("base", base_side, base_artifacts, base_inventories, "base_binary_facts.sqlite", base_jdk),
        ("current", current_side, current_artifacts, current_inventories, "current_binary_facts.sqlite", current_jdk),
    )
    def static_side_key(side, artifacts, jdk_home):
        return (
            str(jdk_home),
            json.dumps(
                artifacts,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            json.dumps(
                side.get("runtime_profile") or {},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    static_side_keys = {
        side_name: static_side_key(side, artifacts, jdk_home)
        for side_name, side, artifacts, _inventories, _db_name, jdk_home
        in side_specs
    }
    database_cache_identities = {
        db_name: str(sidecar_identities.get(db_name) or "")
        for _side_name, _side, _artifacts, _inventories, db_name, _jdk
        in side_specs
    }
    base_spec, current_spec = side_specs
    if static_side_keys["base"] == static_side_keys["current"]:
        base_db_name = base_spec[4]
        current_db_name = current_spec[4]
        databases_equal = (
            database_cache_identities[base_db_name]
            == database_cache_identities[current_db_name]
        )
        if not databases_equal:
            _notify_progress(
                progress_callback,
                "validation-side-cache",
                "两侧运行输入相同，开始一次性比较 SQLite 逻辑内容",
                0,
                1,
            )
            databases_equal = _sqlite_logical_contents_equal(
                generation / base_db_name,
                generation / current_db_name,
                progress_callback=progress_callback,
            )
            _notify_progress(
                progress_callback,
                "validation-side-cache",
                "SQLite 逻辑内容比较完成",
                1,
                1,
            )
        if databases_equal:
            shared_database_identity = canonical_identity_streaming(
                "binary_validation_logically_equal_databases",
                sorted((
                    database_cache_identities[base_db_name],
                    database_cache_identities[current_db_name],
                )),
                schema_version="1",
            )
            database_cache_identities[base_db_name] = shared_database_identity
            database_cache_identities[current_db_name] = shared_database_identity

    side_validation_keys = {
        side_name: (
            database_cache_identities[db_name],
            *static_side_keys[side_name],
        )
        for side_name, _side, _artifacts, _inventories, db_name, _jdk_home
        in side_specs
    }
    foundational_truth_by_side: dict[str, dict[str, Any]] = {}
    foundational_validation_cache: dict[
        tuple[Any, ...], dict[str, Any]
    ] = {}
    foundational_member_ranges_cache: dict[
        tuple[Any, ...], Mapping[str, tuple[int, int, int]] | None
    ] = {}
    member_rowid_ranges_by_side: dict[
        str, Mapping[str, tuple[int, int, int]] | None
    ] = {}

    # Pass 1 proves every immutable/artifact/bytecode fact for both sides.
    # Do not start target-JVM reflection or graph semantics until this cheaper
    # layer is clean: a deterministic direct-edge mismatch must not consume
    # hours in phases that cannot make the generation activatable.
    for side_name, side, artifacts, inventories, db_name, jdk_home in side_specs:
        side_validation_key = side_validation_keys[side_name]
        cached_foundational_truth = foundational_validation_cache.get(
            side_validation_key
        )
        if cached_foundational_truth is not None:
            foundational_truth_by_side[side_name] = (
                cached_foundational_truth
            )
            truth_parts[side_name] = cached_foundational_truth
            member_rowid_ranges_by_side[side_name] = (
                foundational_member_ranges_cache.get(side_validation_key)
            )
            _notify_progress(
                progress_callback,
                "validation-side-cache",
                f"{side_name}：复用已证明完全相同的基础事实",
                1,
                1,
            )
            continue
        side_issue_start = len(issues)
        db_path = generation / db_name
        connection = _open_immutable_sqlite(db_path)
        connection.row_factory = sqlite3.Row
        production_structural_cache = _ProductionStructuralSpoolCache()
        member_range_output: dict[str, Any] = {}
        try:
            javap = str(jdk_tool_path(jdk_home, "javap"))
            edge_issues, edge_truth = _validate_direct_edges(
                connection,
                artifacts,
                javap=javap,
                scan_cache=direct_scan_cache,
                truth_cache=None,
                string_pool=validation_string_pool,
                progress_callback=progress_callback,
                progress_label=side_name,
                time_budget_seconds=tool_policy[
                    "javap_time_budget_seconds"
                ],
                retain_truth_rows=False,
                production_structural_cache=production_structural_cache,
                validated_projection_cache=validated_projection_cache,
                member_rowid_ranges_output=member_range_output,
            )
            member_rowid_ranges_by_side[side_name] = (
                member_range_output.get("ranges")
            )
            structural_issues, structural_truth = _validate_structural_edges(
                connection,
                artifacts,
                inventories,
                javap=javap,
                scan_cache=None,
                direct_scan_cache=direct_scan_cache,
                string_pool=validation_string_pool,
                progress_callback=progress_callback,
                progress_label=side_name,
                retain_truth_rows=False,
                production_structural_cache=production_structural_cache,
                validated_projection_cache=validated_projection_cache,
            )
            issues.extend(edge_issues)
            issues.extend(structural_issues)
            foundational_truth = {**edge_truth, **structural_truth}
            foundational_truth_by_side[side_name] = foundational_truth
            truth_parts[side_name] = foundational_truth
            if len(issues) == side_issue_start:
                foundational_validation_cache[
                    side_validation_key
                ] = foundational_truth
                foundational_member_ranges_cache[
                    side_validation_key
                ] = member_range_output.get("ranges")
        finally:
            production_structural_cache.clear()
            connection.close()

    validated_projection_cache.clear()
    foundational_validation_cache.clear()
    foundational_member_ranges_cache.clear()
    clear_immutable_oracle_cache()

    if issues:
        not_run = {
            "status": "not_run",
            "reason_code": "FOUNDATIONAL_VALIDATION_FAILED",
        }
        for side_name in ("base", "current"):
            truth_parts[side_name] = {
                **foundational_truth_by_side.get(side_name, {}),
                "runtime_outcomes": dict(not_run),
                "resource_selection_validation": dict(not_run),
            }
        truth_parts.update({
            "cross_version_semantics": dict(not_run),
            "entrypoint_discovery": dict(not_run),
            "runtime_semantic_overlay": dict(not_run),
            "closed_world_results": dict(not_run),
        })
        direct_scan_cache.clear()
        inventory_cache.clear()
        validation_string_pool.clear()
        gc.collect()
        return _finalize_validation_result(
            generation,
            manifest,
            truth_parts,
            helper_identities,
            issues,
            progress_callback,
        )

    # Pass 2 performs target-JVM and runtime-outcome validation only after the
    # entire foundational layer is proven clean.
    issue_count_before_runtime = len(issues)
    for side_name, side, artifacts, inventories, db_name, jdk_home in side_specs:
        db_path = generation / db_name
        side_validation_key = side_validation_keys[side_name]
        cached_side = side_validation_cache.get(side_validation_key)
        if cached_side is not None:
            observations, helper_identity, side_truth = cached_side
            helper_identities[side_name] = helper_identity
            observations_by_side[side_name] = observations
            truth_parts[side_name] = side_truth
            continue
        connection = _open_immutable_sqlite(db_path)
        connection.row_factory = sqlite3.Row
        try:
            edge_truth = foundational_truth_by_side[side_name]
            independent_classes = {
                name for inventory in inventories for name in inventory["classes"]
            }
            independent_classes.update(
                name for name in edge_truth["discovery_classes"]
            )
            topology = (
                (side.get("runtime_profile") or {}).get("loader_topology") or {}
            )
            realms = {
                str(item.get("identity"))
                for item in topology.get("realms") or ()
                if item.get("kind") != "platform"
            }
            entrypoint_realms = tuple(
                topology.get("entrypoint_realms") or sorted(realms)
            )
            platform_realms = [
                str(item.get("identity"))
                for item in topology.get("realms") or ()
                if item.get("kind") == "platform"
            ]
            platform_realm = (
                platform_realms[0]
                if len(platform_realms) == 1
                else "platform-loader"
            )
            oracle_artifacts = _oracle_artifacts_for_entrypoint_realms(
                artifacts, topology, entrypoint_realms
            )
            observations, helper_identity = _observe_classes(
                jdk_home,
                oracle_artifacts,
                independent_classes,
                compile_timeout_seconds=tool_policy[
                    "compile_timeout_seconds"
                ],
                runtime_timeout_seconds=tool_policy[
                    "runtime_timeout_seconds"
                ],
                phase_time_budget_seconds=tool_policy[
                    "runtime_phase_time_budget_seconds"
                ],
                max_attempts=tool_policy["max_attempts"],
                progress_callback=progress_callback,
                progress_label=side_name,
                string_pool=validation_string_pool,
            )
            side_javap = str(jdk_tool_path(jdk_home, "javap"))
            _attach_provider_declared_members_from_scan_cache(
                artifacts,
                side_javap,
                direct_scan_cache,
                observations,
                validation_string_pool,
            )
            reference_observations = observations_by_side.get("base")
            proven_equal_observation_set_identity = ""
            if reference_observations is not None:
                shared_rows, _shared_values = _share_equal_observation_values(
                    reference_observations, observations
                )
                if (
                    shared_rows == len(observations)
                    and len(observations) == len(reference_observations)
                ):
                    proven_equal_observation_set_identity = str(
                        (truth_parts.get("base") or {}).get(
                            "runtime_observation_set_identity"
                        )
                        or ""
                    )
            observations = _compact_observations(
                observations,
                validation_string_pool,
                values_compacted=True,
            )
            helper_identities[side_name] = helper_identity
            observations_by_side[side_name] = observations
            runtime_issues, runtime_truth = _validate_runtime_outcomes(
                connection,
                artifacts,
                oracle_artifacts,
                inventories,
                observations,
                entrypoint_realms,
                independent_classes,
                platform_realm,
                jdk_home,
                runtime_security_policy_identity=str(
                    (side.get("runtime_profile") or {}).get(
                        "runtime_security_and_package_sealing_policy_identity"
                    )
                    or ""
                ),
                proven_equal_observation_set_identity=(
                    proven_equal_observation_set_identity
                ),
                progress_callback=progress_callback,
                progress_label=side_name,
            )
            resource_issues, resource_truth = _validate_resource_selections(
                connection,
                artifacts,
                inventories,
                entrypoint_realms,
                topology,
            )
            issues.extend(runtime_issues)
            issues.extend(resource_issues)
            side_truth = {
                **edge_truth, **runtime_truth, **resource_truth,
            }
            truth_parts[side_name] = side_truth
            side_validation_cache[side_validation_key] = (
                observations,
                helper_identity,
                side_truth,
            )
            _notify_progress(
                progress_callback,
                "validation-runtime",
                f"{side_name}：目标 JVM 结果校验完成",
                len(independent_classes),
                len(independent_classes),
            )
        finally:
            connection.close()

    if len(issues) > issue_count_before_runtime:
        not_run = {
            "status": "not_run",
            "reason_code": "RUNTIME_OUTCOME_VALIDATION_FAILED",
        }
        truth_parts.update({
            "cross_version_semantics": dict(not_run),
            "entrypoint_discovery": dict(not_run),
            "runtime_semantic_overlay": dict(not_run),
            "closed_world_results": dict(not_run),
        })
        observations_by_side.clear()
        side_validation_cache.clear()
        direct_scan_cache.clear()
        inventory_cache.clear()
        validation_string_pool.clear()
        gc.collect()
        return _finalize_validation_result(
            generation,
            manifest,
            truth_parts,
            helper_identities,
            issues,
            progress_callback,
        )

    issue_count_before_semantics = len(issues)
    _prime_large_sidecar_fields(generation, progress_callback)
    _notify_progress(
        progress_callback,
        "validation-semantics",
        "开始校验跨版本与运行时语义",
        0,
        3,
    )
    cross_issues, cross_truth = _validate_cross_version_semantics(
        generation, config, truth_parts, observations_by_side
    )
    issues.extend(cross_issues)
    truth_parts["cross_version_semantics"] = cross_truth
    _notify_progress(
        progress_callback,
        "validation-semantics",
        "跨版本语义校验完成",
        1,
        3,
    )
    current_javap = str(jdk_tool_path(current_jdk, "javap"))
    current_instruction_source = _SpoolStructuralInstructionSource(
        direct_scan_cache,
        current_artifacts,
        current_javap,
        validation_string_pool,
    )
    current_declared_members_cache: dict[
        str, tuple[tuple[str, str, str, int], ...]
    ] = {}
    entrypoint_issues, entrypoint_truth = _validate_entrypoint_discovery(
        generation,
        current_side,
        current_artifacts,
        observations_by_side.get("current") or {},
        (truth_parts.get("current") or {}).get("resource_selections") or (),
        _iter_validated_direct_edges(
            generation / "current_binary_facts.sqlite",
            # Entrypoint reconstruction consumes direct-edge truth only to
            # prove SpringApplication.run activation. The foundational pass
            # has already established full edge-set equality, so selecting
            # this exact symbolic target in immutable SQLite is equivalent to
            # filtering the former all-edge Python iterator.
            symbolic_method_target=(
                "org/springframework/boot/SpringApplication", "run",
            ),
            member_rowid_ranges=member_rowid_ranges_by_side.get("current"),
            progress_callback=progress_callback,
            progress_label="current：重放入口发现调用边",
        ),
        current_instruction_source,
        inventories=current_inventories,
        declared_members_cache=current_declared_members_cache,
    )
    issues.extend(entrypoint_issues)
    truth_parts["entrypoint_discovery"] = entrypoint_truth
    _notify_progress(
        progress_callback,
        "validation-semantics",
        "入口发现校验完成",
        2,
        3,
    )
    semantic_issues, semantic_truth = _validate_runtime_semantic_overlay(
        generation,
        current_side,
        current_artifacts,
        observations_by_side.get("base") or {},
        observations_by_side.get("current") or {},
        current_instruction_source,
        _iter_validated_direct_edges(
            generation / "current_binary_facts.sqlite",
            member_rowid_ranges=member_rowid_ranges_by_side.get("current"),
            progress_callback=progress_callback,
            progress_label="current：重放语义覆盖调用边",
        ),
        (truth_parts.get("current") or {}).get("resource_selections") or (),
        current_declared_members_cache=current_declared_members_cache,
    )
    current_declared_members_cache.clear()
    issues.extend(semantic_issues)
    truth_parts["runtime_semantic_overlay"] = semantic_truth
    _notify_progress(
        progress_callback,
        "validation-semantics",
        "运行时语义覆盖校验完成",
        3,
        3,
    )
    if len(issues) > issue_count_before_semantics:
        truth_parts["closed_world_results"] = {
            "status": "not_run",
            "reason_code": "SEMANTIC_VALIDATION_FAILED",
        }
        observations_by_side.clear()
        side_validation_cache.clear()
        direct_scan_cache.clear()
        inventory_cache.clear()
        validation_string_pool.clear()
        clear_immutable_oracle_cache()
        gc.collect()
        return _finalize_validation_result(
            generation,
            manifest,
            truth_parts,
            helper_identities,
            issues,
            progress_callback,
        )
    # The following closed-world pass and final truth hashing do not consume
    # raw class observations or scan caches. Drop those large, independently
    # reconstructed working sets before any graph materialization so validation
    # phases do not overlap at the RSS peak.
    observations_by_side.clear()
    side_validation_cache.clear()
    direct_scan_cache.clear()
    inventory_cache.clear()
    validation_string_pool.clear()
    clear_immutable_oracle_cache()
    observations = None
    independent_classes = None
    javap_members = None
    cached_side = None
    inventories = None
    del base_inventories, current_inventories, side_specs
    gc.collect()
    _notify_progress(
        progress_callback,
        "validation-closed-world",
        "开始校验闭世界追踪结果",
        0,
        1,
    )
    closed_issues, closed_truth = _validate_closed_world_results(
        generation,
        entrypoint_validation_issues=entrypoint_issues,
        entrypoint_truth=entrypoint_truth,
        progress_callback=progress_callback,
    )
    issues.extend(closed_issues)
    truth_parts["closed_world_results"] = closed_truth
    _notify_progress(
        progress_callback,
        "validation-closed-world",
        "闭世界追踪结果校验完成",
        1,
        1,
    )

    stability_issues, final_artifact_hashes = _final_artifact_stability((
        ("base", base_artifacts), ("current", current_artifacts),
    ))
    issues.extend(stability_issues)
    truth_parts["final_artifact_stability"] = final_artifact_hashes

    return _finalize_validation_result(
        generation,
        manifest,
        truth_parts,
        helper_identities,
        issues,
        progress_callback,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate a binary generation independently")
    parser.add_argument("--config", required=True)
    parser.add_argument("--generation-directory", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)
    result = validate_generation(_load_json(args.config), args.generation_directory)
    if args.output:
        write_json_streaming_atomic(Path(args.output), result, indent=2)
    stream_json(result, sys.stdout, indent=2)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
