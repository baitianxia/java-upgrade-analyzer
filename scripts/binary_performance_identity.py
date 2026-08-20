#!/usr/bin/env python3
"""Pure identities shared by release performance evidence and production.

This module deliberately knows nothing about the binary pipeline or the
independent validator.  Callers collect their own trusted source/runtime
records, while this file owns the canonical composition algorithm so the
benchmark and the production authority gate cannot silently diverge.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from binary_first_contract import canonical_identity


IMPLEMENTATION_PROTOCOL_VERSION = "binary-performance-implementation-v2"
GENERATION_SUPPORT_MANIFEST_LOGICAL_PATH = (
    "binary_first_support_manifest.json"
)
HARNESS_SOURCE_PATHS = (
    "binary_performance_gate.py",
    "binary_performance_identity.py",
    "binary_performance_release_policy.py",
    # These modules do not produce generation or Oracle truth bytes, but they
    # execute inside the measured full-pipeline path.  Omitting them would let
    # activation-lock or progress-I/O regressions reuse unrelated evidence.
    "process_lock.py",
    "process_metrics.py",
    "progress_logging.py",
)


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def is_sha256_identity(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def generation_source_identity(
    source_records: Iterable[Mapping[str, Any]],
) -> str:
    if isinstance(source_records, (str, bytes)):
        raise ValueError("generation source records must be an iterable of objects")
    records = []
    all_paths = []
    for record in source_records:
        if not isinstance(record, Mapping) or set(record) != {"path", "sha256"}:
            raise ValueError("generation source record fields are invalid")
        path = record.get("path")
        sha256 = record.get("sha256")
        if type(path) is not str or not path or not is_sha256_identity(sha256):
            raise ValueError("generation source records are incomplete or invalid")
        all_paths.append(path)
        if not path.startswith("@runtime/"):
            records.append({"path": path, "sha256": sha256})
    if not records or len(set(all_paths)) != len(all_paths):
        raise ValueError("generation source records are incomplete or invalid")
    return _identity(
        "binary_performance_generation_source_identity",
        {
            "scope_policy": "generation-producing-explicit-closure-v3",
            "inputs": records,
        },
    )


def harness_source_identity(scripts_dir: Path) -> str:
    return _identity(
        "binary_performance_harness_source_identity",
        [
            {
                "path": relative,
                "sha256": _sha256_file(scripts_dir / relative),
            }
            for relative in HARNESS_SOURCE_PATHS
        ],
    )


def source_implementation_identity(components: Mapping[str, Any]) -> str:
    required_fields = (
        "generation_source_identity",
        "validator_source_identity",
        "oracle_support_manifest_identity",
        "harness_source_identity",
    )
    if not isinstance(components, Mapping) or any(
        not is_sha256_identity(components.get(field))
        for field in required_fields
    ):
        raise ValueError("source implementation identity components are invalid")
    return _identity(
        "binary_performance_source_implementation_identity",
        {
            "policy_version": IMPLEMENTATION_PROTOCOL_VERSION,
            **{field: components[field] for field in required_fields},
        },
    )


def runtime_implementation_identity(components: Mapping[str, Any]) -> str:
    required_fields = (
        "source_implementation_identity",
        "pipeline_generation_implementation_identity",
        "validator_implementation_identity",
        "jdk_preflight_identity",
    )
    if not isinstance(components, Mapping) or any(
        not is_sha256_identity(components.get(field))
        for field in required_fields
    ):
        raise ValueError("runtime implementation identity components are invalid")
    return _identity(
        "binary_performance_runtime_implementation_identity",
        {
            "policy_version": IMPLEMENTATION_PROTOCOL_VERSION,
            **{field: components[field] for field in required_fields},
        },
    )


__all__ = [
    "GENERATION_SUPPORT_MANIFEST_LOGICAL_PATH",
    "HARNESS_SOURCE_PATHS",
    "IMPLEMENTATION_PROTOCOL_VERSION",
    "generation_source_identity",
    "harness_source_identity",
    "is_sha256_identity",
    "runtime_implementation_identity",
    "source_implementation_identity",
]
