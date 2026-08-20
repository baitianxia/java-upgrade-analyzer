#!/usr/bin/env python3
"""Diagnostic identities emitted by independent binary validation.

These identities describe the validator loaded by the process.  They are not
runtime authority gates: correctness is decided by the Oracle's fact/result
comparison, not by repeatedly hashing implementation files.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Mapping
import zlib

from binary_first_contract import BinaryFirstContractError, canonical_identity


VALIDATION_POLICY_VERSION = "binary-independent-validation-v3"
SUPPORT_MANIFEST_PATH = Path(__file__).with_name(
    "binary_first_support_manifest.json"
)

# These files can change validation truth, accepted inputs, process execution,
# canonical identities or persisted validation bytes.  Progress-only code is
# deliberately absent because callbacks are isolated from validation truth.
VALIDATOR_IMPLEMENTATION_SOURCE_PATHS = (
    "artifact_safety.py",
    "binary_first_contract.py",
    "binary_tool_execution.py",
    "binary_validation_contract.py",
    "binary_validation_oracle.py",
    "compat.py",
    "edge_truth.py",
    "final_artifact_edge_oracle.py",
    "jdk_preflight.py",
    "javap_contract.py",
    "java/RuntimeOutcomeOracle.java",
    "path_runtime.py",
    "streaming_json.py",
)


class BinaryValidationContractError(BinaryFirstContractError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validator_source_digests() -> dict[str, str]:
    scripts_dir = Path(__file__).resolve().parent
    return {
        relative: _sha256_file(scripts_dir / relative)
        for relative in VALIDATOR_IMPLEMENTATION_SOURCE_PATHS
    }


def _python_runtime_identity() -> dict[str, Any]:
    return {
        "implementation": str(sys.implementation.name),
        "cache_tag": str(sys.implementation.cache_tag or ""),
        "version": [
            int(sys.version_info.major),
            int(sys.version_info.minor),
            int(sys.version_info.micro),
        ],
        "platform": str(sys.platform),
        "sqlite_version": str(sqlite3.sqlite_version),
        "zlib_runtime_version": str(zlib.ZLIB_RUNTIME_VERSION),
    }


def _validator_implementation_payload(
    source_digests: Mapping[str, str],
    runtime_identity: Mapping[str, Any],
) -> dict[str, Any]:
    if set(source_digests) != set(VALIDATOR_IMPLEMENTATION_SOURCE_PATHS):
        raise BinaryValidationContractError(
            "BINARY_VALIDATION_IMPLEMENTATION_SOURCE_SET_INVALID",
            "validator implementation source set is incomplete",
        )
    return {
        "policy_version": VALIDATION_POLICY_VERSION,
        "implementation_sources": [
            {
                "path": relative,
                "sha256": str(source_digests[relative]),
            }
            for relative in VALIDATOR_IMPLEMENTATION_SOURCE_PATHS
        ],
        "python_runtime": dict(runtime_identity),
    }


def _validator_implementation_identity_from_inputs(
    source_digests: Mapping[str, str],
    runtime_identity: Mapping[str, Any],
) -> str:
    return canonical_identity(
        "binary_validation_implementation_identity",
        _validator_implementation_payload(source_digests, runtime_identity),
        schema_version="1",
    )


def _validator_source_identity_from_inputs(
    source_digests: Mapping[str, str],
) -> str:
    if set(source_digests) != set(VALIDATOR_IMPLEMENTATION_SOURCE_PATHS):
        raise BinaryValidationContractError(
            "BINARY_VALIDATION_IMPLEMENTATION_SOURCE_SET_INVALID",
            "validator implementation source set is incomplete",
        )
    return canonical_identity(
        "binary_performance_validator_source_identity",
        {
            "policy_version": VALIDATION_POLICY_VERSION,
            "inputs": [
                {"path": relative, "sha256": str(source_digests[relative])}
                for relative in VALIDATOR_IMPLEMENTATION_SOURCE_PATHS
            ],
        },
        schema_version="1",
    )


def _load_oracle_support_manifest() -> dict[str, Any]:
    try:
        support = json.loads(SUPPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
        oracle_support = support["oracle_support_manifest"]
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
    ) as error:
        raise BinaryValidationContractError(
            "BINARY_ORACLE_SUPPORT_MANIFEST_INVALID", str(error)
        ) from error
    if not isinstance(oracle_support, dict):
        raise BinaryValidationContractError(
            "BINARY_ORACLE_SUPPORT_MANIFEST_INVALID",
            "oracle_support_manifest must be an object",
        )
    return oracle_support


def _oracle_support_identity(value: Mapping[str, Any]) -> str:
    return canonical_identity(
        "oracle_support_manifest_identity",
        dict(value),
        schema_version="1",
    )


# Capture the source/runtime actually loaded by this process.  Re-reading at
# every authority boundary detects edits during a multi-hour Step4 run instead
# of relabelling already-executed code with the new on-disk digest.
_CAPTURED_VALIDATOR_SOURCE_DIGESTS = _validator_source_digests()
_CAPTURED_PYTHON_RUNTIME_IDENTITY = _python_runtime_identity()
_CAPTURED_VALIDATOR_IMPLEMENTATION_IDENTITY = (
    _validator_implementation_identity_from_inputs(
        _CAPTURED_VALIDATOR_SOURCE_DIGESTS,
        _CAPTURED_PYTHON_RUNTIME_IDENTITY,
    )
)
_CAPTURED_VALIDATOR_SOURCE_IDENTITY = _validator_source_identity_from_inputs(
    _CAPTURED_VALIDATOR_SOURCE_DIGESTS
)
_CAPTURED_ORACLE_SUPPORT_MANIFEST = _load_oracle_support_manifest()
_CAPTURED_ORACLE_SUPPORT_MANIFEST_IDENTITY = _oracle_support_identity(
    _CAPTURED_ORACLE_SUPPORT_MANIFEST
)


def validator_implementation_identity() -> str:
    return _CAPTURED_VALIDATOR_IMPLEMENTATION_IDENTITY


def validator_source_identity() -> str:
    return _CAPTURED_VALIDATOR_SOURCE_IDENTITY


def oracle_support_manifest_identity() -> str:
    return _CAPTURED_ORACLE_SUPPORT_MANIFEST_IDENTITY


__all__ = [
    "BinaryValidationContractError",
    "VALIDATION_POLICY_VERSION",
    "VALIDATOR_IMPLEMENTATION_SOURCE_PATHS",
    "oracle_support_manifest_identity",
    "validator_implementation_identity",
    "validator_source_identity",
]
