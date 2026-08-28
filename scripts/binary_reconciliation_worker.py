#!/usr/bin/env python3
"""Isolated one-side runtime reconciliation worker.

The parent owns scheduling and only uses this worker when two independent
runtime sides can safely consume separate SQLite files in parallel.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from binary_fact_store import BinaryFactStore
from binary_first_model import RuntimeProfile
from binary_asm_helper import (
    BinaryAsmError,
    CompiledAsmHelperBinding,
    capture_parser_identity_binding,
    compiled_asm_helper_binding_from_mapping,
    install_compiled_asm_helper_binding,
    verify_compiled_asm_helper_binding,
    verify_parser_identity_binding,
)
from binary_definition_verifier import (
    ClassDefinitionVerifierError,
    CompiledDefinitionHelperBinding,
    compiled_definition_helper_binding_from_mapping,
    install_compiled_definition_helper_binding,
    verify_compiled_definition_helper_binding,
)
from binary_platform_image import JdkPlatformImage
from binary_runtime_reconciler import RuntimeCapabilityPolicy, RuntimeReconciler
from streaming_json import write_json_streaming_atomic


SCHEMA = "java-upgrade-analyzer.binary-reconciliation-worker.v2"
_CAPABILITY_FIELDS = (
    "supported_loader_policy_versions",
    "supported_delegation_modes",
    "supported_security_policy_identities",
    "supported_module_modes",
    "supported_transformer_profile_identities",
    "signed_artifacts_supported",
    "sealed_packages_supported",
    "closed_world_dispatch",
    "policy_version",
)
_RESULT_COLLECTION_FIELDS = (
    "provider_bindings",
    "class_definitions",
    "member_resolutions",
    "dispatch_resolutions",
    "type_resolutions",
    "class_initialization_resolutions",
    "linkage_resolutions",
    "resource_selections",
)


def _required_identity(value: Any, field: str) -> str:
    normalized = str(value or "")
    if (
        len(normalized) != 64
        or any(character not in "0123456789abcdef" for character in normalized)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 identity")
    return normalized


def _required_absolute_path(value: Any, field: str) -> Path:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a path string")
    path = Path(value)
    if not path.is_absolute() or str(path.resolve()) != value:
        raise ValueError(f"{field} must be canonical and absolute")
    return path


def _spec(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "store_path",
        "runtime_profile",
        "runtime_profile_identity",
        "jdk_home",
        "platform_identity",
        "asm_jar",
        "analysis_context_identity",
        "capability_policy",
        "capability_policy_identity",
        "additional_initial_classes",
        "retain_record_kinds",
        "compiled_asm_helper_binding",
        "compiled_definition_helper_binding",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("worker input fields do not match the exact schema")
    result = dict(value)
    if result.get("schema") != SCHEMA:
        raise ValueError("worker input schema is invalid")
    result["store_path"] = _required_absolute_path(
        result["store_path"], "store_path"
    )
    result["jdk_home"] = _required_absolute_path(result["jdk_home"], "jdk_home")
    result["asm_jar"] = _required_absolute_path(result["asm_jar"], "asm_jar")
    if not isinstance(result.get("runtime_profile"), Mapping):
        raise ValueError("runtime_profile must be an object")
    result["runtime_profile"] = dict(result["runtime_profile"])
    for field in (
        "runtime_profile_identity",
        "platform_identity",
        "analysis_context_identity",
        "capability_policy_identity",
    ):
        result[field] = _required_identity(result[field], field)
    capability = result.get("capability_policy")
    if not isinstance(capability, Mapping) or set(capability) != set(
        _CAPABILITY_FIELDS
    ):
        raise ValueError("capability_policy fields are invalid")
    capability = dict(capability)
    for field in _CAPABILITY_FIELDS[:5]:
        raw = capability[field]
        if (
            not isinstance(raw, list)
            or any(type(item) is not str or not item for item in raw)
        ):
            raise ValueError(f"capability_policy.{field} must be a string list")
        capability[field] = tuple(raw)
    for field in _CAPABILITY_FIELDS[5:8]:
        if type(capability[field]) is not bool:
            raise ValueError(f"capability_policy.{field} must be boolean")
    if type(capability["policy_version"]) is not str or not capability[
        "policy_version"
    ]:
        raise ValueError("capability_policy.policy_version must be text")
    result["capability_policy"] = capability
    raw_asm_binding = result.get("compiled_asm_helper_binding")
    if raw_asm_binding is not None and not isinstance(raw_asm_binding, Mapping):
        raise ValueError("compiled_asm_helper_binding must be an object or null")
    result["compiled_asm_helper_binding"] = (
        compiled_asm_helper_binding_from_mapping(raw_asm_binding)
        if raw_asm_binding is not None else None
    )
    raw_definition_binding = result.get("compiled_definition_helper_binding")
    if (
        raw_definition_binding is not None
        and not isinstance(raw_definition_binding, Mapping)
    ):
        raise ValueError(
            "compiled_definition_helper_binding must be an object or null"
        )
    result["compiled_definition_helper_binding"] = (
        compiled_definition_helper_binding_from_mapping(
            raw_definition_binding
        )
        if raw_definition_binding is not None else None
    )
    classes = result.get("additional_initial_classes")
    if (
        not isinstance(classes, list)
        or any(type(item) is not str or not item for item in classes)
        or classes != sorted(set(classes))
    ):
        raise ValueError("additional_initial_classes must be sorted and unique")
    kinds = result.get("retain_record_kinds")
    if (
        not isinstance(kinds, list)
        or any(type(item) is not str or not item for item in kinds)
        or kinds != sorted(set(kinds))
    ):
        raise ValueError("retain_record_kinds must be sorted and unique")
    return result


def _result_mapping(result) -> dict[str, Any]:
    return {
        "analysis_context_identity": result.analysis_context_identity,
        "runtime_profile_identity": result.runtime_profile_identity,
        "universe_identity": result.universe_identity,
        **{
            field: list(getattr(result, field))
            for field in _RESULT_COLLECTION_FIELDS
        },
        "coverage_status": result.coverage_status,
        "coverage_gaps": list(result.coverage_gaps),
        "identity": result.identity,
    }


def run(spec: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _spec(spec)
    profile = RuntimeProfile(normalized["runtime_profile"])
    if profile.identity != normalized["runtime_profile_identity"]:
        raise ValueError("runtime profile identity changed in worker")
    capability = RuntimeCapabilityPolicy(**normalized["capability_policy"])
    if capability.identity != normalized["capability_policy_identity"]:
        raise ValueError("runtime capability identity changed in worker")
    parser_binding = capture_parser_identity_binding(
        asm_jar=normalized["asm_jar"]
    )
    installed_asm_binding: CompiledAsmHelperBinding | None = None
    candidate_asm_binding = normalized["compiled_asm_helper_binding"]
    if candidate_asm_binding is not None:
        try:
            install_compiled_asm_helper_binding(candidate_asm_binding)
            installed_asm_binding = candidate_asm_binding
        except (BinaryAsmError, OSError, ValueError):
            # Optional transport reuse failed its byte proof. The worker still
            # compiles the same pinned source locally; no class is omitted.
            pass
    platform = JdkPlatformImage(
        normalized["jdk_home"],
        asm_jar=normalized["asm_jar"],
        parser_identity_binding=parser_binding,
    )
    if platform.identity != normalized["platform_identity"]:
        raise ValueError("runtime platform identity changed in worker")
    installed_definition_binding: CompiledDefinitionHelperBinding | None = None
    candidate_definition_binding = normalized[
        "compiled_definition_helper_binding"
    ]
    if candidate_definition_binding is not None:
        try:
            install_compiled_definition_helper_binding(
                candidate_definition_binding
            )
            installed_definition_binding = candidate_definition_binding
        except (ClassDefinitionVerifierError, OSError, ValueError):
            pass
    store = BinaryFactStore(normalized["store_path"])
    try:
        if store.connection.execute(
            "SELECT 1 FROM reconciliation_records LIMIT 1"
        ).fetchone() is not None:
            raise ValueError("worker fact store already contains reconciliation")
        result = RuntimeReconciler(
            store,
            profile,
            platform,
            analysis_context_identity=normalized[
                "analysis_context_identity"
            ],
            capability_policy=capability,
            additional_initial_classes=normalized[
                "additional_initial_classes"
            ],
        ).reconcile(
            retain_record_kinds=normalized["retain_record_kinds"]
        )
        if installed_asm_binding is not None:
            verify_compiled_asm_helper_binding(installed_asm_binding)
        if installed_definition_binding is not None:
            verify_compiled_definition_helper_binding(
                installed_definition_binding
            )
        verify_parser_identity_binding(parser_binding)
        return {
            "schema": SCHEMA,
            "status": "passed",
            "result": _result_mapping(result),
        }
    finally:
        store.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
        response = run(raw)
        returncode = 0
    except BaseException as error:
        response = {
            "schema": SCHEMA,
            "status": "failed",
            "failure": {
                "error_type": type(error).__name__,
                "detail": str(error)[:16000],
            },
        }
        returncode = 1
    write_json_streaming_atomic(
        Path(args.output), response, indent=None,
    )
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
