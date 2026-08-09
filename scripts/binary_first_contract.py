#!/usr/bin/env python3
"""Versioned contracts for the binary-first migration.

This module deliberately contains no graph-building or change-detection logic.
It freezes the identities and truth-table boundaries that shadow components can
use without accidentally changing the legacy authoritative result set.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping


ENGINE_MODES = (
    "legacy",
    "shadow",
    "binary_strict",
    "binary_with_legacy_fallback",
)
IMPLEMENTED_ENGINE_MODES = frozenset(ENGINE_MODES)

PHASE_ORDER = (
    "step4a_artifact_local_diff",
    "step5a_target_independent_reconciliation",
    "step4b_decision_projection_freeze",
    "step5b_trace",
    "step6_report",
)

FORMAL_REACHABILITY_STATUSES = (
    "reachable",
    "uncertain",
    "not_found_in_static_analysis",
    "not_analyzed",
)
FORMAL_IMPACT_CONCLUSIONS = ("probable_impact", "inconclusive")
FORMAL_RUNTIME_VERIFICATION_STATUSES = (
    "required_not_executed",
    "undetermined",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BinaryFirstContractError(ValueError):
    """Raised when a binary-first identity or state contract is violated."""

    def __init__(self, reason_code, message):
        super().__init__(message)
        self.reason_code = str(reason_code or "BINARY_FIRST_CONTRACT_VIOLATION")


def normalize_engine_mode(value, *, default="legacy"):
    mode = str(value or default).strip().lower()
    if mode not in ENGINE_MODES:
        raise BinaryFirstContractError(
            "BINARY_ENGINE_MODE_INVALID",
            f"engine_mode must be one of {', '.join(ENGINE_MODES)}; got {mode or '<empty>'}",
        )
    return mode


def require_implemented_engine_mode(value):
    mode = normalize_engine_mode(value)
    if mode not in IMPLEMENTED_ENGINE_MODES:
        raise BinaryFirstContractError(
            "BINARY_ENGINE_MODE_NOT_IMPLEMENTED",
            f"engine_mode={mode} is not implemented",
        )
    return mode


def _canonical_value(value):
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise BinaryFirstContractError(
                "BINARY_IDENTITY_KEY_INVALID",
                "identity object keys must be strings",
            )
        return {
            key: _canonical_value(item)
            for key, item in sorted(value.items(), key=lambda pair: pair[0])
        }
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, set):
        canonical_items = [_canonical_value(item) for item in value]
        return sorted(
            canonical_items,
            key=lambda item: json.dumps(
                item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise BinaryFirstContractError(
        "BINARY_IDENTITY_VALUE_UNSUPPORTED",
        f"unsupported identity value type: {type(value).__name__}",
    )


def canonical_payload_bytes(payload):
    canonical = _canonical_value(payload)
    return json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_identity(namespace, payload, *, schema_version):
    namespace = str(namespace or "").strip()
    schema_version = str(schema_version or "").strip()
    if not namespace or not schema_version:
        raise BinaryFirstContractError(
            "BINARY_IDENTITY_NAMESPACE_MISSING",
            "identity namespace and schema_version are required",
        )
    envelope = {
        "namespace": namespace,
        "schema_version": schema_version,
        "payload": _canonical_value(payload),
    }
    return hashlib.sha256(canonical_payload_bytes(envelope)).hexdigest()


def artifact_content_identity(content_sha256, byte_length, *, schema_version="1"):
    content_sha256 = str(content_sha256 or "").strip().lower()
    try:
        byte_length = int(byte_length)
    except (TypeError, ValueError) as exc:
        raise BinaryFirstContractError(
            "ARTIFACT_CONTENT_LENGTH_INVALID", "byte_length must be a non-negative integer"
        ) from exc
    if not _SHA256_RE.fullmatch(content_sha256):
        raise BinaryFirstContractError(
            "ARTIFACT_CONTENT_SHA256_INVALID", "content_sha256 must be 64 lowercase hex characters"
        )
    if byte_length < 0:
        raise BinaryFirstContractError(
            "ARTIFACT_CONTENT_LENGTH_INVALID", "byte_length must be a non-negative integer"
        )
    payload = {
        "content_sha256": content_sha256,
        "byte_length": byte_length,
    }
    return canonical_identity(
        "artifact_content_identity", payload, schema_version=schema_version
    )


def analysis_context_identity(
    runtime_comparison_identity,
    analysis_scope_identity,
    *,
    schema_version="1",
):
    runtime_comparison_identity = str(runtime_comparison_identity or "").strip()
    analysis_scope_identity = str(analysis_scope_identity or "").strip()
    if not runtime_comparison_identity or not analysis_scope_identity:
        raise BinaryFirstContractError(
            "ANALYSIS_CONTEXT_INPUT_MISSING",
            "runtime comparison and analysis scope identities are required",
        )
    return canonical_identity(
        "analysis_context_identity",
        {
            "runtime_comparison_identity": runtime_comparison_identity,
            "analysis_scope_identity": analysis_scope_identity,
        },
        schema_version=schema_version,
    )


def observed_delta_identity(
    *,
    delta_source_kind,
    comparison_or_runtime_scope,
    fact_or_mechanism_scope,
    base_fingerprint,
    current_fingerprint,
    schema_version="1",
):
    """Build a scope-independent observed identity.

    AnalysisScopeIdentity is intentionally not accepted here. Different
    analysis scopes share the same observation and receive distinct disposition
    obligations instead.
    """
    payload = {
        "delta_source_kind": str(delta_source_kind or "").strip(),
        "comparison_or_runtime_scope": _canonical_value(
            comparison_or_runtime_scope
        ),
        "fact_or_mechanism_scope": _canonical_value(fact_or_mechanism_scope),
        "base_fingerprint": str(base_fingerprint or "").strip(),
        "current_fingerprint": str(current_fingerprint or "").strip(),
    }
    if not all(
        payload[key]
        for key in (
            "delta_source_kind",
            "comparison_or_runtime_scope",
            "fact_or_mechanism_scope",
            "base_fingerprint",
            "current_fingerprint",
        )
    ):
        raise BinaryFirstContractError(
            "OBSERVED_DELTA_INPUT_MISSING", "all observed-delta identity fields are required"
        )
    return canonical_identity(
        "observed_delta_identity", payload, schema_version=schema_version
    )


def disposition_obligation_identity(
    observed_delta_id,
    analysis_context_id,
    *,
    schema_version="1",
):
    observed_delta_id = str(observed_delta_id or "").strip()
    analysis_context_id = str(analysis_context_id or "").strip()
    if not observed_delta_id or not analysis_context_id:
        raise BinaryFirstContractError(
            "DISPOSITION_OBLIGATION_INPUT_MISSING",
            "observed delta and analysis context identities are required",
        )
    return canonical_identity(
        "disposition_obligation_identity",
        {
            "observed_delta_identity": observed_delta_id,
            "analysis_context_identity": analysis_context_id,
        },
        schema_version=schema_version,
    )


def projection_obligation_key(
    projection_rule_contract_identity,
    analysis_target_identity,
    required_edge_family,
    *,
    schema_version="1",
):
    payload = {
        "projection_rule_contract_identity": str(
            projection_rule_contract_identity or ""
        ).strip(),
        "analysis_target_identity": str(analysis_target_identity or "").strip(),
        "required_edge_family": str(required_edge_family or "").strip(),
    }
    if not all(payload.values()):
        raise BinaryFirstContractError(
            "PROJECTION_OBLIGATION_INPUT_MISSING",
            "projection rule, target, and required edge family are required",
        )
    return canonical_identity(
        "projection_obligation_key", payload, schema_version=schema_version
    )


def derive_formal_result_state(
    reachability_status,
    *,
    best_path_certainty=None,
    possible_path_exists=None,
):
    reachability_status = str(reachability_status or "").strip()
    if reachability_status not in FORMAL_REACHABILITY_STATUSES:
        raise BinaryFirstContractError(
            "FORMAL_REACHABILITY_STATUS_INVALID",
            f"unsupported formal reachability status: {reachability_status or '<empty>'}",
        )
    expected_certainty = {
        "reachable": "exact_or_proven",
        "uncertain": "possible",
        "not_found_in_static_analysis": "none",
        "not_analyzed": "none",
    }[reachability_status]
    certainty = str(best_path_certainty or expected_certainty).strip()
    if certainty != expected_certainty:
        raise BinaryFirstContractError(
            "FORMAL_BEST_PATH_CERTAINTY_INVALID",
            f"{reachability_status} requires best_path_certainty={expected_certainty}",
        )
    reachable = reachability_status == "reachable"
    if reachability_status == "reachable":
        possible_exists = bool(possible_path_exists)
    elif reachability_status == "uncertain":
        if possible_path_exists is False:
            raise BinaryFirstContractError(
                "FORMAL_POSSIBLE_PATH_STATE_INVALID",
                "uncertain requires at least one complete possible path",
            )
        possible_exists = True
    else:
        if possible_path_exists:
            raise BinaryFirstContractError(
                "FORMAL_POSSIBLE_PATH_STATE_INVALID",
                f"{reachability_status} cannot claim a complete possible path",
            )
        possible_exists = False
    return {
        "change_fact_status": "confirmed",
        "reachability_status": reachability_status,
        "analysis_status": reachability_status,
        "is_reachable": reachable,
        "impact_conclusion": "probable_impact" if reachable else "inconclusive",
        "decision_bucket": "probable_impact" if reachable else "inconclusive",
        "runtime_verification_status": (
            "required_not_executed" if reachable else "undetermined"
        ),
        "runtime_verification_executed_by_system": False,
        "runtime_verification_evidence": [],
        "best_path_certainty": certainty,
        "existence_proven": reachable,
        "exact_path_exists": reachable,
        # A reachable target can also have additional possible paths. Those
        # paths lower path-set completeness, never the already-proven
        # reachability result.
        "possible_path_exists": possible_exists,
    }


def validate_formal_result_state(payload):
    payload = dict(payload or {})
    if payload.get("change_fact_status") != "confirmed":
        raise BinaryFirstContractError(
            "FORMAL_CHANGE_FACT_NOT_CONFIRMED",
            "formal results require change_fact_status=confirmed",
        )
    derived = derive_formal_result_state(
        payload.get("reachability_status"),
        best_path_certainty=payload.get("best_path_certainty"),
        possible_path_exists=payload.get("possible_path_exists"),
    )
    forbidden = {
        "confirmed_impact",
        "confirmed_no_impact",
        "not_required",
        "passed",
        "failed",
    }
    observed_values = {
        str(payload.get("impact_conclusion") or "").strip(),
        str(payload.get("decision_bucket") or "").strip(),
        str(payload.get("runtime_verification_status") or "").strip(),
    }
    if forbidden & observed_values:
        raise BinaryFirstContractError(
            "FORMAL_STATIC_V2_FORBIDDEN_STATE",
            "static v2 cannot emit confirmed impact/no-impact, not_required, passed, or failed",
        )
    for key in (
        "analysis_status",
        "is_reachable",
        "impact_conclusion",
        "decision_bucket",
        "runtime_verification_status",
        "runtime_verification_executed_by_system",
        "runtime_verification_evidence",
        "existence_proven",
        "exact_path_exists",
        "possible_path_exists",
    ):
        if payload.get(key) != derived[key]:
            raise BinaryFirstContractError(
                "FORMAL_STATE_TRUTH_TABLE_VIOLATION",
                f"{key}={payload.get(key)!r} conflicts with {payload.get('reachability_status')}",
            )
    return derived


def derive_path_set_complete(
    *,
    exact_path_set_complete,
    possible_path_layer_applicable,
    possible_path_set_complete,
):
    return bool(exact_path_set_complete) and (
        not bool(possible_path_layer_applicable)
        or bool(possible_path_set_complete)
    )


def validate_projection_assessment(payload):
    payload = dict(payload or {})
    status = str(payload.get("analysis_projection_status") or "").strip()
    coverage = str(payload.get("projection_coverage_status") or "").strip()
    target_count = int(payload.get("target_count") or 0)
    obligation_count = int(payload.get("projection_obligation_count") or 0)
    projection_count = int(payload.get("projection_count") or 0)
    partial_scopes = list(payload.get("partial_scopes") or [])
    if status == "unsupported":
        if coverage != "unsupported" or any(
            (target_count, obligation_count, projection_count, len(partial_scopes))
        ):
            raise BinaryFirstContractError(
                "UNSUPPORTED_PROJECTION_ASSESSMENT_INVALID",
                "unsupported assessments require zero targets/obligations/projections/partial scopes",
            )
    elif status == "targetable":
        if coverage not in {"complete", "partial"}:
            raise BinaryFirstContractError(
                "TARGETABLE_PROJECTION_COVERAGE_INVALID",
                "targetable assessment coverage must be complete or partial",
            )
        if target_count <= 0 or obligation_count <= 0:
            raise BinaryFirstContractError(
                "TARGETABLE_PROJECTION_OBLIGATION_MISSING",
                "targetable assessments require at least one target and obligation",
            )
        if obligation_count != projection_count:
            raise BinaryFirstContractError(
                "PROJECTION_OBLIGATION_COUNT_MISMATCH",
                "every projection obligation requires exactly one projection",
            )
        if coverage == "complete" and partial_scopes:
            raise BinaryFirstContractError(
                "COMPLETE_PROJECTION_HAS_PARTIAL_SCOPE",
                "complete targetable assessments cannot reference partial scopes",
            )
        if coverage == "partial" and not partial_scopes:
            raise BinaryFirstContractError(
                "PARTIAL_PROJECTION_SCOPE_MISSING",
                "partial targetable assessments require at least one partial scope",
            )
    else:
        raise BinaryFirstContractError(
            "PROJECTION_ASSESSMENT_STATUS_INVALID",
            "analysis_projection_status must be targetable or unsupported",
        )
    return True


def validate_phase_manifest(records):
    records = [dict(item or {}) for item in (records or [])]
    seen = set()
    completed_prefix = 0
    for item in records:
        phase = str(item.get("phase") or "").strip()
        if phase not in PHASE_ORDER or phase in seen:
            raise BinaryFirstContractError(
                "BINARY_PHASE_MANIFEST_INVALID", f"invalid or duplicate phase: {phase or '<empty>'}"
            )
        expected = PHASE_ORDER[len(seen)]
        if phase != expected:
            raise BinaryFirstContractError(
                "BINARY_PHASE_ORDER_INVALID", f"expected {expected} before {phase}"
            )
        seen.add(phase)
        status = str(item.get("status") or "").strip()
        if status not in {"completed", "failed", "blocked", "pending"}:
            raise BinaryFirstContractError(
                "BINARY_PHASE_STATUS_INVALID", f"invalid phase status: {status or '<empty>'}"
            )
        if status == "completed":
            if not str(item.get("input_digest") or "").strip() or not str(
                item.get("output_digest") or ""
            ).strip():
                raise BinaryFirstContractError(
                    "BINARY_PHASE_DIGEST_MISSING", "completed phases require input and output digests"
                )
            completed_prefix += 1
        elif len(seen) != len(records):
            raise BinaryFirstContractError(
                "BINARY_PHASE_AFTER_TERMINAL_STATE",
                "no later phase may follow a non-completed phase",
            )
    return {"completed_phase_count": completed_prefix, "next_phase": (
        PHASE_ORDER[completed_prefix] if completed_prefix < len(PHASE_ORDER) else ""
    )}


__all__ = [
    "BinaryFirstContractError",
    "ENGINE_MODES",
    "FORMAL_IMPACT_CONCLUSIONS",
    "FORMAL_REACHABILITY_STATUSES",
    "FORMAL_RUNTIME_VERIFICATION_STATUSES",
    "IMPLEMENTED_ENGINE_MODES",
    "PHASE_ORDER",
    "analysis_context_identity",
    "artifact_content_identity",
    "canonical_identity",
    "canonical_payload_bytes",
    "derive_formal_result_state",
    "derive_path_set_complete",
    "disposition_obligation_identity",
    "normalize_engine_mode",
    "observed_delta_identity",
    "projection_obligation_key",
    "require_implemented_engine_mode",
    "validate_formal_result_state",
    "validate_phase_manifest",
    "validate_projection_assessment",
]
