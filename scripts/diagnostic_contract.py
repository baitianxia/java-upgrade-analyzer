#!/usr/bin/env python3
"""Shared public contract for cross-step diagnostic identifiers."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping


DIAGNOSTIC_CONTRACT_SCHEMA = "java-upgrade-analyzer.diagnostic.v1"
REASON_CODE_PATTERN = r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$"

DEPENDENCY_COORDINATES_UNRESOLVED = "DEPENDENCY_COORDINATES_UNRESOLVED"
DEPENDENCY_SOURCE_REF_UNAVAILABLE = "DEPENDENCY_SOURCE_REF_UNAVAILABLE"
JAPICMP_EXECUTION_FAILED = "JAPICMP_EXECUTION_FAILED"
JAPICMP_TIMEOUT = "JAPICMP_TIMEOUT"
SPRING_RUNTIME_CLASS_AMBIGUOUS = "SPRING_RUNTIME_CLASS_AMBIGUOUS"
MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED = "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED"


_PUBLISHED_ALIASES = {
    DEPENDENCY_COORDINATES_UNRESOLVED: (
        "unresolved_dependency_coordinates_after_enrichment",
    ),
    SPRING_RUNTIME_CLASS_AMBIGUOUS: (
        "SPRING_PACKAGED_CLASS_AMBIGUOUS",
    ),
}


def _upper_snake(value):
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_").upper()


_ALIAS_TO_CANONICAL = {
    _upper_snake(alias): canonical
    for canonical, aliases in _PUBLISHED_ALIASES.items()
    for alias in aliases
}


def canonical_reason_code(value, default="UNKNOWN"):
    """Return the stable public UPPER_SNAKE_CASE identifier for ``value``."""
    normalized = _upper_snake(value)
    if not normalized:
        normalized = _upper_snake(default) or "UNKNOWN"
    return _ALIAS_TO_CANONICAL.get(normalized, normalized)


def canonical_reason_codes(values: Iterable[object] | None):
    """Normalize, de-duplicate and sort a reason-code collection."""
    return sorted({
        canonical_reason_code(value)
        for value in (values or ())
        if str(value or "").strip()
    })


def reason_code_aliases(value):
    """Return published legacy spellings for a canonical reason code."""
    canonical = canonical_reason_code(value)
    return list(_PUBLISHED_ALIASES.get(canonical, ()))


def diagnostic_contract_metadata():
    """Describe naming and compatibility rules embedded in public JSON."""
    return {
        "schema": DIAGNOSTIC_CONTRACT_SCHEMA,
        "json_field_style": "lower_snake_case",
        "reason_code_style": "UPPER_SNAKE_CASE",
        "reason_code_pattern": REASON_CODE_PATTERN,
        "reason_code_grammar": "DOMAIN_SUBJECT_CONDITION",
        "origin_step_field": "origin_step",
        "legacy_alias_field": "reason_code_aliases",
    }


def diagnostic_identity(reason_code, origin_step):
    """Build the common identity fields used by step-specific diagnostics."""
    canonical = canonical_reason_code(reason_code)
    return {
        "diagnostic_schema": DIAGNOSTIC_CONTRACT_SCHEMA,
        "origin_step": str(origin_step or "").strip().lower(),
        "reason_code": canonical,
        "reason_code_aliases": reason_code_aliases(canonical),
    }


def normalize_diagnostic_payload(payload, *, origin_step=""):
    """Normalize a top-level diagnostic object without mutating its caller."""
    result = dict(payload or {})
    raw_reason = str(result.get("reason_code") or "").strip()
    raw_reasons = result.get("reason_codes")
    if raw_reason:
        existing_aliases = [
            str(value).strip()
            for value in (result.get("reason_code_aliases") or ())
            if str(value or "").strip()
        ]
        identity = diagnostic_identity(
            raw_reason, result.get("origin_step") or origin_step
        )
        aliases = list(identity.get("reason_code_aliases") or ())
        for alias in existing_aliases:
            if alias not in aliases:
                aliases.append(alias)
        if raw_reason != identity["reason_code"]:
            if raw_reason not in aliases:
                aliases.append(raw_reason)
        identity["reason_code_aliases"] = aliases
        result.update(identity)
    elif origin_step and not result.get("origin_step"):
        result["origin_step"] = str(origin_step).strip().lower()
    if isinstance(raw_reasons, (list, tuple, set, frozenset)):
        result["reason_codes"] = canonical_reason_codes(raw_reasons)
    result.setdefault("diagnostic_schema", DIAGNOSTIC_CONTRACT_SCHEMA)
    result.setdefault("reason_code_aliases", [])
    result.setdefault("diagnostic_contract", diagnostic_contract_metadata())
    return result


def normalize_component_reason_codes(component):
    """Normalize one coverage component while retaining legacy aliases."""
    result = dict(component or {})
    raw_codes = list(result.get("reason_codes") or ())
    canonical_codes = canonical_reason_codes(raw_codes)
    legacy_aliases = {}
    for raw_code in raw_codes:
        canonical = canonical_reason_code(raw_code)
        raw_text = str(raw_code or "").strip()
        if raw_text and raw_text != canonical:
            legacy_aliases.setdefault(canonical, [])
            if raw_text not in legacy_aliases[canonical]:
                legacy_aliases[canonical].append(raw_text)
    result["reason_codes"] = canonical_codes
    if legacy_aliases:
        result["reason_code_aliases"] = legacy_aliases
    return result


def normalize_diagnostic_mapping(payload):
    """Normalize diagnostic keys in a shallow public mapping."""
    if not isinstance(payload, Mapping):
        return payload
    result = dict(payload)
    if "reason_code" in result:
        result["reason_code"] = canonical_reason_code(result.get("reason_code"))
    if "reason_codes" in result and isinstance(
        result.get("reason_codes"), (list, tuple, set, frozenset)
    ):
        result["reason_codes"] = canonical_reason_codes(result.get("reason_codes"))
    return result
