#!/usr/bin/env python3
"""Compare binary formal results with predeclared, reviewable truth.

This module is test/release-gate infrastructure.  Truth is authored before a
case is run; analyzer output is never accepted as an implicit expectation.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping


TRUTH_SCHEMA = "java-upgrade-analyzer.binary-result-truth.v1"
RESULT_SET_POLICIES = frozenset({"exact", "subset"})
REACHABILITY_STATUSES = frozenset({
    "reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed",
})
STATE_VALUES = {
    "reachability_status": REACHABILITY_STATUSES,
    "static_linkage_status": frozenset({
        "compatible_or_not_applicable", "incompatible_if_executed", "undetermined",
    }),
    "impact_conclusion": frozenset({"probable_impact", "inconclusive"}),
    "runtime_verification_status": frozenset({
        "required_not_executed", "undetermined",
    }),
}
IDENTITY_FIELDS = ("owner", "member", "descriptor", "member_kind")
LIST_FIELDS = (
    "dependency_lineages", "base_dependency_coords", "current_dependency_coords",
)
STATE_FIELDS = (
    "reachability_status", "static_linkage_status", "impact_conclusion",
    "runtime_verification_status", "exact_path_exists", "possible_path_exists",
    "path_set_complete",
)
EXPECTED_FIELDS = frozenset(
    (*IDENTITY_FIELDS, *LIST_FIELDS, *STATE_FIELDS, "required_paths", "minimum_path_count")
)
FORBIDDEN_FIELDS = frozenset((*IDENTITY_FIELDS, *LIST_FIELDS, *STATE_FIELDS))
DISPLAY_FIELD = {
    "owner": "display_owner",
    "member": "display_member",
    "descriptor": "display_descriptor",
    "member_kind": "display_member_kind",
}


def _issue(reason_code: str, **detail: Any) -> dict[str, Any]:
    return {"reason_code": reason_code, **detail}


def _normalized_list(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(sorted(str(item) for item in value))


def _actual_identity(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return tuple(str(row.get(DISPLAY_FIELD[field]) or "") for field in IDENTITY_FIELDS)


def _expected_identity(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return tuple(str(row.get(field) or "") for field in IDENTITY_FIELDS)


def _identity_mapping(identity: tuple[str, str, str, str]) -> dict[str, str]:
    return dict(zip(IDENTITY_FIELDS, identity))


def _identity_missing_fields(
    identity: tuple[str, str, str, str],
) -> tuple[str, ...]:
    owner, member, descriptor, member_kind = identity
    missing = []
    if not owner:
        missing.append("owner")
    if not member_kind:
        missing.append("member_kind")
    if member_kind != "provider_topology":
        if not member:
            missing.append("member")
        if not descriptor:
            missing.append("descriptor")
    elif bool(member) != bool(descriptor):
        missing.append("member_or_descriptor")
    return tuple(missing)


def _identity_complete(identity: tuple[str, str, str, str]) -> bool:
    return not _identity_missing_fields(identity)


def validate_result_truth(truth: Any) -> tuple[dict[str, Any], ...]:
    """Validate authored truth without comparing it to analyzer output."""
    if not isinstance(truth, Mapping):
        return (_issue("BINARY_TRUTH_DOCUMENT_INVALID"),)
    issues: list[dict[str, Any]] = []
    if truth.get("schema") != TRUTH_SCHEMA:
        issues.append(_issue(
            "BINARY_TRUTH_SCHEMA_INVALID", actual=truth.get("schema"), expected=TRUTH_SCHEMA,
        ))
    policy = str(truth.get("result_set_policy") or "")
    if policy not in RESULT_SET_POLICIES:
        issues.append(_issue("BINARY_TRUTH_RESULT_SET_POLICY_INVALID", actual=policy))
    exact_statuses = truth.get("exact_reachability_statuses") or []
    if not isinstance(exact_statuses, list) or any(
        str(status) not in REACHABILITY_STATUSES for status in exact_statuses
    ):
        issues.append(_issue(
            "BINARY_TRUTH_EXACT_STATUS_SET_INVALID", actual=exact_statuses,
        ))
    for collection_name, allowed_fields in (
        ("expected_results", EXPECTED_FIELDS),
        ("forbidden_results", FORBIDDEN_FIELDS),
    ):
        rows = truth.get(collection_name)
        if not isinstance(rows, list):
            issues.append(_issue(
                "BINARY_TRUTH_RESULT_COLLECTION_INVALID", collection=collection_name,
            ))
            continue
        identities = []
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                issues.append(_issue(
                    "BINARY_TRUTH_RESULT_INVALID", collection=collection_name, index=index,
                ))
                continue
            unknown = sorted(set(row) - allowed_fields)
            if unknown:
                issues.append(_issue(
                    "BINARY_TRUTH_FIELD_UNKNOWN", collection=collection_name,
                    index=index, fields=unknown,
                ))
            identity = _expected_identity(row)
            missing = _identity_missing_fields(identity)
            if missing:
                issues.append(_issue(
                    "BINARY_TRUTH_IDENTITY_INCOMPLETE", collection=collection_name,
                    index=index, fields=missing,
                ))
            else:
                identities.append(identity)
            for field in LIST_FIELDS:
                if field in row and not isinstance(row[field], list):
                    issues.append(_issue(
                        "BINARY_TRUTH_LIST_FIELD_INVALID", collection=collection_name,
                        index=index, field=field,
                    ))
            for field in ("exact_path_exists", "possible_path_exists", "path_set_complete"):
                if field in row and not isinstance(row[field], bool):
                    issues.append(_issue(
                        "BINARY_TRUTH_BOOLEAN_FIELD_INVALID", collection=collection_name,
                        index=index, field=field,
                    ))
            for field, allowed_values in STATE_VALUES.items():
                if field in row and row[field] not in allowed_values:
                    issues.append(_issue(
                        "BINARY_TRUTH_STATE_VALUE_INVALID",
                        collection=collection_name, index=index, field=field,
                        actual=row[field], expected=sorted(allowed_values),
                    ))
            if collection_name == "expected_results":
                if "minimum_path_count" in row and (
                    not isinstance(row["minimum_path_count"], int)
                    or isinstance(row["minimum_path_count"], bool)
                    or row["minimum_path_count"] < 0
                ):
                    issues.append(_issue(
                        "BINARY_TRUTH_MINIMUM_PATH_COUNT_INVALID",
                        identity=_identity_mapping(_expected_identity(row)),
                        actual=row["minimum_path_count"],
                    ))
                if "required_paths" in row and not isinstance(row["required_paths"], list):
                    issues.append(_issue(
                        "BINARY_TRUTH_REQUIRED_PATHS_INVALID",
                        identity=_identity_mapping(_expected_identity(row)),
                    ))
        duplicates = sorted(identity for identity, count in Counter(identities).items() if count > 1)
        for identity in duplicates:
            issues.append(_issue(
                "BINARY_TRUTH_DUPLICATE_EXPECTED_IDENTITY",
                collection=collection_name, identity=_identity_mapping(identity),
            ))
    return tuple(issues)


def _matches_forbidden(actual: Mapping[str, Any], forbidden: Mapping[str, Any]) -> bool:
    for field in IDENTITY_FIELDS:
        if str(actual.get(DISPLAY_FIELD[field]) or "") != str(forbidden.get(field) or ""):
            return False
    for field in LIST_FIELDS:
        if field in forbidden and _normalized_list(actual.get(field)) != _normalized_list(forbidden[field]):
            return False
    for field in STATE_FIELDS:
        if field in forbidden and actual.get(field) != forbidden[field]:
            return False
    return True


def _compare_expected_row(
    actual: Mapping[str, Any], expected: Mapping[str, Any],
) -> list[dict[str, Any]]:
    identity = _identity_mapping(_expected_identity(expected))
    issues: list[dict[str, Any]] = []
    for field in LIST_FIELDS:
        if field not in expected:
            continue
        expected_value = _normalized_list(expected[field])
        raw_actual_value = actual.get(field)
        actual_value = _normalized_list(raw_actual_value)
        if not isinstance(raw_actual_value, list):
            issues.append(_issue(
                "BINARY_TRUTH_ACTUAL_LIST_FIELD_INVALID", identity=identity,
                field=field, actual_type=type(raw_actual_value).__name__,
            ))
            continue
        if actual_value != expected_value:
            issues.append(_issue(
                "BINARY_TRUTH_OWNERSHIP_MISMATCH", identity=identity, field=field,
                expected=list(expected_value), actual=list(actual_value),
            ))
    for field in STATE_FIELDS:
        if field in expected and actual.get(field) != expected[field]:
            issues.append(_issue(
                "BINARY_TRUTH_STATE_MISMATCH", identity=identity, field=field,
                expected=expected[field], actual=actual.get(field),
            ))
    raw_paths = actual.get("paths")
    if not isinstance(raw_paths, list):
        issues.append(_issue(
            "BINARY_TRUTH_ACTUAL_PATHS_INVALID", identity=identity,
            actual_type=type(raw_paths).__name__,
        ))
        paths = []
    else:
        paths = raw_paths
    if "minimum_path_count" in expected:
        minimum = expected["minimum_path_count"]
        if isinstance(minimum, int) and not isinstance(minimum, bool) and len(paths) < minimum:
            issues.append(_issue(
                "BINARY_TRUTH_PATH_COUNT_TOO_SMALL", identity=identity,
                expected_minimum=minimum, actual=len(paths),
            ))
    required_paths = expected.get("required_paths") or []
    if not isinstance(required_paths, list):
        issues.append(_issue(
            "BINARY_TRUTH_REQUIRED_PATHS_INVALID", identity=identity,
        ))
    else:
        for required in required_paths:
            if not isinstance(required, Mapping):
                issues.append(_issue(
                    "BINARY_TRUTH_REQUIRED_PATH_INVALID", identity=identity,
                    expected=required,
                ))
                continue
            expected_text = str(required.get("text") or "")
            expected_certainty = str(required.get("certainty") or "")
            if not expected_text or not expected_certainty or not any(
                str(path.get("path_text") or "") == expected_text
                and str(path.get("path_certainty") or "") == expected_certainty
                for path in paths if isinstance(path, Mapping)
            ):
                issues.append(_issue(
                    "BINARY_TRUTH_REQUIRED_PATH_MISSING", identity=identity,
                    expected={"text": expected_text, "certainty": expected_certainty},
                ))
    return issues


def evaluate_formal_result_truth(
    formal_payload: Mapping[str, Any], truth: Mapping[str, Any],
) -> dict[str, Any]:
    """Return an exact, machine-readable comparison without mutating inputs."""
    issues = list(validate_result_truth(truth))
    if not isinstance(truth, Mapping):
        truth = {}
    if not isinstance(formal_payload, Mapping):
        issues.append(_issue("BINARY_TRUTH_FORMAL_DOCUMENT_INVALID"))
        formal_payload = {}
    rows = formal_payload.get("by_api")
    if not isinstance(rows, list):
        issues.append(_issue("BINARY_TRUTH_FORMAL_RESULTS_INVALID"))
        rows = []
    actual_by_identity: dict[tuple[str, str, str, str], Mapping[str, Any]] = {}
    actual_counts = Counter()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            issues.append(_issue("BINARY_TRUTH_ACTUAL_RESULT_INVALID", index=index))
            continue
        identity = _actual_identity(row)
        if not _identity_complete(identity):
            issues.append(_issue(
                "BINARY_TRUTH_ACTUAL_IDENTITY_INCOMPLETE", index=index,
                identity=_identity_mapping(identity),
            ))
            continue
        actual_counts[identity] += 1
        actual_by_identity.setdefault(identity, row)
    for identity, count in sorted(actual_counts.items()):
        if count > 1:
            issues.append(_issue(
                "BINARY_TRUTH_DUPLICATE_ACTUAL_IDENTITY",
                identity=_identity_mapping(identity), count=count,
            ))

    expected_rows = [
        row for row in truth.get("expected_results") or () if isinstance(row, Mapping)
    ]
    expected_by_identity = {
        _expected_identity(row): row for row in expected_rows
        if _identity_complete(_expected_identity(row))
    }
    actual_identities = set(actual_by_identity)
    expected_identities = set(expected_by_identity)
    missing = sorted(expected_identities - actual_identities)
    for identity in missing:
        issues.append(_issue(
            "BINARY_TRUTH_EXPECTED_RESULT_MISSING", identity=_identity_mapping(identity),
        ))
    unexpected: set[tuple[str, str, str, str]] = set()
    if truth.get("result_set_policy") == "exact":
        unexpected = actual_identities - expected_identities
        for identity in sorted(unexpected):
            issues.append(_issue(
                "BINARY_TRUTH_UNEXPECTED_RESULT", identity=_identity_mapping(identity),
            ))

    for identity in sorted(expected_identities & actual_identities):
        issues.extend(_compare_expected_row(
            actual_by_identity[identity], expected_by_identity[identity]
        ))

    exact_status_unexpected: set[tuple[str, str, str, str]] = set()
    for status in truth.get("exact_reachability_statuses") or ():
        expected_for_status = {
            identity for identity, row in expected_by_identity.items()
            if row.get("reachability_status") == status
        }
        actual_for_status = {
            identity for identity, row in actual_by_identity.items()
            if row.get("reachability_status") == status
        }
        for identity in sorted(expected_for_status - actual_for_status):
            issues.append(_issue(
                "BINARY_TRUTH_EXPECTED_STATUS_RESULT_MISSING", status=status,
                identity=_identity_mapping(identity),
            ))
        for identity in sorted(actual_for_status - expected_for_status):
            exact_status_unexpected.add(identity)
            issues.append(_issue(
                "BINARY_TRUTH_UNEXPECTED_STATUS_RESULT", status=status,
                identity=_identity_mapping(identity),
            ))

    forbidden_hits = []
    for forbidden in truth.get("forbidden_results") or ():
        if not isinstance(forbidden, Mapping):
            continue
        for actual in actual_by_identity.values():
            if _matches_forbidden(actual, forbidden):
                identity = _actual_identity(actual)
                forbidden_hits.append(identity)
                issues.append(_issue(
                    "BINARY_TRUTH_FORBIDDEN_RESULT_PRESENT",
                    identity=_identity_mapping(identity),
                ))

    state_reason_codes = {
        "BINARY_TRUTH_OWNERSHIP_MISMATCH", "BINARY_TRUTH_STATE_MISMATCH",
        "BINARY_TRUTH_ACTUAL_LIST_FIELD_INVALID",
    }
    path_reason_codes = {
        "BINARY_TRUTH_MINIMUM_PATH_COUNT_INVALID",
        "BINARY_TRUTH_PATH_COUNT_TOO_SMALL", "BINARY_TRUTH_REQUIRED_PATHS_INVALID",
        "BINARY_TRUTH_REQUIRED_PATH_INVALID", "BINARY_TRUTH_REQUIRED_PATH_MISSING",
        "BINARY_TRUTH_ACTUAL_PATHS_INVALID",
    }
    metrics = {
        "expected_result_count": len(expected_identities),
        "actual_result_count": len(actual_identities),
        "true_positive_count": len(expected_identities & actual_identities),
        "false_negative_count": len(missing),
        "false_positive_count": len(unexpected | exact_status_unexpected | set(forbidden_hits)),
        "state_mismatch_count": sum(
            issue["reason_code"] in state_reason_codes for issue in issues
        ),
        "path_mismatch_count": sum(
            issue["reason_code"] in path_reason_codes for issue in issues
        ),
    }
    return {
        "schema": "java-upgrade-analyzer.binary-result-truth-evaluation.v1",
        "status": "failed" if issues else "passed",
        "metrics": metrics,
        "issues": issues,
    }


__all__ = [
    "TRUTH_SCHEMA", "evaluate_formal_result_truth", "validate_result_truth",
]
