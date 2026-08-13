#!/usr/bin/env python3
"""Fail closed when test classification, black-box isolation, or truth is weak."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "tests" / "fixtures" / "test_suite_policy.json"
IDENTITY_FIELDS = ("owner", "member", "descriptor", "member_kind")
RESULT_FIELDS = (
    "dependency_lineages", "base_dependency_coords", "current_dependency_coords",
    "reachability_status", "static_linkage_status", "impact_conclusion",
    "runtime_verification_status", "exact_path_exists", "possible_path_exists",
    "path_set_complete", "paths",
)
REACHABILITY_VALUES = {
    "reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed",
}
LINKAGE_VALUES = {
    "compatible_or_not_applicable", "incompatible_if_executed", "undetermined",
}
IMPACT_VALUES = {"probable_impact", "inconclusive"}
RUNTIME_VALUES = {"required_not_executed", "undetermined"}
SKIP_NAMES = {
    "skip", "skipIf", "skipUnless", "skipTest", "SkipTest", "expectedFailure",
}
MOCK_NAMES = {"mock", "patch", "patch.object"}
SCENARIO_DIMENSIONS = {
    "nominal", "counterexample", "boundary", "failure_closed", "recovery",
    "metamorphic",
}
ADVERSE_SCENARIO_DIMENSIONS = SCENARIO_DIMENSIONS - {"nominal"}


def _issue(code: str, location: str, detail: str = "") -> dict[str, str]:
    return {"code": code, "location": location, "detail": detail}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_json_identity(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _attribute_name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _function_has_assertion(
    name: str,
    functions: Mapping[str, ast.AST],
    visiting: frozenset[str] = frozenset(),
) -> bool:
    """Follow local helper calls so delegated assertions still count."""
    if name in visiting or name not in functions:
        return False
    node = functions[name]
    if any(isinstance(child, ast.Assert) for child in ast.walk(node)):
        return True
    calls = [
        _attribute_name(child.func).rsplit(".", 1)[-1]
        for child in ast.walk(node) if isinstance(child, ast.Call)
    ]
    if any(value.startswith("assert") for value in calls):
        return True
    nested_visiting = visiting | {name}
    return any(
        _function_has_assertion(value, functions, nested_visiting)
        for value in calls if value in functions
    )


def _function_string_literals(
    name: str,
    functions: Mapping[str, ast.AST],
    visiting: frozenset[str] = frozenset(),
) -> set[str]:
    if name in visiting or name not in functions:
        return set()
    node = functions[name]
    values = {
        child.value for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    }
    calls = {
        _attribute_name(child.func).rsplit(".", 1)[-1]
        for child in ast.walk(node) if isinstance(child, ast.Call)
    }
    nested_visiting = visiting | {name}
    for called in calls:
        if called in functions:
            values.update(_function_string_literals(
                called, functions, nested_visiting,
            ))
    return values


def _production_module_names(repository_root: Path) -> set[str]:
    return {
        path.stem
        for path in (repository_root / "scripts").glob("*.py")
        if path.name != "__init__.py"
    }


def audit_blackbox_sources(
    repository_root: str | Path,
    source_paths: Iterable[str | Path],
) -> list[dict[str, str]]:
    """Audit black-box Python sources without importing or executing them."""
    root = Path(repository_root).resolve()
    production_modules = _production_module_names(root)
    issues: list[dict[str, str]] = []
    for source_path in source_paths:
        path = Path(source_path).resolve()
        try:
            location = path.relative_to(root).as_posix()
        except ValueError:
            location = str(path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as error:
            issues.append(_issue(
                "BLACKBOX_SOURCE_UNREADABLE", location,
                f"{type(error).__name__}: {error}",
            ))
            continue
        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported = [node.module or ""]
            for module in imported:
                top = module.split(".", 1)[0]
                if top == "scripts" or top in production_modules:
                    issues.append(_issue(
                        "BLACKBOX_IMPORTS_PRODUCTION", location, module,
                    ))
                if module == "unittest.mock" or top == "mock":
                    issues.append(_issue("BLACKBOX_USES_MOCK", location, module))
            if isinstance(node, ast.ImportFrom) and node.module == "unittest":
                for alias in node.names:
                    if alias.name == "mock":
                        issues.append(_issue(
                            "BLACKBOX_USES_MOCK", location, "unittest.mock",
                        ))
                    if alias.name in SKIP_NAMES:
                        issues.append(_issue(
                            "BLACKBOX_USES_SKIP", location,
                            f"unittest.{alias.name}",
                        ))
            if isinstance(node, ast.Call):
                called = _attribute_name(node.func)
                leaf = called.rsplit(".", 1)[-1]
                if leaf in SKIP_NAMES:
                    issues.append(_issue("BLACKBOX_USES_SKIP", location, called))
                if called in MOCK_NAMES or leaf == "patch":
                    issues.append(_issue("BLACKBOX_USES_MOCK", location, called))
                if called in {"sys.path.append", "sys.path.insert", "sys.path.extend"}:
                    issues.append(_issue(
                        "BLACKBOX_MUTATES_IMPORT_PATH", location, called,
                    ))
            if isinstance(node, ast.Name) and node.id == "monkeypatch":
                issues.append(_issue(
                    "BLACKBOX_USES_MOCK", location, "pytest monkeypatch",
                ))
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(_attribute_name(target) == "sys.path" for target in targets):
                    issues.append(_issue(
                        "BLACKBOX_MUTATES_IMPORT_PATH", location, "sys.path assignment",
                    ))
    return issues


def source_tree_identity(case_directory: str | Path) -> tuple[str, list[str]]:
    """Hash every fixture source using a documented path/content framing."""
    root = Path(case_directory).resolve()
    source_root = root / "src"
    files = sorted(path for path in source_root.rglob("*") if path.is_file())
    digest = hashlib.sha256()
    relative_files = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        relative_files.append(relative)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest(), relative_files


def _identity(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return tuple(str(row.get(field) or "") for field in IDENTITY_FIELDS)


def validate_truth_document(
    case: Mapping[str, Any],
    truth: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    source_digest: str,
    source_files: Iterable[str],
    location: str = "truth.json",
    repository_root: str | Path = ROOT,
) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    if not isinstance(case, Mapping):
        return [_issue("BLACKBOX_CASE_DOCUMENT_INVALID", location)]
    if not isinstance(truth, Mapping):
        return [_issue("TRUTH_DOCUMENT_INVALID", location)]
    if truth.get("schema") != policy.get("truth_schema"):
        issues.append(_issue("TRUTH_SCHEMA_INVALID", location))
    if truth.get("case_id") != case.get("case_id"):
        issues.append(_issue("TRUTH_CASE_ID_MISMATCH", location))
    if truth.get("dataset_version") != case.get("dataset_version"):
        issues.append(_issue("TRUTH_DATASET_VERSION_MISMATCH", location))
    if truth.get("scope") != "closed_set":
        issues.append(_issue("TRUTH_NOT_CLOSED_SET", location))
    if truth.get("system_generated") is not False:
        issues.append(_issue("TRUTH_SYSTEM_GENERATED", location))

    raw_producers = truth.get("oracle_producers")
    if not isinstance(raw_producers, list):
        issues.append(_issue("TRUTH_ORACLE_PRODUCERS_INVALID", location))
        raw_producers = []
    producers = list(raw_producers)
    mechanisms = {
        str(item.get("mechanism") or "")
        for item in producers if isinstance(item, Mapping)
    }
    mechanisms.discard("")
    producer_ids = [
        str(item.get("id") or "")
        for item in producers if isinstance(item, Mapping)
    ]
    if len(producer_ids) != len(set(producer_ids)):
        issues.append(_issue("TRUTH_ORACLE_PRODUCER_ID_DUPLICATE", location))
    raw_minimum = policy.get("minimum_oracle_mechanisms")
    minimum = (
        raw_minimum
        if isinstance(raw_minimum, int) and not isinstance(raw_minimum, bool)
        and raw_minimum > 0
        else 2
    )
    if len(mechanisms) < minimum:
        issues.append(_issue(
            "TRUTH_ORACLE_MECHANISMS_INSUFFICIENT", location,
            f"required={minimum}, actual={len(mechanisms)}",
        ))
    for index, producer in enumerate(producers):
        if not isinstance(producer, Mapping) or not all(
            producer.get(field) for field in ("id", "organization", "mechanism", "verifies")
        ):
            issues.append(_issue(
                "TRUTH_ORACLE_PRODUCER_INCOMPLETE", location, str(index),
            ))
    raw_implementations = truth.get("oracle_implementations")
    if not isinstance(raw_implementations, list) or not raw_implementations:
        issues.append(_issue("TRUTH_ORACLE_IMPLEMENTATIONS_INVALID", location))
        raw_implementations = []
    implementation_paths = []
    root = Path(repository_root).resolve()
    for index, implementation in enumerate(raw_implementations):
        if not isinstance(implementation, Mapping):
            issues.append(_issue(
                "TRUTH_ORACLE_IMPLEMENTATION_INVALID", location, str(index),
            ))
            continue
        relative = str(implementation.get("path") or "")
        expected_sha = str(implementation.get("sha256") or "")
        implementation_paths.append(relative)
        candidate = (root / relative).resolve()
        if (
            not relative
            or not candidate.is_relative_to(root)
            or not candidate.is_file()
            or len(expected_sha) != 64
        ):
            issues.append(_issue(
                "TRUTH_ORACLE_IMPLEMENTATION_INVALID", location, relative,
            ))
            continue
        actual_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            issues.append(_issue(
                "TRUTH_ORACLE_IMPLEMENTATION_IDENTITY_MISMATCH",
                location, relative,
            ))
    if len(implementation_paths) != len(set(implementation_paths)):
        issues.append(_issue(
            "TRUTH_ORACLE_IMPLEMENTATION_DUPLICATE", location,
        ))

    raw_completeness = truth.get("completeness")
    completeness = raw_completeness if isinstance(raw_completeness, Mapping) else {}
    if not isinstance(raw_completeness, Mapping) or not str(
        completeness.get("argument") or ""
    ).strip():
        issues.append(_issue("TRUTH_COMPLETENESS_ARGUMENT_MISSING", location))
    raw_verified = completeness.get("verified_dimensions")
    if not isinstance(raw_verified, list):
        issues.append(_issue("TRUTH_VERIFIED_DIMENSIONS_INVALID", location))
        raw_verified = []
    verified = set(raw_verified)
    required_dimensions = set(policy.get("required_closed_set_dimensions") or ())
    missing_dimensions = sorted(required_dimensions - verified)
    if missing_dimensions:
        issues.append(_issue(
            "TRUTH_VERIFIED_DIMENSIONS_INCOMPLETE", location,
            ",".join(missing_dimensions),
        ))
    if not isinstance(completeness.get("known_limits"), list):
        issues.append(_issue("TRUTH_KNOWN_LIMITS_UNDECLARED", location))

    raw_human_review = truth.get("human_review")
    human_review = raw_human_review if isinstance(raw_human_review, Mapping) else {}
    if human_review.get("status") not in {"not_claimed", "reviewed"}:
        issues.append(_issue("TRUTH_HUMAN_REVIEW_STATUS_INVALID", location))
    if human_review.get("status") == "reviewed" and not str(
        human_review.get("reviewer") or ""
    ).strip():
        issues.append(_issue("TRUTH_HUMAN_REVIEWER_MISSING", location))

    raw_evidence = truth.get("input_evidence")
    evidence = raw_evidence if isinstance(raw_evidence, Mapping) else {}
    if evidence.get("algorithm") != "sha256-path-nul-content-nul-v1":
        issues.append(_issue("TRUTH_INPUT_IDENTITY_ALGORITHM_INVALID", location))
    if evidence.get("source_tree_sha256") != source_digest:
        issues.append(_issue("TRUTH_INPUT_IDENTITY_MISMATCH", location))
    evidence_source_files = evidence.get("source_files")
    if not isinstance(evidence_source_files, list):
        evidence_source_files = []
    if evidence_source_files != list(source_files):
        issues.append(_issue("TRUTH_INPUT_FILE_SET_MISMATCH", location))
    if evidence.get("case_algorithm") != "sha256-canonical-json-v1":
        issues.append(_issue("TRUTH_CASE_IDENTITY_ALGORITHM_INVALID", location))
    try:
        case_identity = canonical_json_identity(case)
    except (TypeError, ValueError) as error:
        issues.append(_issue(
            "BLACKBOX_CASE_CANONICALIZATION_FAILED", location, str(error),
        ))
        case_identity = ""
    if evidence.get("case_sha256") != case_identity:
        issues.append(_issue("TRUTH_CASE_IDENTITY_MISMATCH", location))

    raw_expected = truth.get("expected_results")
    if not isinstance(raw_expected, list):
        issues.append(_issue("TRUTH_EXPECTED_RESULTS_INVALID", location))
        raw_expected = []
    expected = list(raw_expected)
    declared_result_count = truth.get("expected_result_count")
    if not isinstance(declared_result_count, int) or isinstance(
        declared_result_count, bool
    ) or declared_result_count != len(expected):
        issues.append(_issue(
            "TRUTH_EXPECTED_RESULT_COUNT_MISMATCH", location,
            f"declared={truth.get('expected_result_count')!r}, actual={len(expected)}",
        ))
    identities = []
    library_classes = {
        str(value).replace(".", "/")
        for value in (
            case.get("library_classes") or [case.get("library_class")]
        )
        if value
    }
    business_classes = {
        str(value).replace(".", "/")
        for value in (
            case.get("business_classes") or [case.get("business_class")]
        )
        if value
    }
    for index, row in enumerate(expected):
        row_location = f"{location}:expected_results[{index}]"
        if not isinstance(row, Mapping):
            issues.append(_issue("TRUTH_RESULT_INVALID", row_location))
            continue
        missing = [
            field for field in (*IDENTITY_FIELDS, *RESULT_FIELDS)
            if field not in row
        ]
        if missing:
            issues.append(_issue(
                "TRUTH_RESULT_FIELDS_MISSING", row_location, ",".join(missing),
            ))
        identity = _identity(row)
        identities.append(identity)
        member_kind = row.get("member_kind")
        ordinary_member = member_kind in {"method", "field"}
        class_contract = member_kind == "class"
        runtime_outcome = member_kind in {
            "provider_topology", "class_definition",
        }
        if (
            (ordinary_member and not all(identity))
            or (
                class_contract
                and (
                    not identity[0]
                    or identity[1] != "<class>"
                    or identity[2] != f"L{identity[0]};"
                )
            )
            or (
                runtime_outcome
                and (
                    not identity[0] or not identity[3]
                    or identity[1] or identity[2]
                )
            )
            or (not ordinary_member and not class_contract and not runtime_outcome)
        ):
            issues.append(_issue("TRUTH_RESULT_IDENTITY_INCOMPLETE", row_location))
        allowed_owners = (
            business_classes if member_kind == "class_definition"
            else library_classes
        )
        if row.get("owner") not in allowed_owners:
            issues.append(_issue("TRUTH_RESULT_OWNER_OUTSIDE_CASE", row_location))
        if ordinary_member or class_contract:
            expected_ownership = {
                "dependency_lineages": [str(case.get("library_lineage") or "")],
                "base_dependency_coords": [str(case.get("base_coordinate") or "")],
                "current_dependency_coords": [str(case.get("current_coordinate") or "")],
            }
        elif member_kind == "provider_topology":
            expected_ownership = {
                "dependency_lineages": [],
                "base_dependency_coords": [str(case.get("base_coordinate") or "")],
                "current_dependency_coords": [],
            }
        else:
            expected_ownership = {
                "dependency_lineages": [],
                "base_dependency_coords": [str(case.get("business_coordinate") or "")],
                "current_dependency_coords": [str(case.get("business_coordinate") or "")],
            }
        for field, expected_values in expected_ownership.items():
            if not isinstance(row.get(field), list):
                issues.append(_issue(
                    "TRUTH_RESULT_LIST_INVALID", row_location, field,
                ))
            elif row.get(field) != expected_values:
                issues.append(_issue(
                    "TRUTH_RESULT_OWNERSHIP_MISMATCH", row_location, field,
                ))
        enum_checks = (
            ("reachability_status", REACHABILITY_VALUES),
            ("static_linkage_status", LINKAGE_VALUES),
            ("impact_conclusion", IMPACT_VALUES),
            ("runtime_verification_status", RUNTIME_VALUES),
        )
        for field, allowed in enum_checks:
            if row.get(field) not in allowed:
                issues.append(_issue(
                    "TRUTH_RESULT_ENUM_INVALID", row_location,
                    f"{field}={row.get(field)!r}",
                ))
        for field in (
            "exact_path_exists", "possible_path_exists", "path_set_complete",
        ):
            if not isinstance(row.get(field), bool):
                issues.append(_issue(
                    "TRUTH_RESULT_BOOLEAN_INVALID", row_location, field,
                ))
        status = row.get("reachability_status")
        expected_state = {
            "reachable": (True, "probable_impact", "required_not_executed"),
            "not_found_in_static_analysis": (False, "inconclusive", "undetermined"),
            "not_analyzed": (False, "inconclusive", "undetermined"),
        }.get(status)
        if expected_state and (
            row.get("exact_path_exists"),
            row.get("impact_conclusion"),
            row.get("runtime_verification_status"),
        ) != expected_state:
            issues.append(_issue(
                "TRUTH_RESULT_STATE_INCONSISTENT", row_location, str(status),
            ))
        if status == "uncertain" and row.get("exact_path_exists") is True:
            issues.append(_issue(
                "TRUTH_RESULT_STATE_INCONSISTENT", row_location, "uncertain exact path",
            ))
        if status == "uncertain" and (
            row.get("possible_path_exists") is not True
            or row.get("impact_conclusion") != "inconclusive"
            or row.get("runtime_verification_status") != "undetermined"
        ):
            issues.append(_issue(
                "TRUTH_RESULT_STATE_INCONSISTENT", row_location, "uncertain",
            ))
        paths = row.get("paths")
        if not isinstance(paths, list):
            issues.append(_issue("TRUTH_RESULT_PATHS_INVALID", row_location))
            paths = []
        valid_paths = True
        for path_index, path in enumerate(paths):
            if not isinstance(path, Mapping) or path.get("certainty") not in {
                "exact", "possible",
            } or not str(path.get("text") or "").strip():
                issues.append(_issue(
                    "TRUTH_RESULT_PATH_INVALID", row_location, str(path_index),
                ))
                valid_paths = False
        exact_path_in_list = any(
            isinstance(path, Mapping) and path.get("certainty") == "exact"
            for path in paths
        )
        possible_path_in_list = any(
            isinstance(path, Mapping) and path.get("certainty") == "possible"
            for path in paths
        )
        if valid_paths and (
            bool(row.get("exact_path_exists")) != exact_path_in_list
            or bool(row.get("possible_path_exists")) != possible_path_in_list
        ):
            issues.append(_issue(
                "TRUTH_RESULT_PATH_FLAGS_MISMATCH", row_location,
            ))
    if len(identities) != len(set(identities)):
        issues.append(_issue("TRUTH_EXPECTED_IDENTITY_DUPLICATE", location))
    if case.get("oracle_contract") in {
        "removed_member_linkage_closed_set",
        "complete_member_change_closed_set",
        "member_contract_linkage_closed_set",
        "implementation_change_closed_set",
    }:
        probe_identities = {
            _identity(probe)
            for probe in (
                list(case.get("linkage_probes") or ())
                + list(case.get("behavior_probes") or ())
            )
            if isinstance(probe, Mapping)
        }
        member_identities = {
            _identity(row) for row in expected
            if isinstance(row, Mapping)
            and row.get("member_kind") in {"method", "field"}
        }
        added_member_identities = {
            _identity(row) for row in expected
            if isinstance(row, Mapping)
            and row.get("oracle_relation") == "added_member"
        }
        if member_identities != (probe_identities | added_member_identities):
            issues.append(_issue(
                "TRUTH_EXPECTED_PROBE_SET_MISMATCH", location,
            ))

    raw_forbidden = truth.get("forbidden_results")
    if not isinstance(raw_forbidden, list):
        issues.append(_issue("TRUTH_FORBIDDEN_RESULTS_INVALID", location))
        raw_forbidden = []
    forbidden = list(raw_forbidden)
    if not forbidden:
        issues.append(_issue("TRUTH_FORBIDDEN_RESULTS_EMPTY", location))
    forbidden_identities = []
    for index, row in enumerate(forbidden):
        row_location = f"{location}:forbidden_results[{index}]"
        if not isinstance(row, Mapping):
            issues.append(_issue("TRUTH_FORBIDDEN_RESULT_INVALID", row_location))
            continue
        identity = _identity(row)
        forbidden_identities.append(identity)
        if not all(identity) or not str(row.get("reason") or "").strip():
            issues.append(_issue("TRUTH_FORBIDDEN_RESULT_INCOMPLETE", row_location))
        if row.get("oracle_relation") != "unchanged_member":
            issues.append(_issue(
                "TRUTH_FORBIDDEN_ORACLE_RELATION_INVALID", row_location,
                str(row.get("oracle_relation") or ""),
            ))
    if set(identities).intersection(forbidden_identities):
        issues.append(_issue("TRUTH_EXPECTED_FORBIDDEN_OVERLAP", location))
    return issues


def validate_supplemental_truth_document(
    truth: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    location: str,
) -> list[dict[str, str]]:
    """Validate workflow/runtime truth that is not a compiled fixture case.

    These documents intentionally have domain-specific expected-result shapes,
    but they share the same provenance boundary: expected values must be
    authored outside the production pipeline and supported by at least two
    distinct oracle mechanisms.
    """
    if not isinstance(truth, Mapping):
        return [_issue("SUPPLEMENTAL_TRUTH_DOCUMENT_INVALID", location)]
    issues: list[dict[str, str]] = []
    allowed_schemas = set(
        str(value)
        for value in policy.get("supplemental_blackbox_truth_schemas") or ()
    )
    if not allowed_schemas or truth.get("schema") not in allowed_schemas:
        issues.append(_issue("SUPPLEMENTAL_TRUTH_SCHEMA_INVALID", location))
    if not str(truth.get("case_id") or "").strip():
        issues.append(_issue("SUPPLEMENTAL_TRUTH_CASE_ID_MISSING", location))
    if truth.get("system_generated") is not False:
        issues.append(_issue("SUPPLEMENTAL_TRUTH_SYSTEM_GENERATED", location))

    raw_producers = truth.get("oracle_producers")
    if not isinstance(raw_producers, list):
        issues.append(_issue(
            "SUPPLEMENTAL_TRUTH_ORACLE_PRODUCERS_INVALID", location,
        ))
        raw_producers = []
    producer_ids: list[str] = []
    mechanisms: set[str] = set()
    for index, producer in enumerate(raw_producers):
        if not isinstance(producer, Mapping):
            issues.append(_issue(
                "SUPPLEMENTAL_TRUTH_ORACLE_PRODUCER_INCOMPLETE",
                location, str(index),
            ))
            continue
        producer_id = str(producer.get("id") or "")
        mechanism = str(producer.get("mechanism") or "")
        verifies = producer.get("verifies")
        producer_ids.append(producer_id)
        mechanisms.add(mechanism)
        if (
            not producer_id
            or not str(producer.get("organization") or "").strip()
            or not mechanism
            or not isinstance(verifies, list)
            or not verifies
            or any(not isinstance(value, str) or not value.strip() for value in verifies)
        ):
            issues.append(_issue(
                "SUPPLEMENTAL_TRUTH_ORACLE_PRODUCER_INCOMPLETE",
                location, str(index),
            ))
    if len(producer_ids) != len(set(producer_ids)):
        issues.append(_issue(
            "SUPPLEMENTAL_TRUTH_ORACLE_PRODUCER_ID_DUPLICATE", location,
        ))
    mechanisms.discard("")
    raw_minimum = policy.get("minimum_oracle_mechanisms")
    minimum = (
        raw_minimum
        if isinstance(raw_minimum, int) and not isinstance(raw_minimum, bool)
        and raw_minimum > 0
        else 2
    )
    if len(mechanisms) < minimum:
        issues.append(_issue(
            "SUPPLEMENTAL_TRUTH_ORACLE_MECHANISMS_INSUFFICIENT", location,
            f"required={minimum}, actual={len(mechanisms)}",
        ))

    metadata_keys = {
        "schema", "case_id", "system_generated", "oracle_producers",
    }
    if not any(key not in metadata_keys for key in truth):
        issues.append(_issue("SUPPLEMENTAL_TRUTH_EXPECTATIONS_EMPTY", location))
    return issues


def _validate_case(
    repository_root: Path,
    case_path: Path,
    policy: Mapping[str, Any],
) -> tuple[list[dict[str, str]], int]:
    location = case_path.relative_to(repository_root).as_posix()
    issues: list[dict[str, str]] = []
    try:
        case = _load_json(case_path)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return [_issue(
            "BLACKBOX_CASE_UNREADABLE", location,
            f"{type(error).__name__}: {error}",
        )], 0
    if not isinstance(case, Mapping):
        return [_issue("BLACKBOX_CASE_DOCUMENT_INVALID", location)], 0
    if case.get("schema") != "java-upgrade-analyzer.blackbox-case.v1":
        issues.append(_issue("BLACKBOX_CASE_SCHEMA_INVALID", location))
    required_case_fields = (
        "case_id", "dataset_version", "public_entrypoint", "truth_file",
        "library_class", "business_class", "oracle_main_class",
        "library_lineage", "base_coordinate", "current_coordinate",
        "oracle_contract",
    )
    missing_case_fields = [
        field for field in required_case_fields if not case.get(field)
    ]
    if missing_case_fields:
        issues.append(_issue(
            "BLACKBOX_CASE_FIELDS_MISSING", location,
            ",".join(missing_case_fields),
        ))
    if not isinstance(case.get("dataset_version"), int) or isinstance(
        case.get("dataset_version"), bool
    ) or int(case.get("dataset_version") or 0) <= 0:
        issues.append(_issue("BLACKBOX_CASE_VERSION_INVALID", location))
    oracle_contract = case.get("oracle_contract")
    if oracle_contract not in {
        "removed_member_linkage_closed_set",
        "complete_member_change_closed_set",
        "member_contract_linkage_closed_set",
        "implementation_change_closed_set",
    }:
        issues.append(_issue("BLACKBOX_ORACLE_CONTRACT_INVALID", location))
    capabilities = case.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities or any(
        not isinstance(value, str) or not value.strip() for value in capabilities
    ):
        issues.append(_issue("BLACKBOX_CAPABILITIES_INVALID", location))
    elif len(capabilities) != len(set(capabilities)):
        issues.append(_issue("BLACKBOX_CAPABILITY_DUPLICATE", location))
    if case.get("case_id") != case_path.parent.name:
        issues.append(_issue("BLACKBOX_CASE_DIRECTORY_MISMATCH", location))
    raw_entrypoints = case.get("entrypoints")
    if not isinstance(raw_entrypoints, list):
        issues.append(_issue("BLACKBOX_ENTRYPOINT_SET_INVALID", location))
        raw_entrypoints = []
    entrypoints = list(raw_entrypoints)
    if not entrypoints:
        issues.append(_issue("BLACKBOX_ENTRYPOINT_SET_EMPTY", location))
    for index, entrypoint_row in enumerate(entrypoints):
        if not isinstance(entrypoint_row, Mapping) or not all(
            entrypoint_row.get(field)
            for field in ("class_name", "member_name", "descriptor")
        ):
            issues.append(_issue(
                "BLACKBOX_ENTRYPOINT_INVALID", location, str(index),
            ))
    raw_probes = case.get("linkage_probes")
    if raw_probes is None:
        raw_probes = []
    if not isinstance(raw_probes, list):
        issues.append(_issue("BLACKBOX_LINKAGE_PROBE_SET_INVALID", location))
        raw_probes = []
    probes = list(raw_probes)
    probe_identities = []
    for index, probe in enumerate(probes):
        if not isinstance(probe, Mapping) or not all(
            probe.get(field)
            for field in (
                "mode", "owner", "member", "descriptor", "member_kind",
                "linkage_error",
            )
        ):
            issues.append(_issue(
                "BLACKBOX_LINKAGE_PROBE_INVALID", location, str(index),
            ))
            continue
        probe_identities.append(_identity(probe))
        if probe.get("member_kind") not in {"method", "field"} or probe.get(
            "linkage_error"
        ) not in {
            "NoSuchMethodError", "NoSuchFieldError", "NoClassDefFoundError",
            "IllegalAccessError", "IncompatibleClassChangeError",
            "AbstractMethodError", "VerifyError",
        }:
            issues.append(_issue(
                "BLACKBOX_LINKAGE_PROBE_INVALID", location, str(index),
            ))
    if len(probe_identities) != len(set(probe_identities)):
        issues.append(_issue("BLACKBOX_LINKAGE_PROBE_DUPLICATE", location))
    raw_behavior_probes = case.get("behavior_probes")
    if raw_behavior_probes is None:
        raw_behavior_probes = []
    if not isinstance(raw_behavior_probes, list):
        issues.append(_issue("BLACKBOX_BEHAVIOR_PROBE_SET_INVALID", location))
        raw_behavior_probes = []
    behavior_probes = list(raw_behavior_probes)
    if oracle_contract in {
        "removed_member_linkage_closed_set",
        "complete_member_change_closed_set",
        "member_contract_linkage_closed_set",
    } and not probes and not behavior_probes and not any(
        isinstance(outcome, Mapping)
        and outcome.get("member_kind") == "class_definition"
        for outcome in (case.get("runtime_outcome_probes") or ())
    ):
        issues.append(_issue("BLACKBOX_RUNTIME_PROBE_SET_EMPTY", location))
    if oracle_contract == "implementation_change_closed_set" and not behavior_probes:
        issues.append(_issue("BLACKBOX_BEHAVIOR_PROBE_SET_EMPTY", location))
    behavior_identities = []
    for index, probe in enumerate(behavior_probes):
        if not isinstance(probe, Mapping) or not all(
            probe.get(field) is not None and probe.get(field) != ""
            for field in (
                "mode", "owner", "member", "descriptor", "member_kind",
                "base_stdout", "current_stdout",
            )
        ):
            issues.append(_issue(
                "BLACKBOX_BEHAVIOR_PROBE_INVALID", location, str(index),
            ))
            continue
        behavior_identities.append(_identity(probe))
        if probe.get("member_kind") != "method" or (
            str(probe.get("base_stdout")) == str(probe.get("current_stdout"))
            and probe.get("allow_equal_stdout") is not True
        ):
            issues.append(_issue(
                "BLACKBOX_BEHAVIOR_PROBE_INVALID", location, str(index),
            ))
    if len(behavior_identities) != len(set(behavior_identities)):
        issues.append(_issue("BLACKBOX_BEHAVIOR_PROBE_DUPLICATE", location))
    if set(probe_identities).intersection(behavior_identities):
        issues.append(_issue("BLACKBOX_RUNTIME_PROBE_OVERLAP", location))
    raw_outcomes = case.get("runtime_outcome_probes") or []
    if not isinstance(raw_outcomes, list):
        issues.append(_issue("BLACKBOX_RUNTIME_OUTCOME_SET_INVALID", location))
        raw_outcomes = []
    outcome_identities = []
    for index, outcome in enumerate(raw_outcomes):
        if not isinstance(outcome, Mapping):
            issues.append(_issue(
                "BLACKBOX_RUNTIME_OUTCOME_INVALID", location, str(index),
            ))
            continue
        kind = outcome.get("member_kind")
        owner = outcome.get("owner")
        if not owner or kind not in {"provider_topology", "class_definition"}:
            issues.append(_issue(
                "BLACKBOX_RUNTIME_OUTCOME_INVALID", location, str(index),
            ))
            continue
        if kind == "class_definition" and not all((
            case.get("definition_oracle_main_class"),
            case.get("business_coordinate"),
            outcome.get("linkage_error"),
            outcome.get("error_symbol"),
        )):
            issues.append(_issue(
                "BLACKBOX_RUNTIME_OUTCOME_INVALID", location, str(index),
            ))
        outcome_identities.append((str(owner), "", "", str(kind)))
    if len(outcome_identities) != len(set(outcome_identities)):
        issues.append(_issue("BLACKBOX_RUNTIME_OUTCOME_DUPLICATE", location))
    for partition in ("base", "current", "business", "oracle"):
        partition_root = case_path.parent / "src" / partition
        if not partition_root.is_dir() or not any(partition_root.rglob("*.java")):
            issues.append(_issue(
                "BLACKBOX_SOURCE_PARTITION_MISSING", location, partition,
            ))
    entrypoint = str(case.get("public_entrypoint") or "")
    if entrypoint not in set(policy.get("allowed_public_entrypoints") or ()):
        issues.append(_issue("BLACKBOX_ENTRYPOINT_NOT_ALLOWED", location, entrypoint))
    elif not (repository_root / entrypoint).is_file():
        issues.append(_issue("BLACKBOX_ENTRYPOINT_MISSING", location, entrypoint))
    truth_name = str(case.get("truth_file") or "")
    truth_path = (case_path.parent / truth_name).resolve()
    if not truth_name or truth_path.parent != case_path.parent.resolve():
        issues.append(_issue("BLACKBOX_TRUTH_PATH_INVALID", location, truth_name))
        return issues, 0
    try:
        truth = _load_json(truth_path)
        digest, source_files = source_tree_identity(case_path.parent)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        issues.append(_issue(
            "BLACKBOX_TRUTH_OR_SOURCE_UNREADABLE", location,
            f"{type(error).__name__}: {error}",
        ))
        return issues, 0
    if not source_files:
        issues.append(_issue("BLACKBOX_SOURCE_SET_EMPTY", location))
    truth_location = truth_path.relative_to(repository_root).as_posix()
    issues.extend(validate_truth_document(
        case, truth, policy,
        source_digest=digest,
        source_files=source_files,
        location=truth_location,
        repository_root=repository_root,
    ))
    return issues, len(truth.get("expected_results") or ())


def _selector_module(selector: str) -> str:
    parts = selector.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else selector


def _json_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    """Resolve RFC 6901 pointers without treating a false/zero value as absent."""
    if pointer == "":
        return True, document
    if not pointer.startswith("/"):
        return False, None
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit():
            index = int(token)
            if index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current


def _value_has_expectation(value: Any) -> bool:
    if value is None or value == "" or value == [] or value == {}:
        return False
    return True


def _blackbox_assertion_sites(source_paths: Iterable[Path]) -> int:
    count = 0
    for path in source_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError):
            continue
        count += sum(
            1 for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and _attribute_name(node.func).rsplit(".", 1)[-1].startswith("assert")
        )
    return count


def _authored_expectation_leaves(value: Any, *, metadata: bool = False) -> int:
    metadata_keys = {
        "schema", "case_id", "system_generated", "oracle_producers",
    }
    if isinstance(value, Mapping):
        return sum(
            _authored_expectation_leaves(child)
            for key, child in value.items()
            if metadata or key not in metadata_keys
        )
    if isinstance(value, list):
        return sum(_authored_expectation_leaves(child) for child in value)
    return 1


def _scenario_contract_for_capabilities(
    repository_root: Path,
    policy: Mapping[str, Any],
    capabilities: list[Mapping[str, Any]],
    case_capabilities: Mapping[str, set[str]],
) -> tuple[list[dict[str, str]], dict[str, tuple[str, ...]]]:
    """Require scenario strength, not just a file/method reference.

    Closed cases derive their dimensions from executable truth and the common
    baseline/repacked harness. Test-only capabilities must explicitly bind
    dimensions to authored truth values by JSON pointer.
    """
    root = repository_root
    issues: list[dict[str, str]] = []
    relative = str(policy.get("public_scenario_contracts") or "")
    location = relative or "<missing public_scenario_contracts>"
    path = (root / relative).resolve() if relative else root
    try:
        contract = _load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return [_issue(
            "PUBLIC_SCENARIO_CONTRACTS_UNREADABLE", location,
            f"{type(error).__name__}: {error}",
        )], {}
    if not isinstance(contract, Mapping) or contract.get("schema") != (
        "java-upgrade-analyzer.system-test-scenario-contracts.v1"
    ):
        return [_issue("PUBLIC_SCENARIO_CONTRACTS_INVALID", location)], {}
    vocabulary = set(contract.get("dimension_vocabulary") or ())
    if vocabulary != SCENARIO_DIMENSIONS:
        issues.append(_issue(
            "PUBLIC_SCENARIO_DIMENSION_VOCABULARY_INVALID", location,
        ))
    floors = contract.get("risk_minimum_dimensions")
    expected_floors = {"critical": 3, "high": 2, "medium": 2, "low": 1}
    if floors != expected_floors:
        issues.append(_issue("PUBLIC_SCENARIO_RISK_FLOORS_INVALID", location))
        floors = expected_floors

    raw_entries = contract.get("capabilities")
    if not isinstance(raw_entries, list):
        issues.append(_issue("PUBLIC_SCENARIO_CAPABILITY_SET_INVALID", location))
        raw_entries = []
    entries = [row for row in raw_entries if isinstance(row, Mapping)]
    if len(entries) != len(raw_entries):
        issues.append(_issue("PUBLIC_SCENARIO_CAPABILITY_ENTRY_INVALID", location))
    ids = [str(row.get("id") or "") for row in entries]
    if any(not value for value in ids) or len(ids) != len(set(ids)):
        issues.append(_issue("PUBLIC_SCENARIO_CAPABILITY_IDS_INVALID", location))
    by_id = {str(row.get("id") or ""): row for row in entries if row.get("id")}
    matrix_ids = {str(row.get("id") or "") for row in capabilities}
    unknown = sorted(set(by_id) - matrix_ids)
    if unknown:
        issues.append(_issue(
            "PUBLIC_SCENARIO_UNKNOWN_CAPABILITY", location, ",".join(unknown),
        ))

    case_backed: dict[str, set[str]] = {}
    for case_id, tags in case_capabilities.items():
        for tag in tags:
            case_backed.setdefault(tag, set()).add(case_id)

    coverage: dict[str, tuple[str, ...]] = {}
    for capability in capabilities:
        capability_id = str(capability.get("id") or "")
        item_location = f"{location}:{capability_id or '<missing>'}"
        risk = str(capability.get("risk") or "")
        dimensions: set[str] = set()
        if capability_id in case_backed:
            dimensions.update({"nominal", "counterexample", "metamorphic"})
            if capability_id in by_id:
                issues.append(_issue(
                    "PUBLIC_SCENARIO_CASE_DERIVATION_OVERRIDDEN", item_location,
                ))
        else:
            entry = by_id.get(capability_id)
            if entry is None:
                issues.append(_issue(
                    "PUBLIC_SCENARIO_CAPABILITY_MISSING", item_location,
                ))
                coverage[capability_id] = ()
                continue
            truth_relative = str(entry.get("truth") or "")
            truth_path = (root / truth_relative).resolve()
            if (
                not truth_relative
                or not truth_path.is_relative_to(root)
                or not truth_path.is_file()
            ):
                issues.append(_issue(
                    "PUBLIC_SCENARIO_TRUTH_MISSING", item_location, truth_relative,
                ))
                truth = None
            else:
                try:
                    truth = _load_json(truth_path)
                except (OSError, UnicodeError, json.JSONDecodeError):
                    truth = None
                    issues.append(_issue(
                        "PUBLIC_SCENARIO_TRUTH_UNREADABLE", item_location,
                        truth_relative,
                    ))
            raw_dimensions = entry.get("dimensions")
            if not isinstance(raw_dimensions, Mapping) or not raw_dimensions:
                issues.append(_issue(
                    "PUBLIC_SCENARIO_DIMENSIONS_INVALID", item_location,
                ))
                raw_dimensions = {}
            for dimension, raw_pointers in raw_dimensions.items():
                dimension = str(dimension)
                if dimension not in SCENARIO_DIMENSIONS:
                    issues.append(_issue(
                        "PUBLIC_SCENARIO_DIMENSION_INVALID", item_location,
                        dimension,
                    ))
                    continue
                if (
                    not isinstance(raw_pointers, list) or not raw_pointers
                    or any(not isinstance(value, str) for value in raw_pointers)
                ):
                    issues.append(_issue(
                        "PUBLIC_SCENARIO_TRUTH_POINTERS_INVALID", item_location,
                        dimension,
                    ))
                    continue
                valid_dimension = True
                for pointer in raw_pointers:
                    found, value = _json_pointer(truth, pointer)
                    if not found or not _value_has_expectation(value):
                        issues.append(_issue(
                            "PUBLIC_SCENARIO_TRUTH_POINTER_MISSING", item_location,
                            f"{truth_relative}#{pointer}",
                        ))
                        valid_dimension = False
                if valid_dimension:
                    dimensions.add(dimension)
            evidence = (capability.get("blackbox") or {}).get("evidence") or ()
            truth_name = Path(truth_relative).name
            test_sources = []
            evidence_literals: set[str] = set()
            for evidence_item in evidence:
                if isinstance(evidence_item, Mapping) and evidence_item.get("kind") == "test":
                    candidate = root / str(evidence_item.get("path") or "")
                    try:
                        source = candidate.read_text(encoding="utf-8")
                        test_sources.append(source)
                        tree = ast.parse(source)
                        functions = {
                            node.name: node for node in ast.walk(tree)
                            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        }
                        evidence_literals.update(_function_string_literals(
                            str(evidence_item.get("test") or ""), functions,
                        ))
                    except (OSError, UnicodeError, SyntaxError):
                        pass
            if truth_name and not any(truth_name in source for source in test_sources):
                issues.append(_issue(
                    "PUBLIC_SCENARIO_TRUTH_NOT_USED_BY_EVIDENCE", item_location,
                    truth_name,
                ))
            for raw_pointers in (
                entry.get("dimensions") or {}
            ).values() if isinstance(entry.get("dimensions"), Mapping) else ():
                if not isinstance(raw_pointers, list):
                    continue
                for pointer in raw_pointers:
                    if not isinstance(pointer, str):
                        continue
                    required_tokens = {
                        token.replace("~1", "/").replace("~0", "~")
                        for token in pointer.lstrip("/").split("/")
                        if token and not token.isdigit()
                    }
                    missing_tokens = sorted(required_tokens - evidence_literals)
                    if missing_tokens:
                        issues.append(_issue(
                            "PUBLIC_SCENARIO_TRUTH_POINTER_NOT_ASSERTED",
                            item_location,
                            f"{pointer}:missing={','.join(missing_tokens)}",
                        ))

        minimum = int(floors.get(risk, 1))
        if "nominal" not in dimensions:
            issues.append(_issue(
                "PUBLIC_SCENARIO_NOMINAL_MISSING", item_location,
            ))
        if not dimensions.intersection(ADVERSE_SCENARIO_DIMENSIONS):
            issues.append(_issue(
                "PUBLIC_SCENARIO_ADVERSE_MISSING", item_location,
            ))
        if len(dimensions) < minimum:
            issues.append(_issue(
                "PUBLIC_SCENARIO_RISK_FLOOR_NOT_MET", item_location,
                f"risk={risk},required={minimum},actual={len(dimensions)}",
            ))
        coverage[capability_id] = tuple(sorted(dimensions))
    return issues, coverage


def _support_claim_paths(support_manifest: Mapping[str, Any]) -> set[str]:
    claims: set[str] = set()
    for section, field in (
        ("entrypoint_discovery_support_manifest", "automatic_discovery"),
        ("runtime_semantic_overlay_support_manifest", "supported_edge_families"),
    ):
        values = ((support_manifest.get(section) or {}).get(field) or ())
        if isinstance(values, list):
            claims.update(f"{section}.{field}[{index}]" for index in range(len(values)))
    return claims


def audit_public_capability_matrix(
    repository_root: str | Path,
    matrix_path: str | Path,
    policy: Mapping[str, Any],
    case_capabilities: Mapping[str, set[str]],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Validate the public capability inventory without pretending gaps pass."""
    root = Path(repository_root).resolve()
    path = Path(matrix_path)
    if not path.is_absolute():
        path = root / path
    path = path.resolve()
    location = (
        path.relative_to(root).as_posix()
        if path.is_relative_to(root) else str(path)
    )
    issues: list[dict[str, str]] = []
    try:
        matrix = _load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return [_issue(
            "PUBLIC_CAPABILITY_MATRIX_UNREADABLE", location,
            f"{type(error).__name__}: {error}",
        )], {
            "status": "invalid", "matrix": location,
            "covered": 0, "partial": 0, "missing": 0,
            "blocking_capabilities": [],
        }
    if not isinstance(matrix, Mapping):
        return [_issue("PUBLIC_CAPABILITY_MATRIX_INVALID", location)], {
            "status": "invalid", "matrix": location,
            "covered": 0, "partial": 0, "missing": 0,
            "blocking_capabilities": [],
        }
    if matrix.get("schema") != (
        "java-upgrade-analyzer.system-test-capability-matrix.v1"
    ):
        issues.append(_issue(
            "PUBLIC_CAPABILITY_MATRIX_SCHEMA_INVALID", location,
        ))
    statuses = set(matrix.get("status_vocabulary") or ())
    if statuses != {"covered", "partial", "missing"}:
        issues.append(_issue(
            "PUBLIC_CAPABILITY_STATUS_VOCABULARY_INVALID", location,
        ))
    required_domains = set(matrix.get("required_domains") or ())
    if not required_domains:
        issues.append(_issue("PUBLIC_CAPABILITY_DOMAIN_SET_EMPTY", location))
    raw_capabilities = matrix.get("capabilities")
    if not isinstance(raw_capabilities, list) or not raw_capabilities:
        issues.append(_issue("PUBLIC_CAPABILITY_SET_EMPTY", location))
        raw_capabilities = []
    capabilities = [
        item for item in raw_capabilities if isinstance(item, Mapping)
    ]
    if len(capabilities) != len(raw_capabilities):
        issues.append(_issue("PUBLIC_CAPABILITY_ENTRY_INVALID", location))
    ids = [str(item.get("id") or "") for item in capabilities]
    if any(not value for value in ids):
        issues.append(_issue("PUBLIC_CAPABILITY_ID_MISSING", location))
    if len(ids) != len(set(ids)):
        issues.append(_issue("PUBLIC_CAPABILITY_ID_DUPLICATE", location))
    by_id = {
        str(item.get("id") or ""): item for item in capabilities
        if item.get("id")
    }
    covered_domains = {
        str(item.get("domain") or "") for item in capabilities
        if item.get("domain")
    }
    for domain in sorted(required_domains - covered_domains):
        issues.append(_issue(
            "PUBLIC_CAPABILITY_DOMAIN_UNMAPPED", location, domain,
        ))

    allowed_entrypoints = set(policy.get("allowed_public_entrypoints") or ())
    mapped_entrypoints: set[str] = set()
    mapped_steps: set[str] = set()
    mapped_support_sections: set[str] = set()
    status_counts = {"covered": 0, "partial": 0, "missing": 0}
    blocking_capabilities = []
    policy_performance = set(policy.get("performance_test_selectors") or ())
    for item in capabilities:
        capability_id = str(item.get("id") or "")
        item_location = f"{location}:{capability_id or '<missing>'}"
        domain = str(item.get("domain") or "")
        if domain not in required_domains:
            issues.append(_issue(
                "PUBLIC_CAPABILITY_DOMAIN_INVALID", item_location, domain,
            ))
        if item.get("risk") not in {"critical", "high", "medium", "low"}:
            issues.append(_issue(
                "PUBLIC_CAPABILITY_RISK_INVALID", item_location,
                str(item.get("risk") or ""),
            ))
        raw_entrypoints = item.get("public_entrypoints")
        if not isinstance(raw_entrypoints, list) or not raw_entrypoints:
            issues.append(_issue(
                "PUBLIC_CAPABILITY_ENTRYPOINTS_INVALID", item_location,
            ))
            raw_entrypoints = []
        for entrypoint in raw_entrypoints:
            entrypoint = str(entrypoint)
            mapped_entrypoints.add(entrypoint)
            if (
                entrypoint not in allowed_entrypoints
                or not (root / entrypoint).is_file()
            ):
                issues.append(_issue(
                    "PUBLIC_CAPABILITY_ENTRYPOINT_INVALID",
                    item_location, entrypoint,
                ))
        raw_blackbox = item.get("blackbox")
        blackbox = raw_blackbox if isinstance(raw_blackbox, Mapping) else {}
        if not isinstance(raw_blackbox, Mapping):
            issues.append(_issue(
                "PUBLIC_CAPABILITY_BLACKBOX_INVALID", item_location,
            ))
        status = str(blackbox.get("status") or "")
        if status not in status_counts:
            issues.append(_issue(
                "PUBLIC_CAPABILITY_STATUS_INVALID", item_location, status,
            ))
        else:
            status_counts[status] += 1
            if status != "covered":
                blocking_capabilities.append(capability_id)
        raw_evidence = blackbox.get("evidence")
        if not isinstance(raw_evidence, list):
            issues.append(_issue(
                "PUBLIC_CAPABILITY_EVIDENCE_INVALID", item_location,
            ))
            raw_evidence = []
        evidence = list(raw_evidence)
        if status == "covered" and (
            not evidence or not str(blackbox.get("oracle") or "").strip()
        ):
            issues.append(_issue(
                "PUBLIC_CAPABILITY_COVERED_WITHOUT_ORACLE",
                item_location,
            ))
        if status in {"partial", "missing"} and not str(
            blackbox.get("gap") or ""
        ).strip():
            issues.append(_issue(
                "PUBLIC_CAPABILITY_GAP_UNDECLARED", item_location,
            ))
        for index, evidence_item in enumerate(evidence):
            evidence_location = f"{item_location}:evidence[{index}]"
            if not isinstance(evidence_item, Mapping):
                issues.append(_issue(
                    "PUBLIC_CAPABILITY_EVIDENCE_INVALID", evidence_location,
                ))
                continue
            kind = evidence_item.get("kind")
            if kind == "case":
                case_id = str(evidence_item.get("id") or "")
                if case_id not in case_capabilities:
                    issues.append(_issue(
                        "PUBLIC_CAPABILITY_CASE_EVIDENCE_MISSING",
                        evidence_location, case_id,
                    ))
                elif (
                    status == "covered"
                    and capability_id not in case_capabilities[case_id]
                ):
                    issues.append(_issue(
                        "PUBLIC_CAPABILITY_CASE_TAG_MISMATCH",
                        evidence_location, f"{case_id}:{capability_id}",
                    ))
            elif kind == "test":
                relative = str(evidence_item.get("path") or "")
                test_name = str(evidence_item.get("test") or "")
                candidate = (root / relative).resolve()
                if (
                    not relative.startswith("tests/blackbox/")
                    or not candidate.is_relative_to(root)
                    or not candidate.is_file()
                ):
                    issues.append(_issue(
                        "PUBLIC_CAPABILITY_TEST_EVIDENCE_MISSING",
                        evidence_location, relative,
                    ))
                else:
                    try:
                        tree = ast.parse(candidate.read_text(encoding="utf-8"))
                        test_functions = {
                            node.name: node for node in ast.walk(tree)
                            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        }
                        test_names = set(test_functions)
                    except (OSError, UnicodeError, SyntaxError):
                        test_functions = {}
                        test_names = set()
                    if test_name not in test_names:
                        issues.append(_issue(
                            "PUBLIC_CAPABILITY_TEST_NAME_MISSING",
                            evidence_location, test_name,
                        ))
                    elif not test_name.startswith("test"):
                        issues.append(_issue(
                            "PUBLIC_CAPABILITY_EVIDENCE_NOT_A_TEST",
                            evidence_location, test_name,
                        ))
                    elif not _function_has_assertion(
                        test_name, test_functions,
                    ):
                        issues.append(_issue(
                            "PUBLIC_CAPABILITY_TEST_WITHOUT_ASSERTION",
                            evidence_location, test_name,
                        ))
            else:
                issues.append(_issue(
                    "PUBLIC_CAPABILITY_EVIDENCE_KIND_INVALID",
                    evidence_location, str(kind or ""),
                ))
        for relative in item.get("whitebox_paths") or ():
            if not (root / str(relative)).is_file():
                issues.append(_issue(
                    "PUBLIC_CAPABILITY_WHITEBOX_EVIDENCE_MISSING",
                    item_location, str(relative),
                ))
        for selector in item.get("performance_selectors") or ():
            if str(selector) not in policy_performance:
                issues.append(_issue(
                    "PUBLIC_CAPABILITY_PERFORMANCE_EVIDENCE_INVALID",
                    item_location, str(selector),
                ))
        mapped_steps.update(str(value) for value in item.get("workflow_steps") or ())
        mapped_support_sections.update(
            str(value) for value in item.get("support_sections") or ()
        )

    for case_id, capability_tags in case_capabilities.items():
        for tag in sorted(capability_tags):
            entry = by_id.get(tag)
            if entry is None:
                issues.append(_issue(
                    "BLACKBOX_CASE_CAPABILITY_NOT_IN_PUBLIC_MATRIX",
                    location, f"{case_id}:{tag}",
                ))
                continue
            blackbox = entry.get("blackbox") or {}
            if blackbox.get("status") != "covered":
                issues.append(_issue(
                    "BLACKBOX_CASE_CAPABILITY_MATRIX_MISMATCH",
                    location, f"{case_id}:{tag}",
                ))

    missing_entrypoints = sorted(allowed_entrypoints - mapped_entrypoints)
    if missing_entrypoints:
        issues.append(_issue(
            "PUBLIC_ENTRYPOINT_NOT_IN_CAPABILITY_MATRIX", location,
            ",".join(missing_entrypoints),
        ))
    try:
        step_manifest = _load_json(root / "scripts" / "step_manifest.json")
        required_steps = {
            str(item.get("id") or "")
            for item in step_manifest.get("steps") or ()
            if isinstance(item, Mapping) and item.get("id")
        }
    except (OSError, UnicodeError, json.JSONDecodeError):
        required_steps = set()
        issues.append(_issue(
            "PUBLIC_CAPABILITY_STEP_MANIFEST_UNREADABLE", location,
        ))
    missing_steps = sorted(required_steps - mapped_steps)
    if missing_steps:
        issues.append(_issue(
            "PUBLIC_WORKFLOW_STEP_NOT_IN_CAPABILITY_MATRIX", location,
            ",".join(missing_steps),
        ))
    support_manifest: Mapping[str, Any] = {}
    try:
        support_manifest = _load_json(
            root / "scripts" / "binary_first_support_manifest.json"
        )
        required_support_sections = {
            str(key) for key in support_manifest.keys()
            if key not in {"schema", "status", "authority", "phase_contract"}
        }
    except (OSError, UnicodeError, json.JSONDecodeError):
        required_support_sections = set()
        issues.append(_issue(
            "PUBLIC_CAPABILITY_SUPPORT_MANIFEST_UNREADABLE", location,
        ))
    missing_support = sorted(required_support_sections - mapped_support_sections)
    if missing_support:
        issues.append(_issue(
            "PUBLIC_SUPPORT_SECTION_NOT_IN_CAPABILITY_MATRIX", location,
            ",".join(missing_support),
        ))
    required_support_claims = _support_claim_paths(support_manifest)
    raw_claim_coverage = matrix.get("support_claim_coverage")
    claim_coverage = (
        raw_claim_coverage if isinstance(raw_claim_coverage, Mapping) else {}
    )
    if not isinstance(raw_claim_coverage, Mapping):
        issues.append(_issue("PUBLIC_SUPPORT_CLAIM_COVERAGE_INVALID", location))
    mapped_claims = set(str(value) for value in claim_coverage)
    missing_claims = sorted(required_support_claims - mapped_claims)
    unknown_claims = sorted(mapped_claims - required_support_claims)
    if missing_claims:
        issues.append(_issue(
            "PUBLIC_SUPPORT_CLAIM_NOT_IN_CAPABILITY_MATRIX", location,
            ",".join(missing_claims),
        ))
    if unknown_claims:
        issues.append(_issue(
            "PUBLIC_SUPPORT_CLAIM_NO_LONGER_DECLARED", location,
            ",".join(unknown_claims),
        ))
    for claim, raw_ids in claim_coverage.items():
        claim_location = f"{location}:{claim}"
        if (
            not isinstance(raw_ids, list) or not raw_ids
            or any(not isinstance(value, str) or not value for value in raw_ids)
        ):
            issues.append(_issue(
                "PUBLIC_SUPPORT_CLAIM_CAPABILITIES_INVALID", claim_location,
            ))
            continue
        for capability_id in raw_ids:
            capability = by_id.get(capability_id)
            if capability is None:
                issues.append(_issue(
                    "PUBLIC_SUPPORT_CLAIM_CAPABILITY_MISSING", claim_location,
                    capability_id,
                ))
            elif (capability.get("blackbox") or {}).get("status") != "covered":
                issues.append(_issue(
                    "PUBLIC_SUPPORT_CLAIM_CAPABILITY_NOT_COVERED", claim_location,
                    capability_id,
                ))

    scenario_issues, scenario_coverage = _scenario_contract_for_capabilities(
        root, policy, capabilities, case_capabilities,
    )
    issues.extend(scenario_issues)
    readiness = {
        "status": (
            "complete"
            if not blocking_capabilities and not issues
            else "incomplete" if not issues else "invalid"
        ),
        "matrix": location,
        **status_counts,
        "total": len(capabilities),
        "blocking_capabilities": sorted(blocking_capabilities),
        "scenario_contracts": len(scenario_coverage),
        "scenario_dimensions": sum(
            len(values) for values in scenario_coverage.values()
        ),
        "support_claims": len(required_support_claims),
    }
    return issues, readiness


def run_trust_gate(
    repository_root: str | Path = ROOT,
    policy_path: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    policy_file = Path(policy_path).resolve() if policy_path else (
        root / "tests" / "fixtures" / "test_suite_policy.json"
    )
    issues: list[dict[str, str]] = []
    try:
        policy = _load_json(policy_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return {
            "schema": "java-upgrade-analyzer.test-trust-gate.v1",
            "status": "failed",
            "issues": [_issue(
                "TEST_SUITE_POLICY_UNREADABLE", str(policy_file),
                f"{type(error).__name__}: {error}",
            )],
        }
    if not isinstance(policy, Mapping):
        return {
            "schema": "java-upgrade-analyzer.test-trust-gate.v1",
            "status": "failed",
            "issues": [_issue(
                "TEST_SUITE_POLICY_DOCUMENT_INVALID", str(policy_file),
            )],
        }
    if policy.get("schema") != "java-upgrade-analyzer.test-suite-policy.v1":
        issues.append(_issue("TEST_SUITE_POLICY_SCHEMA_INVALID", str(policy_file)))

    blackbox_sources: list[Path] = []
    for relative_root in policy.get("blackbox_test_roots") or ():
        source_root = (root / str(relative_root)).resolve()
        if not source_root.is_dir():
            issues.append(_issue(
                "BLACKBOX_TEST_ROOT_MISSING", str(relative_root),
            ))
            continue
        blackbox_sources.extend(sorted(source_root.rglob("*.py")))
    issues.extend(audit_blackbox_sources(root, blackbox_sources))

    blackbox_string_literals: set[str] = set()
    for source in blackbox_sources:
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError):
            continue
        blackbox_string_literals.update(
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )

    raw_supplemental_globs = policy.get("supplemental_blackbox_truth_globs")
    if (
        not isinstance(raw_supplemental_globs, list)
        or not raw_supplemental_globs
        or any(not isinstance(value, str) or not value for value in raw_supplemental_globs)
    ):
        issues.append(_issue(
            "SUPPLEMENTAL_TRUTH_GLOBS_POLICY_INVALID", str(policy_file),
        ))
        raw_supplemental_globs = []
    supplemental_paths = sorted({
        path.resolve()
        for pattern in raw_supplemental_globs
        for path in root.glob(pattern)
        if path.is_file()
    })
    supplemental_case_ids: list[str] = []
    supplemental_expectation_leaves = 0
    for truth_path in supplemental_paths:
        location = truth_path.relative_to(root).as_posix()
        try:
            truth = _load_json(truth_path)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            issues.append(_issue(
                "SUPPLEMENTAL_TRUTH_UNREADABLE", location,
                f"{type(error).__name__}: {error}",
            ))
            continue
        issues.extend(validate_supplemental_truth_document(
            truth, policy, location=location,
        ))
        if isinstance(truth, Mapping):
            supplemental_case_ids.append(str(truth.get("case_id") or ""))
            supplemental_expectation_leaves += _authored_expectation_leaves(truth)
        if truth_path.name not in blackbox_string_literals:
            issues.append(_issue(
                "SUPPLEMENTAL_TRUTH_NOT_REFERENCED_BY_BLACKBOX_TEST", location,
            ))
    if len(supplemental_case_ids) != len(set(supplemental_case_ids)):
        issues.append(_issue(
            "SUPPLEMENTAL_TRUTH_CASE_ID_DUPLICATE", str(policy_file),
        ))

    case_paths = sorted(root.glob(str(policy.get("blackbox_case_glob") or "")))
    if not case_paths:
        issues.append(_issue("BLACKBOX_CASE_SET_EMPTY", str(policy_file)))
    truth_result_count = 0
    forbidden_result_count = 0
    case_ids = []
    case_capabilities: dict[str, set[str]] = {}
    covered_capabilities: set[str] = set()
    for case_path in case_paths:
        try:
            case_metadata = _load_json(case_path)
        except (OSError, UnicodeError, json.JSONDecodeError):
            case_metadata = {}
        if isinstance(case_metadata, Mapping):
            case_id = str(case_metadata.get("case_id") or "")
            case_ids.append(case_id)
            capabilities = case_metadata.get("capabilities")
            if isinstance(capabilities, list):
                case_tags = {
                    str(value) for value in capabilities
                    if isinstance(value, str)
                }
                covered_capabilities.update(case_tags)
                case_capabilities[case_id] = case_tags
        case_issues, result_count = _validate_case(root, case_path, policy)
        issues.extend(case_issues)
        truth_result_count += result_count
        try:
            truth_name = str(case_metadata.get("truth_file") or "")
            truth_document = _load_json(case_path.parent / truth_name)
            if isinstance(truth_document, Mapping):
                forbidden = truth_document.get("forbidden_results")
                if isinstance(forbidden, list):
                    forbidden_result_count += len(forbidden)
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass
    if len(case_ids) != len(set(case_ids)):
        issues.append(_issue("BLACKBOX_CASE_ID_DUPLICATE", str(policy_file)))
    required_case_ids = set(policy.get("required_blackbox_case_ids") or ())
    missing_case_ids = sorted(required_case_ids - set(case_ids))
    if missing_case_ids:
        issues.append(_issue(
            "BLACKBOX_REQUIRED_CASE_MISSING", str(policy_file),
            ",".join(missing_case_ids),
        ))
    undeclared_case_ids = sorted(set(case_ids) - required_case_ids)
    if undeclared_case_ids:
        issues.append(_issue(
            "BLACKBOX_CASE_NOT_REQUIRED_BY_POLICY", str(policy_file),
            ",".join(undeclared_case_ids),
        ))
    required_capabilities = set(
        policy.get("required_blackbox_capabilities") or ()
    )
    missing_capabilities = sorted(
        required_capabilities - covered_capabilities
    )
    if missing_capabilities:
        issues.append(_issue(
            "BLACKBOX_REQUIRED_CAPABILITY_MISSING", str(policy_file),
            ",".join(missing_capabilities),
        ))
    undeclared_capabilities = sorted(
        covered_capabilities - required_capabilities
    )
    if undeclared_capabilities:
        issues.append(_issue(
            "BLACKBOX_CAPABILITY_NOT_REQUIRED_BY_POLICY", str(policy_file),
            ",".join(undeclared_capabilities),
        ))

    matrix_relative = str(policy.get("public_capability_matrix") or "")
    if not matrix_relative:
        issues.append(_issue(
            "PUBLIC_CAPABILITY_MATRIX_POLICY_MISSING", str(policy_file),
        ))
        capability_readiness = {
            "status": "invalid", "matrix": "",
            "covered": 0, "partial": 0, "missing": 0, "total": 0,
            "blocking_capabilities": [],
        }
    else:
        matrix_issues, capability_readiness = audit_public_capability_matrix(
            root, matrix_relative, policy, case_capabilities,
        )
        issues.extend(matrix_issues)

    minimum_counts = {
        "blackbox_cases": len(case_paths),
        "closed_truth_results": truth_result_count,
        "forbidden_truth_results": forbidden_result_count,
        "supplemental_truth_documents": len(supplemental_paths),
        "blackbox_assertion_sites": _blackbox_assertion_sites(blackbox_sources),
        "supplemental_expectation_leaves": supplemental_expectation_leaves,
        "public_scenario_contracts": capability_readiness.get(
            "scenario_contracts", 0
        ),
        "public_scenario_dimensions": capability_readiness.get(
            "scenario_dimensions", 0
        ),
        "public_support_claims": capability_readiness.get("support_claims", 0),
    }
    minimum_fields = {
        "blackbox_cases": "minimum_blackbox_cases",
        "closed_truth_results": "minimum_closed_truth_results",
        "forbidden_truth_results": "minimum_forbidden_truth_results",
        "supplemental_truth_documents": (
            "minimum_supplemental_blackbox_truth_documents"
        ),
        "blackbox_assertion_sites": "minimum_blackbox_assertion_sites",
        "supplemental_expectation_leaves": (
            "minimum_supplemental_expectation_leaves"
        ),
        "public_scenario_contracts": "minimum_public_scenario_contracts",
        "public_scenario_dimensions": "minimum_public_scenario_dimensions",
        "public_support_claims": "minimum_public_support_claims",
    }
    for count_name, actual_count in minimum_counts.items():
        policy_field = minimum_fields[count_name]
        required_count = policy.get(policy_field)
        if (
            not isinstance(required_count, int)
            or isinstance(required_count, bool)
            or required_count <= 0
        ):
            issues.append(_issue(
                "BLACKBOX_MINIMUM_POLICY_INVALID", str(policy_file),
                policy_field,
            ))
        elif actual_count < required_count:
            issues.append(_issue(
                "BLACKBOX_COVERAGE_FLOOR_NOT_MET", str(policy_file),
                f"{count_name}:required={required_count},actual={actual_count}",
            ))

    selectors = [str(value) for value in policy.get("performance_test_selectors") or ()]
    if not selectors:
        issues.append(_issue("PERFORMANCE_SELECTOR_SET_EMPTY", str(policy_file)))
    if len(selectors) != len(set(selectors)):
        issues.append(_issue("PERFORMANCE_SELECTOR_DUPLICATE", str(policy_file)))
    for selector in selectors:
        if selector == "tests.blackbox" or selector.startswith("tests.blackbox."):
            issues.append(_issue(
                "TEST_SUITE_SELECTOR_OVERLAP", str(policy_file), selector,
            ))
        module = _selector_module(selector)
        module_path = root / (module.replace(".", "/") + ".py")
        package_path = root / module.replace(".", "/") / "__init__.py"
        if not module_path.is_file() and not package_path.is_file():
            issues.append(_issue(
                "PERFORMANCE_SELECTOR_MODULE_MISSING", str(policy_file), selector,
            ))

    unique_issues = sorted(
        {json.dumps(issue, ensure_ascii=False, sort_keys=True) for issue in issues}
    )
    normalized_issues = [json.loads(item) for item in unique_issues]
    return {
        "schema": "java-upgrade-analyzer.test-trust-gate.v1",
        "status": "passed" if not normalized_issues else "failed",
        "policy": str(policy_file),
        "counts": {
            "blackbox_python_files": len(blackbox_sources),
            "blackbox_cases": len(case_paths),
            "closed_truth_results": truth_result_count,
            "forbidden_truth_results": forbidden_result_count,
            "supplemental_truth_documents": len(supplemental_paths),
            "blackbox_assertion_sites": minimum_counts[
                "blackbox_assertion_sites"
            ],
            "supplemental_expectation_leaves": supplemental_expectation_leaves,
            "blackbox_capabilities": len(covered_capabilities),
            "public_capabilities": capability_readiness.get("total", 0),
            "public_capabilities_covered": capability_readiness.get(
                "covered", 0
            ),
            "public_capabilities_partial": capability_readiness.get(
                "partial", 0
            ),
            "public_capabilities_missing": capability_readiness.get(
                "missing", 0
            ),
            "performance_selectors": len(selectors),
            "public_scenario_contracts": capability_readiness.get(
                "scenario_contracts", 0
            ),
            "public_scenario_dimensions": capability_readiness.get(
                "scenario_dimensions", 0
            ),
            "public_support_claims": capability_readiness.get(
                "support_claims", 0
            ),
        },
        "capability_readiness": capability_readiness,
        "classification": {
            "blackbox": list(policy.get("blackbox_test_roots") or ()),
            "performance": selectors,
            "whitebox": "all discovered tests not selected above",
        },
        "issues": normalized_issues,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit test-suite trust contracts")
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--policy", default="")
    parser.add_argument("--json-out", default="")
    args = parser.parse_args(argv)
    result = run_trust_gate(args.root, args.policy or None)
    if args.json_out:
        target = Path(args.json_out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
