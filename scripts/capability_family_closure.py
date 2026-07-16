#!/usr/bin/env python3
"""Validate executable closure evidence for architecture capability families."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import unittest


ALLOWED_ROOT_CAUSE_FAMILIES = {
    "artifact_provenance",
    "business_activation_not_proven",
    "coverage_scope",
    "error_visibility",
    "evidence_identity",
    "framework_semantics",
    "new_architecture_gap",
    "oracle_gap",
    "output_contract",
    "ownership_classification",
    "performance_complexity",
    "static_evidence_limit",
    "test_asset_invalid",
    "workflow_gate",
}
TEST_FIELDS = ("positive_tests", "negative_tests", "mutation_tests")
ALLOWED_STATES = {"open", "enforced"}


def load_registry(path: Path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("capability registry must be a JSON object")
    return payload


def _string_list(value) -> list[str] | None:
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) and item.strip() for item in value):
        return None
    return [item.strip() for item in value]


def validate_registry(registry: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(registry, dict):
        return ["registry_not_object"]
    if registry.get("schema_version") != 1:
        errors.append("unsupported_schema_version")
    families = registry.get("families")
    if not isinstance(families, list) or not families:
        return errors + ["missing_families"]

    seen_family_ids: set[str] = set()
    seen_invariant_ids: set[str] = set()
    for index, family in enumerate(families):
        if not isinstance(family, dict):
            errors.append(f"family_not_object:{index}")
            continue
        family_id = str(family.get("family_id") or "").strip()
        if not family_id:
            errors.append(f"missing_family_id:{index}")
            family_id = f"index-{index}"
        elif family_id in seen_family_ids:
            errors.append(f"duplicate_family_id:{family_id}")
        seen_family_ids.add(family_id)

        invariant_id = str(family.get("invariant_id") or "").strip()
        if not invariant_id:
            errors.append(f"missing_invariant_id:{family_id}")
        elif invariant_id in seen_invariant_ids:
            errors.append(f"duplicate_invariant_id:{invariant_id}")
        seen_invariant_ids.add(invariant_id)
        if not str(family.get("invariant") or "").strip():
            errors.append(f"missing_invariant:{family_id}")

        state = str(family.get("state") or "").strip()
        if state not in ALLOWED_STATES:
            errors.append(f"invalid_state:{family_id}:{state}")

        root_causes = _string_list(family.get("root_cause_families"))
        if not root_causes:
            errors.append(f"missing_root_cause_families:{family_id}")
        else:
            for root_cause in root_causes:
                if root_cause not in ALLOWED_ROOT_CAUSE_FAMILIES:
                    errors.append(
                        f"unknown_root_cause_family:{family_id}:{root_cause}"
                    )

        production_paths = _string_list(family.get("production_paths"))
        if not production_paths:
            errors.append(f"missing_production_paths:{family_id}")

        all_test_references: list[str] = []
        for field in TEST_FIELDS:
            references = _string_list(family.get(field))
            if state == "enforced" and not references:
                errors.append(f"missing_{field}:{family_id}")
            all_test_references.extend(references or [])
        seen_tests: set[str] = set()
        for reference in all_test_references:
            if reference in seen_tests:
                errors.append(f"duplicate_test_reference:{family_id}:{reference}")
            seen_tests.add(reference)

        guards = _string_list(family.get("cross_project_guards"))
        if guards is None:
            errors.append(f"invalid_cross_project_guards:{family_id}")
        if type(family.get("architecture_review_on_repeat")) is not bool:
            errors.append(f"invalid_architecture_review_on_repeat:{family_id}")

    return errors


def _resolves_to_unittest(reference: str) -> bool:
    if not reference.startswith("tests."):
        return False
    try:
        suite = unittest.defaultTestLoader.loadTestsFromName(reference)
    except (AttributeError, ImportError, TypeError, ValueError):
        return False

    def contains_failed_test(node) -> bool:
        if isinstance(node, unittest.TestSuite):
            return any(contains_failed_test(child) for child in node)
        return type(node).__name__ == "_FailedTest"

    return suite.countTestCases() > 0 and not contains_failed_test(suite)


def _history_root_causes(history) -> set[str]:
    if not isinstance(history, list):
        return set()
    repeated: set[str] = set()
    for entry in history:
        if not isinstance(entry, dict):
            continue
        values = entry.get("root_cause_families") or []
        if isinstance(values, list):
            repeated.update(str(value) for value in values if str(value).strip())
    return repeated


def build_closure_report(
    registry: dict,
    real_payload: dict,
    reviews: dict,
    history: list,
    *,
    project_root: Path,
    retrospective_payload: dict | None = None,
) -> dict:
    errors = list(validate_registry(registry))
    families = {
        str(family.get("family_id") or ""): family
        for family in registry.get("families") or []
        if isinstance(family, dict)
    }
    current_guard_results = {
        str(result.get("case") or ""): result
        for result in real_payload.get("results") or []
        if isinstance(result, dict)
    }
    repeated_root_causes = _history_root_causes(history)
    review_rows = reviews.get("findings") if isinstance(reviews, dict) else None
    if not isinstance(review_rows, list):
        review_rows = []
        errors.append("reviews_findings_missing")
    reviewed_ids = {
        str(review.get("finding_id") or "")
        for review in review_rows
        if isinstance(review, dict) and str(review.get("finding_id") or "")
    }
    if retrospective_payload is not None:
        retrospective_findings = retrospective_payload.get("findings")
        if not isinstance(retrospective_findings, list):
            errors.append("retrospective_findings_missing")
        else:
            for finding in retrospective_findings:
                if not isinstance(finding, dict):
                    errors.append("retrospective_finding_not_object")
                    continue
                finding_id = str(finding.get("finding_id") or "")
                if finding_id and finding_id not in reviewed_ids:
                    errors.append(
                        f"retrospective_finding_review_missing:{finding_id}"
                    )

    findings = []
    for index, review in enumerate(review_rows):
        if not isinstance(review, dict):
            errors.append(f"review_not_object:{index}")
            continue
        finding_id = str(review.get("finding_id") or f"index-{index}")
        finding_errors: list[str] = []
        family_id = str(review.get("capability_family") or "")
        family = families.get(family_id)
        if family is None:
            finding_errors.append(f"unknown_capability_family:{finding_id}:{family_id}")
            family = {}
        root_cause = str(review.get("root_cause_family") or "")
        if root_cause not in (family.get("root_cause_families") or []):
            finding_errors.append(f"root_cause_family_mismatch:{finding_id}:{root_cause}")
        invariant_id = str(review.get("invariant_id") or "")
        if invariant_id != str(family.get("invariant_id") or ""):
            finding_errors.append(f"invariant_mismatch:{finding_id}:{invariant_id}")

        status = str(review.get("status") or "")
        if status == "fixed":
            if str(review.get("resolution_scope") or "") == "case_patch":
                finding_errors.append(f"case_patch_forbidden:{finding_id}")
            if str(family.get("state") or "") != "enforced":
                finding_errors.append(f"capability_family_not_enforced:{finding_id}:{family_id}")

            expected_paths = set(_string_list(family.get("production_paths")) or [])
            audited_paths = set(
                _string_list(review.get("audited_production_paths")) or []
            )
            if audited_paths != expected_paths:
                finding_errors.append(
                    f"production_path_coverage_mismatch:{finding_id}"
                )
            for path in sorted(expected_paths):
                if not (Path(project_root) / path).is_file():
                    finding_errors.append(f"production_path_missing:{finding_id}:{path}")

            review_test_fields = {
                "positive_tests": "generalized_regression_tests",
                "negative_tests": "negative_regression_tests",
                "mutation_tests": "mutation_tests",
            }
            for registry_field, review_field in review_test_fields.items():
                expected = set(_string_list(family.get(registry_field)) or [])
                actual = set(_string_list(review.get(review_field)) or [])
                if actual != expected:
                    label = {
                        "positive_tests": "generalized_test",
                        "negative_tests": "negative_test",
                        "mutation_tests": "mutation_test",
                    }[registry_field]
                    finding_errors.append(f"{label}_coverage_mismatch:{finding_id}")
                for reference in sorted(expected):
                    if not _resolves_to_unittest(reference):
                        finding_errors.append(
                            f"unloadable_test_reference:{finding_id}:{reference}"
                        )

            expected_guards = set(
                _string_list(family.get("cross_project_guards")) or []
            )
            actual_guards = set(
                _string_list(review.get("cross_project_guards")) or []
            )
            if actual_guards != expected_guards:
                finding_errors.append(f"cross_project_guard_coverage_mismatch:{finding_id}")
            for guard in sorted(expected_guards):
                guard_result = current_guard_results.get(guard) or {}
                if str(guard_result.get("status") or "") != "passed":
                    finding_errors.append(
                        f"cross_project_guard_not_passed:{finding_id}:{guard}"
                    )
                oracle_audit = guard_result.get("oracle_audit")
                if isinstance(oracle_audit, dict) and oracle_audit:
                    selected = int(oracle_audit.get("selected") or 0)
                    verified = int(oracle_audit.get("verified") or 0)
                    oracle_incomplete = (
                        bool(oracle_audit.get("blocking"))
                        or selected <= 0
                        or verified != selected
                        or int(oracle_audit.get("unverified") or 0) != 0
                        or int(oracle_audit.get("incorrect") or 0) != 0
                        or int(oracle_audit.get("oracle_conflicts") or 0) != 0
                    )
                    if oracle_incomplete:
                        finding_errors.append(
                            "cross_project_guard_oracle_incomplete:"
                            f"{finding_id}:{guard}"
                        )

            if (
                root_cause in repeated_root_causes
                and family.get("architecture_review_on_repeat") is True
                and not str(review.get("architecture_decision") or "").strip()
            ):
                finding_errors.append(
                    f"architecture_decision_required:{finding_id}:{root_cause}"
                )

        errors.extend(finding_errors)
        findings.append({
            "finding_id": finding_id,
            "capability_family": family_id,
            "invariant_id": invariant_id,
            "status": status,
            "errors": finding_errors,
        })

    return {
        "schema_version": 1,
        "status": "failed" if errors else "passed",
        "errors": errors,
        "findings": findings,
    }


def evaluate_closure(report: dict) -> list[str]:
    if not isinstance(report, dict):
        return ["closure_report_not_object"]
    errors = report.get("errors")
    if not isinstance(errors, list):
        return ["closure_report_errors_missing"]
    return [str(error) for error in errors]


def _read_json(path: Path, label: str, errors: list[str], default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label}_input_error:{type(exc).__name__}:{exc}")
        return default


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Gate architecture capability-family closure evidence."
    )
    parser.add_argument("registry")
    parser.add_argument("real_project_result")
    parser.add_argument("--reviews", required=True)
    parser.add_argument("--history", required=True)
    parser.add_argument("--retrospective", required=True)
    parser.add_argument("--json-out", required=True)
    args = parser.parse_args(argv)

    input_errors: list[str] = []
    registry = _read_json(Path(args.registry), "registry", input_errors, {})
    real_payload = _read_json(
        Path(args.real_project_result), "real_project", input_errors, {}
    )
    reviews = _read_json(Path(args.reviews), "reviews", input_errors, {"findings": []})
    history = _read_json(Path(args.history), "history", input_errors, [])
    retrospective = _read_json(
        Path(args.retrospective), "retrospective", input_errors, {}
    )
    try:
        report = build_closure_report(
            registry,
            real_payload,
            reviews,
            history,
            project_root=Path(__file__).resolve().parents[1],
            retrospective_payload=retrospective,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        report = {
            "schema_version": 1,
            "status": "failed",
            "errors": [f"closure_build_error:{type(exc).__name__}:{exc}"],
            "findings": [],
        }
    if input_errors:
        report["errors"] = input_errors + list(report.get("errors") or [])
        report["status"] = "failed"
    output = Path(args.json_out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if evaluate_closure(report) else 0


if __name__ == "__main__":
    sys.exit(main())
