#!/usr/bin/env python3
"""Audit escaped-defect regression ownership and merge-gate execution.

The public capability matrix answers which declared capabilities have tests.
This gate answers a different question: whether every product defect that has
already escaped is permanently tied to independently authored truth, an exact
test method, a nearby counterexample, and at least one pre-merge profile.

It never runs product code or adds a runtime validation.  It is a developer/CI
quality check intended to prevent a regression from remaining in the tree but
silently falling out of the commands that protect a change.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import unittest
from typing import Any, Iterable, Mapping

import quality_gate
from test_suite_runner import (
    classify_test_id,
    discover_tests,
    iter_tests,
    load_policy,
    load_windows_tests,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = (
    ROOT / "tests" / "fixtures" / "escaped_defect_regressions.json"
)
SCHEMA = "java-upgrade-analyzer.escaped-defect-regressions.v1"
DEFECT_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ALLOWED_RISKS = frozenset({"critical", "high", "medium", "low"})
ALLOWED_ROLES = frozenset({"blackbox", "whitebox", "performance", "platform"})
ALLOWED_PROFILES = frozenset({
    "quick", "step5", "blackbox", "whitebox", "performance", "windows",
    "release",
})
PRE_MERGE_PROFILES = frozenset({
    "quick", "blackbox", "whitebox", "performance", "windows",
})


def _issue(code: str, location: str, detail: str = "") -> dict[str, str]:
    return {"code": code, "location": location, "detail": detail}


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _root_path(root: Path, value: Any) -> Path | None:
    if not _nonempty_text(value):
        return None
    candidate = (root / str(value)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _json_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return False, None
    value = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, Mapping) and token in value:
            value = value[token]
            continue
        if isinstance(value, list) and token.isdigit():
            index = int(token)
            if index < len(value):
                value = value[index]
                continue
        return False, None
    return True, value


def _authored_value(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, (list, dict)) and not value:
        return False
    return True


def _load_exact_test(selector: str) -> tuple[list[str], list[str]]:
    loaded = unittest.defaultTestLoader.loadTestsFromName(selector)
    tests = list(iter_tests(loaded))
    failures = [
        test.id() for test in tests
        if test.__class__.__name__ == "_FailedTest"
    ]
    return [test.id() for test in tests if test.id() not in failures], failures


def _selector_covers(test_id: str, selector: str) -> bool:
    normalized = selector.rstrip(".")
    return test_id == normalized or test_id.startswith(normalized + ".")


def _profile_coverage(root: Path) -> dict[str, Any]:
    policy = load_policy(root / "tests" / "fixtures" / "test_suite_policy.json")
    discovered = discover_tests(root)
    discovered_ids = {test.id() for test in discovered}
    windows, windows_gaps = load_windows_tests(policy, root)
    return {
        "policy": policy,
        "discovered": discovered_ids,
        "blackbox": {
            test_id for test_id in discovered_ids
            if classify_test_id(test_id, policy) == "blackbox"
        },
        "whitebox": {
            test_id for test_id in discovered_ids
            if classify_test_id(test_id, policy) == "whitebox"
        },
        "performance": {
            test_id for test_id in discovered_ids
            if classify_test_id(test_id, policy) == "performance"
        },
        "windows": {test.id() for test in windows},
        "windows_gaps": windows_gaps,
    }


def _covered_by_profile(
    test_id: str, profile: str, coverage: Mapping[str, Any],
) -> bool:
    if profile == "quick":
        return any(
            _selector_covers(test_id, selector)
            for selector in quality_gate.QUICK_MODULES
        )
    if profile == "step5":
        return any(
            _selector_covers(test_id, selector)
            for selector in quality_gate.STEP5_MODULES
        )
    if profile == "release":
        return test_id in coverage["discovered"]
    return test_id in coverage[profile]


def _audit_truth(
    root: Path,
    truth: Mapping[str, Any],
    *,
    location: str,
) -> tuple[list[dict[str, str]], int]:
    issues: list[dict[str, str]] = []
    path = _root_path(root, truth.get("path"))
    if path is None or not path.is_file():
        return [
            _issue("DEFECT_TRUTH_MISSING", location, str(truth.get("path") or ""))
        ], 0
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return [
            _issue(
                "DEFECT_TRUTH_INVALID", location,
                f"{type(error).__name__}: {error}",
            )
        ], 0
    if not isinstance(document, Mapping):
        issues.append(_issue("DEFECT_TRUTH_INVALID", location, "not an object"))
        return issues, 0
    if document.get("system_generated") is not False:
        issues.append(_issue("DEFECT_TRUTH_NOT_INDEPENDENT", location))
    producers = document.get("oracle_producers")
    mechanisms = {
        str(item.get("mechanism") or "").strip()
        for item in producers or () if isinstance(item, Mapping)
    }
    mechanisms.discard("")
    if not isinstance(producers, list) or len(mechanisms) < 2:
        issues.append(_issue(
            "DEFECT_TRUTH_ORACLE_DIVERSITY_INSUFFICIENT",
            location,
            f"independent_mechanisms={len(mechanisms)}",
        ))
    pointers = truth.get("control_pointers")
    if not isinstance(pointers, list) or not pointers:
        issues.append(_issue("DEFECT_COUNTEREXAMPLE_MISSING", location))
        return issues, 0
    valid_controls = 0
    for index, pointer in enumerate(pointers):
        pointer_location = f"{location}.control_pointers[{index}]"
        found, value = _json_pointer(document, pointer)
        if not found:
            issues.append(_issue(
                "DEFECT_TRUTH_POINTER_MISSING", pointer_location, str(pointer)
            ))
        elif not _authored_value(value):
            issues.append(_issue(
                "DEFECT_TRUTH_POINTER_EMPTY", pointer_location, str(pointer)
            ))
        else:
            valid_controls += 1
    return issues, valid_controls


def audit_defect_regressions(
    repository_root: str | Path = ROOT,
    registry_path: str | Path = DEFAULT_REGISTRY,
) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    path = Path(registry_path).resolve()
    issues: list[dict[str, str]] = []
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        registry = {}
        issues.append(_issue(
            "DEFECT_REGISTRY_INVALID", str(path),
            f"{type(error).__name__}: {error}",
        ))
    if not isinstance(registry, Mapping) or registry.get("schema") != SCHEMA:
        issues.append(_issue("DEFECT_REGISTRY_SCHEMA_INVALID", str(path)))
    defects = registry.get("defects") if isinstance(registry, Mapping) else None
    if not isinstance(defects, list):
        defects = []
        issues.append(_issue("DEFECT_REGISTRY_ENTRIES_INVALID", str(path)))
    minimum = registry.get("minimum_registered_defects", 0)
    if (
        not isinstance(minimum, int) or isinstance(minimum, bool)
        or minimum <= 0 or len(defects) < minimum
    ):
        issues.append(_issue(
            "DEFECT_REGISTRY_FLOOR_NOT_MET", str(path),
            f"actual={len(defects)} minimum={minimum}",
        ))

    try:
        coverage = _profile_coverage(root)
    except Exception as error:  # noqa: BLE001 - emit all audit failures as data
        coverage = {}
        issues.append(_issue(
            "DEFECT_PROFILE_DISCOVERY_FAILED", str(path),
            f"{type(error).__name__}: {error}",
        ))
    if coverage.get("windows_gaps"):
        issues.append(_issue(
            "DEFECT_WINDOWS_PROFILE_HAS_SELECTOR_GAPS", str(path),
            ",".join(coverage["windows_gaps"]),
        ))

    seen_ids: set[str] = set()
    regression_count = 0
    truth_binding_count = 0
    truth_documents: set[Path] = set()
    control_count = 0
    profile_bindings = 0
    for index, defect in enumerate(defects):
        location = f"defects[{index}]"
        if not isinstance(defect, Mapping):
            issues.append(_issue("DEFECT_ENTRY_INVALID", location))
            continue
        defect_id = str(defect.get("id") or "")
        if not DEFECT_ID.fullmatch(defect_id):
            issues.append(_issue("DEFECT_ID_INVALID", location, defect_id))
        elif defect_id in seen_ids:
            issues.append(_issue("DEFECT_ID_DUPLICATE", location, defect_id))
        seen_ids.add(defect_id)
        for field in (
            "title", "observed_behavior", "correct_behavior",
            "root_cause_family", "escape_reason", "resolution_scope",
        ):
            if not _nonempty_text(defect.get(field)):
                issues.append(_issue(
                    "DEFECT_REQUIRED_FIELD_MISSING", f"{location}.{field}"
                ))
        if defect.get("resolution_scope") == "case_patch":
            issues.append(_issue("DEFECT_CASE_PATCH_FORBIDDEN", location))
        if defect.get("risk") not in ALLOWED_RISKS:
            issues.append(_issue("DEFECT_RISK_INVALID", location))

        source_evidence = defect.get("source_evidence")
        if not isinstance(source_evidence, list) or not source_evidence:
            issues.append(_issue("DEFECT_SOURCE_EVIDENCE_MISSING", location))
        else:
            for source_index, source in enumerate(source_evidence):
                source_path = _root_path(root, source)
                if source_path is None or not source_path.is_file():
                    issues.append(_issue(
                        "DEFECT_SOURCE_EVIDENCE_MISSING",
                        f"{location}.source_evidence[{source_index}]",
                        str(source),
                    ))

        truths = defect.get("truth_evidence")
        if not isinstance(truths, list) or not truths:
            issues.append(_issue("DEFECT_TRUTH_MISSING", location))
            truths = []
        for truth_index, truth in enumerate(truths):
            truth_location = f"{location}.truth_evidence[{truth_index}]"
            if not isinstance(truth, Mapping):
                issues.append(_issue("DEFECT_TRUTH_INVALID", truth_location))
                continue
            truth_issues, controls = _audit_truth(
                root, truth, location=truth_location,
            )
            issues.extend(truth_issues)
            truth_binding_count += 1
            truth_path = _root_path(root, truth.get("path"))
            if truth_path is not None and truth_path.is_file():
                truth_documents.add(truth_path)
            control_count += controls

        regressions = defect.get("regressions")
        if not isinstance(regressions, list) or not regressions:
            issues.append(_issue("DEFECT_REGRESSION_MISSING", location))
            continue
        has_blackbox = False
        has_pre_merge = False
        selectors_in_defect: set[str] = set()
        for regression_index, regression in enumerate(regressions):
            regression_location = f"{location}.regressions[{regression_index}]"
            if not isinstance(regression, Mapping):
                issues.append(_issue("DEFECT_REGRESSION_INVALID", regression_location))
                continue
            selector = str(regression.get("selector") or "").strip()
            role = regression.get("role")
            profiles = regression.get("required_profiles")
            if role not in ALLOWED_ROLES:
                issues.append(_issue("DEFECT_REGRESSION_ROLE_INVALID", regression_location))
            has_blackbox = has_blackbox or role == "blackbox"
            if selector in selectors_in_defect:
                issues.append(_issue(
                    "DEFECT_REGRESSION_DUPLICATE", regression_location, selector
                ))
            selectors_in_defect.add(selector)
            loaded_ids, loader_failures = _load_exact_test(selector)
            if loader_failures or loaded_ids != [selector]:
                issues.append(_issue(
                    "DEFECT_REGRESSION_SELECTOR_INVALID", regression_location,
                    f"selector={selector} loaded={loaded_ids} failures={loader_failures}",
                ))
            if not isinstance(profiles, list) or not profiles:
                issues.append(_issue(
                    "DEFECT_REGRESSION_PROFILE_MISSING", regression_location
                ))
                profiles = []
            has_pre_merge = has_pre_merge or bool(
                PRE_MERGE_PROFILES.intersection(profiles)
            )
            for profile in profiles:
                if profile not in ALLOWED_PROFILES:
                    issues.append(_issue(
                        "DEFECT_REGRESSION_PROFILE_INVALID",
                        regression_location, str(profile),
                    ))
                elif coverage and selector and not _covered_by_profile(
                    selector, profile, coverage,
                ):
                    issues.append(_issue(
                        "DEFECT_REGRESSION_NOT_EXECUTED_BY_PROFILE",
                        regression_location,
                        f"selector={selector} profile={profile}",
                    ))
                else:
                    profile_bindings += 1
            regression_count += 1
        if not has_blackbox:
            issues.append(_issue("DEFECT_PUBLIC_REGRESSION_MISSING", location))
        if not has_pre_merge:
            issues.append(_issue("DEFECT_PRE_MERGE_REGRESSION_MISSING", location))

    minimum_truth_documents = registry.get(
        "minimum_independent_truth_documents", 0
    ) if isinstance(registry, Mapping) else 0
    if (
        not isinstance(minimum_truth_documents, int)
        or isinstance(minimum_truth_documents, bool)
        or minimum_truth_documents <= 0
        or len(truth_documents) < minimum_truth_documents
    ):
        issues.append(_issue(
            "DEFECT_TRUTH_DOCUMENT_FLOOR_NOT_MET",
            str(path),
            f"actual={len(truth_documents)} minimum={minimum_truth_documents}",
        ))

    return {
        "schema": "java-upgrade-analyzer.defect-regression-gate.v1",
        "status": "passed" if not issues else "failed",
        "registry": str(path),
        "counts": {
            "registered_defects": len(defects),
            "regression_tests": regression_count,
            "truth_bindings": truth_binding_count,
            "independent_truth_documents": len(truth_documents),
            "authored_control_values": control_count,
            "profile_bindings": profile_bindings,
        },
        "issues": issues,
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit escaped-defect regression ownership and execution"
    )
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--registry", default="")
    args = parser.parse_args(list(argv) if argv is not None else None)
    root = Path(args.root).resolve()
    registry = Path(args.registry).resolve() if args.registry else (
        root / "tests" / "fixtures" / "escaped_defect_regressions.json"
    )
    result = audit_defect_regressions(root, registry)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
