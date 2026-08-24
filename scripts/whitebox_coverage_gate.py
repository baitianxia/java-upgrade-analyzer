#!/usr/bin/env python3
"""Execute governed tests and prove production callable/call-edge coverage.

This gate deliberately keeps *execution success* and *structural coverage*
separate.  A green unittest result cannot erase an uncovered production
callable, and a coverage observation cannot turn a failed assertion into a
pass.  The JSON report retains both facts and the exact test identities that
exercised each callable and edge.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest
from typing import Any, Iterable

from test_suite_runner import (
    classify_test_id,
    discover_tests,
    load_windows_tests,
    load_policy,
    partition_tests,
    skipped_test_is_forbidden,
)
from path_runtime import short_temporary_directory
from whitebox_call_coverage import (
    SCHEMA as CALL_EVIDENCE_SCHEMA,
    ENV_INDEX,
    ENV_OUTPUT_DIRECTORY,
    audit_internal_test_scope,
    build_static_call_graph,
    callable_index_from_payload,
    call_site_index_from_payload,
    create_runtime_profiler,
    merge_process_payloads,
    start_runtime_profiler,
    stop_runtime_profiler,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENTRY_MODULES = (
    "run_step",
    "s1_dep_diff",
    "s2_context_from_deps",
    "s3_scan",
    "binary_pipeline",
    "binary_report",
    "s5_query_call_chain",
    "s6_report",
    "gate",
)
REPORT_SCHEMA = "java-upgrade-analyzer.whitebox-coverage-gate.v1"
SUITES = (
    "blackbox", "whitebox", "performance", "windows", "all-internal",
    "all-tests",
)


def _source_branch_key(record) -> tuple[Any, ...]:
    """Identify one source decision independently of compiler duplication.

    CPython can duplicate a ``finally`` body for normal and exceptional exits.
    Both bytecode offsets represent the same source condition, so completeness
    is governed by the exact source span, operation and side.  Distinct
    short-circuit operands on one line retain distinct column spans.
    """

    return (
        record.callable_id,
        record.code_qualname,
        record.code_first_line,
        record.line,
        record.end_line,
        record.column,
        record.end_column,
        record.opname,
        record.side,
    )


def _evidence_input_identity(root: Path, production_identity: str) -> str:
    """Bind structural evidence to production, tests, truth and the profiler.

    Production identity alone is insufficient for evidence reuse: a deleted
    assertion or changed fixture could otherwise leave an old coverage report
    looking current.  Hash every versioned-style test input plus both coverage
    tools using length-delimited records so paths and bytes cannot alias.
    """

    candidates = [
        path for path in (root / "tests").rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    ]
    candidates.extend((
        root / "scripts" / "whitebox_call_coverage.py",
        root / "scripts" / "whitebox_coverage_gate.py",
    ))
    digest = hashlib.sha256()
    digest.update(b"java-upgrade-analyzer.whitebox-evidence-input.v1\0")
    digest.update(production_identity.encode("ascii"))
    for path in sorted(set(candidates), key=lambda item: str(item.relative_to(root))):
        relative = str(path.relative_to(root)).replace(os.sep, "/").encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


class _ActiveTest:
    value = ""


class CoverageResult(unittest.TextTestResult):
    def __init__(self, *args, active_test: _ActiveTest, **kwargs) -> None:
        self._active_test = active_test
        super().__init__(*args, **kwargs)

    def startTest(self, test) -> None:  # noqa: N802 - unittest API
        self._active_test.value = test.id()
        os.environ["JUA_WHITEBOX_ACTIVE_TEST"] = test.id()
        super().startTest(test)

    def stopTest(self, test) -> None:  # noqa: N802 - unittest API
        try:
            super().stopTest(test)
        finally:
            self._active_test.value = ""
            os.environ.pop("JUA_WHITEBOX_ACTIVE_TEST", None)


def _outcomes(rows: Iterable[tuple[Any, str]]) -> list[dict[str, str]]:
    return [
        {"test_id": test.id(), "detail": str(detail)[-8000:]}
        for test, detail in rows
    ]


def _entry_modules(policy: dict[str, Any]) -> tuple[str, ...]:
    configured = tuple(
        str(value).strip()
        for value in policy.get("whitebox_entry_modules") or ()
        if str(value).strip()
    )
    return configured or DEFAULT_ENTRY_MODULES


def _select_tests(
    suite_name: str,
    partitions: dict[str, list[unittest.TestCase]],
) -> list[unittest.TestCase]:
    if suite_name == "blackbox":
        return list(partitions["blackbox"])
    if suite_name == "whitebox":
        return list(partitions["whitebox"])
    if suite_name == "performance":
        return list(partitions["performance"])
    if suite_name == "all-tests":
        return [
            *partitions["blackbox"],
            *partitions["whitebox"],
            *partitions["performance"],
        ]
    return [*partitions["whitebox"], *partitions["performance"]]


def _matches_selector(test_id: str, selectors: Iterable[str]) -> bool:
    return any(
        test_id == selector.rstrip(".")
        or test_id.startswith(selector.rstrip(".") + ".")
        for selector in selectors
    )


def _test_owner_file_exists(root: Path, test_id: str) -> bool:
    """Prove an imported observation names a test source in this tree."""

    normalized = str(test_id).split(" (", 1)[0].strip()
    if not normalized.startswith("tests."):
        return False
    parts = normalized.split(".")
    for length in range(len(parts), 1, -1):
        candidate = root.joinpath(*parts[:length]).with_suffix(".py")
        if candidate.is_file() and candidate.is_relative_to(root / "tests"):
            return True
    return False


def _dynamic_edge_contract(
    root: Path,
    scope_contract: dict[str, Any],
    *,
    source_identity: str,
    callable_ids: set[str],
) -> tuple[set[tuple[str, str]], dict[str, Any]]:
    root = Path(root).resolve()
    relative = str(scope_contract.get("dynamic_call_edges") or "").strip()
    if not relative:
        raise ValueError("internal dynamic call edge contract is not configured")
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("internal dynamic call edge contract is missing")
    content = path.read_bytes()
    payload = json.loads(content)
    if payload.get("schema") != (
        "java-upgrade-analyzer.internal-dynamic-call-edges.v1"
    ):
        raise ValueError("internal dynamic call edge contract schema is invalid")
    if payload.get("source_identity") != source_identity:
        raise ValueError("internal dynamic call edge contract source is stale")
    rows = payload.get("edges")
    if not isinstance(rows, list):
        raise ValueError("internal dynamic call edge contract rows are invalid")
    edges: list[tuple[str, str]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"caller", "callee"}:
            raise ValueError("internal dynamic call edge contract row is invalid")
        caller = row.get("caller")
        callee = row.get("callee")
        if (
            type(caller) is not str
            or type(callee) is not str
            or caller not in callable_ids
            or callee not in callable_ids
        ):
            raise ValueError(
                "internal dynamic call edge contract endpoint is invalid"
            )
        edges.append((caller, callee))
    if edges != sorted(set(edges)):
        raise ValueError(
            "internal dynamic call edge contract must be unique and sorted"
        )
    return set(edges), {
        "path": relative.replace(os.sep, "/"),
        "sha256": hashlib.sha256(content).hexdigest(),
        "edge_count": len(edges),
        "source_identity": source_identity,
    }


def _coverage_payload_from_report(
    root: Path,
    report_path: str | Path,
    *,
    source_identity: str,
    evidence_input_identity: str,
    callable_ids: set[str],
    static_edges: set[tuple[str, str]],
    static_branches: set[tuple[str, str, int, int, str]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate and normalize one same-tree structural evidence report."""

    path = Path(report_path).resolve()
    content = path.read_bytes()
    report = json.loads(content)
    if report.get("schema") != REPORT_SCHEMA:
        raise ValueError(f"merged coverage report schema is invalid: {path}")
    scope = report.get("scope") or {}
    if scope.get("source_identity") != source_identity:
        raise ValueError(f"merged coverage report source is stale: {path}")
    if scope.get("evidence_input_identity") != evidence_input_identity:
        raise ValueError(
            f"merged coverage report tests or truth are stale: {path}"
        )
    if (scope.get("audit") or {}).get("status") != "passed":
        raise ValueError(f"merged coverage report scope audit failed: {path}")
    execution = report.get("execution") or {}
    if (
        execution.get("status") != "passed"
        or type(execution.get("selected")) is not int
        or execution.get("selected") <= 0
        or execution.get("selected") != execution.get("unique_selected")
        or execution.get("selected") != execution.get("run")
        or any(execution.get(field) for field in (
            "duplicate_test_ids", "failures", "errors", "unexpected_skips",
            "expected_failures", "unexpected_successes", "loader_failures",
            "child_profile_errors",
        ))
    ):
        raise ValueError(f"merged coverage report execution failed: {path}")
    coverage = report.get("coverage") or {}
    if (
        coverage.get("call_evidence_schema") != CALL_EVIDENCE_SCHEMA
        or coverage.get("branch_supported") is not True
        or coverage.get("call_site_supported") is not True
    ):
        raise ValueError(f"merged coverage report evidence is invalid: {path}")

    def owners(row: dict[str, Any], field: str) -> list[str]:
        values = row.get("tests")
        if not isinstance(values, list) or any(
            type(value) is not str for value in values
        ):
            raise ValueError(
                f"merged coverage report {field} owners are invalid: {path}"
            )
        normalized = sorted(set(values) - {"<unattributed>"})
        if not normalized or any(
            not _test_owner_file_exists(root, value) for value in normalized
        ):
            raise ValueError(
                f"merged coverage report {field} owner is unresolved: {path}"
            )
        return normalized

    called: list[dict[str, Any]] = []
    seen_called: set[str] = set()
    for row in coverage.get("called") or ():
        if not isinstance(row, dict):
            raise ValueError(f"merged coverage callable row is invalid: {path}")
        callable_id = row.get("callable")
        if (
            type(callable_id) is not str
            or callable_id not in callable_ids
            or callable_id in seen_called
        ):
            raise ValueError(f"merged coverage callable is invalid: {path}")
        seen_called.add(callable_id)
        called.append({
            "callable": callable_id,
            "tests": owners(row, "callable"),
        })

    edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str]] = set()
    for row in coverage.get("edges") or ():
        if not isinstance(row, dict):
            raise ValueError(f"merged coverage edge row is invalid: {path}")
        key = (row.get("caller"), row.get("callee"))
        if (
            any(type(value) is not str or value not in callable_ids for value in key)
            or key in seen_edges
        ):
            raise ValueError(f"merged coverage edge is invalid: {path}")
        seen_edges.add(key)
        edges.append({
            "caller": key[0], "callee": key[1],
            "tests": owners(row, "edge"),
        })

    call_sites: list[dict[str, Any]] = []
    seen_call_sites: set[tuple[str, str]] = set()
    for row in coverage.get("call_sites") or ():
        if not isinstance(row, dict):
            raise ValueError(f"merged coverage call site row is invalid: {path}")
        key = (row.get("caller"), row.get("callee"))
        if key not in static_edges or key in seen_call_sites:
            raise ValueError(f"merged coverage call site is invalid: {path}")
        seen_call_sites.add(key)
        call_sites.append({
            "caller": key[0], "callee": key[1],
            "tests": owners(row, "call site"),
        })

    branches: list[dict[str, Any]] = []
    seen_branches: set[tuple[str, str, int, int, str]] = set()
    for row in coverage.get("branches") or ():
        if not isinstance(row, dict):
            raise ValueError(f"merged coverage branch row is invalid: {path}")
        try:
            key = (
                row.get("callable"), row.get("code_qualname"),
                int(row.get("code_first_line")), int(row.get("offset")),
                row.get("side"),
            )
            destinations = sorted({
                int(value) for value in row.get("destinations") or ()
            })
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"merged coverage branch is invalid: {path}"
            ) from error
        if (
            key not in static_branches
            or key in seen_branches
            or not destinations
        ):
            raise ValueError(f"merged coverage branch is invalid: {path}")
        seen_branches.add(key)
        branches.append({
            "callable": key[0], "code_qualname": key[1],
            "code_first_line": key[2], "offset": key[3], "side": key[4],
            "destinations": destinations, "tests": owners(row, "branch"),
        })

    return ({
        "schema": CALL_EVIDENCE_SCHEMA,
        "branch_supported": True,
        "call_site_supported": True,
        "called": called,
        "edges": edges,
        "call_sites": call_sites,
        "branches": branches,
    }, {
        "path": str(path),
        "sha256": hashlib.sha256(content).hexdigest(),
        "suite": report.get("suite"),
        "selected": execution["selected"],
    })


def run_gate(
    repository_root: str | Path,
    *,
    suite_name: str,
    policy_path: str | Path,
    selectors: Iterable[str] = (),
    exclude_selectors: Iterable[str] = (),
    merge_report_paths: Iterable[str | Path] = (),
    require_complete: bool = False,
    verbosity: int = 1,
) -> tuple[int, dict[str, Any]]:
    root = Path(repository_root).resolve()
    if suite_name == "windows" and os.name != "nt":
        raise ValueError("WINDOWS_STRUCTURAL_EVIDENCE_REQUIRES_NATIVE_WINDOWS")
    policy = load_policy(policy_path)
    scope_relative = str(policy.get("internal_test_scope") or "").strip()
    if not scope_relative:
        raise ValueError("internal_test_scope is not configured")
    scope_path = (root / scope_relative).resolve()
    if not scope_path.is_relative_to(root) or not scope_path.is_file():
        raise ValueError("internal_test_scope is outside the repository or missing")
    scope_contract = json.loads(scope_path.read_text(encoding="utf-8"))
    graph = build_static_call_graph(
        root / "scripts", _entry_modules(policy),
    )
    static_callable_ids = {record.callable_id for record in graph.callables}
    static_edges = set(graph.resolved_edges)
    static_branch_records = {
        (
            record.callable_id,
            record.code_qualname,
            record.code_first_line,
            record.offset,
            record.side,
        ): record
        for record in graph.branch_alternatives
    }
    static_branches = set(static_branch_records)
    raw_branch_to_source = {
        key: _source_branch_key(record)
        for key, record in static_branch_records.items()
    }
    static_source_branch_records = {}
    for record in graph.branch_alternatives:
        static_source_branch_records.setdefault(
            _source_branch_key(record), record,
        )
    static_source_branches = set(static_source_branch_records)
    evidence_input_identity = _evidence_input_identity(
        root, graph.source_identity,
    )
    required_dynamic_edges, dynamic_edge_contract = _dynamic_edge_contract(
        root,
        scope_contract,
        source_identity=graph.source_identity,
        callable_ids=static_callable_ids,
    )
    imported_process_payloads: list[dict[str, Any]] = []
    merged_report_provenance: list[dict[str, Any]] = []
    for report_path in merge_report_paths:
        process_payload, provenance = _coverage_payload_from_report(
            root,
            report_path,
            source_identity=graph.source_identity,
            evidence_input_identity=evidence_input_identity,
            callable_ids=static_callable_ids,
            static_edges=static_edges,
            static_branches=static_branches,
        )
        imported_process_payloads.append(process_payload)
        merged_report_provenance.append(provenance)
    discovered = discover_tests(root)
    windows_selected: list[unittest.TestCase] = []
    if suite_name == "windows":
        windows_selected, windows_selector_gaps = load_windows_tests(
            policy, root,
        )
        if windows_selector_gaps:
            raise ValueError(
                "Windows structural selectors are unresolved: "
                + ",".join(windows_selector_gaps)
            )
    scope_audit = audit_internal_test_scope(
        root,
        scope_contract,
        discovered_test_ids=[
            test.id() for test in [*discovered, *windows_selected]
        ],
    )
    if set(_entry_modules(policy)) != set(
        str(value).strip()
        for value in scope_contract.get("analysis_entry_modules") or ()
    ):
        scope_audit["issues"].append({
            "code": "POLICY_ANALYSIS_ENTRY_MODULES_MISMATCH",
            "detail": "test_suite_policy.json != internal_test_scope.json",
        })
        scope_audit["status"] = "failed"
    partitions = partition_tests(discovered, policy)
    selected = (
        windows_selected
        if suite_name == "windows"
        else _select_tests(suite_name, partitions)
    )
    selector_values = tuple(
        str(value).strip() for value in selectors if str(value).strip()
    )
    if selector_values:
        selected = [
            test for test in selected
            if _matches_selector(test.id(), selector_values)
        ]
    excluded_values = tuple(
        str(value).strip()
        for value in exclude_selectors if str(value).strip()
    )
    if excluded_values:
        selected = [
            test for test in selected
            if not _matches_selector(test.id(), excluded_values)
        ]
    profile_exclusion_rows = {
        str(row.get("test_id") or "").strip(): row
        for row in scope_contract.get("structural_profile_exclusions") or ()
        if isinstance(row, dict) and str(row.get("test_id") or "").strip()
    }
    applied_profile_exclusions = [
        {
            "test_id": test.id(),
            "reason_code": str(
                profile_exclusion_rows[test.id()].get("reason_code") or ""
            ),
            "replacement_test_ids": list(
                profile_exclusion_rows[test.id()].get("replacement_test_ids")
                or []
            ),
        }
        for test in selected
        if test.id() in profile_exclusion_rows
    ]
    if applied_profile_exclusions:
        selected = [
            test for test in selected
            if test.id() not in profile_exclusion_rows
        ]
        selected_ids_after_profile_exclusion = {
            test.id() for test in selected
        }
        if not selector_values:
            for row in applied_profile_exclusions:
                missing_replacements = sorted(
                    set(row["replacement_test_ids"])
                    - selected_ids_after_profile_exclusion
                )
                if missing_replacements:
                    scope_audit["issues"].append({
                        "code": "STRUCTURAL_PROFILE_REPLACEMENT_NOT_SELECTED",
                        "detail": json.dumps({
                            "test_id": row["test_id"],
                            "missing_replacements": missing_replacements,
                        }, ensure_ascii=False, sort_keys=True),
                    })
                    scope_audit["status"] = "failed"
    selected_by_id: dict[str, unittest.TestCase] = {}
    duplicate_test_ids: list[str] = []
    for test in selected:
        if test.id() in selected_by_id:
            duplicate_test_ids.append(test.id())
        else:
            selected_by_id[test.id()] = test
    selected = list(selected_by_id.values())

    active_test = _ActiveTest()
    graph_index_payload = graph.index_payload()
    profiler = create_runtime_profiler(
        callable_index_from_payload(graph_index_payload),
        call_site_index=call_site_index_from_payload(graph_index_payload),
        active_test_getter=lambda: active_test.value,
        local_only=True,
    )
    result_class = lambda *args, **kwargs: CoverageResult(  # noqa: E731
        *args, active_test=active_test, **kwargs,
    )
    started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    child_profile_errors: list[dict[str, Any]] = []
    with short_temporary_directory(
        prefix="whitebox-call-evidence",
    ) as temporary:
        evidence_root = Path(temporary)
        index_path = evidence_root / "call-index.json"
        child_output = evidence_root / "children"
        index_path.write_text(
            json.dumps(graph.index_payload(), ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        child_output.mkdir()
        profile_site = root / "tests" / "whitebox_profile_site"
        original_environment = {
            key: os.environ.get(key)
            for key in (ENV_INDEX, ENV_OUTPUT_DIRECTORY, "PYTHONPATH")
        }
        python_path_parts = [
            str(profile_site), str(root / "scripts"), str(root),
        ]
        if original_environment["PYTHONPATH"]:
            python_path_parts.append(str(original_environment["PYTHONPATH"]))
        os.environ[ENV_INDEX] = str(index_path)
        os.environ[ENV_OUTPUT_DIRECTORY] = str(child_output)
        os.environ["PYTHONPATH"] = os.pathsep.join(python_path_parts)
        start_runtime_profiler(profiler)
        try:
            result = unittest.TextTestRunner(
                verbosity=verbosity, resultclass=result_class,
            ).run(unittest.TestSuite(selected))
        finally:
            stop_runtime_profiler(profiler)
            active_test.value = ""
            os.environ.pop("JUA_WHITEBOX_ACTIVE_TEST", None)
            for key, value in original_environment.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        process_payloads = [*imported_process_payloads, profiler.payload()]
        for path in sorted(child_output.glob("process-*.json")):
            process_payloads.append(json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(child_output.glob("profile-error-*.json")):
            child_profile_errors.append(
                json.loads(path.read_text(encoding="utf-8"))
            )
        calls = merge_process_payloads(process_payloads)
    called_rows = {
        str(row["callable"]): row for row in calls["called"]
    }
    edge_rows = {
        (str(row["caller"]), str(row["callee"])): row
        for row in calls["edges"]
    }
    call_site_rows = {
        (str(row["caller"]), str(row["callee"])): row
        for row in calls["call_sites"]
    }
    branch_rows = {}
    for row in calls["branches"]:
        key = (
            str(row["callable"]),
            str(row["code_qualname"]),
            int(row["code_first_line"]),
            int(row["offset"]),
            str(row["side"]),
        )
        if key in static_branches:
            branch_rows[key] = row
    observed_source_branches = {
        raw_branch_to_source[key] for key in branch_rows
    }
    missing_callables = sorted(static_callable_ids - set(called_rows))
    observed_static_edges = (
        (static_edges & set(edge_rows)) | set(call_site_rows)
    )
    missing_edges = sorted(static_edges - observed_static_edges)
    observed_dynamic_edges = sorted(set(edge_rows) - static_edges)
    missing_required_dynamic_edges = sorted(
        required_dynamic_edges - set(edge_rows)
    )
    unregistered_dynamic_edges = sorted(
        set(observed_dynamic_edges) - required_dynamic_edges
    )
    missing_source_branches = sorted(
        static_source_branches - observed_source_branches
    )
    missing_branch_records = [
        static_source_branch_records[key]
        for key in missing_source_branches
    ]
    skips = [
        {"test_id": test.id(), "reason": reason}
        for test, reason in result.skipped
    ]
    unexpected_skips = [
        row for row in skips
        if skipped_test_is_forbidden(
            "all" if suite_name in {"all-internal", "all-tests"}
            else suite_name,
            row["test_id"],
            policy,
        )
    ]
    loader_failures = [
        test.id() for test in selected
        if test.__class__.__name__ == "_FailedTest"
    ]
    execution_passed = (
        bool(selected)
        and result.testsRun == len(selected)
        and result.wasSuccessful()
        and not duplicate_test_ids
        and not result.expectedFailures
        and not unexpected_skips
        and not loader_failures
        and not child_profile_errors
    )
    scope_valid = scope_audit.get("status") == "passed"
    coverage_complete = (
        bool(calls.get("branch_supported"))
        and bool(calls.get("call_site_supported"))
        and not missing_callables
        and not missing_edges
        and not missing_required_dynamic_edges
        and not unregistered_dynamic_edges
        and not missing_source_branches
    )
    selection_is_complete = not selector_values and not excluded_values
    successful = execution_passed and scope_valid and (
        coverage_complete if require_complete and selection_is_complete else True
    )
    payload: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "passed" if successful else "failed",
        "reason_code": (
            "WHITEBOX_EXECUTION_FAILED" if not execution_passed
            else "INTERNAL_TEST_SCOPE_INVALID" if not scope_valid
            else "WHITEBOX_STRUCTURAL_COVERAGE_INCOMPLETE"
            if require_complete and selection_is_complete and not coverage_complete
            else "WHITEBOX_COVERAGE_OBSERVED"
        ),
        "suite": suite_name,
        "selectors": list(selector_values),
        "exclude_selectors": list(excluded_values),
        "require_complete": require_complete,
        "merged_coverage_reports": merged_report_provenance,
        "execution": {
            "status": "passed" if execution_passed else "failed",
            "selection_empty": not bool(selected),
            "selected": len(selected_by_id) + len(duplicate_test_ids),
            "unique_selected": len(selected),
            "duplicate_test_ids": duplicate_test_ids,
            "run": result.testsRun,
            "failures": _outcomes(result.failures),
            "errors": _outcomes(result.errors),
            "skips": skips,
            "unexpected_skips": unexpected_skips,
            "expected_failures": _outcomes(result.expectedFailures),
            "unexpected_successes": [
                test.id() for test in result.unexpectedSuccesses
            ],
            "loader_failures": loader_failures,
            "child_profile_errors": child_profile_errors,
            "profile_exclusions": applied_profile_exclusions,
        },
        "scope": {
            "entry_modules": list(graph.entry_modules),
            "reachable_modules": list(graph.reachable_modules),
            "reachable_module_count": len(graph.reachable_modules),
            "source_identity": graph.source_identity,
            "evidence_input_identity": evidence_input_identity,
            "dynamic_call_edge_contract": dynamic_edge_contract,
            "audit": scope_audit,
        },
        "coverage": {
            "status": "complete" if coverage_complete else "incomplete",
            "call_evidence_schema": CALL_EVIDENCE_SCHEMA,
            "static_callable_count": len(static_callable_ids),
            "observed_callable_count": len(
                static_callable_ids & set(called_rows)
            ),
            "missing_callable_count": len(missing_callables),
            "static_edge_count": len(static_edges),
            "observed_static_edge_count": len(observed_static_edges),
            "observed_static_runtime_edge_count": len(
                static_edges & set(edge_rows)
            ),
            "observed_static_call_site_edge_count": len(call_site_rows),
            "missing_static_edge_count": len(missing_edges),
            "observed_dynamic_edge_count": len(observed_dynamic_edges),
            "required_dynamic_edge_count": len(required_dynamic_edges),
            "observed_required_dynamic_edge_count": len(
                required_dynamic_edges & set(edge_rows)
            ),
            "missing_required_dynamic_edge_count": len(
                missing_required_dynamic_edges
            ),
            "unregistered_dynamic_edge_count": len(
                unregistered_dynamic_edges
            ),
            "branch_supported": bool(calls.get("branch_supported")),
            "call_site_supported": bool(calls.get("call_site_supported")),
            "static_branch_alternative_count": len(static_source_branches),
            "observed_static_branch_alternative_count": len(
                static_source_branches & observed_source_branches
            ),
            "missing_static_branch_alternative_count": len(
                missing_source_branches
            ),
            "missing_callables": missing_callables,
            "missing_static_edges": [
                {"caller": caller, "callee": callee}
                for caller, callee in missing_edges
            ],
            "observed_dynamic_edges": [
                {"caller": caller, "callee": callee}
                for caller, callee in observed_dynamic_edges
            ],
            "missing_required_dynamic_edges": [
                {"caller": caller, "callee": callee}
                for caller, callee in missing_required_dynamic_edges
            ],
            "unregistered_dynamic_edges": [
                {"caller": caller, "callee": callee}
                for caller, callee in unregistered_dynamic_edges
            ],
            "missing_static_branch_alternatives": [
                {
                    "callable": record.callable_id,
                    "code_qualname": record.code_qualname,
                    "code_first_line": record.code_first_line,
                    "offset": record.offset,
                    "side": record.side,
                    "line": record.line,
                    "end_line": record.end_line,
                    "column": record.column,
                    "end_column": record.end_column,
                    "opname": record.opname,
                }
                for record in missing_branch_records
            ],
            "called": list(called_rows.values()),
            "edges": list(edge_rows.values()),
            "call_sites": list(call_site_rows.values()),
            "branches": list(branch_rows.values()),
        },
        "duration_seconds": round(time.monotonic() - started, 6),
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    return (0 if successful else 1), payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute and audit production white-box call coverage",
    )
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--policy", default="")
    parser.add_argument("--suite", choices=SUITES, default="all-internal")
    parser.add_argument("--selector", action="append", default=[])
    parser.add_argument("--exclude-selector", action="append", default=[])
    parser.add_argument(
        "--merge-coverage-report", action="append", default=[],
        help=(
            "merge successful structural evidence with identical production "
            "and test/truth identities"
        ),
    )
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--verbosity", type=int, choices=(0, 1, 2), default=1)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    policy_path = (
        Path(args.policy).resolve() if args.policy
        else root / "tests" / "fixtures" / "test_suite_policy.json"
    )
    try:
        exit_code, payload = run_gate(
            root,
            suite_name=args.suite,
            policy_path=policy_path,
            selectors=args.selector,
            exclude_selectors=args.exclude_selector,
            merge_report_paths=args.merge_coverage_report,
            require_complete=args.require_complete,
            verbosity=args.verbosity,
        )
    except Exception as error:  # noqa: BLE001 - emit stable gate evidence
        exit_code = 2
        payload = {
            "schema": REPORT_SCHEMA,
            "status": "failed",
            "reason_code": "WHITEBOX_COVERAGE_GATE_ERROR",
            "detail": f"{type(error).__name__}: {error}",
        }
    if args.json_out:
        target = Path(args.json_out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        rendered = json.dumps({
            "schema": payload.get("schema"),
            "status": payload.get("status"),
            "reason_code": payload.get("reason_code"),
            "execution": payload.get("execution"),
            "coverage": {
                key: value
                for key, value in (payload.get("coverage") or {}).items()
                if key.endswith("_count") or key in {
                    "status", "branch_supported",
                }
            },
            "json_out": str(target),
        }, ensure_ascii=False)
    else:
        rendered = json.dumps(payload, ensure_ascii=False)
    print(rendered)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
