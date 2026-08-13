#!/usr/bin/env python3
"""Dependency-free branch, mutation, repeatability and slow-test release gate."""

from __future__ import annotations

import argparse
import ast
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import unittest

from binary_capability_migration_audit import (
    REGISTRY_PATH,
    audit_capability_migration,
)
from compat import subprocess_platform_kwargs
from path_runtime import short_temporary_directory


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
BRANCH_FUNCTIONS = {
    "_canonical_value",
    "_iter_canonical_json",
    "artifact_content_identity",
    "derive_formal_result_state",
    "validate_formal_result_state",
    "validate_projection_assessment",
    "validate_phase_manifest",
}
REPEAT_MODULES = (
    "tests.test_binary_first_contract",
    "tests.test_binary_result_truth",
    "tests.test_binary_tool_execution",
    "tests.test_binary_entrypoint_discovery",
)
MUTATIONS = (
    {
        "id": "identity_accepts_non_finite_float",
        "module": "binary_first_contract",
        "path": SCRIPTS / "binary_first_contract.py",
        "old": """return json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(\",\", \":\"),
        allow_nan=False,
    ).encode(\"utf-8\")""",
        "new": """return json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(\",\", \":\"),
        allow_nan=True,
    ).encode(\"utf-8\")""",
        "test": (
            "tests.test_binary_first_contract.BinaryFirstContractTest."
            "test_canonical_identity_rejects_non_finite_float"
        ),
    },
    {
        "id": "streaming_identity_accepts_non_finite_float",
        "module": "binary_first_contract",
        "path": SCRIPTS / "binary_first_contract.py",
        "old": """_CANONICAL_JSON_ENCODER = json.JSONEncoder(
    ensure_ascii=False,
    sort_keys=True,
    separators=(\",\", \":\"),
    allow_nan=False,
)""",
        "new": """_CANONICAL_JSON_ENCODER = json.JSONEncoder(
    ensure_ascii=False,
    sort_keys=True,
    separators=(\",\", \":\"),
    allow_nan=True,
)""",
        "test": (
            "tests.test_binary_first_contract.BinaryFirstContractTest."
            "test_streaming_canonical_identity_is_byte_equivalent"
        ),
    },
    {
        "id": "reachable_downgraded_to_inconclusive",
        "module": "binary_first_contract",
        "path": SCRIPTS / "binary_first_contract.py",
        "old": '"impact_conclusion": "probable_impact" if reachable else "inconclusive",',
        "new": '"impact_conclusion": "inconclusive",',
        "test": (
            "tests.test_binary_first_contract.BinaryFirstContractTest."
            "test_reachable_truth_table_preserves_static_reachability"
        ),
    },
    {
        "id": "truth_exact_policy_ignores_false_positive",
        "module": "binary_result_truth",
        "path": SCRIPTS / "binary_result_truth.py",
        "old": 'if truth.get("result_set_policy") == "exact":',
        "new": 'if False and truth.get("result_set_policy") == "exact":',
        "test": (
            "tests.test_binary_result_truth.BinaryResultTruthTest."
            "test_exact_truth_rejects_unexpected_false_positive"
        ),
    },
    {
        "id": "truth_ignores_state_mismatch",
        "module": "binary_result_truth",
        "path": SCRIPTS / "binary_result_truth.py",
        "old": "if field in expected and actual.get(field) != expected[field]:",
        "new": "if False and field in expected and actual.get(field) != expected[field]:",
        "test": (
            "tests.test_binary_result_truth.BinaryResultTruthTest."
            "test_truth_rejects_wrong_overload_dependency_and_four_state_result"
        ),
    },
    {
        "id": "truth_ignores_required_paths",
        "module": "binary_result_truth",
        "path": SCRIPTS / "binary_result_truth.py",
        "old": "for required in required_paths:",
        "new": "for required in ():",
        "test": (
            "tests.test_binary_result_truth.BinaryResultTruthTest."
            "test_truth_rejects_missing_or_incorrect_required_path"
        ),
    },
    {
        "id": "access_reduction_treated_as_linkage_compatible",
        "module": "binary_trace_engine",
        "path": SCRIPTS / "binary_trace_engine.py",
        "old": "_visibility_rank(current_access) < _visibility_rank(base_access)",
        "new": "_visibility_rank(current_access) > _visibility_rank(base_access)",
        "test": (
            "tests.test_binary_trace_engine.BinaryTraceFastPathTest."
            "test_contract_access_reduction_is_linkage_incompatible_without_a_path"
        ),
    },
    {
        "id": "paired_missing_class_path_downgraded_to_possible",
        "module": "binary_trace_engine",
        "path": SCRIPTS / "binary_trace_engine.py",
        "old": 'if status == "no_such_member"\n        or (\n            paired_artifact_change',
        "new": 'if status == "no_such_member"\n        or (\n            False and paired_artifact_change',
        "test": (
            "tests.test_binary_trace_engine.BinaryTraceFastPathTest."
            "test_definitive_missing_linkage_edges_are_exact"
        ),
    },
    {
        "id": "concrete_to_abstract_treated_as_compatible",
        "module": "binary_trace_engine",
        "path": SCRIPTS / "binary_trace_engine.py",
        "old": """not bool(base_access & ACC_ABSTRACT)
        and bool(current_access & ACC_ABSTRACT)""",
        "new": """False and not bool(base_access & ACC_ABSTRACT)
        and bool(current_access & ACC_ABSTRACT)""",
        "test": (
            "tests.test_binary_trace_engine.BinaryTraceFastPathTest."
            "test_concrete_method_becoming_abstract_breaks_binary_compatibility"
        ),
    },
    {
        "id": "non_final_method_becoming_final_treated_as_compatible",
        "module": "binary_trace_engine",
        "path": SCRIPTS / "binary_trace_engine.py",
        "old": """scope.get("member_kind") == "method"
        and not bool(base_access & ACC_FINAL)""",
        "new": """False and scope.get("member_kind") == "method"
        and not bool(base_access & ACC_FINAL)""",
        "test": (
            "tests.test_binary_trace_engine.BinaryTraceFastPathTest."
            "test_non_final_method_becoming_final_breaks_binary_compatibility"
        ),
    },
    {
        "id": "failed_caller_definition_treated_as_legal_access",
        "module": "binary_trace_engine",
        "path": SCRIPTS / "binary_trace_engine.py",
        "old": 'and caller_definition_statuses == {"definition_ready"}',
        "new": "and True",
        "test": (
            "tests.test_binary_trace_engine.BinaryTraceFastPathTest."
            "test_observed_legal_protected_path_refines_access_reduction"
        ),
    },
    {
        "id": "inherited_removed_member_loses_base_resolution_anchor",
        "module": "binary_decision_engine",
        "path": SCRIPTS / "binary_decision_engine.py",
        "old": "grouped.setdefault(target, set()).add(",
        "new": "{}.setdefault(target, set()).add(",
        "test": (
            "tests.test_binary_decision_engine.BinaryDecisionIdentityRegressionTest."
            "test_removed_inherited_member_keeps_base_resolution_as_trace_anchor"
        ),
    },
    {
        "id": "current_hierarchy_ignores_selected_variant_facts",
        "module": "binary_decision_engine",
        "path": SCRIPTS / "binary_decision_engine.py",
        "old": """if variant:
            row = self.current_store.connection.execute(""",
        "new": """if False and variant:
            row = self.current_store.connection.execute(""",
        "test": (
            "tests.test_binary_decision_engine.BinaryDecisionIdentityRegressionTest."
            "test_current_hierarchy_uses_selected_variant_facts"
        ),
    },
    {
        "id": "validated_nestmate_private_access_is_rejected",
        "module": "binary_runtime_reconciler",
        "path": SCRIPTS / "binary_runtime_reconciler.py",
        "old": """            return (
                caller_class == owner and caller_realm == defining
            ) or self._validated_nestmates(
                caller_class, caller_realm, owner, defining
            )""",
        "new": """            return (
                caller_class == owner and caller_realm == defining
            )""",
        "test": (
            "tests.test_binary_runtime_reconciler.BinaryRuntimeReconcilerTest."
            "test_private_access_between_validated_nestmates_is_linkage_compatible"
        ),
    },
)


def _function_branch_lines(path: Path) -> set[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    alternatives = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in BRANCH_FUNCTIONS:
            continue
        for branch in ast.walk(node):
            if isinstance(branch, ast.If):
                if branch.body:
                    alternatives.add(branch.body[0].lineno)
                if branch.orelse:
                    alternatives.add(branch.orelse[0].lineno)
            elif isinstance(branch, (ast.For, ast.While)):
                if branch.body:
                    alternatives.add(branch.body[0].lineno)
                if branch.orelse:
                    alternatives.add(branch.orelse[0].lineno)
            elif isinstance(branch, ast.Try):
                alternatives.update(
                    handler.body[0].lineno
                    for handler in branch.handlers if handler.body
                )
            elif isinstance(branch, ast.Match):
                alternatives.update(
                    case.body[0].lineno for case in branch.cases if case.body
                )
    return alternatives


def branch_probe() -> dict:
    target = (SCRIPTS / "binary_first_contract.py").resolve()
    alternatives = _function_branch_lines(target)
    executed = set()
    previous = sys.gettrace()

    def tracer(frame, event, _arg):
        if event == "line" and Path(frame.f_code.co_filename).resolve() == target:
            executed.add(frame.f_lineno)
        return tracer

    suite = unittest.defaultTestLoader.loadTestsFromName(
        "tests.test_binary_first_contract"
    )
    stream = io.StringIO()
    try:
        sys.settrace(tracer)
        result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    finally:
        sys.settrace(previous)
    covered = alternatives & executed
    ratio = len(covered) / len(alternatives) if alternatives else 1.0
    return {
        "status": "passed" if result.wasSuccessful() and ratio == 1.0 else "failed",
        "test_count": result.testsRun,
        "branch_alternative_count": len(alternatives),
        "covered_branch_alternative_count": len(covered),
        "coverage_ratio": round(ratio, 6),
        "uncovered_lines": sorted(alternatives - executed),
    }


def mutation_probe(mutations=MUTATIONS) -> dict:
    rows = []
    with short_temporary_directory(prefix="binary-mutations") as temp_text:
        temp = Path(temp_text)
        for mutation in mutations:
            source = Path(mutation["path"]).read_text(encoding="utf-8")
            if source.count(mutation["old"]) != 1:
                rows.append({
                    "mutation_id": mutation["id"],
                    "status": "invalid_mutation_site",
                })
                continue
            mutant = temp / f"{mutation['module']}-{mutation['id']}.py"
            mutant.write_text(
                source.replace(mutation["old"], mutation["new"], 1),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "binary_mutation_worker.py"),
                    "--module", str(mutation["module"]),
                    "--mutant", str(mutant),
                    "--test", str(mutation["test"]),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=30,
                **subprocess_platform_kwargs(),
            )
            rows.append({
                "mutation_id": mutation["id"],
                "status": "killed" if completed.returncode != 0 else "survived",
                "test": mutation["test"],
            })
    return {
        "status": "passed" if rows and all(
            row["status"] == "killed" for row in rows
        ) else "failed",
        "mutation_count": len(rows),
        "killed_count": sum(row["status"] == "killed" for row in rows),
        "rows": rows,
    }


def repeat_health_probe(
    modules=REPEAT_MODULES, *, repeats=2, timeout_seconds=90,
) -> dict:
    rows = []
    for iteration in range(1, repeats + 1):
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                [sys.executable, "-m", "unittest", *modules],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=timeout_seconds,
                **subprocess_platform_kwargs(),
            )
            output = f"{completed.stdout}\n{completed.stderr}"
            match = re.search(r"Ran (\d+) tests?", output)
            rows.append({
                "iteration": iteration,
                "status": "passed" if completed.returncode == 0 else "failed",
                "returncode": completed.returncode,
                "test_count": int(match.group(1)) if match else -1,
                "elapsed_seconds": round(time.perf_counter() - started, 6),
            })
        except subprocess.TimeoutExpired:
            rows.append({
                "iteration": iteration,
                "status": "timeout",
                "returncode": -1,
                "test_count": -1,
                "elapsed_seconds": round(time.perf_counter() - started, 6),
            })
    counts = {row["test_count"] for row in rows}
    elapsed = [row["elapsed_seconds"] for row in rows]
    stable_timing = not elapsed or min(elapsed) == 0 or max(elapsed) / min(elapsed) <= 3.0
    passed = (
        len(rows) == repeats
        and all(row["status"] == "passed" for row in rows)
        and len(counts) == 1
        and counts != {-1}
        and stable_timing
    )
    return {
        "status": "passed" if passed else "failed",
        "repeat_count": repeats,
        "stable_test_count": len(counts) == 1 and counts != {-1},
        "stable_timing_within_3x": stable_timing,
        "per_iteration_timeout_seconds": timeout_seconds,
        "rows": rows,
    }


def run_health_gate() -> dict:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    catalog = audit_capability_migration(ROOT, registry)
    branch = branch_probe()
    mutation = mutation_probe()
    repeat = repeat_health_probe()
    checks = {
        "capability_catalog": {
            "status": "passed"
            if catalog["registry_structurally_valid"]
            and catalog["release_status"] == "passed"
            else "failed",
            "release_status": catalog["release_status"],
            "issues": catalog["issues"],
        },
        "branch_coverage": branch,
        "mutation": mutation,
        "repeat_and_slow_health": repeat,
    }
    return {
        "schema": "java-upgrade-analyzer.binary-test-health.v1",
        "status": "passed" if all(
            item["status"] == "passed" for item in checks.values()
        ) else "failed",
        "checks": checks,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)
    result = run_health_gate()
    encoded = json.dumps(result, ensure_ascii=False, sort_keys=True)
    if args.output:
        target = Path(args.output).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
