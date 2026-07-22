#!/usr/bin/env python3
"""Measure decision-branch coverage for selected core functions using stdlib tracing."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
import unittest

from capability_test_catalog import build_profile_catalog, _load_json


ROOT = Path(__file__).resolve().parents[1]


def _first_line(statements, fallback):
    return int(statements[0].lineno) if statements else int(fallback)


def function_branch_arcs(source: str, function_names) -> dict[str, set[tuple[int, int]]]:
    """Return executable true/false line arcs for ``if`` decisions."""
    tree = ast.parse(source)
    selected = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in set(function_names)
    }
    result = {}

    def visit_block(statements, fallthrough, arcs):
        for index, statement in enumerate(statements):
            next_line = (
                int(statements[index + 1].lineno)
                if index + 1 < len(statements)
                else int(fallthrough)
            )
            if isinstance(statement, ast.If):
                true_line = _first_line(statement.body, next_line)
                false_line = _first_line(statement.orelse, next_line)
                arcs.add((int(statement.lineno), true_line))
                arcs.add((int(statement.lineno), false_line))
                visit_block(statement.body, next_line, arcs)
                visit_block(statement.orelse, next_line, arcs)
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                visit_block(statement.body, int(statement.lineno), arcs)
                visit_block(statement.orelse, next_line, arcs)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                visit_block(statement.body, next_line, arcs)
            elif isinstance(statement, ast.Try):
                visit_block(statement.body, next_line, arcs)
                visit_block(statement.orelse, next_line, arcs)
                visit_block(statement.finalbody, next_line, arcs)
                for handler in statement.handlers:
                    visit_block(handler.body, next_line, arcs)

    for name in function_names:
        node = selected.get(name)
        if node is None:
            result[name] = set()
            continue
        arcs = set()
        visit_block(node.body, -1, arcs)
        result[name] = arcs
    return result


def trace_test_arcs(test_ids, target_paths) -> tuple[dict[str, set[tuple[int, int]]], bool]:
    canonical = {str(Path(path).resolve()): set() for path in target_paths}
    previous = {}

    def local_tracer(frame, event, arg):
        filename = frame.f_code.co_filename
        frame_id = id(frame)
        if event == "line":
            line = int(frame.f_lineno)
            old = previous.get(frame_id)
            if old is not None and old != line:
                canonical[filename].add((old, line))
            previous[frame_id] = line
        elif event == "return":
            old = previous.pop(frame_id, None)
            if old is not None:
                canonical[filename].add((old, -1))
        return local_tracer

    def global_tracer(frame, event, arg):
        if event == "call" and frame.f_code.co_filename in canonical:
            return local_tracer
        return None

    suite = unittest.defaultTestLoader.loadTestsFromNames(list(test_ids))
    sys.settrace(global_tracer)
    try:
        result = unittest.TextTestRunner(verbosity=1).run(suite)
    finally:
        sys.settrace(None)
    return canonical, result.wasSuccessful()


def evaluate_branch_coverage(config: dict, test_ids) -> dict:
    targets = config.get("branch_coverage") or []
    paths = [ROOT / str(item.get("module") or "") for item in targets]
    observed, tests_passed = trace_test_arcs(test_ids, paths)
    reports = []
    errors = []
    for item, path in zip(targets, paths):
        functions = [str(name) for name in item.get("functions") or []]
        expected_by_function = function_branch_arcs(
            path.read_text(encoding="utf-8"), functions
        )
        expected = set().union(*expected_by_function.values()) if functions else set()
        actual = observed.get(str(path.resolve()), set())
        covered = expected & actual
        percent = round((100.0 * len(covered) / len(expected)) if expected else 0.0, 2)
        minimum = float(item.get("min_percent") or 0.0)
        missing_functions = sorted(
            name for name, arcs in expected_by_function.items() if not arcs
        )
        uncovered = sorted(expected - covered)
        if missing_functions:
            errors.append(f"branch_function_missing_or_branchless:{path.name}:{','.join(missing_functions)}")
        if percent < minimum:
            errors.append(f"branch_coverage_below_threshold:{path.name}:{percent}:{minimum}")
        reports.append({
            "module": str(path.relative_to(ROOT)),
            "functions": functions,
            "branch_count": len(expected),
            "covered_branch_count": len(covered),
            "branch_percent": percent,
            "min_percent": minimum,
            "uncovered_arcs": [list(arc) for arc in uncovered],
        })
    if not tests_passed:
        errors.append("branch_test_profile_failed")
    return {
        "status": "passed" if not errors else "failed",
        "test_count": len(test_ids),
        "modules": reports,
        "errors": errors,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default="tests/fixtures/capability_families.json")
    parser.add_argument("--manifest", default="tests/fixtures/test_profiles.json")
    parser.add_argument("--profile", default="branch_core")
    parser.add_argument("--json-out", default="")
    args = parser.parse_args(argv)

    registry = _load_json(ROOT / args.registry)
    manifest = _load_json(ROOT / args.manifest)
    catalog = build_profile_catalog(registry, manifest, args.profile)
    payload = evaluate_branch_coverage(manifest, catalog["test_ids"])
    payload["profile"] = args.profile
    if catalog["errors"]:
        payload["status"] = "failed"
        payload["errors"].extend(catalog["errors"])
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
