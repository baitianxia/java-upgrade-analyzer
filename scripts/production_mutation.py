#!/usr/bin/env python3
"""Apply typed AST mutations in copied repositories and run exact tests."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import difflib
from pathlib import Path
import shutil
import subprocess
import sys


@dataclass(frozen=True)
class MutationSpec:
    id: str
    category: str
    module: str
    selector: dict
    replacement: str
    required_tests: tuple[str, ...]

    @classmethod
    def from_dict(cls, payload: dict) -> "MutationSpec":
        return cls(
            id=str(payload["id"]),
            category=str(payload["category"]),
            module=str(payload["module"]),
            selector=dict(payload["selector"]),
            replacement=str(payload["replacement"]),
            required_tests=tuple(payload["required_tests"]),
        )


@dataclass(frozen=True)
class MutationRun:
    mutation_id: str
    status: str
    returncode: int
    command: tuple[str, ...]
    diff_path: str
    log_path: str
    error: str = ""


class _ReplaceNode(ast.NodeTransformer):
    def __init__(self, target: ast.AST, replacement: ast.stmt):
        self.target = target
        self.replacement = replacement

    def generic_visit(self, node):
        if node is self.target:
            return ast.copy_location(self.replacement, node)
        return super().generic_visit(node)


def _mutate_source(source: str, spec: MutationSpec) -> tuple[str, str]:
    tree = ast.parse(source)
    function_name = str(spec.selector.get("function") or "")
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    ]
    if len(functions) != 1:
        raise ValueError(f"selector_match_count:{len(functions)}")
    node_name = str(spec.selector.get("node_type") or "")
    node_type = getattr(ast, node_name, None)
    if not isinstance(node_type, type) or not issubclass(node_type, ast.AST):
        raise ValueError(f"invalid_node_type:{node_name}")
    candidates = [node for node in ast.walk(functions[0]) if isinstance(node, node_type)]
    source_contains = str(spec.selector.get("source_contains") or "")
    if source_contains:
        candidates = [
            node for node in candidates if source_contains in ast.unparse(node)
        ]
    occurrence = int(spec.selector.get("occurrence") or 1)
    if occurrence < 1 or occurrence > len(candidates):
        raise ValueError(f"selector_node_count:{len(candidates)}")
    replacement_tree = ast.parse(spec.replacement)
    if len(replacement_tree.body) != 1 or not isinstance(replacement_tree.body[0], ast.stmt):
        raise ValueError("replacement_must_be_one_statement")
    mutated = _ReplaceNode(candidates[occurrence - 1], replacement_tree.body[0]).visit(tree)
    ast.fix_missing_locations(mutated)
    return ast.unparse(mutated) + "\n", node_name


def validate_mutation_spec(repo_root: Path, spec: MutationSpec) -> str:
    try:
        source = (Path(repo_root) / spec.module).read_text(encoding="utf-8")
        _mutate_source(source, spec)
    except (OSError, SyntaxError, ValueError) as exc:
        return str(exc)
    return ""


def run_mutant(
    repo_root: Path,
    spec: MutationSpec,
    report_root: Path,
    timeout_seconds: int,
) -> MutationRun:
    repo_root = Path(repo_root)
    report_root = Path(report_root)
    copy_root = report_root / spec.id / "repo"
    diff_path = report_root / spec.id / "mutation.diff"
    log_path = report_root / spec.id / "test.log"
    command = (sys.executable, "-m", "unittest", "-v", *spec.required_tests)
    try:
        if copy_root.exists():
            shutil.rmtree(copy_root)
        copy_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(repo_root, copy_root, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        module = copy_root / spec.module
        original = module.read_text(encoding="utf-8")
        mutated, _ = _mutate_source(original, spec)
        module.write_text(mutated, encoding="utf-8")
        diff = "".join(
            difflib.unified_diff(
                original.splitlines(True),
                mutated.splitlines(True),
                fromfile=spec.module,
                tofile=f"{spec.module} ({spec.id})",
            )
        )
        diff_path.write_text(diff, encoding="utf-8")
        completed = subprocess.run(
            command,
            cwd=str(copy_root),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        log_path.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        return MutationRun(
            spec.id,
            "killed" if completed.returncode else "survived",
            completed.returncode,
            command,
            str(diff_path),
            str(log_path),
        )
    except subprocess.TimeoutExpired as exc:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(str(exc), encoding="utf-8")
        return MutationRun(
            spec.id, "infrastructure_failed", -1, command,
            str(diff_path), str(log_path), "test_timeout",
        )
    except (OSError, SyntaxError, ValueError) as exc:
        return MutationRun(
            spec.id, "infrastructure_failed", -1, command,
            str(diff_path), str(log_path), str(exc),
        )
