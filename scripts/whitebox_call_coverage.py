#!/usr/bin/env python3
"""Static and runtime coverage of production Python call relationships.

The ordinary unittest result proves that test methods ran.  It does not prove
which production callables or caller -> callee relationships they exercised.
This module provides a dependency-free call profiler and a conservative AST
resolver so the white-box gate can make that distinction explicit.

Only callables in modules reachable from the versioned production entrypoint
set are governed.  Test/release tooling that is not reachable from those
entrypoints cannot inflate the analysis coverage denominator.
"""

from __future__ import annotations

import ast
import atexit
from dataclasses import dataclass
import dis
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import types
from typing import Any, Iterable, Mapping
import uuid


SCHEMA = "java-upgrade-analyzer.whitebox-call-coverage.v1"
INDEX_SCHEMA = "java-upgrade-analyzer.whitebox-call-index.v1"
ENV_INDEX = "JUA_WHITEBOX_CALL_INDEX"
ENV_OUTPUT_DIRECTORY = "JUA_WHITEBOX_CALL_OUTPUT_DIRECTORY"
ENV_ACTIVE_TEST = "JUA_WHITEBOX_ACTIVE_TEST"
SCOPE_SCHEMA = "java-upgrade-analyzer.internal-test-scope.v1"


@dataclass(frozen=True)
class CallableRecord:
    callable_id: str
    module: str
    qualname: str
    path: Path
    line: int
    node: ast.FunctionDef | ast.AsyncFunctionDef
    owner_class: str


@dataclass(frozen=True)
class BranchAlternativeRecord:
    callable_id: str
    module: str
    qualname: str
    path: Path
    line: int
    end_line: int
    column: int
    end_column: int
    code_qualname: str
    code_first_line: int
    offset: int
    opname: str
    side: str


@dataclass(frozen=True)
class StaticCallSiteRecord:
    caller: str
    callee: str
    path: Path
    line: int
    code_qualname: str
    code_first_line: int
    offset: int


@dataclass(frozen=True)
class StaticCallGraph:
    entry_modules: tuple[str, ...]
    reachable_modules: tuple[str, ...]
    source_identity: str
    callables: tuple[CallableRecord, ...]
    resolved_edges: tuple[tuple[str, str], ...]
    call_sites: tuple[StaticCallSiteRecord, ...]
    branch_alternatives: tuple[BranchAlternativeRecord, ...]

    def index_payload(self) -> dict[str, Any]:
        return {
            "schema": INDEX_SCHEMA,
            "entry_modules": list(self.entry_modules),
            "reachable_modules": list(self.reachable_modules),
            "source_identity": self.source_identity,
            "callables": [
                {
                    "id": record.callable_id,
                    "module": record.module,
                    "qualname": record.qualname,
                    "path": str(record.path),
                    "line": record.line,
                }
                for record in self.callables
            ],
            "resolved_edges": [
                {"caller": caller, "callee": callee}
                for caller, callee in self.resolved_edges
            ],
            "call_sites": [
                {
                    "caller": record.caller,
                    "callee": record.callee,
                    "path": str(record.path),
                    "line": record.line,
                    "code_qualname": record.code_qualname,
                    "code_first_line": record.code_first_line,
                    "offset": record.offset,
                }
                for record in self.call_sites
            ],
            "branch_alternatives": [
                {
                    "callable": record.callable_id,
                    "module": record.module,
                    "qualname": record.qualname,
                    "path": str(record.path),
                    "line": record.line,
                    "end_line": record.end_line,
                    "column": record.column,
                    "end_column": record.end_column,
                    "code_qualname": record.code_qualname,
                    "code_first_line": record.code_first_line,
                    "offset": record.offset,
                    "opname": record.opname,
                    "side": record.side,
                }
                for record in self.branch_alternatives
            ],
        }


def _module_paths(scripts_root: Path) -> dict[str, Path]:
    return {
        path.stem: path.resolve()
        for path in scripts_root.glob("*.py")
        if path.is_file()
    }


def _local_import_modules(
    tree: ast.AST, available_modules: set[str],
) -> set[str]:
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                candidate = alias.name.split(".")[-1]
                if candidate in available_modules:
                    imported.add(candidate)
        elif isinstance(node, ast.ImportFrom):
            candidate = (node.module or "").split(".")[-1]
            if candidate in available_modules:
                imported.add(candidate)
    return imported


def reachable_production_modules(
    scripts_root: str | Path,
    entry_modules: Iterable[str],
) -> tuple[tuple[str, ...], dict[str, ast.Module], dict[str, Path]]:
    root = Path(scripts_root).resolve()
    paths = _module_paths(root)
    entries = tuple(sorted({str(value).strip() for value in entry_modules}))
    missing = sorted(set(entries) - set(paths))
    if missing:
        raise ValueError("missing production entry modules: " + ",".join(missing))
    trees = {
        module: ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for module, path in paths.items()
    }
    available = set(paths)
    imports = {
        module: _local_import_modules(tree, available)
        for module, tree in trees.items()
    }
    reachable = set(entries)
    frontier = list(entries)
    while frontier:
        module = frontier.pop()
        for imported in imports.get(module, ()):
            if imported not in reachable:
                reachable.add(imported)
                frontier.append(imported)
    return tuple(sorted(reachable)), trees, paths


def audit_internal_test_scope(
    repository_root: str | Path,
    contract: Mapping[str, Any],
    *,
    discovered_test_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """Prove that every implementation file has one explicit test owner."""
    root = Path(repository_root).resolve()
    issues: list[dict[str, str]] = []

    def issue(code: str, detail: str = "") -> None:
        issues.append({"code": code, "detail": detail})

    if contract.get("schema") != SCOPE_SCHEMA:
        issue("INTERNAL_TEST_SCOPE_SCHEMA_INVALID")
    entries = tuple(
        str(value).strip()
        for value in contract.get("analysis_entry_modules") or ()
        if str(value).strip()
    )
    declared_analysis = tuple(
        str(value).strip()
        for value in contract.get("analysis_modules") or ()
        if str(value).strip()
    )
    if not entries or len(entries) != len(set(entries)):
        issue("ANALYSIS_ENTRY_MODULES_INVALID")
    if not declared_analysis or len(declared_analysis) != len(
        set(declared_analysis)
    ):
        issue("ANALYSIS_MODULES_INVALID")
    try:
        reachable, _trees, _paths = reachable_production_modules(
            root / "scripts", entries,
        )
    except (OSError, SyntaxError, ValueError) as error:
        reachable = ()
        issue(
            "ANALYSIS_IMPORT_CLOSURE_INVALID",
            f"{type(error).__name__}: {error}",
        )
    if set(declared_analysis) != set(reachable):
        issue(
            "ANALYSIS_MODULE_CLOSURE_MISMATCH",
            json.dumps({
                "missing": sorted(set(reachable) - set(declared_analysis)),
                "stale": sorted(set(declared_analysis) - set(reachable)),
            }, ensure_ascii=False, sort_keys=True),
        )

    support_rows = contract.get("governed_support_modules") or ()
    support_modules: list[str] = []
    selectors: list[tuple[str, str]] = []
    allowed_categories = {
        "quality_tool", "release_tool", "test_generator",
        "independent_test_oracle", "runtime_setup",
        "integration_contract", "repository_quality_tool",
        "test_infrastructure",
    }
    if not isinstance(support_rows, list):
        issue("SUPPORT_MODULE_CLASSIFICATION_INVALID")
        support_rows = []
    for index, row in enumerate(support_rows):
        if not isinstance(row, Mapping):
            issue("SUPPORT_MODULE_CLASSIFICATION_INVALID", str(index))
            continue
        module = str(row.get("module") or "").strip()
        category = str(row.get("category") or "").strip()
        test_selectors = row.get("test_selectors")
        if (
            not module
            or category not in allowed_categories
            or not isinstance(test_selectors, list)
            or not test_selectors
        ):
            issue("SUPPORT_MODULE_CLASSIFICATION_INVALID", module or str(index))
            continue
        support_modules.append(module)
        for selector in test_selectors:
            value = str(selector).strip().rstrip(".")
            if not value:
                issue("SUPPORT_MODULE_TEST_SELECTOR_INVALID", module)
            else:
                selectors.append((module, value))
    if len(support_modules) != len(set(support_modules)):
        issue("SUPPORT_MODULE_CLASSIFICATION_DUPLICATED")
    overlap = sorted(set(declared_analysis) & set(support_modules))
    if overlap:
        issue("INTERNAL_MODULE_SCOPE_OVERLAP", ",".join(overlap))
    python_modules = {
        path.stem for path in (root / "scripts").glob("*.py")
        if path.name != "__init__.py"
    }
    classified_modules = set(declared_analysis) | set(support_modules)
    if python_modules != classified_modules:
        issue(
            "INTERNAL_PYTHON_MODULE_INVENTORY_MISMATCH",
            json.dumps({
                "unclassified": sorted(python_modules - classified_modules),
                "missing_files": sorted(classified_modules - python_modules),
            }, ensure_ascii=False, sort_keys=True),
        )

    shell_rows = contract.get("shell_entrypoints", [])
    declared_shell_paths: list[str] = []
    if not isinstance(shell_rows, list):
        issue("SHELL_ENTRYPOINT_CLASSIFICATION_INVALID")
        shell_rows = []
    for index, row in enumerate(shell_rows):
        if not isinstance(row, Mapping):
            issue("SHELL_ENTRYPOINT_CLASSIFICATION_INVALID", str(index))
            continue
        relative = str(row.get("path") or "").strip()
        test_selectors = row.get("test_selectors")
        if not relative or not isinstance(test_selectors, list) or not test_selectors:
            issue("SHELL_ENTRYPOINT_CLASSIFICATION_INVALID", relative or str(index))
            continue
        declared_shell_paths.append(relative)
        for selector in test_selectors:
            value = str(selector).strip().rstrip(".")
            if not value:
                issue("SHELL_ENTRYPOINT_TEST_SELECTOR_INVALID", relative)
            else:
                selectors.append((relative, value))
    actual_shell_paths = {
        path.relative_to(root).as_posix()
        for pattern in ("*.sh", "*.ps1", "*.bat", "*.cmd")
        for path in (root / "scripts").glob(pattern)
    }
    if set(declared_shell_paths) != actual_shell_paths:
        issue(
            "SHELL_ENTRYPOINT_INVENTORY_MISMATCH",
            json.dumps({
                "unclassified": sorted(
                    actual_shell_paths - set(declared_shell_paths)
                ),
                "missing_files": sorted(
                    set(declared_shell_paths) - actual_shell_paths
                ),
            }, ensure_ascii=False, sort_keys=True),
        )

    test_ids = tuple(str(value) for value in discovered_test_ids)
    if test_ids:
        for owner, selector in selectors:
            if not any(
                test_id == selector or test_id.startswith(selector + ".")
                for test_id in test_ids
            ):
                issue(
                    "INTERNAL_SCOPE_TEST_SELECTOR_UNRESOLVED",
                    f"{owner}:{selector}",
                )
    profile_exclusions = contract.get("structural_profile_exclusions") or []
    valid_profile_exclusion_count = 0
    seen_profile_exclusions: set[str] = set()
    if not isinstance(profile_exclusions, list):
        issue("STRUCTURAL_PROFILE_EXCLUSIONS_INVALID")
        profile_exclusions = []
    for index, row in enumerate(profile_exclusions):
        if not isinstance(row, Mapping) or set(row) != {
            "test_id", "reason_code", "replacement_test_ids",
        }:
            issue("STRUCTURAL_PROFILE_EXCLUSION_INVALID", str(index))
            continue
        test_id = str(row.get("test_id") or "").strip()
        reason_code = str(row.get("reason_code") or "").strip()
        replacements = row.get("replacement_test_ids")
        replacements_are_strings = (
            isinstance(replacements, list)
            and all(type(value) is str for value in replacements)
        )
        normalized_replacements = (
            [value.strip() for value in replacements]
            if replacements_are_strings else []
        )
        if (
            not test_id
            or test_id in seen_profile_exclusions
            or reason_code not in {
                "STRUCTURAL_PROFILER_DISTORTS_CAPACITY_SEMANTICS",
                "STRUCTURAL_PROFILER_DISTORTS_TIMEOUT_SEMANTICS",
            }
            or not normalized_replacements
            or len(normalized_replacements)
            != len(set(normalized_replacements))
            or test_id in normalized_replacements
        ):
            issue("STRUCTURAL_PROFILE_EXCLUSION_INVALID", test_id or str(index))
            continue
        if (
            any(not value for value in normalized_replacements)
            or (
                test_ids
                and (
                    test_id not in test_ids
                    or any(value not in test_ids for value in normalized_replacements)
                )
            )
        ):
            issue("STRUCTURAL_PROFILE_EXCLUSION_TEST_UNRESOLVED", test_id)
            continue
        seen_profile_exclusions.add(test_id)
        valid_profile_exclusion_count += 1
    return {
        "schema": SCOPE_SCHEMA,
        "status": "passed" if not issues else "failed",
        "analysis_entry_module_count": len(entries),
        "analysis_module_count": len(reachable),
        "support_module_count": len(support_modules),
        "shell_entrypoint_count": len(declared_shell_paths),
        "python_module_inventory_count": len(python_modules),
        "structural_profile_exclusion_count": valid_profile_exclusion_count,
        "issues": issues,
    }


class _DefinitionCollector(ast.NodeVisitor):
    def __init__(self, module: str, path: Path) -> None:
        self.module = module
        self.path = path
        self.scope: list[tuple[str, str]] = []
        self.records: list[CallableRecord] = []

    def _qualname(self, name: str) -> str:
        parts: list[str] = []
        for scope_name, scope_kind in self.scope:
            parts.append(scope_name)
            if scope_kind == "function":
                parts.append("<locals>")
        parts.append(name)
        return ".".join(parts)

    def _owner_class(self) -> str:
        parts: list[str] = []
        for scope_name, scope_kind in self.scope:
            if scope_kind == "function":
                break
            if scope_kind == "class":
                parts.append(scope_name)
        return ".".join(parts)

    def _visit_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        qualname = self._qualname(node.name)
        self.records.append(CallableRecord(
            callable_id=f"{self.module}::{qualname}",
            module=self.module,
            qualname=qualname,
            path=self.path,
            line=node.lineno,
            node=node,
            owner_class=self._owner_class(),
        ))
        self.scope.append((node.name, "function"))
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef,
    ) -> None:
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.scope.append((node.name, "class"))
        self.generic_visit(node)
        self.scope.pop()


class _BindingCollector(ast.NodeVisitor):
    def __init__(self, root: ast.AST, available_modules: set[str]) -> None:
        self.root = root
        self.available_modules = available_modules
        self.module_candidates: dict[str, set[str]] = {}
        self.symbol_candidates: dict[str, set[tuple[str, str]]] = {}
        self.names: set[str] = set()
        self.non_import_names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)
            self.non_import_names.add(node.id)

    def visit_arg(self, node: ast.arg) -> None:  # noqa: N802
        self.names.add(node.arg)
        self.non_import_names.add(node.arg)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        if node.name:
            self.names.add(node.name)
            self.non_import_names.add(node.name)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            candidate = alias.name.split(".")[-1]
            if candidate in self.available_modules:
                name = alias.asname or candidate
                self.names.add(name)
                self.module_candidates.setdefault(name, set()).add(candidate)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        candidate = (node.module or "").split(".")[-1]
        if candidate not in self.available_modules:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            name = alias.asname or alias.name
            self.names.add(name)
            self.symbol_candidates.setdefault(name, set()).add(
                (candidate, alias.name)
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        if node is self.root:
            for argument in (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            ):
                self.visit(argument)
            if node.args.vararg:
                self.visit(node.args.vararg)
            if node.args.kwarg:
                self.visit(node.args.kwarg)
            for statement in node.body:
                self.visit(statement)
        else:
            self.names.add(node.name)
            self.non_import_names.add(node.name)

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef,
    ) -> None:
        if node is self.root:
            for argument in (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            ):
                self.visit(argument)
            if node.args.vararg:
                self.visit(node.args.vararg)
            if node.args.kwarg:
                self.visit(node.args.kwarg)
            for statement in node.body:
                self.visit(statement)
        else:
            self.names.add(node.name)
            self.non_import_names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.names.add(node.name)
        self.non_import_names.add(node.name)


def _bindings_in_scope(
    root: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
    available_modules: set[str],
) -> tuple[
    dict[str, str], dict[str, tuple[str, str]], set[str],
]:
    collector = _BindingCollector(root, available_modules)
    if isinstance(root, ast.Module):
        for node in root.body:
            collector.visit(node)
    else:
        collector.visit(root)
    module_aliases = {
        name: next(iter(values))
        for name, values in collector.module_candidates.items()
        if len(values) == 1 and name not in collector.non_import_names
    }
    symbol_aliases = {
        name: next(iter(values))
        for name, values in collector.symbol_candidates.items()
        if len(values) == 1 and name not in collector.non_import_names
    }
    return module_aliases, symbol_aliases, collector.names


def _merged_bindings(
    tree: ast.Module,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    available_modules: set[str],
) -> tuple[dict[str, str], dict[str, tuple[str, str]], set[str]]:
    module_aliases, symbol_aliases, _module_names = _bindings_in_scope(
        tree, available_modules,
    )
    local_modules, local_symbols, local_names = _bindings_in_scope(
        function, available_modules,
    )
    for name in local_names:
        module_aliases.pop(name, None)
        symbol_aliases.pop(name, None)
    module_aliases.update(local_modules)
    symbol_aliases.update(local_symbols)
    return module_aliases, symbol_aliases, local_names


class _CallCollector(ast.NodeVisitor):
    """Collect calls in one function without attributing nested bodies to it."""

    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.root = root
        self.calls: list[ast.Call] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        self.calls.append(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        if node is self.root:
            for statement in node.body:
                self.visit(statement)

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef,
    ) -> None:
        if node is self.root:
            for statement in node.body:
                self.visit(statement)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        return


class _LocalInstanceCollector(ast.NodeVisitor):
    """Collect unambiguous local ``name = Class(...)`` bindings."""

    def __init__(self, root, constructor_identity) -> None:
        self.root = root
        self.constructor_identity = constructor_identity
        self.candidates: dict[str, set[tuple[str, str]]] = {}
        self.invalid: set[str] = set()
        self.first_assignment: dict[str, tuple[int, int]] = {}

    @staticmethod
    def _target_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            names: set[str] = set()
            for element in target.elts:
                names.update(_LocalInstanceCollector._target_names(element))
            return names
        return set()

    def _record(self, target: ast.AST, value: ast.AST | None) -> None:
        names = self._target_names(target)
        identity = self.constructor_identity(value) if len(names) == 1 else None
        for name in names:
            position = (
                int(getattr(target, "lineno", 0) or 0),
                int(getattr(target, "col_offset", 0) or 0),
            )
            self.first_assignment.setdefault(name, position)
            if identity:
                self.candidates.setdefault(name, set()).add(identity)
            else:
                self.invalid.add(name)

    def _record_arguments(self, node) -> None:
        arguments = (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
        if node.args.vararg:
            arguments.append(node.args.vararg)
        if node.args.kwarg:
            arguments.append(node.args.kwarg)
        self.invalid.update(argument.arg for argument in arguments)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        if node is self.root:
            self._record_arguments(node)
            for statement in node.body:
                self.visit(statement)
        else:
            self.invalid.add(node.name)

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef,
    ) -> None:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.invalid.add(node.name)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            self._record(target, node.value)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        self._record(node.target, node.value)
        if node.value is not None:
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        self._record(node.target, None)
        self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:  # noqa: N802
        self._record(node.target, node.value)
        self.visit(node.value)

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        self._record(node.target, None)
        self.visit(node.iter)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:  # noqa: N802
        self.visit_For(node)

    def visit_With(self, node: ast.With) -> None:  # noqa: N802
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._record(item.optional_vars, None)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:  # noqa: N802
        self.visit_With(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self.invalid.add(alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        for alias in node.names:
            if alias.name != "*":
                self.invalid.add(alias.asname or alias.name)

    def visit_Delete(self, node: ast.Delete) -> None:  # noqa: N802
        for target in node.targets:
            self.invalid.update(self._target_names(target))

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self.invalid.add(node.name)
        for statement in node.body:
            self.visit(statement)


def _local_instance_bindings(
    caller: CallableRecord,
    *,
    class_methods: Mapping[tuple[str, str, str], str],
    module_aliases: Mapping[str, str],
    symbol_aliases: Mapping[str, tuple[str, str]],
) -> dict[str, tuple[str, str, int, int]]:
    known_classes = {
        (module, class_name)
        for module, class_name, _method_name in class_methods
    }

    def constructor_identity(value):
        if not isinstance(value, ast.Call):
            return None
        function = value.func
        if isinstance(function, ast.Name):
            identity = symbol_aliases.get(function.id)
            if identity is None:
                identity = (caller.module, function.id)
        elif (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id in module_aliases
        ):
            identity = (module_aliases[function.value.id], function.attr)
        else:
            return None
        return identity if identity in known_classes else None

    collector = _LocalInstanceCollector(caller.node, constructor_identity)
    collector.visit(caller.node)
    bindings = {}
    for name, candidates in collector.candidates.items():
        if name in collector.invalid or len(candidates) != 1:
            continue
        module, class_name = next(iter(candidates))
        line, column = collector.first_assignment.get(name, (0, 0))
        bindings[name] = (module, class_name, line, column)
    return bindings


def _resolve_name_call(
    name: str,
    *,
    caller: CallableRecord,
    callable_ids: set[str],
    top_level: Mapping[tuple[str, str], str],
    nested: Mapping[tuple[str, str, str], str],
    symbol_aliases: Mapping[str, tuple[str, str]],
) -> str:
    imported = symbol_aliases.get(name)
    if imported:
        return top_level.get(imported, "")
    local_nested = nested.get((caller.module, caller.qualname, name))
    if local_nested:
        return local_nested
    candidate = top_level.get((caller.module, name), "")
    return candidate if candidate in callable_ids else ""


def _resolve_attribute_call(
    function: ast.Attribute,
    *,
    caller: CallableRecord,
    callable_ids: set[str],
    top_level: Mapping[tuple[str, str], str],
    class_methods: Mapping[tuple[str, str, str], str],
    module_aliases: Mapping[str, str],
    symbol_aliases: Mapping[str, tuple[str, str]],
    local_instances: Mapping[str, tuple[str, str, int, int]],
    locally_bound_names: set[str],
) -> str:
    owner = function.value
    attribute = function.attr
    if isinstance(owner, ast.Name):
        if owner.id in {"self", "cls"} and caller.owner_class:
            return class_methods.get(
                (caller.module, caller.owner_class, attribute), ""
            )
        local_instance = local_instances.get(owner.id)
        if local_instance:
            module, class_name, line, column = local_instance
            call_position = (
                int(getattr(function, "lineno", 0) or 0),
                int(getattr(function, "col_offset", 0) or 0),
            )
            if call_position >= (line, column):
                return class_methods.get(
                    (module, class_name, attribute), ""
                )
            return ""
        imported_module = module_aliases.get(owner.id)
        if imported_module:
            return top_level.get((imported_module, attribute), "")
        imported_symbol = symbol_aliases.get(owner.id)
        if imported_symbol:
            imported_module, imported_name = imported_symbol
            return class_methods.get(
                (imported_module, imported_name, attribute), ""
            )
        candidate = ""
        if owner.id not in locally_bound_names:
            candidate = class_methods.get(
                (caller.module, owner.id, attribute), ""
            )
        return candidate if candidate in callable_ids else ""
    if isinstance(owner, ast.Call) and isinstance(owner.func, ast.Name):
        constructor_name = owner.func.id
        imported_symbol = symbol_aliases.get(constructor_name)
        if imported_symbol:
            imported_module, imported_name = imported_symbol
            return class_methods.get(
                (imported_module, imported_name, attribute), ""
            )
        return class_methods.get(
            (caller.module, constructor_name, attribute), ""
        )
    return ""


def _iter_code_objects(code: types.CodeType) -> Iterable[types.CodeType]:
    yield code
    for constant in code.co_consts:
        if isinstance(constant, types.CodeType):
            yield from _iter_code_objects(constant)


def _is_conditional_branch_instruction(instruction: dis.Instruction) -> bool:
    name = instruction.opname
    return (
        "IF" in name
        or name in {"FOR_ITER", "SEND"}
    ) and (
        instruction.opcode in dis.hasjabs
        or instruction.opcode in dis.hasjrel
    )


def _is_compiler_builtin_identity_guard(
    instructions: list[dis.Instruction], index: int,
) -> bool:
    """Exclude CPython's adaptive built-in fast-path guard from source branches.

    Python 3.14 may compile calls such as ``any(...)`` and
    ``tuple(generator)`` into fast paths guarded by ``global builtin is
    LOAD_COMMON_CONSTANT(builtin)``.  The fallback is interpreter machinery,
    not a source-level product decision.  A source ``is`` expression does not
    synthesize ``LOAD_COMMON_CONSTANT`` and remains governed.
    """

    if index < 1 or instructions[index - 1].opname != "IS_OP":
        return False
    return any(
        instruction.opname == "LOAD_COMMON_CONSTANT"
        for instruction in instructions[max(0, index - 5):index]
    )


def _is_compiler_protocol_branch(
    instructions: list[dis.Instruction], index: int,
) -> bool:
    """Exclude interpreter protocol jumps that are not source decisions.

    PEP 669 reports source branch events, while ``dis`` also exposes jumps
    used to implement ``yield from``, ``with`` cleanup and exception matching.
    Those protocol jumps cannot be witnessed as BRANCH_LEFT/BRANCH_RIGHT and
    would otherwise create permanent false gaps.  Keep this deliberately
    bytecode-specific: ordinary ``if`` and loop instructions remain governed.
    """

    instruction = instructions[index]
    if instruction.opname == "SEND" or "EXC_MATCH" in instruction.opname:
        return True
    protocol_prefixes = {
        "CHECK_EXC_MATCH", "CHECK_EG_MATCH", "WITH_EXCEPT_START",
    }
    return any(
        previous.opname in protocol_prefixes
        for previous in instructions[max(0, index - 3):index]
    )


def _governed_parent_qualname(qualname: str) -> str:
    candidate = qualname
    anonymous = {"<genexpr>", "<listcomp>", "<setcomp>", "<dictcomp>", "<lambda>"}
    leaf = candidate.rsplit(".", 1)[-1]
    if leaf not in anonymous:
        return ""
    marker = ".<locals>."
    if marker not in candidate:
        return ""
    return candidate.rsplit(marker, 1)[0]


def _static_branch_alternatives(
    records: Iterable[CallableRecord],
) -> tuple[BranchAlternativeRecord, ...]:
    by_runtime_identity = {
        (str(record.path), record.qualname): record
        for record in records
    }
    compiled_paths: set[Path] = set()
    alternatives: list[BranchAlternativeRecord] = []
    for record in records:
        if record.path in compiled_paths:
            continue
        compiled_paths.add(record.path)
        source = record.path.read_text(encoding="utf-8-sig")
        module_code = compile(
            source, str(record.path), "exec", dont_inherit=True,
        )
        for code in _iter_code_objects(module_code):
            governed = by_runtime_identity.get(
                (str(record.path), code.co_qualname)
            )
            if governed is None:
                parent_qualname = _governed_parent_qualname(code.co_qualname)
                governed = by_runtime_identity.get(
                    (str(record.path), parent_qualname)
                )
            if governed is None:
                continue
            instructions = list(dis.get_instructions(code))
            for instruction_index, instruction in enumerate(instructions):
                if not _is_conditional_branch_instruction(instruction):
                    continue
                if _is_compiler_builtin_identity_guard(
                    instructions, instruction_index,
                ):
                    continue
                if _is_compiler_protocol_branch(
                    instructions, instruction_index,
                ):
                    continue
                line = int(
                    instruction.positions.lineno
                    if instruction.positions is not None
                    and instruction.positions.lineno is not None
                    else governed.line
                )
                end_line = int(
                    instruction.positions.end_lineno
                    if instruction.positions is not None
                    and instruction.positions.end_lineno is not None
                    else line
                )
                column = int(
                    instruction.positions.col_offset
                    if instruction.positions is not None
                    and instruction.positions.col_offset is not None
                    else 0
                )
                end_column = int(
                    instruction.positions.end_col_offset
                    if instruction.positions is not None
                    and instruction.positions.end_col_offset is not None
                    else column
                )
                for side in ("left", "right"):
                    alternatives.append(BranchAlternativeRecord(
                        callable_id=governed.callable_id,
                        module=governed.module,
                        qualname=governed.qualname,
                        path=governed.path,
                        line=line,
                        end_line=end_line,
                        column=column,
                        end_column=end_column,
                        code_qualname=code.co_qualname,
                        code_first_line=int(code.co_firstlineno),
                        offset=instruction.offset,
                        opname=instruction.opname,
                        side=side,
                    ))
    return tuple(sorted(
        alternatives,
        key=lambda item: (
            item.module, item.qualname, item.offset, item.side,
        ),
    ))


def _source_position(node: ast.AST) -> tuple[int, int, int, int] | None:
    values = (
        getattr(node, "lineno", None),
        getattr(node, "end_lineno", None),
        getattr(node, "col_offset", None),
        getattr(node, "end_col_offset", None),
    )
    if any(value is None for value in values):
        return None
    return tuple(int(value) for value in values)


def _instruction_position(
    instruction: dis.Instruction,
) -> tuple[int, int, int, int] | None:
    positions = instruction.positions
    if positions is None:
        return None
    values = (
        positions.lineno,
        positions.end_lineno,
        positions.col_offset,
        positions.end_col_offset,
    )
    if any(value is None for value in values):
        return None
    return tuple(int(value) for value in values)


def _static_call_sites(
    records: Iterable[CallableRecord],
    resolved_calls: Iterable[tuple[CallableRecord, str, ast.Call]],
) -> tuple[StaticCallSiteRecord, ...]:
    """Bind resolved AST calls to exact bytecode CALL instructions.

    A runtime CALL event proves that the production call expression executed
    even when a test deliberately replaces the target with a controlled fake.
    Ambiguous source-position mappings are omitted rather than guessed.
    """

    records = tuple(records)
    by_runtime_identity = {
        (str(record.path), record.qualname): record
        for record in records
    }
    by_position: dict[tuple[str, tuple[int, int, int, int]], set[str]] = {}
    for caller, callee, call in resolved_calls:
        position = _source_position(call)
        if position is None:
            continue
        by_position.setdefault((caller.callable_id, position), set()).add(
            callee
        )

    sites: set[StaticCallSiteRecord] = set()
    compiled_paths: set[Path] = set()
    for record in records:
        if record.path in compiled_paths:
            continue
        compiled_paths.add(record.path)
        module_code = compile(
            record.path.read_text(encoding="utf-8-sig"),
            str(record.path),
            "exec",
            dont_inherit=True,
        )
        for code in _iter_code_objects(module_code):
            governed = by_runtime_identity.get(
                (str(record.path), code.co_qualname)
            )
            if governed is None:
                parent_qualname = _governed_parent_qualname(code.co_qualname)
                governed = by_runtime_identity.get(
                    (str(record.path), parent_qualname)
                )
            if governed is None:
                continue
            for instruction in dis.get_instructions(code):
                if not instruction.opname.startswith("CALL"):
                    continue
                position = _instruction_position(instruction)
                if position is None:
                    continue
                callees = by_position.get((governed.callable_id, position), set())
                if len(callees) != 1:
                    continue
                sites.add(StaticCallSiteRecord(
                    caller=governed.callable_id,
                    callee=next(iter(callees)),
                    path=governed.path,
                    line=position[0],
                    code_qualname=code.co_qualname,
                    code_first_line=int(code.co_firstlineno),
                    offset=int(instruction.offset),
                ))
    return tuple(sorted(
        sites,
        key=lambda item: (
            item.caller, item.callee, item.code_qualname, item.offset,
        ),
    ))


def build_static_call_graph(
    scripts_root: str | Path,
    entry_modules: Iterable[str],
) -> StaticCallGraph:
    root = Path(scripts_root).resolve()
    entries = tuple(sorted({str(value).strip() for value in entry_modules}))
    reachable, trees, paths = reachable_production_modules(root, entries)
    records: list[CallableRecord] = []
    for module in reachable:
        collector = _DefinitionCollector(module, paths[module])
        collector.visit(trees[module])
        records.extend(collector.records)
    records.sort(key=lambda item: (item.module, item.line, item.qualname))
    callable_ids = {record.callable_id for record in records}
    top_level: dict[tuple[str, str], str] = {}
    class_methods: dict[tuple[str, str, str], str] = {}
    nested: dict[tuple[str, str, str], str] = {}
    for record in records:
        parts = record.qualname.split(".")
        if "<locals>" in parts:
            marker = len(parts) - 2
            parent = ".".join(parts[:marker])
            nested[(record.module, parent, parts[-1])] = record.callable_id
        elif record.owner_class:
            method_name = record.qualname.rsplit(".", 1)[-1]
            class_methods[(
                record.module, record.owner_class, method_name,
            )] = record.callable_id
        else:
            top_level[(record.module, record.qualname)] = record.callable_id

    edges: set[tuple[str, str]] = set()
    resolved_calls: list[tuple[CallableRecord, str, ast.Call]] = []
    for caller in records:
        calls = _CallCollector(caller.node)
        calls.visit(caller.node)
        module_aliases, symbol_aliases, locally_bound_names = _merged_bindings(
            trees[caller.module], caller.node, set(reachable),
        )
        local_instances = _local_instance_bindings(
            caller,
            class_methods=class_methods,
            module_aliases=module_aliases,
            symbol_aliases=symbol_aliases,
        )
        for call in calls.calls:
            callee = ""
            if isinstance(call.func, ast.Name):
                callee = _resolve_name_call(
                    call.func.id,
                    caller=caller,
                    callable_ids=callable_ids,
                    top_level=top_level,
                    nested=nested,
                    symbol_aliases=symbol_aliases,
                )
            elif isinstance(call.func, ast.Attribute):
                callee = _resolve_attribute_call(
                    call.func,
                    caller=caller,
                    callable_ids=callable_ids,
                    top_level=top_level,
                    class_methods=class_methods,
                    module_aliases=module_aliases,
                    symbol_aliases=symbol_aliases,
                    local_instances=local_instances,
                    locally_bound_names=locally_bound_names,
                )
            if callee and callee in callable_ids:
                edges.add((caller.callable_id, callee))
                resolved_calls.append((caller, callee, call))
    source_digest = hashlib.sha256()
    source_digest.update(b"java-upgrade-analyzer.whitebox-source.v1\0")
    for module in reachable:
        content = paths[module].read_bytes()
        encoded_name = module.encode("utf-8")
        source_digest.update(len(encoded_name).to_bytes(8, "big"))
        source_digest.update(encoded_name)
        source_digest.update(len(content).to_bytes(8, "big"))
        source_digest.update(content)
    return StaticCallGraph(
        entry_modules=entries,
        reachable_modules=reachable,
        source_identity=source_digest.hexdigest(),
        callables=tuple(records),
        resolved_edges=tuple(sorted(edges)),
        call_sites=_static_call_sites(records, resolved_calls),
        branch_alternatives=_static_branch_alternatives(records),
    )


class RuntimeCallProfiler:
    def __init__(
        self,
        callable_index: Mapping[tuple[str, str], str],
        *,
        call_site_index: Mapping[
            tuple[str, str, int, int], tuple[str, str]
        ] | None = None,
        active_test_getter=None,
    ) -> None:
        self.callable_index = dict(callable_index)
        self.call_site_index = dict(call_site_index or {})
        self._code_cache: dict[Any, str] = {}
        self._exact_code_cache: dict[Any, str] = {}
        self.active_test_getter = active_test_getter or (
            lambda: os.environ.get(ENV_ACTIVE_TEST, "")
        )
        self.called_by_test: dict[str, set[str]] = {}
        self.edges_by_test: dict[tuple[str, str], set[str]] = {}
        self.call_sites_by_test: dict[tuple[str, str], set[str]] = {}
        self.branches_by_test: dict[
            tuple[str, str, int, int, str], dict[str, Any]
        ] = {}
        self.branch_supported = False
        self.call_site_supported = False
        self._lock = threading.Lock()

    def _lookup_callable_id(
        self, filename: str, qualname: str, *, allow_parent: bool = True,
    ) -> str:
        paths = (filename, os.path.realpath(os.path.abspath(filename)))
        for path in paths:
            callable_id = self.callable_index.get((path, qualname), "")
            if callable_id:
                return callable_id
        parent = _governed_parent_qualname(qualname) if allow_parent else ""
        if parent:
            for path in paths:
                callable_id = self.callable_index.get((path, parent), "")
                if callable_id:
                    return callable_id
        return ""

    def _exact_callable_id(self, frame) -> str:
        code = frame.f_code
        cached = self._exact_code_cache.get(code)
        if cached is not None:
            return cached
        callable_id = self._lookup_callable_id(
            code.co_filename, code.co_qualname, allow_parent=False,
        )
        self._exact_code_cache[code] = callable_id
        return callable_id

    def _callable_id(self, frame) -> str:
        code = frame.f_code
        cached = self._code_cache.get(code)
        if cached is not None:
            return cached
        # Do not construct pathlib.Path here. Several platform-contract tests
        # deliberately patch os.name to "nt" while running on POSIX; pathlib
        # would then attempt to construct WindowsPath and fail. More
        # importantly, a profiler callback must never resolve the same path on
        # every Python call event. Code objects are stable, so normalize once
        # and cache both positive and negative lookups.
        callable_id = self._lookup_callable_id(
            code.co_filename, code.co_qualname,
        )
        self._code_cache[code] = callable_id
        return callable_id

    def __call__(self, frame, event: str, arg):
        if event != "call":
            return self
        callee = self._exact_callable_id(frame)
        if not callee:
            return self
        caller = self._callable_id(frame.f_back) if frame.f_back else ""
        test_id = str(self.active_test_getter() or "<unattributed>")
        with self._lock:
            self.called_by_test.setdefault(callee, set()).add(test_id)
            if caller:
                self.edges_by_test.setdefault((caller, callee), set()).add(
                    test_id
                )
        return self

    def payload(self, *, process_id: int | None = None) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "process_id": process_id or os.getpid(),
            "called": [
                {"callable": callable_id, "tests": sorted(tests)}
                for callable_id, tests in sorted(self.called_by_test.items())
            ],
            "edges": [
                {"caller": caller, "callee": callee, "tests": sorted(tests)}
                for (caller, callee), tests in sorted(self.edges_by_test.items())
            ],
            "call_site_supported": self.call_site_supported,
            "call_sites": [
                {"caller": caller, "callee": callee, "tests": sorted(tests)}
                for (caller, callee), tests in sorted(
                    self.call_sites_by_test.items()
                )
            ],
            "branch_supported": self.branch_supported,
            "branches": [
                {
                    "callable": key[0],
                    "code_qualname": key[1],
                    "code_first_line": key[2],
                    "offset": key[3],
                    "side": key[4],
                    "destinations": sorted(value["destinations"]),
                    "tests": sorted(value["tests"]),
                }
                for key, value in sorted(self.branches_by_test.items())
            ],
        }


class MonitoringCallProfiler(RuntimeCallProfiler):
    """Low-overhead Python 3.12+ call evidence recorder.

    ``sys.setprofile`` observes every Python and C call and materially changes
    the timing of the process-tree tests in this repository.  PEP 669's
    monitoring API emits only Python-function start events and is sufficiently
    light-weight for those tests.  Keep ``RuntimeCallProfiler`` as the portable
    fallback and as the small, directly testable event implementation.
    """

    _TOOL_NAME = "java-upgrade-analyzer-whitebox-call-coverage"

    def __init__(
        self,
        callable_index: Mapping[tuple[str, str], str],
        *,
        call_site_index: Mapping[
            tuple[str, str, int, int], tuple[str, str]
        ] | None = None,
        active_test_getter=None,
        local_only: bool = True,
    ) -> None:
        super().__init__(
            callable_index,
            call_site_index=call_site_index,
            active_test_getter=active_test_getter,
        )
        self._monitoring = getattr(sys, "monitoring", None)
        if self._monitoring is None:
            raise RuntimeError("sys.monitoring requires Python 3.12 or newer")
        self._local_only = local_only
        self.branch_supported = all(hasattr(
            self._monitoring.events, name,
        ) for name in ("BRANCH_LEFT", "BRANCH_RIGHT"))
        if not self.branch_supported:
            raise RuntimeError(
                "sys.monitoring branch-side events are unavailable"
            )
        self.call_site_supported = hasattr(self._monitoring.events, "CALL")
        if not self.call_site_supported:
            raise RuntimeError("sys.monitoring CALL events are unavailable")
        self._tool_id: int | None = None
        self._local_codes: tuple[types.CodeType, ...] = ()

    def _loaded_production_codes(self) -> tuple[types.CodeType, ...]:
        """Return live production code, including nested code constants.

        Test discovery imports the modules under test before execution.  Local
        monitoring of only those code objects avoids observing unittest,
        multiprocessing and the rest of the interpreter.  That distinction is
        essential: global profiling can turn process-liveness assertions into
        observer-induced timeouts.
        """
        governed_paths = {path for path, _ in self.callable_index}
        seen_objects: set[int] = set()
        codes: dict[int, types.CodeType] = {}

        def add_code(code: types.CodeType) -> None:
            if id(code) in codes:
                return
            if self._callable_id_from_code(code):
                codes[id(code)] = code
            for constant in code.co_consts:
                if isinstance(constant, types.CodeType):
                    add_code(constant)

        def visit(value: Any) -> None:
            identity = id(value)
            if identity in seen_objects:
                return
            seen_objects.add(identity)
            if isinstance(value, types.FunctionType):
                add_code(value.__code__)
                wrapped = getattr(value, "__wrapped__", None)
                if wrapped is not None:
                    visit(wrapped)
                return
            if isinstance(value, (staticmethod, classmethod)):
                visit(value.__func__)
                return
            if isinstance(value, property):
                for accessor in (value.fget, value.fset, value.fdel):
                    if accessor is not None:
                        visit(accessor)
                return
            if isinstance(value, type):
                for member in vars(value).values():
                    visit(member)
                return
            # C-implemented decorators such as functools.lru_cache expose the
            # Python function only through ``__wrapped__`` and are not
            # ``types.FunctionType`` instances. Without following that link,
            # local sys.monitoring silently omits the executed callable and all
            # of its branches.
            wrapped = getattr(value, "__wrapped__", None)
            if wrapped is not None and wrapped is not value:
                visit(wrapped)

        for module in tuple(sys.modules.values()):
            module_path = getattr(module, "__file__", "")
            if not module_path:
                continue
            normalized = os.path.realpath(os.path.abspath(module_path))
            if normalized not in governed_paths:
                continue
            for value in tuple(vars(module).values()):
                visit(value)
        return tuple(codes.values())

    def _python_start(self, code, instruction_offset: int) -> None:
        del instruction_offset
        callee = self._exact_callable_id_from_code(code)
        if not callee:
            return
        try:
            caller_frame = sys._getframe(2)
        except ValueError:
            caller_frame = None
        caller = (
            self._callable_id_from_code(caller_frame.f_code)
            if caller_frame is not None else ""
        )
        test_id = str(self.active_test_getter() or "<unattributed>")
        with self._lock:
            self.called_by_test.setdefault(callee, set()).add(test_id)
            if caller:
                self.edges_by_test.setdefault((caller, callee), set()).add(
                    test_id
                )

    def _record_branch(
        self,
        side: str,
        code,
        instruction_offset: int,
        destination_offset: int,
    ) -> None:
        callable_id = self._callable_id_from_code(code)
        if not callable_id:
            return
        test_id = str(self.active_test_getter() or "<unattributed>")
        key = (
            callable_id,
            str(code.co_qualname),
            int(code.co_firstlineno),
            int(instruction_offset),
            side,
        )
        with self._lock:
            row = self.branches_by_test.setdefault(key, {
                "destinations": set(), "tests": set(),
            })
            row["destinations"].add(int(destination_offset))
            row["tests"].add(test_id)

    def _branch_left(
        self, code, instruction_offset: int, destination_offset: int,
    ) -> None:
        self._record_branch(
            "left", code, instruction_offset, destination_offset,
        )

    def _branch_right(
        self, code, instruction_offset: int, destination_offset: int,
    ) -> None:
        self._record_branch(
            "right", code, instruction_offset, destination_offset,
        )

    def _call_site(
        self, code, instruction_offset: int, callable_object, argument_zero,
    ):
        del callable_object, argument_zero
        paths = (
            code.co_filename,
            os.path.realpath(os.path.abspath(code.co_filename)),
        )
        edge = None
        for path in paths:
            edge = self.call_site_index.get((
                path,
                str(code.co_qualname),
                int(code.co_firstlineno),
                int(instruction_offset),
            ))
            if edge is not None:
                break
        if edge is not None:
            test_id = str(self.active_test_getter() or "<unattributed>")
            with self._lock:
                self.call_sites_by_test.setdefault(edge, set()).add(test_id)
        # CALL is a hot event: large report and graph tests can execute the
        # same instruction millions of times. One production instruction
        # witness is sufficient to prove the static relationship. PEP 669
        # disables only this event location, preserving every other call site
        # and all branch-side monitoring.
        return self._monitoring.DISABLE

    def _callable_id_from_code(self, code) -> str:
        cached = self._code_cache.get(code)
        if cached is not None:
            return cached
        callable_id = self._lookup_callable_id(
            code.co_filename, code.co_qualname,
        )
        self._code_cache[code] = callable_id
        return callable_id

    def _exact_callable_id_from_code(self, code) -> str:
        cached = self._exact_code_cache.get(code)
        if cached is not None:
            return cached
        callable_id = self._lookup_callable_id(
            code.co_filename, code.co_qualname, allow_parent=False,
        )
        self._exact_code_cache[code] = callable_id
        return callable_id

    def start(self) -> None:
        if self._tool_id is not None:
            return
        candidates = (
            self._monitoring.PROFILER_ID,
            3,
            4,
        )
        tool_id = next(
            (
                candidate for candidate in candidates
                if self._monitoring.get_tool(candidate) is None
            ),
            None,
        )
        if tool_id is None:
            raise RuntimeError("no free sys.monitoring tool id")
        self._monitoring.use_tool_id(tool_id, self._TOOL_NAME)
        try:
            branch_events = (
                self._monitoring.events.BRANCH_LEFT
                | self._monitoring.events.BRANCH_RIGHT
            )
            call_events = self._monitoring.events.CALL
            self._monitoring.register_callback(
                tool_id,
                self._monitoring.events.PY_START,
                self._python_start,
            )
            self._monitoring.register_callback(
                tool_id,
                self._monitoring.events.BRANCH_LEFT,
                self._branch_left,
            )
            self._monitoring.register_callback(
                tool_id,
                self._monitoring.events.BRANCH_RIGHT,
                self._branch_right,
            )
            self._monitoring.register_callback(
                tool_id,
                self._monitoring.events.CALL,
                self._call_site,
            )
            if self._local_only:
                self._local_codes = self._loaded_production_codes()
                for code in self._local_codes:
                    self._monitoring.set_local_events(
                        tool_id,
                        code,
                        self._monitoring.events.PY_START
                        | branch_events
                        | call_events,
                    )
            else:
                self._monitoring.set_events(
                    tool_id, self._monitoring.events.PY_START
                    | branch_events
                    | call_events,
                )
        except BaseException:
            self._monitoring.free_tool_id(tool_id)
            raise
        self._tool_id = tool_id

    def stop(self) -> None:
        tool_id = self._tool_id
        if tool_id is None:
            return
        self._monitoring.set_events(tool_id, 0)
        for code in self._local_codes:
            self._monitoring.set_local_events(tool_id, code, 0)
        self._local_codes = ()
        self._monitoring.register_callback(
            tool_id, self._monitoring.events.PY_START, None,
        )
        self._monitoring.register_callback(
            tool_id, self._monitoring.events.BRANCH_LEFT, None,
        )
        self._monitoring.register_callback(
            tool_id, self._monitoring.events.BRANCH_RIGHT, None,
        )
        self._monitoring.register_callback(
            tool_id, self._monitoring.events.CALL, None,
        )
        self._monitoring.free_tool_id(tool_id)
        self._tool_id = None


def create_runtime_profiler(
    callable_index: Mapping[tuple[str, str], str],
    *,
    call_site_index: Mapping[
        tuple[str, str, int, int], tuple[str, str]
    ] | None = None,
    active_test_getter=None,
    local_only: bool = True,
) -> RuntimeCallProfiler:
    """Select the least intrusive profiler supported by this interpreter."""
    if getattr(sys, "monitoring", None) is not None:
        return MonitoringCallProfiler(
            callable_index, call_site_index=call_site_index,
            active_test_getter=active_test_getter,
            local_only=local_only,
        )
    return RuntimeCallProfiler(
        callable_index,
        call_site_index=call_site_index,
        active_test_getter=active_test_getter,
    )


def start_runtime_profiler(profiler: RuntimeCallProfiler) -> None:
    if isinstance(profiler, MonitoringCallProfiler):
        profiler.start()
        return
    sys.setprofile(profiler)
    threading.setprofile(profiler)


def stop_runtime_profiler(profiler: RuntimeCallProfiler) -> None:
    if isinstance(profiler, MonitoringCallProfiler):
        profiler.stop()
        return
    sys.setprofile(None)
    threading.setprofile(None)


def callable_index_from_payload(
    payload: Mapping[str, Any],
) -> dict[tuple[str, str], str]:
    if payload.get("schema") != INDEX_SCHEMA:
        raise ValueError("whitebox call index schema is invalid")
    index: dict[tuple[str, str], str] = {}
    for row in payload.get("callables") or ():
        if not isinstance(row, Mapping):
            raise ValueError("whitebox call index callable is invalid")
        path = str(Path(str(row.get("path") or "")).resolve())
        qualname = str(row.get("qualname") or "")
        callable_id = str(row.get("id") or "")
        if not path or not qualname or not callable_id:
            raise ValueError("whitebox call index callable is incomplete")
        key = (path, qualname)
        if key in index or callable_id in index.values():
            raise ValueError("whitebox call index callable is duplicated")
        index[key] = callable_id
    return index


def call_site_index_from_payload(
    payload: Mapping[str, Any],
) -> dict[tuple[str, str, int, int], tuple[str, str]]:
    if payload.get("schema") != INDEX_SCHEMA:
        raise ValueError("whitebox call index schema is invalid")
    callable_ids = {
        str(row.get("id") or "")
        for row in payload.get("callables") or ()
        if isinstance(row, Mapping)
    }
    index: dict[tuple[str, str, int, int], tuple[str, str]] = {}
    for row in payload.get("call_sites") or ():
        if not isinstance(row, Mapping):
            raise ValueError("whitebox call site is invalid")
        try:
            key = (
                str(Path(str(row.get("path") or "")).resolve()),
                str(row.get("code_qualname") or ""),
                int(row.get("code_first_line")),
                int(row.get("offset")),
            )
        except (TypeError, ValueError) as error:
            raise ValueError("whitebox call site is invalid") from error
        edge = (str(row.get("caller") or ""), str(row.get("callee") or ""))
        if (
            not key[1]
            or key[2] < 0
            or key[3] < 0
            or any(value not in callable_ids for value in edge)
            or key in index
        ):
            raise ValueError("whitebox call site is invalid")
        index[key] = edge
    return index


def write_process_payload(
    profiler: RuntimeCallProfiler,
    output_directory: str | Path,
) -> Path:
    directory = Path(output_directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (
        f"process-{os.getpid()}-{uuid.uuid4().hex}.json"
    )
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(profiler.payload(), ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, target)
    return target


_INSTALLED_PROFILER: RuntimeCallProfiler | None = None


def process_target_is_governed(
    index_payload: Mapping[str, Any],
    *,
    argv: Iterable[str] | None = None,
    orig_argv: Iterable[str] | None = None,
) -> bool:
    """Return whether this Python process was launched through governed code.

    The structural gate exports ``PYTHONPATH`` to child processes so real
    production CLI subprocesses can contribute evidence.  Some black-box
    fixtures intentionally implement fake Java/Gradle executables in Python.
    Attaching the profiler to those external-tool stand-ins changes their
    timeout semantics and measures test infrastructure as if it were product
    code.  Match the interpreter entry target to an indexed production source
    path before installing any monitoring callbacks.
    """

    governed_paths = {
        str(Path(str(row.get("path") or "")).expanduser().resolve())
        for row in index_payload.get("callables") or ()
        if isinstance(row, Mapping) and str(row.get("path") or "").strip()
    }
    if not governed_paths:
        return False

    arguments = tuple(sys.argv if argv is None else argv)
    original = tuple(
        getattr(sys, "orig_argv", ()) if orig_argv is None else orig_argv
    )
    direct_candidates = []
    if arguments:
        direct_candidates.append(str(arguments[0]))
    direct_candidates.extend(str(value) for value in original[1:])
    for candidate in direct_candidates:
        if not candidate or candidate.startswith("-"):
            continue
        if str(Path(candidate).expanduser().resolve()) in governed_paths:
            return True

    if "-m" in original:
        index = original.index("-m")
        if index + 1 < len(original):
            module = str(original[index + 1]).strip()
            if module and not module.startswith("-"):
                module_path = module.replace(".", os.sep)
                suffixes = (
                    os.sep + module_path + ".py",
                    os.sep + module_path + os.sep + "__main__.py",
                )
                if any(
                    governed.endswith(suffixes)
                    for governed in governed_paths
                ):
                    return True
    return False


def install_process_profiler_from_environment() -> bool:
    """Install tracing in child Python processes through sitecustomize."""
    global _INSTALLED_PROFILER
    index_path = os.environ.get(ENV_INDEX, "")
    output_directory = os.environ.get(ENV_OUTPUT_DIRECTORY, "")
    if not index_path or not output_directory or _INSTALLED_PROFILER is not None:
        return False
    payload = json.loads(Path(index_path).read_text(encoding="utf-8-sig"))
    if not process_target_is_governed(payload):
        return False
    profiler = create_runtime_profiler(
        callable_index_from_payload(payload),
        call_site_index=call_site_index_from_payload(payload),
        local_only=False,
    )
    _INSTALLED_PROFILER = profiler
    start_runtime_profiler(profiler)
    atexit.register(write_process_payload, profiler, output_directory)
    return True


def merge_process_payloads(
    payloads: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    called: dict[str, set[str]] = {}
    edges: dict[tuple[str, str], set[str]] = {}
    call_sites: dict[tuple[str, str], set[str]] = {}
    branches: dict[
        tuple[str, str, int, int, str], dict[str, set[Any]]
    ] = {}
    process_ids: set[int] = set()
    branch_supported = True
    call_site_supported = True
    for payload in payloads:
        if payload.get("schema") != SCHEMA:
            raise ValueError("whitebox process call evidence schema is invalid")
        process_id = payload.get("process_id")
        if isinstance(process_id, int) and not isinstance(process_id, bool):
            process_ids.add(process_id)
        branch_supported = branch_supported and bool(
            payload.get("branch_supported")
        )
        call_site_supported = call_site_supported and bool(
            payload.get("call_site_supported")
        )
        for row in payload.get("called") or ():
            callable_id = str(row.get("callable") or "")
            called.setdefault(callable_id, set()).update(
                str(value) for value in row.get("tests") or ()
            )
        for row in payload.get("edges") or ():
            key = (str(row.get("caller") or ""), str(row.get("callee") or ""))
            edges.setdefault(key, set()).update(
                str(value) for value in row.get("tests") or ()
            )
        for row in payload.get("call_sites") or ():
            key = (str(row.get("caller") or ""), str(row.get("callee") or ""))
            call_sites.setdefault(key, set()).update(
                str(value) for value in row.get("tests") or ()
            )
        for row in payload.get("branches") or ():
            key = (
                str(row.get("callable") or ""),
                str(row.get("code_qualname") or ""),
                int(row.get("code_first_line")),
                int(row.get("offset")),
                str(row.get("side") or ""),
            )
            merged = branches.setdefault(key, {
                "destinations": set(), "tests": set(),
            })
            merged["destinations"].update(
                int(value) for value in row.get("destinations") or ()
            )
            merged["tests"].update(
                str(value) for value in row.get("tests") or ()
            )
    return {
        "schema": SCHEMA,
        "process_ids": sorted(process_ids),
        "branch_supported": branch_supported,
        "called": [
            {"callable": key, "tests": sorted(value)}
            for key, value in sorted(called.items())
        ],
        "edges": [
            {"caller": key[0], "callee": key[1], "tests": sorted(value)}
            for key, value in sorted(edges.items())
        ],
        "call_site_supported": call_site_supported,
        "call_sites": [
            {"caller": key[0], "callee": key[1], "tests": sorted(value)}
            for key, value in sorted(call_sites.items())
        ],
        "branches": [
            {
                "callable": key[0],
                "code_qualname": key[1],
                "code_first_line": key[2],
                "offset": key[3],
                "side": key[4],
                "destinations": sorted(value["destinations"]),
                "tests": sorted(value["tests"]),
            }
            for key, value in sorted(branches.items())
        ],
    }


if __name__ == "__main__":
    raise SystemExit("whitebox_call_coverage is a library used by the test gate")
