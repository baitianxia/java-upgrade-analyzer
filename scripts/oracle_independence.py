#!/usr/bin/env python3
"""Static and runtime independence checks for third-party Oracle producers."""

from __future__ import annotations

import ast
import argparse
from dataclasses import asdict
from dataclasses import dataclass
import json
from pathlib import Path
import re


@dataclass(frozen=True)
class BoundaryPolicy:
    oracle_files: tuple[str, ...]
    forbidden_modules: tuple[str, ...]
    allowed_schema_modules: tuple[str, ...]

    @classmethod
    def from_dict(cls, payload: dict) -> "BoundaryPolicy":
        if payload.get("schema_version") != 1:
            raise ValueError("unsupported oracle boundary schema")
        return cls(
            tuple(payload.get("oracle_files") or ()),
            tuple(payload.get("forbidden_modules") or ()),
            tuple(payload.get("allowed_schema_modules") or ()),
        )


@dataclass(frozen=True)
class BoundaryViolation:
    path: str
    line: int
    module: str
    access: str


@dataclass(frozen=True)
class BoundaryAudit:
    status: str
    violations: tuple[BoundaryViolation, ...]
    files_checked: int


def _root_module(name: str) -> str:
    return name.split(".", 1)[0]


def _literal_module(call: ast.Call) -> str:
    if not call.args or not isinstance(call.args[0], ast.Constant):
        return ""
    value = call.args[0].value
    return value if isinstance(value, str) else ""


def _dependencies(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno, "import"
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module, node.lineno, "from_import"
        elif isinstance(node, ast.Call):
            function = node.func
            is_importlib = (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "importlib"
                and function.attr == "import_module"
            )
            is_dunder = isinstance(function, ast.Name) and function.id == "__import__"
            if is_importlib or is_dunder:
                module = _literal_module(node)
                if module:
                    yield module, node.lineno, "dynamic_import"


def audit_oracle_boundaries(root: Path, policy: BoundaryPolicy) -> BoundaryAudit:
    root = Path(root)
    forbidden = set(policy.forbidden_modules) - set(policy.allowed_schema_modules)
    violations = []
    checked = 0
    for relative in policy.oracle_files:
        path = root / relative
        if not path.is_file():
            violations.append(BoundaryViolation(relative, 0, "", "missing_file"))
            continue
        checked += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError):
            violations.append(BoundaryViolation(relative, 0, "", "parse_failure"))
            continue
        for module, line, access in _dependencies(tree):
            root_module = _root_module(module)
            if root_module in forbidden:
                violations.append(BoundaryViolation(relative, line, root_module, access))
    ordered = tuple(sorted(violations, key=lambda row: (row.path, row.line, row.module)))
    return BoundaryAudit("failed" if ordered else "passed", ordered, checked)


def validate_oracle_rows(
    rows: list[dict], *, forbidden_producers: set[str]
) -> tuple[str, ...]:
    errors = []
    sha_pattern = re.compile(r"[0-9a-f]{64}")
    for row in rows:
        identity = str(row.get("identity") or "<missing>")
        producer = str(row.get("producer") or "")
        if producer in forbidden_producers or not producer:
            errors.append(f"forbidden_oracle_producer:{identity}:{producer or '<missing>'}")
        sha = str(row.get("artifact_sha256") or "")
        if not sha_pattern.fullmatch(sha):
            errors.append(f"missing_oracle_artifact_sha:{identity}")
    return tuple(errors)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Audit Oracle implementation independence")
    parser.add_argument("policy")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--json-out", default="")
    args = parser.parse_args(argv)
    try:
        payload = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        report = audit_oracle_boundaries(Path(args.root), BoundaryPolicy.from_dict(payload))
        result = asdict(report)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"status": "failed", "violations": [], "files_checked": 0, "error": str(exc)}
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    print(encoded, end="")
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
