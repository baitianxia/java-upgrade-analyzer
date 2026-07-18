#!/usr/bin/env python3
"""Closed-world reconciliation and production collector probe for generated cases."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import zipfile

from business_bytecode_graph import collect_business_bytecode_edges
from generated_topology import GeneratedTopology, materialize_topology


@dataclass(frozen=True)
class AnalyzerLedgerRow:
    identity: str
    conclusion: str
    evidence_complete: bool
    producer: str


@dataclass(frozen=True)
class GeneratedCaseResult:
    status: str
    errors: tuple[str, ...]
    missing: tuple[str, ...]
    extra: tuple[str, ...]
    duplicates: tuple[str, ...]
    conflicts: tuple[str, ...]
    unsupported: tuple[str, ...]
    wrong_conclusions: tuple[str, ...]
    production_metrics: dict
    report_path: str = ""


def reconcile_generated_case(
    case: GeneratedTopology, analyzer_rows: tuple[AnalyzerLedgerRow, ...]
) -> GeneratedCaseResult:
    truth = {edge.identity for edge in case.spec.truth_edges}
    rows_by_identity: dict[str, list[AnalyzerLedgerRow]] = {}
    for row in analyzer_rows:
        rows_by_identity.setdefault(row.identity, []).append(row)
    actual = set(rows_by_identity)
    missing = tuple(sorted(truth - actual))
    extra = tuple(sorted(actual - truth))
    duplicates = tuple(
        sorted(identity for identity, rows in rows_by_identity.items() if len(rows) > 1)
    )
    conflicts = tuple(
        sorted(
            identity
            for identity, rows in rows_by_identity.items()
            if len({(row.conclusion, row.evidence_complete) for row in rows}) > 1
        )
    )
    unsupported = tuple(
        sorted(
            row.identity
            for row in analyzer_rows
            if row.conclusion == "reachable"
            and (not row.evidence_complete or not row.producer.strip())
        )
    )
    expected_conclusions = {
        edge.identity: edge.expected_conclusion for edge in case.spec.truth_edges
    }
    wrong_conclusions = tuple(sorted(
        row.identity
        for row in analyzer_rows
        if row.identity in expected_conclusions
        and row.conclusion != expected_conclusions[row.identity]
    ))
    errors = []
    if missing:
        errors.append("missing_identity")
    if extra:
        errors.append("extra_identity")
    if duplicates:
        errors.append("duplicate_identity")
    if conflicts:
        errors.append("conflicting_identity")
    if unsupported:
        errors.append("unsupported_strong_conclusion")
    if wrong_conclusions:
        errors.append("wrong_conclusion")
    return GeneratedCaseResult(
        status="failed" if errors else "passed",
        errors=tuple(errors),
        missing=missing,
        extra=extra,
        duplicates=duplicates,
        conflicts=conflicts,
        unsupported=unsupported,
        wrong_conclusions=wrong_conclusions,
        production_metrics={},
    )


def _derive_analyzer_rows(case: GeneratedTopology, edges: list[dict]):
    apis = {api.identity: api for api in case.spec.apis}
    rows = []
    for truth_edge in case.spec.truth_edges:
        caller = truth_edge.caller.split("#", 1)[1].split("(", 1)[0]
        api = apis[truth_edge.target]
        if api.kind == "field":
            matching = [
                edge for edge in edges
                if edge.get("caller_name") == caller
                and str(edge.get("callee_key") or "").endswith(f".{api.member}")
            ]
        else:
            matching = [
                edge for edge in edges
                if edge.get("caller_name") == caller
                and f".{api.member}(" in str(edge.get("callee_key") or "")
            ]
        if matching:
            conclusion = "reachable"
            complete = True
            producer = "+".join(sorted({str(edge.get("parser") or "javap") for edge in matching}))
        elif truth_edge.dimension == "constant":
            conclusion = "uncertain"
            complete = True
            producer = "complete_bytecode_scan_inlined_constant_absence"
        else:
            conclusion = "not_analyzed"
            complete = False
            producer = "complete_bytecode_scan_missing_expected_edge"
        rows.append(AnalyzerLedgerRow(
            truth_edge.identity, conclusion, complete, producer
        ))
    return tuple(rows)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_generated_case(
    case: GeneratedTopology,
    report_root: Path,
    *,
    analyzer_rows: tuple[AnalyzerLedgerRow, ...] | None = None,
) -> GeneratedCaseResult:
    report_root = Path(report_root)
    materialized = materialize_topology(case, report_root / f"seed-{case.spec.seed}")
    jar_path = materialized.root / "application.jar"
    with zipfile.ZipFile(jar_path, "w") as archive:
        for class_file in sorted(materialized.classes_dir.rglob("*.class")):
            archive.write(class_file, class_file.relative_to(materialized.classes_dir).as_posix())
    edges, metrics = collect_business_bytecode_edges(
        [],
        artifact_catalog={
            "by_coord": {
                "__business__": {
                    "jar_path": str(jar_path),
                    "sha256": _sha256(jar_path),
                }
            }
        },
    )
    metrics = dict(metrics)
    metrics["production_edge_identities"] = sorted(
        {
            f"{edge.get('caller_owner')}#{edge.get('caller_name')}"
            f"->{edge.get('callee_key')}"
            for edge in edges
        }
    )
    if analyzer_rows is None:
        analyzer_rows = _derive_analyzer_rows(case, edges)
    metrics["derived_rows"] = len(analyzer_rows)
    reconciled = reconcile_generated_case(case, analyzer_rows)
    errors = list(reconciled.errors)
    if metrics.get("failures"):
        errors.append("production_collector_incomplete")
    if not edges:
        errors.append("production_collector_empty")
    report_path = report_root / f"seed-{case.spec.seed}" / "reconciliation.json"
    result = GeneratedCaseResult(
        status="failed" if errors else "passed",
        errors=tuple(errors),
        missing=reconciled.missing,
        extra=reconciled.extra,
        duplicates=reconciled.duplicates,
        conflicts=reconciled.conflicts,
        unsupported=reconciled.unsupported,
        wrong_conclusions=reconciled.wrong_conclusions,
        production_metrics=metrics,
        report_path=str(report_path),
    )
    report_path.write_text(
        json.dumps(asdict(result), sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return result
