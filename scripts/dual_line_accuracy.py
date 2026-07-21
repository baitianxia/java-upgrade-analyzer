#!/usr/bin/env python3
"""Reconcile analyzer and independent Oracle results for any Java project."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import re

from csv_io import open_csv_read
from exhaustive_api_oracle import (
    audit_api_oracle,
    load_analyzer_rows,
    write_oracle_ledger,
)


SCHEMA = "java-upgrade-analyzer.dual-line-accuracy.v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _read_csv(path: Path) -> list[dict]:
    with open_csv_read(Path(path)) as handle:
        return list(csv.DictReader(handle))


def _read_summary(path: Path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("analyzer_summary_root_not_object")
    return payload


def reconcile_accuracy_lines(
    api_universe_rows: list[dict],
    analyzer_rows: list[dict],
    oracle_rows: list[dict],
    *,
    expected_artifact_sha256: str,
    trusted_capability_records: list[dict] | tuple[dict, ...] = (),
) -> dict:
    """Compare two independently produced ledgers over one closed API universe."""
    artifact_sha256 = str(expected_artifact_sha256 or "").strip().lower()
    if not SHA256_RE.fullmatch(artifact_sha256):
        raise ValueError("expected_artifact_sha256_invalid")
    result = audit_api_oracle(
        list(api_universe_rows or []),
        list(analyzer_rows or []),
        list(oracle_rows or []),
        expected_artifact_sha256=artifact_sha256,
        trusted_capability_records=trusted_capability_records,
        require_artifact_binding_for_all=True,
    )
    errors = [] if api_universe_rows else ["api_universe_empty"]
    if errors:
        result["blocking"] = True
    return {
        "schema": SCHEMA,
        "status": "failed" if result.get("blocking") else "passed",
        "line_counts": {
            "api_universe": len(api_universe_rows or []),
            "analyzer": len(analyzer_rows or []),
            "oracle": len(oracle_rows or []),
        },
        "artifact_sha256": artifact_sha256,
        "errors": errors,
        **result,
    }


def write_line_payload(path: Path, line: str, rows: list[dict]) -> str:
    if line not in {"analyzer", "oracle"}:
        raise ValueError(f"unsupported_accuracy_line:{line}")
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "schema": SCHEMA,
        "line": line,
        "rows": list(rows or []),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return str(output)


def write_accuracy_result(path: Path, result: dict) -> str:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return str(output)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-universe", required=True, type=Path)
    parser.add_argument("--analyzer-summary", required=True, type=Path)
    parser.add_argument("--oracle-ledger", required=True, type=Path)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--ledger-out", type=Path)
    parser.add_argument("--json-out", type=Path)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        universe = _read_csv(args.api_universe)
        analyzer = load_analyzer_rows(_read_summary(args.analyzer_summary))
        oracle = _read_csv(args.oracle_ledger)
        result = reconcile_accuracy_lines(
            universe,
            analyzer,
            oracle,
            expected_artifact_sha256=args.artifact_sha256,
        )
        if args.ledger_out:
            write_oracle_ledger(args.ledger_out, result)
        returncode = 1 if result.get("blocking") else 0
    except (OSError, ValueError, csv.Error, json.JSONDecodeError) as error:
        result = {
            "schema": SCHEMA,
            "status": "failed",
            "blocking": True,
            "errors": [f"{type(error).__name__}:{error}"],
        }
        returncode = 2
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
