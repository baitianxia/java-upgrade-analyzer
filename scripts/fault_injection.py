#!/usr/bin/env python3
"""Test-orchestration mutations for proving quality gates fail closed."""

from copy import deepcopy
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MutationResult:
    mode: str
    analyzer_rows: tuple[dict[str, Any], ...]
    oracle_scan: dict[str, Any]
    oracle_mutated: bool
    expected_verdict: str = ""
    expected_signal: str = "edge_reconciliation"
    metadata: dict[str, Any] | None = None


def _require_edge(rows, mode):
    if not rows:
        raise ValueError(f"injectable_analyzer_edge_missing:{mode}")
    return rows[0]


def apply_fault_injection(mode, analyzer_rows, oracle_scan):
    """Return copied, mutated evidence without changing production inputs."""
    rows = [deepcopy(row) for row in (analyzer_rows or [])]
    scan = deepcopy(oracle_scan or {})
    metadata = {}

    if mode == "drop_analyzer_edge":
        removed = _require_edge(rows, mode)
        rows = rows[1:]
        metadata["mutated_api_identity"] = str(removed.get("api_identity") or "")
        return MutationResult(mode, tuple(rows), scan, False, "missing", metadata=metadata)

    if mode == "add_analyzer_edge":
        source = _require_edge(rows, mode)
        added = deepcopy(source)
        try:
            offset = int(str(added.get("instruction_offset") or "0"))
        except ValueError:
            offset = 0
        added["instruction_offset"] = str(offset + 1_000_000)
        rows.append(added)
        return MutationResult(mode, tuple(rows), scan, False, "extra", metadata=metadata)

    if mode == "wrong_analyzer_descriptor":
        source = _require_edge(rows, mode)
        source["callee_descriptor"] = "(I)V"
        return MutationResult(mode, tuple(rows), scan, False, "missing", metadata=metadata)

    if mode == "corrupt_oracle_digest":
        current = str(scan.get("artifact_sha256") or "")
        scan["artifact_sha256"] = "0" * 64 if current != "0" * 64 else "f" * 64
        return MutationResult(
            mode, tuple(rows), scan, True, expected_signal="oracle_invalid", metadata=metadata
        )

    if mode == "truncate_oracle_scan":
        scan["complete"] = False
        scan["edges"] = list(scan.get("edges") or [])[:-1]
        scan.setdefault("failures", []).append("fault_injection:oracle_scan_truncated")
        return MutationResult(
            mode, tuple(rows), scan, True, expected_signal="oracle_incomplete", metadata=metadata
        )

    raise ValueError(f"unsupported_fault_injection:{mode}")


def detect_oracle_mutation(clean_scan, candidate_scan):
    """Classify an injected Oracle violation without consulting analyzer output."""
    clean = clean_scan or {}
    candidate = candidate_scan or {}
    if str(candidate.get("artifact_sha256") or "") != str(
        clean.get("artifact_sha256") or ""
    ):
        return "oracle_invalid"
    if clean.get("complete") is True and candidate.get("complete") is not True:
        return "oracle_incomplete"
    if len(candidate.get("edges") or []) < len(clean.get("edges") or []):
        return "oracle_incomplete"
    return ""
