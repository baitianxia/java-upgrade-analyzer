#!/usr/bin/env python3
"""Test-orchestration mutations for proving quality gates fail closed."""

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
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


ORACLE_PAYLOAD_DIGEST_FIELD = "oracle_payload_sha256"


def oracle_payload_sha256(oracle_scan):
    payload = deepcopy(oracle_scan or {})
    payload.pop(ORACLE_PAYLOAD_DIGEST_FIELD, None)
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def seal_oracle_scan(oracle_scan):
    sealed = deepcopy(oracle_scan or {})
    sealed[ORACLE_PAYLOAD_DIGEST_FIELD] = oracle_payload_sha256(sealed)
    return sealed


def _require_edge(rows, mode):
    if not rows:
        raise ValueError(f"injectable_analyzer_edge_missing:{mode}")
    return rows[0]


def _different_method_descriptor(original):
    current = str(original or "")
    candidate = "(I)V" if current != "(I)V" else "(J)V"
    if candidate == current:
        raise ValueError("fault_injection_descriptor_mutation_no_op")
    return candidate


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
        original = str(source.get("callee_descriptor") or "")
        mutated = _different_method_descriptor(original)
        source["callee_descriptor"] = mutated
        metadata.update({
            "original_descriptor": original,
            "mutated_descriptor": mutated,
        })
        return MutationResult(mode, tuple(rows), scan, False, "missing", metadata=metadata)

    if mode == "corrupt_oracle_digest":
        edges = list(scan.get("edges") or [])
        if edges:
            edges[0] = deepcopy(edges[0])
            current = str(edges[0].get("callee_descriptor") or "")
            edges[0]["callee_descriptor"] = _different_method_descriptor(current)
            scan["edges"] = edges
            metadata["mutated_oracle_section"] = "edges"
        else:
            reachability = dict(scan.get("api_reachability") or {})
            current = reachability.get("fault-injected-api")
            reachability["fault-injected-api"] = (
                "uncertain" if current == "reachable" else "reachable"
            )
            scan["api_reachability"] = reachability
            metadata["mutated_oracle_section"] = "api_reachability"
        return MutationResult(
            mode, tuple(rows), scan, True, expected_signal="oracle_invalid", metadata=metadata
        )

    if mode == "truncate_oracle_scan":
        scan["complete"] = False
        scan["edges"] = list(scan.get("edges") or [])[:-1]
        scan.setdefault("failures", []).append("fault_injection:oracle_scan_truncated")
        scan = seal_oracle_scan(scan)
        return MutationResult(
            mode, tuple(rows), scan, True, expected_signal="oracle_incomplete", metadata=metadata
        )

    raise ValueError(f"unsupported_fault_injection:{mode}")


def detect_oracle_mutation(clean_scan, candidate_scan):
    """Classify an injected Oracle violation without consulting analyzer output."""
    clean = clean_scan or {}
    candidate = candidate_scan or {}
    if str(candidate.get(ORACLE_PAYLOAD_DIGEST_FIELD) or "") != oracle_payload_sha256(
        candidate
    ):
        return "oracle_invalid"
    if str(candidate.get("artifact_sha256") or "") != str(
        clean.get("artifact_sha256") or ""
    ):
        return "oracle_invalid"
    if clean.get("complete") is True and candidate.get("complete") is not True:
        return "oracle_incomplete"
    if len(candidate.get("edges") or []) < len(clean.get("edges") or []):
        return "oracle_incomplete"
    return ""
