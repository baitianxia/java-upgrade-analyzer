#!/usr/bin/env python3
"""Canonical edge identity and analyzer/oracle reconciliation."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass


EDGE_IDENTITY_FIELDS = (
    "artifact_sha256",
    "caller_owner",
    "caller_member",
    "caller_descriptor",
    "callee_owner",
    "callee_member",
    "callee_descriptor",
    "opcode_family",
)

PROVENANCE_FIELDS = (
    "artifact_sha256",
    "artifact_entry",
    "authority",
    "authority_version",
    "procedure",
)

VERDICTS = (
    "correct",
    "missing",
    "extra",
    "identity_mismatch",
    "provenance_invalid",
    "oracle_conflict",
)


@dataclass(frozen=True, order=True)
class EdgeIdentity:
    artifact_sha256: str
    caller_owner: str
    caller_member: str
    caller_descriptor: str
    callee_owner: str
    callee_member: str
    callee_descriptor: str
    opcode_family: str


def _value(row: dict, field: str) -> str:
    return str((row or {}).get(field) or "").strip()


def _identity_from_row(row: dict) -> EdgeIdentity:
    return EdgeIdentity(*(_value(row, field) for field in EDGE_IDENTITY_FIELDS))


def canonical_edge_identity(row: dict) -> str:
    return "|".join(_value(row, field) for field in EDGE_IDENTITY_FIELDS)


def _relation_key(identity: EdgeIdentity) -> tuple[str, str, str, str]:
    return (
        identity.caller_owner,
        identity.caller_member,
        identity.callee_owner,
        identity.callee_member,
    )


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _truth_state(row: dict) -> str:
    edge_state = _value(row, "edge_state")
    if edge_state:
        state = edge_state.lower()
    else:
        raw_present = (row or {}).get("present")
        if raw_present is None:
            return "present"
        if isinstance(raw_present, bool):
            return "present" if raw_present else "absent"
        state = str(raw_present).strip().lower()
    if state in {"present", "true", "1", "yes", "reachable"}:
        return "present"
    if state in {"absent", "false", "0", "no", "missing"}:
        return "absent"
    return state or "present"


def _provenance_valid(row: dict) -> bool:
    sha256 = _value(row, "artifact_sha256")
    if not _valid_sha256(sha256):
        return False
    if not _value(row, "artifact_entry"):
        return False
    for field in ("authority", "authority_version", "procedure"):
        if not _value(row, field):
            return False
    return True


def _make_record(row: dict) -> dict:
    identity = _identity_from_row(row)
    return {
        "row": dict(row or {}),
        "identity": identity,
        "identity_string": canonical_edge_identity(row),
        "relation_key": _relation_key(identity),
        "truth_state": _truth_state(row),
        "artifact_sha256": _value(row, "artifact_sha256"),
        "artifact_entry": _value(row, "artifact_entry"),
        "provenance_valid": _provenance_valid(row),
        "provenance": tuple(_value(row, field) for field in PROVENANCE_FIELDS),
        "disposition": None,
        "reason": "",
    }


def _set_disposition(record: dict, verdict: str, reason: str = "") -> None:
    if record["disposition"] is None:
        record["disposition"] = verdict
        record["reason"] = reason


def _ledger_entry(record: dict) -> dict:
    entry = {
        "side": record["side"],
        "index": record["index"],
        "verdict": record["disposition"],
        "reason": record["reason"],
        "identity": record["identity_string"],
        "artifact_sha256": record["artifact_sha256"],
        "artifact_entry": record["artifact_entry"],
    }
    if record["side"] == "analyzer":
        entry["analyzer_row"] = record["row"]
    else:
        entry["oracle_row"] = record["row"]
    return entry


def _normalize_artifact_entries(valid_artifact_entries) -> set[str]:
    if valid_artifact_entries is None:
        raise TypeError("valid_artifact_entries is a required keyword argument")
    entries = {str(entry).strip() for entry in valid_artifact_entries if str(entry).strip()}
    if not entries:
        raise ValueError("valid_artifact_entries must not be empty")
    return entries


def _group_active(records: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        if record["disposition"] is None:
            groups[record["identity_string"]].append(record)
    return groups


def reconcile_edges(
    analyzer_rows: list[dict],
    oracle_rows: list[dict],
    *,
    trusted_artifact_sha: str,
    valid_artifact_entries,
) -> dict:
    trusted_artifact_sha = _value({"trusted_artifact_sha": trusted_artifact_sha}, "trusted_artifact_sha")
    if not _valid_sha256(trusted_artifact_sha):
        raise ValueError("trusted_artifact_sha must be a lowercase 64-character SHA-256")
    allowed_entries = _normalize_artifact_entries(valid_artifact_entries)

    analyzer_records = [_make_record(row) for row in (analyzer_rows or [])]
    oracle_records = [_make_record(row) for row in (oracle_rows or [])]
    for index, record in enumerate(analyzer_records):
        record["side"] = "analyzer"
        record["index"] = index
    for index, record in enumerate(oracle_records):
        record["side"] = "oracle"
        record["index"] = index

    ledger_records = analyzer_records + oracle_records

    for record in ledger_records:
        if not record["provenance_valid"]:
            _set_disposition(record, "provenance_invalid", "invalid_provenance")

    for record in ledger_records:
        if record["disposition"] is None and record["artifact_sha256"] != trusted_artifact_sha:
            _set_disposition(record, "provenance_invalid", "trusted_sha_mismatch")

    for record in ledger_records:
        if record["artifact_entry"] not in allowed_entries:
            _set_disposition(record, "provenance_invalid", "artifact_entry_not_allowed")

    active_by_identity = _group_active(ledger_records)
    for identity, bucket in active_by_identity.items():
        truth_states = {record["truth_state"] for record in bucket}
        if "present" in truth_states and "absent" in truth_states:
            for record in bucket:
                _set_disposition(record, "oracle_conflict", "contradictory_truth_state")

    active_by_identity = _group_active(ledger_records)
    for identity, bucket in active_by_identity.items():
        if len({record["artifact_entry"] for record in bucket}) > 1:
            for record in bucket:
                _set_disposition(record, "provenance_invalid", "artifact_entry_mismatch")

    active_by_identity = _group_active(ledger_records)
    for identity in sorted(active_by_identity):
        bucket = active_by_identity[identity]
        if any(record["truth_state"] != "present" for record in bucket):
            continue
        analyzer_bucket = [record for record in bucket if record["side"] == "analyzer"]
        oracle_bucket = [record for record in bucket if record["side"] == "oracle"]
        matched = min(len(analyzer_bucket), len(oracle_bucket))
        for analyzer_record, oracle_record in zip(analyzer_bucket[:matched], oracle_bucket[:matched]):
            _set_disposition(analyzer_record, "correct", "exact_identity_match")
            _set_disposition(oracle_record, "correct", "exact_identity_match")

    active_by_identity = _group_active(ledger_records)
    active_present = [
        record
        for identity in sorted(active_by_identity)
        for record in active_by_identity[identity]
        if record["truth_state"] == "present"
    ]
    analyzer_by_relation: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
    oracle_by_relation: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
    for record in active_present:
        if record["side"] == "analyzer":
            analyzer_by_relation[record["relation_key"]].append(record)
        else:
            oracle_by_relation[record["relation_key"]].append(record)

    for relation_key in sorted(set(analyzer_by_relation) | set(oracle_by_relation)):
        analyzer_bucket = analyzer_by_relation.get(relation_key, [])
        oracle_bucket = oracle_by_relation.get(relation_key, [])
        matched = min(len(analyzer_bucket), len(oracle_bucket))
        for analyzer_record, oracle_record in zip(analyzer_bucket[:matched], oracle_bucket[:matched]):
            if analyzer_record["identity_string"] != oracle_record["identity_string"]:
                _set_disposition(analyzer_record, "identity_mismatch", "same_relation_key_different_identity")
                _set_disposition(oracle_record, "identity_mismatch", "same_relation_key_different_identity")

    for record in ledger_records:
        if record["disposition"] is None:
            if record["side"] == "analyzer":
                _set_disposition(record, "extra", "unmatched_analyzer_row")
            else:
                _set_disposition(record, "missing", "unmatched_oracle_row")

    ledger = sorted(
        (_ledger_entry(record) for record in ledger_records),
        key=lambda row: (
            row["side"],
            row["index"],
            row["verdict"],
            row["identity"],
        ),
    )
    verdict_counts = Counter(row["verdict"] for row in ledger)
    result = {
        "ledger": ledger,
        "verdict_counts": {verdict: int(verdict_counts.get(verdict, 0)) for verdict in VERDICTS},
    }
    result["blocking"] = any(result["verdict_counts"][verdict] for verdict in VERDICTS if verdict != "correct")
    return result
