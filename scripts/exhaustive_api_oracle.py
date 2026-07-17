#!/usr/bin/env python3
"""Exhaustive per-API comparison against third-party authority records."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from pathlib import Path

from csv_io import open_csv_read
from signature_utils import canonical_api_identity


PROVENANCE_FIELDS = (
    "authority",
    "authority_version",
    "procedure",
    "evidence_path",
    "evidence_sha256",
    "generated_at",
)
SELF_AUTHORITIES = {"java-upgrade-analyzer", "jua", "self", "analyzer"}


def canonical_identity(row: dict) -> str:
    return canonical_api_identity(row)


def _valid_provenance(record: dict) -> bool:
    if str(record.get("authority") or "").strip().lower() in SELF_AUTHORITIES:
        return False
    if any(not str(record.get(field) or "").strip() for field in PROVENANCE_FIELDS):
        return False
    digest = str(record.get("evidence_sha256") or "").strip().lower()
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def load_analyzer_rows(summary: dict) -> list[dict]:
    rows: list[dict] = []
    for field, status in (
        ("reachable_apis", "reachable"),
        ("not_impacted_apis", "not_impacted"),
        ("uncertain_apis", "uncertain"),
        ("not_analyzed_apis", "not_analyzed"),
        ("not_found_apis", "not_found_in_static_analysis"),
    ):
        for raw in summary.get(field) or []:
            row = dict(raw)
            row["api_name"] = str(row.get("api_name") or row.get("api") or "")
            row["analysis_status"] = status
            rows.append(row)
    return rows


def load_oracle_manifest(path: Path | None) -> list[dict]:
    if path is None or not path.is_file():
        return []
    with open_csv_read(path) as fh:
        return list(csv.DictReader(fh))


def write_oracle_ledger(path: Path, audit: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "identity", "analyzer_conclusion", "oracle_conclusion", "verdict",
        "authorities", "evidence_paths",
    )
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for raw in audit.get("ledger") or []:
            row = dict(raw)
            row["authorities"] = ";".join(row.get("authorities") or [])
            row["evidence_paths"] = ";".join(row.get("evidence_paths") or [])
            writer.writerow({field: row.get(field, "") for field in fields})


def _resolve_oracle_conclusions(records: list[dict]) -> set[str]:
    conclusions = {
        str(item.get("oracle_conclusion") or "").strip()
        for item in records
    } - {"", "uncertain"}
    if "reachable" not in conclusions:
        return conclusions
    alternatives = conclusions - {"reachable"}
    if alternatives != {"not_found_in_static_analysis"}:
        return conclusions
    static_absences = [
        item for item in records
        if str(item.get("oracle_conclusion") or "").strip()
        == "not_found_in_static_analysis"
    ]
    if static_absences and all(
        str(item.get("conclusion_scope") or "").strip() == "static_analysis"
        for item in static_absences
    ):
        return {"reachable"}
    return conclusions


def audit_api_oracle(changed_rows: list[dict], analyzer_rows: list[dict], oracle_rows: list[dict]) -> dict:
    changed_counts = Counter(canonical_identity(row) for row in changed_rows)
    changed_by_id = {canonical_identity(row): row for row in changed_rows}
    analyzer_rows_by_id: dict[str, list[dict]] = defaultdict(list)
    for row in analyzer_rows:
        analyzer_rows_by_id[canonical_identity(row)].append(row)
    analyzer_by_id = {
        identity: rows[0] for identity, rows in analyzer_rows_by_id.items()
    }
    oracle_by_id: dict[str, list[dict]] = defaultdict(list)
    for row in oracle_rows:
        oracle_by_id[canonical_identity(row)].append(row)

    counts = Counter(canonical_identity(row) for row in oracle_rows)
    duplicate_identities = sorted(identity for identity, count in counts.items() if count > 1 and len({
        str(item.get("authority") or "") for item in oracle_by_id[identity]
    }) < count)
    extra_identities = sorted(set(oracle_by_id) - set(changed_by_id))
    analyzer_extra_identities = sorted(set(analyzer_by_id) - set(changed_by_id))
    analyzer_missing_identities = sorted(set(changed_by_id) - set(analyzer_by_id))
    changed_duplicate_identities = sorted(
        identity for identity, count in changed_counts.items() if count > 1
    )
    analyzer_duplicate_identities = sorted(
        identity for identity, rows in analyzer_rows_by_id.items() if len(rows) > 1
    )
    analyzer_conflict_identities = sorted(
        identity for identity, rows in analyzer_rows_by_id.items()
        if len({str(row.get("analysis_status") or "") for row in rows}) > 1
    )
    missing_identities = sorted(set(changed_by_id) - set(oracle_by_id))
    invalid_provenance: list[str] = []
    ledger: list[dict] = []

    for identity in sorted(changed_by_id):
        analyzer = analyzer_by_id.get(identity) or {}
        records = oracle_by_id.get(identity) or []
        valid_records = []
        for record in records:
            if _valid_provenance(record):
                valid_records.append(record)
            else:
                invalid_provenance.append(identity)
        conclusions = _resolve_oracle_conclusions(valid_records)
        analyzer_conclusion = str(analyzer.get("analysis_status") or "")
        if len(conclusions) > 1:
            verdict = "oracle_conflict"
            oracle_conclusion = ""
        elif not valid_records:
            verdict = "unverified"
            oracle_conclusion = ""
        elif not conclusions and analyzer_conclusion != "uncertain":
            verdict = "unverified"
            oracle_conclusion = ""
        else:
            oracle_conclusion = next(iter(conclusions), "uncertain")
            severity = str(changed_by_id[identity].get("severity") or "").upper()
            requires_two = severity in {"P0", "P1", "HIGH"} and analyzer_conclusion in {
                "not_impacted", "not_found_in_static_analysis", "uncertain",
            }
            supporting_records = [
                item for item in valid_records
                if str(item.get("oracle_conclusion") or "") == oracle_conclusion
            ]
            authority_count = len({
                str(item.get("authority") or "") for item in supporting_records
            })
            has_project_test = any(
                str(item.get("evidence_mode") or "") == "project_test"
                for item in supporting_records
            )
            if requires_two and authority_count < 2 and not has_project_test:
                verdict = "unverified"
            else:
                verdict = "correct" if analyzer_conclusion == oracle_conclusion else "incorrect"
        ledger.append({
            "identity": identity,
            "analyzer_conclusion": analyzer_conclusion,
            "oracle_conclusion": oracle_conclusion,
            "verdict": verdict,
            "authorities": sorted({str(item.get("authority") or "") for item in valid_records}),
            "evidence_paths": sorted({str(item.get("evidence_path") or "") for item in valid_records}),
        })

    verdicts = Counter(row["verdict"] for row in ledger)
    result = {
        "ledger": ledger,
        "selected": len(changed_by_id),
        "verified": verdicts["correct"],
        "incorrect": verdicts["incorrect"],
        "unverified": verdicts["unverified"],
        "oracle_conflicts": verdicts["oracle_conflict"],
        "missing_identities": missing_identities,
        "duplicate_identities": duplicate_identities,
        "extra_identities": extra_identities,
        "analyzer_extra_identities": analyzer_extra_identities,
        "analyzer_missing_identities": analyzer_missing_identities,
        "changed_duplicate_identities": changed_duplicate_identities,
        "analyzer_duplicate_identities": analyzer_duplicate_identities,
        "analyzer_conflict_identities": analyzer_conflict_identities,
        "invalid_provenance": sorted(set(invalid_provenance)),
    }
    result.update({
        "missing_identity_count": len(result["missing_identities"]),
        "duplicate_identity_count": len(result["duplicate_identities"]),
        "extra_identity_count": len(result["extra_identities"]),
        "analyzer_extra_identity_count": len(result["analyzer_extra_identities"]),
        "analyzer_missing_identity_count": len(result["analyzer_missing_identities"]),
        "changed_duplicate_identity_count": len(result["changed_duplicate_identities"]),
        "analyzer_duplicate_identity_count": len(result["analyzer_duplicate_identities"]),
        "analyzer_conflict_identity_count": len(result["analyzer_conflict_identities"]),
        "invalid_provenance_count": len(result["invalid_provenance"]),
    })
    result["blocking"] = any((
        result["verified"] != result["selected"],
        result["incorrect"],
        result["unverified"],
        result["oracle_conflicts"],
        result["duplicate_identities"],
        result["extra_identities"],
        result["analyzer_extra_identities"],
        result["analyzer_missing_identities"],
        result["changed_duplicate_identities"],
        result["analyzer_duplicate_identities"],
        result["analyzer_conflict_identities"],
        result["invalid_provenance"],
    ))
    return result
