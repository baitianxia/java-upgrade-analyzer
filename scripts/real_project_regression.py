#!/usr/bin/env python3
"""
Real-project regression runner for java-upgrade-analyzer.

This script is intentionally not part of the default CI smoke suite: it expects
real project checkouts under /private/tmp (or explicit paths passed by CLI) and
therefore validates ecosystem-shaped source code rather than synthetic fixtures.

The checks are deliberately conservative:
  * Step5 must complete.
  * Production-source baseline references for selected APIs must not be missing
    from alerts.csv.
  * Test-source references are reported separately and do not fail the run.
  * Extra alert files are reported but not treated as failures because a full
    call chain can legitimately include helper methods or target declarations.
"""

from __future__ import annotations

import argparse
import copy
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import importlib
import io
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Iterable

from csv_io import open_csv_read, open_csv_write
from analysis_contract import (
    build_project_scope,
    project_scope_provenance_errors,
    project_scope_provenance_fields,
)
from constant_impact import classify_constant_impact
from constant_impact_oracle import audit_constant_evidence, run_constant_oracle
from s4_jar_compare import attach_constant_field_evidence
from artifact_safety import inspect_archive
from exhaustive_api_oracle import (
    load_analyzer_rows,
    load_oracle_manifest,
    write_oracle_ledger,
)
from dual_line_accuracy import (
    reconcile_accuracy_lines,
    write_accuracy_result,
    write_line_payload,
)
from edge_truth import EDGE_IDENTITY_FIELDS, canonical_edge_identity, reconcile_edges
from final_artifact_edge_oracle import scan_final_artifact
from fault_injection import (
    apply_fault_injection,
    detect_oracle_mutation,
    oracle_payload_sha256,
    seal_oracle_scan,
)
from mybatis_mapper_oracle import (
    inspect_mybatis_artifact,
    verify_runtime_activation,
)
from s4_contract import ALL_CHANGED_APIS_FIELDS
from signature_utils import (
    canonical_api_identity,
    normalize_signature_for_lookup,
    signatures_match_identity,
)
from third_party_jdk_oracle import _source_signature
from third_party_jdk_oracle import discover_calls, scan_class_files
from third_party_jdeps_oracle import scan_artifact_class_references as scan_jdeps_class_references
from topology_coverage import (
    classify_topologies,
    compute_topology_coverage,
    extract_artifact_topology_evidence,
)


ROOT_DIR = Path(__file__).resolve().parents[1]

ORACLE_EDGE_FIELDS = (
    "artifact_sha256", "artifact_entry", *EDGE_IDENTITY_FIELDS[1:],
    "instruction_offset", "authority", "authority_version", "procedure",
)
EDGE_RECONCILIATION_FIELDS = (
    "side", "index", "verdict", "reason", "identity", "artifact_sha256", "artifact_entry", "api_identity",
    "physical_occurrence",
)
EDGE_COMPARISON_FIELDS = EDGE_IDENTITY_FIELDS[1:]
EDGE_RECONCILIATION_VERDICTS = (
    "correct", "missing", "extra", "identity_mismatch", "provenance_invalid", "oracle_conflict",
)
V3_GATE_NAMES = (
    "asset", "api_coverage", "topology_coverage", "edge_truth",
    "conclusion", "oracle_accuracy", "performance", "fixture_debt",
)
GUARD_LIFECYCLES = ("core", "capability", "exploratory")
GUARD_SELECTORS = ("guard", "guard-core", "guard-capability", "guard-exploratory")
STANDARD_FAULT_INJECTIONS = (
    "drop_analyzer_edge",
    "add_analyzer_edge",
    "wrong_analyzer_descriptor",
    "corrupt_oracle_digest",
    "truncate_oracle_scan",
)
ORACLE_INTEGRITY_FAULT_INJECTIONS = (
    "corrupt_oracle_digest",
    "truncate_oracle_scan",
)


_STEP5_FINGERPRINT_VOLATILE_KEYS = frozenset({
    "generated_at", "created_at", "updated_at", "started_at", "finished_at",
    "elapsed", "elapsed_sec", "duration_sec", "peak_rss_mb", "current_rss_mb",
    "memory_samples", "step5_perf",
    "javap_peak_pending_tasks", "javap_pending_limit",
    "cache_hit",
})


def _canonicalize_step5_result_value(value, report_roots):
    if isinstance(value, dict):
        result = {}
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            key = str(key)
            if (
                key in _STEP5_FINGERPRINT_VOLATILE_KEYS
                or key.endswith("_elapsed_sec")
            ):
                continue
            if key == "evidence_ingestion" and isinstance(item, dict):
                ingestion = {
                    str(inner_key): _canonicalize_step5_result_value(
                        inner_value, report_roots
                    )
                    for inner_key, inner_value in sorted(
                        item.items(), key=lambda pair: str(pair[0])
                    )
                    if str(inner_key) not in {
                        "failure_count", "failure_occurrence_fields", "failures",
                    }
                }
                occurrence_fields = tuple(
                    str(field) for field in item.get("failure_occurrence_fields") or ()
                )
                failure_semantics = {}
                for failure in (item.get("failures") or ()):
                    if not isinstance(failure, dict):
                        continue
                    occurrences = failure.get("occurrences") or ()
                    normalized_occurrences = []
                    for occurrence in occurrences:
                        if isinstance(occurrence, dict):
                            normalized_occurrences.append(occurrence)
                        elif occurrence_fields and isinstance(
                            occurrence, (list, tuple)
                        ):
                            normalized_occurrences.append(dict(zip(
                                occurrence_fields, occurrence,
                            )))
                    if not normalized_occurrences:
                        normalized_occurrences.append(failure)
                    for occurrence in normalized_occurrences:
                        canonical_failure = {
                            "collector": failure.get("collector"),
                            "reason_code": failure.get("reason_code"),
                            "blocking": bool(failure.get("blocking")),
                            "api_identity": failure.get("api_identity"),
                        }
                        canonical_failure.update(occurrence)
                        canonical_failure.setdefault(
                            "artifact", failure.get("artifact"),
                        )
                        canonical_failure.setdefault(
                            "class_name", failure.get("class_name"),
                        )
                        canonical_failure = _canonicalize_step5_result_value(
                            canonical_failure, report_roots,
                        )
                        identity = json.dumps(
                            canonical_failure, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":"),
                        )
                        failure_semantics[identity] = canonical_failure
                ingestion["failure_semantics"] = [
                    failure_semantics[key] for key in sorted(failure_semantics)
                ]
                result[key] = ingestion
                continue
            result[key] = _canonicalize_step5_result_value(item, report_roots)
        return result
    if isinstance(value, list):
        return [
            _canonicalize_step5_result_value(item, report_roots)
            for item in value
        ]
    if isinstance(value, str):
        normalized = value
        for report_root in report_roots:
            normalized = normalized.replace(report_root, "<REPORT_ROOT>")
        return normalized
    return value


def _canonicalize_step5_query_index(value, report_roots):
    canonical = _canonicalize_step5_result_value(value, report_roots)
    reverse_edges = canonical.get("reverse_edges") if isinstance(canonical, dict) else None
    if isinstance(reverse_edges, dict):
        for lookup_key, edges in reverse_edges.items():
            if isinstance(edges, list):
                reverse_edges[lookup_key] = sorted(
                    edges,
                    key=lambda item: json.dumps(
                        item, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                    ),
                )
    return canonical


def step5_result_contract(report_dir):
    """Return stable Step5 conclusions and paths without runtime telemetry."""
    report_input = Path(report_dir).expanduser().absolute()
    report_root = report_input.resolve()
    report_roots = tuple(dict.fromkeys((str(report_input), str(report_root))))
    call_chain_dir = report_root / "evidence" / "call_chain"
    if not call_chain_dir.is_dir():
        call_chain_dir = report_root
    payload = {}
    summary_path = call_chain_dir / "summary.json"
    if summary_path.is_file():
        payload["summary"] = _canonicalize_step5_result_value(
            json.loads(summary_path.read_text(encoding="utf-8-sig")),
            report_roots,
        )
    alerts_path = call_chain_dir / "alerts.csv"
    if alerts_path.is_file():
        with alerts_path.open("r", encoding="utf-8-sig", newline="") as handle:
            payload["alerts"] = [
                _canonicalize_step5_result_value(dict(row), report_roots)
                for row in csv.DictReader(handle)
            ]
    query_index = report_root / ".runtime" / "indexes" / "s5_query_index.json"
    if query_index.is_file():
        payload["query_index"] = _canonicalize_step5_query_index(
            json.loads(query_index.read_text(encoding="utf-8-sig")),
            report_roots,
        )
    if not payload:
        raise FileNotFoundError(
            f"no Step5 summary, alerts or query index found under {report_root}"
        )
    return payload


def canonical_step5_result_fingerprint(report_dir):
    """Hash stable Step5 conclusions and paths while excluding runtime telemetry."""
    payload = step5_result_contract(report_dir)
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def cold_run_metrics(report_dir):
    """Read scalar Step5 observability values without interpreting conclusions."""
    path = Path(report_dir) / ".runtime" / "observability" / "step5_timing.csv"
    if not path.is_file():
        raise FileNotFoundError(f"Step5 timing CSV not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return {
            f"{row.get('section', '')}.{row.get('metric', '')}": row.get("value", "")
            for row in csv.DictReader(handle)
            if row.get("section") and row.get("metric")
        }


@dataclass(frozen=True)
class BaselineSpec:
    symbol: str
    pattern: str
    import_pattern: str
    require_zero_production_missing: bool = True
    notes: str = ""
    file_path_pattern: str = ""


@dataclass(frozen=True)
class RealProjectCase:
    name: str
    default_project: Path
    default_changed_apis: Path
    baseline_specs: tuple[BaselineSpec, ...]
    target_module: str = ""
    active_maven_profiles: tuple[str, ...] = field(default_factory=tuple)
    manual_coord_overrides: tuple[str, ...] = field(default_factory=tuple)
    source_dirs: tuple[Path, ...] = field(default_factory=tuple)
    changed_api_rows: tuple[dict[str, str], ...] = field(default_factory=tuple)
    prefer_embedded_changed_api_rows: bool = False
    source_shape_patterns: dict[str, str] = field(default_factory=dict)
    min_source_shape_files: dict[str, int] = field(default_factory=dict)
    min_methods_indexed: int = 0
    min_reverse_edges_indexed: int = 0
    max_elapsed_seconds: float = 0.0
    max_full_step4_api_elapsed_seconds: float = 0.0
    run_step4: bool = False
    derive_step1_from_artifacts: bool = False
    base_final_artifact: Path | None = None
    base_source_project: Path | None = None
    current_source_project: Path | None = None
    base_revision: str = ""
    current_revision: str = ""
    step4_dep_rows: tuple[dict[str, str], ...] = field(default_factory=tuple)
    expected_step4_api_names: tuple[str, ...] = field(default_factory=tuple)
    max_step4_elapsed_seconds: float = 0.0
    run_step6_report: bool = False
    expected_report_texts: tuple[str, ...] = field(default_factory=tuple)
    query_methods: tuple[str, ...] = field(default_factory=tuple)
    require_valid_git: bool = False
    min_project_java_files: int = 0
    min_main_java_files: int = 0
    max_generated_java_ratio: float = 0.0
    case_mode: str = "guard"
    ground_truth_status: str = "reviewed"
    max_potential_pairs_per_api: float = 0.0
    max_duplicate_class_scans: int = -1
    max_seconds_per_100k_edges: float = 0.0
    min_edges_for_normalized_rate: int = 0
    min_classes_per_second: float = 0.0
    max_oracle_seconds: float = 0.0
    oracle_manifest: Path | None = None
    enable_jdk_oracle: bool = False
    bytecode_owner_prefixes: tuple[str, ...] = field(default_factory=tuple)
    bytecode_coord: str = ""
    final_artifact: Path | None = None
    required_topologies: tuple[str, ...] = field(default_factory=tuple)
    prior_covered_topologies: tuple[str, ...] = field(default_factory=tuple)
    target_owner_entries: dict[str, tuple[str, ...]] = field(default_factory=dict)
    source_attestation: Path | None = None
    prior_topology_matrix: Path | None = None
    fixture_manifest: Path | None = None
    required_fault_injections: tuple[str, ...] = field(default_factory=tuple)
    require_relative_performance_baseline: bool = False
    performance_manifest: Path | None = None


REAL_CASE_PERFORMANCE_BUDGET = {
    # The mall full-artifact baseline took about 63.7 seconds for 8 reconciled
    # edges, or about 796,250 seconds per 100k edges. Keep a conservative 1M
    # ceiling, require at least one parsed class per second, and permit no
    # duplicate physical class scans so these remain enforceable regression gates.
    "max_elapsed_seconds": 300.0,
    "max_potential_pairs_per_api": 100000.0,
    "max_duplicate_class_scans": 0,
    "max_seconds_per_100k_edges": 1000000.0,
    "min_edges_for_normalized_rate": 100,
    "min_classes_per_second": 1.0,
    "max_oracle_seconds": 120.0,
}


def apply_real_case_performance_budget(case: RealProjectCase) -> RealProjectCase:
    return replace(
        case,
        max_elapsed_seconds=case.max_elapsed_seconds or REAL_CASE_PERFORMANCE_BUDGET["max_elapsed_seconds"],
        max_potential_pairs_per_api=(
            case.max_potential_pairs_per_api
            or REAL_CASE_PERFORMANCE_BUDGET["max_potential_pairs_per_api"]
        ),
        max_duplicate_class_scans=(
            case.max_duplicate_class_scans
            if case.max_duplicate_class_scans >= 0
            else REAL_CASE_PERFORMANCE_BUDGET["max_duplicate_class_scans"]
        ),
        max_seconds_per_100k_edges=(
            case.max_seconds_per_100k_edges
            or REAL_CASE_PERFORMANCE_BUDGET["max_seconds_per_100k_edges"]
        ),
        min_edges_for_normalized_rate=(
            case.min_edges_for_normalized_rate
            or REAL_CASE_PERFORMANCE_BUDGET["min_edges_for_normalized_rate"]
        ),
        min_classes_per_second=(
            case.min_classes_per_second
            or REAL_CASE_PERFORMANCE_BUDGET["min_classes_per_second"]
        ),
        max_oracle_seconds=(
            case.max_oracle_seconds
            or REAL_CASE_PERFORMANCE_BUDGET["max_oracle_seconds"]
        ),
    )


CASES = {
    "commons-text": RealProjectCase(
        name="commons-text",
        default_project=Path("/private/tmp/jua-real-system-commons-text-20260716-c"),
        default_changed_apis=(
            ROOT_DIR / "tests" / "fixtures" / "real_projects"
            / "commons-text-changed-apis.csv"
        ),
        source_dirs=(Path("src/main/java"),),
        require_valid_git=True,
        min_project_java_files=100,
        min_main_java_files=100,
        required_topologies=("source_bytecode_agree",),
        final_artifact=Path(
            "/private/tmp/jua-real-system-commons-text-20260716-c/target/commons-text-1.12.0.jar"
        ),
        source_attestation=(
            ROOT_DIR / "tests" / "fixtures" / "real_projects" / "evidence"
            / "commons-text-source-attestation.json"
        ),
        fixture_manifest=(
            ROOT_DIR / "tests" / "fixtures" / "real_projects" / "commons-text.json"
        ),
        required_fault_injections=STANDARD_FAULT_INJECTIONS,
        require_relative_performance_baseline=True,
        changed_api_rows=(
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.StringUtils.isBlank",
                "api_simple": "isBlank",
                "symbol_kind": "method",
                "api_signature": "(CharSequence)",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.ArrayUtils.EMPTY_CHAR_ARRAY",
                "api_simple": "EMPTY_CHAR_ARRAY",
                "symbol_kind": "field",
                "api_signature": "",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
                "compatibility_flags": "CONSTANT_REMOVED",
            },
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.StringUtils.isEmpty",
                "api_simple": "isEmpty",
                "symbol_kind": "method",
                "api_signature": "(CharSequence)",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.StringUtils.defaultString",
                "api_simple": "defaultString",
                "symbol_kind": "method",
                "api_signature": "(String)",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.StringUtils.EMPTY",
                "api_simple": "EMPTY",
                "symbol_kind": "field",
                "api_signature": "",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.ArrayUtils.isEmpty",
                "api_simple": "isEmpty",
                "symbol_kind": "method",
                "api_signature": "(char[])",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.Validate.isTrue",
                "api_simple": "isTrue",
                "symbol_kind": "method",
                "api_signature": "(boolean, String, Object...)",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
        ),
        prefer_embedded_changed_api_rows=False,
        baseline_specs=(
            BaselineSpec(
                symbol="org.apache.commons.lang3.StringUtils.isBlank",
                pattern=r"\bStringUtils\s*\.\s*isBlank\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.commons\.lang3\.StringUtils\s*;"
                    r"|import\s+org\.apache\.commons\.lang3\.\*\s*;"
                ),
                notes="commons-lang3 removal probe; direct production utility calls must be represented",
            ),
            BaselineSpec(
                symbol="org.apache.commons.lang3.StringUtils.isEmpty",
                pattern=r"\bStringUtils\s*\.\s*isEmpty\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.commons\.lang3\.StringUtils\s*;"
                    r"|import\s+org\.apache\.commons\.lang3\.\*\s*;"
                ),
                notes="commons-lang3 CharSequence-compatible utility method",
            ),
            BaselineSpec(
                symbol="org.apache.commons.lang3.StringUtils.defaultString",
                pattern=r"\bStringUtils\s*\.\s*defaultString\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.commons\.lang3\.StringUtils\s*;"
                    r"|import\s+org\.apache\.commons\.lang3\.\*\s*;"
                ),
                notes="commons-lang3 single-argument String utility method",
            ),
            BaselineSpec(
                symbol="org.apache.commons.lang3.StringUtils.EMPTY",
                pattern=r"\bStringUtils\s*\.\s*EMPTY\b",
                import_pattern=(
                    r"import\s+org\.apache\.commons\.lang3\.StringUtils\s*;"
                    r"|import\s+org\.apache\.commons\.lang3\.\*\s*;"
                ),
                notes="field owner resolution for commons-lang3 StringUtils.EMPTY",
            ),
            BaselineSpec(
                symbol="org.apache.commons.lang3.ArrayUtils.isEmpty",
                pattern=r"\bArrayUtils\s*\.\s*isEmpty\s*\(\s*(?:chars|delimiters)\s*\)",
                import_pattern=(
                    r"import\s+org\.apache\.commons\.lang3\.ArrayUtils\s*;"
                    r"|import\s+org\.apache\.commons\.lang3\.\*\s*;"
                ),
                file_path_pattern=r"(?:StrMatcher|CaseUtils)\.java$",
                notes="char[] overload probe; variable-name filter intentionally excludes other array overloads",
            ),
            BaselineSpec(
                symbol="org.apache.commons.lang3.Validate.isTrue",
                pattern=r"\bValidate\s*\.\s*isTrue\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.commons\.lang3\.Validate\s*;"
                    r"|import\s+org\.apache\.commons\.lang3\.\*\s*;"
                ),
                notes="varargs method probe",
            ),
        ),
    ),
    "seata": RealProjectCase(
        name="seata",
        default_project=Path("/private/tmp/jua-real-project-seata"),
        default_changed_apis=Path(""),
        required_topologies=("business_direct", "static_dispatch", "field_access"),
        changed_api_rows=(
            {
                "coord": "org.apache.seata:seata-common",
                "old_version": "probe",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.seata.common.util.StringUtils.isBlank",
                "api_simple": "isBlank",
                "symbol_kind": "method",
                "api_signature": "(String)",
                "confirmed": "false",
                "severity": "P1",
                "source": "real_project_seata_probe",
            },
            {
                "coord": "org.apache.seata:seata-common",
                "old_version": "probe",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.seata.common.util.StringUtils.isEmpty",
                "api_simple": "isEmpty",
                "symbol_kind": "method",
                "api_signature": "(CharSequence)",
                "confirmed": "false",
                "severity": "P1",
                "source": "real_project_seata_probe",
            },
            {
                "coord": "org.apache.seata:seata-common",
                "old_version": "probe",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.seata.common.util.StringUtils.EMPTY",
                "api_simple": "EMPTY",
                "symbol_kind": "field",
                "api_signature": "",
                "confirmed": "false",
                "severity": "P1",
                "source": "real_project_seata_probe",
            },
        ),
        prefer_embedded_changed_api_rows=True,
        baseline_specs=(
            BaselineSpec(
                symbol="org.apache.seata.common.util.StringUtils.isBlank",
                pattern=r"\bStringUtils\s*\.\s*isBlank\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.seata\.common\.util\.StringUtils\s*;"
                    r"|import\s+org\.apache\.seata\.common\.util\.\*\s*;"
                ),
                notes="single-signature target; production direct calls should all be represented",
            ),
            BaselineSpec(
                symbol="org.apache.seata.common.util.StringUtils.isEmpty",
                pattern=r"\bStringUtils\s*\.\s*isEmpty\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.seata\.common\.util\.StringUtils\s*;"
                    r"|import\s+org\.apache\.seata\.common\.util\.\*\s*;"
                ),
                notes="CharSequence-compatible target; direct production calls should be represented",
            ),
            BaselineSpec(
                symbol="org.apache.seata.common.util.StringUtils.EMPTY",
                pattern=r"\bStringUtils\s*\.\s*EMPTY\b",
                import_pattern=(
                    r"import\s+org\.apache\.seata\.common\.util\.StringUtils\s*;"
                    r"|import\s+org\.apache\.seata\.common\.util\.\*\s*;"
                ),
                notes="field owner resolution baseline",
            ),
        ),
    ),
    "dubbo": RealProjectCase(
        name="dubbo",
        default_project=Path("/private/tmp/jua-real-project-dubbo"),
        default_changed_apis=Path(""),
        required_topologies=("business_direct", "static_dispatch"),
        changed_api_rows=(
            {
                "coord": "org.apache.dubbo:dubbo-common",
                "old_version": "probe",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.dubbo.common.utils.StringUtils.isEquals",
                "api_simple": "isEquals",
                "symbol_kind": "method",
                "api_signature": "(String, String)",
                "confirmed": "true",
                "severity": "P1",
                "source": "real_project_dubbo_probe",
            },
            {
                "coord": "org.apache.dubbo:dubbo-common",
                "old_version": "probe",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.dubbo.common.utils.StringUtils.parseQueryString",
                "api_simple": "parseQueryString",
                "symbol_kind": "method",
                "api_signature": "(String)",
                "confirmed": "true",
                "severity": "P1",
                "source": "real_project_dubbo_probe",
            },
            {
                "coord": "org.apache.dubbo:dubbo-common",
                "old_version": "probe",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap",
                "api_simple": "isEmptyMap",
                "symbol_kind": "method",
                "api_signature": "(Map<?, ?>)",
                "confirmed": "true",
                "severity": "P1",
                "source": "real_project_dubbo_probe",
            },
            {
                "coord": "org.apache.dubbo:dubbo-common",
                "old_version": "probe",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.dubbo.common.URL.valueOf",
                "api_simple": "valueOf",
                "symbol_kind": "method",
                "api_signature": "(String)",
                "confirmed": "true",
                "severity": "P1",
                "source": "real_project_dubbo_probe",
            },
            {
                "coord": "org.apache.dubbo:dubbo-common",
                "old_version": "probe",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.dubbo.common.utils.NetUtils.getLocalHost",
                "api_simple": "getLocalHost",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P1",
                "source": "real_project_dubbo_probe",
            },
        ),
        prefer_embedded_changed_api_rows=True,
        baseline_specs=(
            BaselineSpec(
                symbol="org.apache.dubbo.common.utils.StringUtils.isEquals",
                pattern=r"\bStringUtils\s*\.\s*isEquals\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.dubbo\.common\.utils\.StringUtils\s*;"
                    r"|import\s+org\.apache\.dubbo\.common\.utils\.\*\s*;"
                ),
                notes="static utility method with String/String signature",
            ),
            BaselineSpec(
                symbol="org.apache.dubbo.common.utils.StringUtils.parseQueryString",
                pattern=r"\bStringUtils\s*\.\s*parseQueryString\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.dubbo\.common\.utils\.StringUtils\s*;"
                    r"|import\s+org\.apache\.dubbo\.common\.utils\.\*\s*;"
                ),
                notes="single-argument String utility method",
            ),
            BaselineSpec(
                symbol="org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap",
                pattern=r"\bCollectionUtils\s*\.\s*isEmptyMap\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.dubbo\.common\.utils\.CollectionUtils\s*;"
                    r"|import\s+org\.apache\.dubbo\.common\.utils\.\*\s*;"
                ),
                notes="Map-specific utility method; source calls should not be confused with Collection overloads",
            ),
            BaselineSpec(
                symbol="org.apache.dubbo.common.URL.valueOf",
                pattern=r"\bURL\s*\.\s*valueOf\s*\(\s*[^,()]+?\s*\)",
                import_pattern=r"import\s+org\.apache\.dubbo\.common\.URL\s*;",
                notes="single-argument String URL.valueOf overload; broader overloads are intentionally excluded",
            ),
            BaselineSpec(
                symbol="org.apache.dubbo.common.utils.NetUtils.getLocalHost",
                pattern=r"\bNetUtils\s*\.\s*getLocalHost\s*\(",
                import_pattern=(
                    r"import\s+org\.apache\.dubbo\.common\.utils\.NetUtils\s*;"
                    r"|import\s+org\.apache\.dubbo\.common\.utils\.\*\s*;"
                ),
                notes="zero-argument utility method",
            ),
        ),
        source_shape_patterns={
            "static_stringutils_import": r"import\s+static\s+org\.apache\.dubbo\.common\.utils\.StringUtils\.",
            "static_collectionutils_import": r"import\s+static\s+org\.apache\.dubbo\.common\.utils\.CollectionUtils\.",
            "lambda_expression": r"->",
            "method_reference": r"::",
            "class_for_name": r"\bClass\.forName\s*\(",
            "reflection_get_method": r"\.getMethod\s*\(",
        },
        min_source_shape_files={
            "static_stringutils_import": 20,
            "static_collectionutils_import": 5,
            "lambda_expression": 300,
            "method_reference": 100,
            "class_for_name": 10,
            "reflection_get_method": 30,
        },
        min_methods_indexed=15000,
        min_reverse_edges_indexed=100000,
        max_elapsed_seconds=60.0,
        max_full_step4_api_elapsed_seconds=180.0,
        run_step4=True,
        step4_dep_rows=(
            {
                "coord": "org.apache.dubbo:dubbo-common",
                "old_version": "3.3.7-SNAPSHOT",
                "new_version": "-",
                "change_type": "移除",
                "scope": "compile",
            },
        ),
        expected_step4_api_names=(
            "org.apache.dubbo.common.utils.StringUtils.isEquals",
            "org.apache.dubbo.common.utils.StringUtils.parseQueryString",
            "org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap",
            "org.apache.dubbo.common.URL.valueOf",
            "org.apache.dubbo.common.utils.NetUtils.getLocalHost",
        ),
        max_step4_elapsed_seconds=120.0,
        run_step6_report=True,
        expected_report_texts=(
            "org.apache.dubbo:dubbo-common",
            "org.apache.dubbo.common",
        ),
        query_methods=(
            "org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap(Map<?, ?>)",
            "org.apache.dubbo.common.URL.valueOf(String)",
        ),
        require_valid_git=True,
        min_project_java_files=500,
        min_main_java_files=300,
        max_generated_java_ratio=0.5,
        case_mode="discovery",
        ground_truth_status="unreviewed",
        max_potential_pairs_per_api=30000.0,
        enable_jdk_oracle=True,
        prior_topology_matrix=ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json",
    ),
    "commons-lang": RealProjectCase(
        name="commons-lang",
        default_project=Path("/private/tmp/jua-real-git-commons-lang"),
        default_changed_apis=Path(""),
        require_valid_git=True,
        min_project_java_files=500,
        min_main_java_files=400,
        required_topologies=("same_jar_bridge", "static_dispatch", "field_access"),
        target_owner_entries={
            "org.apache.commons.lang3.StringUtils": ("org/apache/commons/lang3/StringUtils.class",),
            "org.apache.commons.lang3.Validate": ("org/apache/commons/lang3/Validate.class",),
        },
        changed_api_rows=(
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.StringUtils.isBlank",
                "api_simple": "isBlank",
                "symbol_kind": "method",
                "api_signature": "(CharSequence)",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.StringUtils.isEmpty",
                "api_simple": "isEmpty",
                "symbol_kind": "method",
                "api_signature": "(CharSequence)",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.StringUtils.EMPTY",
                "api_simple": "EMPTY",
                "symbol_kind": "field",
                "api_signature": "",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
            {
                "coord": "org.apache.commons:commons-lang3",
                "old_version": "3.x",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.commons.lang3.Validate.isTrue",
                "api_simple": "isTrue",
                "symbol_kind": "method",
                "api_signature": "(boolean, String, Object...)",
                "confirmed": "true",
                "severity": "HIGH",
                "source": "manual_real_project_probe",
            },
        ),
        prefer_embedded_changed_api_rows=True,
        baseline_specs=(
            BaselineSpec(
                symbol="org.apache.commons.lang3.StringUtils.isBlank",
                pattern=r"\bStringUtils\s*\.\s*isBlank\s*\(",
                import_pattern=r"package\s+org\.apache\.commons\.lang3\s*;",
                notes="same-package method references inside commons-lang itself",
            ),
            BaselineSpec(
                symbol="org.apache.commons.lang3.StringUtils.isEmpty",
                pattern=r"\bStringUtils\s*\.\s*isEmpty\s*\(",
                import_pattern=r"package\s+org\.apache\.commons\.lang3\s*;",
                notes="same-package method references and internal helper usage",
            ),
            BaselineSpec(
                symbol="org.apache.commons.lang3.StringUtils.EMPTY",
                pattern=r"\bStringUtils\s*\.\s*EMPTY\b",
                import_pattern=r"package\s+org\.apache\.commons\.lang3\s*;",
                notes="same-package static field owner resolution without import",
            ),
            BaselineSpec(
                symbol="org.apache.commons.lang3.Validate.isTrue",
                pattern=r"\bValidate\s*\.\s*isTrue\s*\([^)]*,",
                import_pattern=(
                    r"import\s+org\.apache\.commons\.lang3\.Validate\s*;"
                    r"|package\s+org\.apache\.commons\.lang3\s*;"
                ),
                notes="varargs/message overload probe; boolean-only overload is intentionally excluded",
            ),
        ),
    ),
}

CASES["dubbo-samples"] = replace(
    CASES["dubbo"],
    name="dubbo-samples",
    default_project=Path("/private/tmp/jua-real-project-dubbo-samples-retry"),
    baseline_specs=(),
    source_shape_patterns={},
    min_source_shape_files={},
    min_methods_indexed=500,
    min_reverse_edges_indexed=1000,
    max_elapsed_seconds=180.0,
    max_full_step4_api_elapsed_seconds=300.0,
    expected_report_texts=("org.apache.dubbo",),
    query_methods=(),
    min_project_java_files=1000,
    min_main_java_files=900,
    max_generated_java_ratio=0.1,
)

CASES["mall"] = RealProjectCase(
    name="mall",
    default_project=Path("/private/tmp/jua-real-project-mall"),
    default_changed_apis=Path(""),
    baseline_specs=(),
    min_project_java_files=500,
    min_main_java_files=500,
    max_generated_java_ratio=0.1,
    require_valid_git=True,
    max_elapsed_seconds=180.0,
    max_oracle_seconds=135.0,
    case_mode="discovery",
    ground_truth_status="unreviewed",
    enable_jdk_oracle=True,
    bytecode_owner_prefixes=("cn/hutool/",),
    bytecode_coord="cn.hutool:hutool-all",
    final_artifact=Path("/private/tmp/jua-real-project-mall/mall-admin/target/mall-admin-1.0-SNAPSHOT.jar"),
    required_topologies=("business_direct", "business_to_cross_jar_bridge"),
    prior_topology_matrix=ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json",
)

CASES["spring-security-config"] = RealProjectCase(
    name="spring-security-config",
    default_project=Path("/private/tmp/jua-real-project-spring-security-6.5.10"),
    default_changed_apis=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects"
        / "spring-security-config-changed-apis.csv"
    ),
    source_dirs=(Path("config/src/main/java"),),
    baseline_specs=(),
    min_project_java_files=200,
    min_main_java_files=200,
    max_generated_java_ratio=0.1,
    require_valid_git=True,
    max_elapsed_seconds=130.0,
    max_oracle_seconds=135.0,
    case_mode="guard",
    ground_truth_status="reviewed",
    enable_jdk_oracle=True,
    bytecode_owner_prefixes=(
        "org/springframework/security/authentication/ProviderManager",
        "org/springframework/security/core/context/SecurityContextHolder",
        "org/springframework/security/authorization/method/AuthorizationAdvisorProxyFactory",
    ),
    bytecode_coord="org.springframework.security:spring-security-core",
    final_artifact=Path(
        "/private/tmp/jua-real-project-spring-security-6.5.10/config/build/libs/"
        "spring-security-config-6.5.10.jar"
    ),
    required_topologies=("business_direct", "constructor", "static_dispatch"),
    prior_topology_matrix=ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json",
    fixture_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects"
        / "spring-security-config.json"
    ),
    required_fault_injections=STANDARD_FAULT_INJECTIONS,
    require_relative_performance_baseline=True,
)

CASES["grpc-netty-shaded"] = RealProjectCase(
    name="grpc-netty-shaded",
    default_project=Path("/private/tmp/jua-real-grpc-java-1.81.0"),
    default_changed_apis=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects"
        / "grpc-netty-shaded-changed-apis.csv"
    ),
    baseline_specs=(),
    source_dirs=(Path("netty/src/main/java"),),
    min_project_java_files=1500,
    min_main_java_files=900,
    max_generated_java_ratio=0.1,
    require_valid_git=True,
    max_elapsed_seconds=180.0,
    max_oracle_seconds=135.0,
    case_mode="guard",
    ground_truth_status="reviewed",
    enable_jdk_oracle=True,
    bytecode_owner_prefixes=(
        "io/grpc/netty/shaded/io/netty/handler/ssl/SslContext",
        "io/netty/handler/ssl/SslContext",
    ),
    bytecode_coord="io.grpc:grpc-netty-shaded",
    final_artifact=Path(
        "/private/tmp/jua-real-grpc-java-1.81.0/netty/shaded/build/libs/"
        "grpc-netty-shaded-1.81.0.jar"
    ),
    required_topologies=("source_bytecode_true_conflict",),
    target_owner_entries={
        owner: (owner.replace(".", "/") + ".class",)
        for owner in (
            "io.grpc.netty.shaded.io.netty.handler.ssl.SslContext",
            "io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder",
            "io.grpc.netty.shaded.io.netty.handler.ssl.SslContextOption",
            "io.grpc.netty.shaded.io.netty.handler.ssl.SslContextOption$1",
        )
    },
    source_attestation=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" / "evidence"
        / "grpc-netty-shaded-source-attestation.json"
    ),
    prior_topology_matrix=(
        ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json"
    ),
    fixture_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects"
        / "grpc-netty-shaded.json"
    ),
    required_fault_injections=STANDARD_FAULT_INJECTIONS,
    require_relative_performance_baseline=True,
)

CASES["dubbo-fatjar"] = RealProjectCase(
    name="dubbo-fatjar",
    default_project=Path("/private/tmp/jua-real-project-dubbo-source-20260710"),
    default_changed_apis=Path(""),
    baseline_specs=(),
    source_dirs=(
        Path(
            "dubbo-demo/dubbo-demo-spring-boot/"
            "dubbo-demo-spring-boot-consumer/src/main/java"
        ),
    ),
    min_project_java_files=500,
    min_main_java_files=300,
    max_generated_java_ratio=0.5,
    require_valid_git=True,
    max_elapsed_seconds=180.0,
    case_mode="discovery",
    ground_truth_status="unreviewed",
    enable_jdk_oracle=True,
    bytecode_owner_prefixes=("org/apache/dubbo/springboot/demo/DemoService",),
    bytecode_coord="org.apache.dubbo:dubbo-demo-spring-boot-interface",
    final_artifact=Path(
        "/private/tmp/jua-real-project-dubbo-source-20260710/"
        "dubbo-demo/dubbo-demo-spring-boot/"
        "dubbo-demo-spring-boot-consumer/target/"
        "dubbo-demo-spring-boot-consumer-3.3.7-SNAPSHOT.jar"
    ),
    required_topologies=(
        "business_direct",
        "business_to_same_jar_bridge",
        "interface_dispatch",
        "same_jar_bridge",
    ),
    prior_topology_matrix=ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json",
)

CASES["dubbo-rpc-proxy-consumer"] = RealProjectCase(
    name="dubbo-rpc-proxy-consumer",
    default_project=Path(
        "/private/tmp/jua-real-project-dubbo-samples-retry/10-task/"
        "dubbo-samples-rpc-basic/dubbo-samples-rpc-basic-consumer"
    ),
    default_changed_apis=Path(""),
    baseline_specs=(),
    source_dirs=(Path("src/main/java"),),
    min_project_java_files=1,
    min_main_java_files=1,
    max_generated_java_ratio=0.1,
    require_valid_git=True,
    max_elapsed_seconds=180.0,
    max_oracle_seconds=135.0,
    case_mode="discovery",
    ground_truth_status="unreviewed",
    enable_jdk_oracle=True,
    bytecode_owner_prefixes=("org/apache/dubbo/samples/DemoService",),
    bytecode_coord=(
        "org.apache.dubbo.samples:dubbo-samples-rpc-basic-api"
    ),
    final_artifact=Path(
        "/private/tmp/jua-real-project-dubbo-samples-retry/10-task/"
        "dubbo-samples-rpc-basic/dubbo-samples-rpc-basic-consumer/target/"
        "dubbo-samples-rpc-basic-consumer-0.0.1-SNAPSHOT.jar"
    ),
    required_topologies=(
        "business_direct", "framework_callback", "interface_dispatch",
    ),
    prior_topology_matrix=(
        ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json"
    ),
)

CASES["spring-petclinic"] = RealProjectCase(
    name="spring-petclinic",
    default_project=Path("/private/tmp/jua-real-project-spring-petclinic"),
    default_changed_apis=Path(""),
    baseline_specs=(),
    source_dirs=(Path("src/main/java"),),
    min_project_java_files=45,
    min_main_java_files=30,
    max_generated_java_ratio=0.1,
    require_valid_git=True,
    case_mode="discovery",
    ground_truth_status="unreviewed",
    enable_jdk_oracle=True,
    bytecode_owner_prefixes=("org/springframework/data/domain/",),
    bytecode_coord="org.springframework.data:spring-data-commons",
    final_artifact=Path(
        "/private/tmp/jua-real-project-spring-petclinic/target/"
        "spring-petclinic-4.0.0-SNAPSHOT.jar"
    ),
    required_topologies=(
        "business_direct", "cross_jar_bridge", "interface_dispatch", "static_dispatch",
    ),
    prior_topology_matrix=ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json",
)

CASES["gs-multi-module"] = RealProjectCase(
    name="gs-multi-module",
    default_project=Path("/private/tmp/gs-multi-module/complete"),
    default_changed_apis=Path(""),
    baseline_specs=(),
    changed_api_rows=(
        {
            "coord": "com.example:library",
            "old_version": "0.0.1-SNAPSHOT",
            "new_version": "-",
            "change_type": "REMOVED",
            "api_name": "com.example.multimodule.service.ServiceProperties.getMessage",
            "api_simple": "getMessage",
            "symbol_kind": "method",
            "api_signature": "()",
            "confirmed": "true",
            "severity": "P1",
            "source": "pinned_real_project_guard",
        },
    ),
    source_dirs=(Path("application/src/main/java"),),
    prefer_embedded_changed_api_rows=True,
    require_valid_git=True,
    min_project_java_files=3,
    min_main_java_files=3,
    case_mode="guard",
    ground_truth_status="reviewed",
    enable_jdk_oracle=True,
    bytecode_coord="com.example:library",
    final_artifact=Path(
        "/private/tmp/gs-multi-module/complete/application/target/application-0.0.1-SNAPSHOT.jar"
    ),
    required_topologies=("business_to_same_jar_bridge", "same_coord_multimodule"),
    fixture_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
    ),
)

CASES["gs-messaging-rabbitmq"] = RealProjectCase(
    name="gs-messaging-rabbitmq",
    default_project=Path("/private/tmp/gs-messaging-rabbitmq/complete"),
    default_changed_apis=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "gs-messaging-rabbitmq-changed-apis.csv"
    ),
    baseline_specs=(),
    source_dirs=(Path("src/main/java"),),
    require_valid_git=True,
    min_project_java_files=3,
    min_main_java_files=3,
    case_mode="guard",
    ground_truth_status="reviewed",
    enable_jdk_oracle=True,
    bytecode_coord="jdk:java.base",
    final_artifact=Path(
        "/private/tmp/gs-messaging-rabbitmq/complete/target/"
        "messaging-rabbitmq-complete-0.0.1-SNAPSHOT.jar"
    ),
    required_topologies=("business_direct", "framework_callback"),
    fixture_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "gs-messaging-rabbitmq.json"
    ),
    required_fault_injections=STANDARD_FAULT_INJECTIONS,
    require_relative_performance_baseline=True,
)

CASES["gs-managing-transactions"] = RealProjectCase(
    name="gs-managing-transactions",
    default_project=Path("/private/tmp/jua-real-project-gs-managing-transactions/complete"),
    default_changed_apis=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "gs-managing-transactions-changed-apis.csv"
    ),
    baseline_specs=(),
    source_dirs=(Path("src/main/java"),),
    require_valid_git=True,
    min_project_java_files=3,
    min_main_java_files=3,
    case_mode="guard",
    ground_truth_status="reviewed",
    oracle_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "gs-managing-transactions-oracle.csv"
    ),
    bytecode_coord="org.springframework:spring-tx",
    final_artifact=Path(
        "/private/tmp/jua-real-project-gs-managing-transactions/complete/target/"
        "managing-transactions-complete-0.0.1-SNAPSHOT.jar"
    ),
    required_topologies=("framework_proxy",),
    target_owner_entries={
        "org.springframework.transaction.interceptor.TransactionInterceptor": (
            "BOOT-INF/lib/spring-tx-7.0.8.jar!/org/springframework/transaction/"
            "interceptor/TransactionInterceptor.class",
        ),
        "org.springframework.transaction.interceptor.TransactionAspectSupport": (
            "BOOT-INF/lib/spring-tx-7.0.8.jar!/org/springframework/transaction/"
            "interceptor/TransactionAspectSupport.class",
        ),
        "org.springframework.aop.framework.ReflectiveMethodInvocation": (
            "BOOT-INF/lib/spring-aop-7.0.8.jar!/org/springframework/aop/framework/"
            "ReflectiveMethodInvocation.class",
        ),
    },
    fixture_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "gs-managing-transactions.json"
    ),
    prior_topology_matrix=(
        ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json"
    ),
    required_fault_injections=STANDARD_FAULT_INJECTIONS,
    require_relative_performance_baseline=True,
)

CASES["dubbo-spring6-security"] = RealProjectCase(
    name="dubbo-spring6-security",
    default_project=Path("/private/tmp/jua-real-project-dubbo-source-20260710"),
    default_changed_apis=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "dubbo-spring6-security-changed-apis.csv"
    ),
    baseline_specs=(),
    source_dirs=(Path("dubbo-plugin/dubbo-spring6-security/src/main/java"),),
    require_valid_git=True,
    min_project_java_files=500,
    min_main_java_files=300,
    max_generated_java_ratio=0.5,
    case_mode="guard",
    ground_truth_status="reviewed",
    bytecode_owner_prefixes=("org/springframework/security/oauth2/core/",),
    bytecode_coord="org.springframework.security:spring-security-oauth2-core",
    final_artifact=Path(
        "/private/tmp/jua-real-project-dubbo-source-20260710/dubbo-plugin/"
        "dubbo-spring6-security/target/dubbo-spring6-security-3.3.7-SNAPSHOT.jar"
    ),
    required_topologies=("reflection",),
    fixture_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "dubbo-spring6-security.json"
    ),
)

CASES["mybatis-sample-annotation"] = RealProjectCase(
    name="mybatis-sample-annotation",
    default_project=Path("/private/tmp/jua-real-project-mybatis-spring-boot-4.0.1"),
    default_changed_apis=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "mybatis-sample-annotation-changed-apis.csv"
    ),
    baseline_specs=(),
    source_dirs=(
        Path(
            "mybatis-spring-boot-samples/mybatis-spring-boot-sample-annotation/"
            "src/main/java"
        ),
    ),
    require_valid_git=True,
    min_project_java_files=100,
    min_main_java_files=3,
    max_generated_java_ratio=0.1,
    case_mode="guard",
    ground_truth_status="reviewed",
    bytecode_coord="org.mybatis:mybatis",
    final_artifact=Path(
        "/private/tmp/mybatis-spring-boot-sample-annotation-4.0.1.jar"
    ),
    required_topologies=("mybatis_mapper_proxy",),
    target_owner_entries={
        "org.apache.ibatis.binding.MapperProxy": (
            "BOOT-INF/lib/mybatis-3.5.19.jar!/org/apache/ibatis/binding/MapperProxy.class",
        ),
        "org.apache.ibatis.binding.MapperMethod": (
            "BOOT-INF/lib/mybatis-3.5.19.jar!/org/apache/ibatis/binding/MapperMethod.class",
        ),
        "org.apache.ibatis.session.SqlSession": (
            "BOOT-INF/lib/mybatis-3.5.19.jar!/org/apache/ibatis/session/SqlSession.class",
        ),
    },
    fixture_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "mybatis-sample-annotation.json"
    ),
)

CASES["mybatis-sample-xml"] = RealProjectCase(
    name="mybatis-sample-xml",
    default_project=Path("/private/tmp/jua-real-project-mybatis-spring-boot-4.0.1"),
    default_changed_apis=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "mybatis-sample-xml-changed-apis.csv"
    ),
    baseline_specs=(),
    source_dirs=(
        Path(
            "mybatis-spring-boot-samples/mybatis-spring-boot-sample-xml/"
            "src/main/java"
        ),
    ),
    require_valid_git=True,
    min_project_java_files=100,
    min_main_java_files=6,
    max_generated_java_ratio=0.1,
    case_mode="guard",
    ground_truth_status="reviewed",
    bytecode_coord="org.mybatis:mybatis",
    final_artifact=Path("/private/tmp/mybatis-spring-boot-sample-xml-4.0.1.jar"),
    required_topologies=("business_direct", "mybatis_mapper_proxy"),
    target_owner_entries={
        "org.apache.ibatis.binding.MapperProxy": (
            "BOOT-INF/lib/mybatis-3.5.19.jar!/org/apache/ibatis/binding/MapperProxy.class",
        ),
        "org.apache.ibatis.binding.MapperMethod": (
            "BOOT-INF/lib/mybatis-3.5.19.jar!/org/apache/ibatis/binding/MapperMethod.class",
        ),
        "org.apache.ibatis.session.SqlSession": (
            "BOOT-INF/lib/mybatis-3.5.19.jar!/org/apache/ibatis/session/SqlSession.class",
        ),
    },
    fixture_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "mybatis-sample-xml.json"
    ),
    required_fault_injections=STANDARD_FAULT_INJECTIONS,
    require_relative_performance_baseline=True,
)

CASES["ruoyi-full-artifact-discovery"] = RealProjectCase(
    name="ruoyi-full-artifact-discovery",
    default_project=Path("/private/tmp/jua-ruoyi-current-git"),
    default_changed_apis=Path(""),
    baseline_specs=(),
    run_step4=True,
    derive_step1_from_artifacts=True,
    base_final_artifact=Path(
        "/private/tmp/jua-ruoyi-before-12f30758/ruoyi-admin/target/ruoyi-admin.jar"
    ),
    final_artifact=Path(
        "/private/tmp/jua-ruoyi-after-12f30758/ruoyi-admin/target/ruoyi-admin.jar"
    ),
    base_source_project=Path("/private/tmp/jua-ruoyi-base-git"),
    current_source_project=Path("/private/tmp/jua-ruoyi-current-git"),
    base_revision="a1df379e5c0091eaa11608ae6c431828a62cd7fc",
    current_revision="12f307586bdcd6983abe92047baa7736c168ca04",
    require_valid_git=True,
    min_project_java_files=100,
    min_main_java_files=100,
    max_generated_java_ratio=0.1,
    case_mode="discovery",
    ground_truth_status="unreviewed",
    required_topologies=("field_access", "same_jar_bridge"),
    prior_topology_matrix=ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json",
    required_fault_injections=STANDARD_FAULT_INJECTIONS,
    require_relative_performance_baseline=True,
    performance_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "ruoyi-full-artifact-discovery.json"
    ),
    max_step4_elapsed_seconds=120.0,
    max_oracle_seconds=240.0,
)

CASES["pig-v4-full-artifact-discovery"] = RealProjectCase(
    name="pig-v4-full-artifact-discovery",
    default_project=Path("/private/tmp/jua-target-pig-min"),
    default_changed_apis=Path(""),
    baseline_specs=(),
    target_module="pig-boot",
    active_maven_profiles=("boot",),
    manual_coord_overrides=(
        "lombok:1.18.46 -> org.projectlombok:lombok",
    ),
    source_dirs=(Path("."),),
    run_step4=True,
    derive_step1_from_artifacts=True,
    base_final_artifact=Path(
        "/private/tmp/jua-target-pig-v4.0/pig-boot/target/pig-boot.jar"
    ),
    final_artifact=Path(
        "/private/tmp/jua-target-pig-min/pig-boot/target/pig-boot.jar"
    ),
    base_source_project=Path("/private/tmp/jua-target-pig-v4.0"),
    current_source_project=Path("/private/tmp/jua-target-pig-min"),
    base_revision="7197ec39e16e45f35ef8b47d381f2c833eaf66ed",
    current_revision="f4e5a3a4b902dc00c192b878d7587cec93698803",
    require_valid_git=True,
    min_project_java_files=500,
    min_main_java_files=500,
    max_generated_java_ratio=0.1,
    case_mode="discovery",
    ground_truth_status="unreviewed",
    required_topologies=(
        "cross_jar_bridge",
        "field_access",
        "overloaded_method",
        "same_jar_bridge",
        "virtual_dispatch",
    ),
    prior_topology_matrix=(
        ROOT_DIR / "tests" / "fixtures" / "topologies" / "prior_matrix.json"
    ),
    required_fault_injections=STANDARD_FAULT_INJECTIONS,
    require_relative_performance_baseline=True,
    performance_manifest=(
        ROOT_DIR / "tests" / "fixtures" / "real_projects" /
        "pig-v4-full-artifact-discovery.json"
    ),
    max_step4_elapsed_seconds=300.0,
    max_oracle_seconds=600.0,
)

CASES = {
    name: apply_real_case_performance_budget(case)
    for name, case in CASES.items()
}


_CHANGE_API_MARKER_RE = re.compile(r"变更\s*API\s*[：:]")
_BUSINESS_ARTIFACT_NODE_PREFIX_RE = re.compile(r"^(?:业务制品|BUSINESS)\s*[：:]\s*")


def _expected_target_signature(expected_api: dict) -> str:
    descriptor = str((expected_api or {}).get("descriptor") or "").strip()
    if not descriptor.startswith("("):
        return ""
    try:
        return normalize_signature_for_lookup(_source_signature(descriptor).replace("$", "."))
    except (IndexError, ValueError):
        return ""


def _matches_expected_call_chain(path_text: str, expected_chain: list[str], expected_api: dict) -> bool:
    nodes = [node.strip() for node in re.split(r"\s*(?:->|→)\s*", str(path_text or "").strip())]
    if not nodes or any(not node for node in nodes) or len(nodes) != len(expected_chain):
        return False
    marker_indexes = [index for index, node in enumerate(nodes) if _CHANGE_API_MARKER_RE.search(node)]
    if any(index != len(nodes) - 1 for index in marker_indexes) or len(marker_indexes) > 1:
        return False
    for actual, expected in zip(nodes[:-1], expected_chain[:-1]):
        normalized_actual = _BUSINESS_ARTIFACT_NODE_PREFIX_RE.sub(
            "", actual, count=1
        )
        signature_match = re.fullmatch(r"(.+?)(\(.*\))", normalized_actual)
        actual_identity = (signature_match.group(1) if signature_match else normalized_actual).replace("$", ".")
        expected_identity = expected.replace("$", ".")
        if actual_identity != expected_identity and not (
            "(" not in expected
            and signature_match
            and signature_match.group(1).strip().replace("$", ".") == expected_identity
        ):
            return False

    target_identity = ".".join(
        item for item in (
            str((expected_api or {}).get("owner") or "").strip(),
            str((expected_api or {}).get("member") or "").strip(),
        ) if item
    )
    expected_signature = _expected_target_signature(expected_api)
    if not target_identity or expected_chain[-1].replace("$", ".") != target_identity.replace("$", "."):
        return False
    terminal = nodes[-1]
    if marker_indexes:
        terminal = _CHANGE_API_MARKER_RE.sub("", terminal, count=1).strip()
    if str((expected_api or {}).get("symbol_kind") or "").strip() == "field":
        return terminal == target_identity
    if str((expected_api or {}).get("symbol_kind") or "").strip() == "class":
        return terminal == target_identity
    if not expected_signature:
        return False
    terminal_match = re.fullmatch(r"(.+?)(\(.*\))", terminal)
    if (
        not terminal_match
        or terminal_match.group(1).strip().replace("$", ".")
        != target_identity.replace("$", ".")
    ):
        return False
    descriptor = str((expected_api or {}).get("descriptor") or "").strip()
    try:
        descriptor_signature = _source_signature(descriptor)
    except (IndexError, ValueError):
        descriptor_signature = ""
    return bool(descriptor_signature) and signatures_match_identity(
        terminal_match.group(2), descriptor_signature
    )


def _reachable_call_paths(row: dict) -> list[str]:
    paths = [str(path) for path in (row.get("call_paths") or []) if str(path).strip()]
    paths.extend(
        str(detail.get("path_text") or "")
        for detail in (row.get("path_details") or [])
        if str(detail.get("path_text") or "").strip()
    )
    return paths


def _correct_reconciled_physical_edges(ledger: list[dict]) -> set[str]:
    matched_sides: dict[str, set[str]] = defaultdict(set)
    for entry in ledger or []:
        side = str(entry.get("side") or "")
        nested_key = "analyzer_row" if side == "analyzer" else "oracle_row"
        row = entry.get(nested_key)
        if side not in {"analyzer", "oracle"} or not isinstance(row, dict):
            continue
        identity = canonical_edge_identity(row)
        occurrence = physical_edge_occurrence(row)
        if (
            str(entry.get("verdict") or "") != "correct"
            or str(entry.get("identity") or "") != identity
            or str(entry.get("physical_occurrence") or "") != occurrence
        ):
            continue
        matched_sides[occurrence].add(side)
    return {occurrence for occurrence, sides in matched_sides.items() if sides == {"analyzer", "oracle"}}


def _stable_edge_anchor(edge: dict) -> tuple[str, ...]:
    """Compiler-independent edge identity retained by source-build manifests."""
    return (
        str((edge or {}).get("artifact_entry") or "").strip(),
        *(str((edge or {}).get(field) or "").strip() for field in EDGE_COMPARISON_FIELDS),
    )


def _correct_reconciled_edge_anchors(ledger: list[dict]) -> set[tuple[str, ...]]:
    rows_by_occurrence: dict[str, dict[str, dict]] = defaultdict(dict)
    for entry in ledger or []:
        side = str(entry.get("side") or "")
        nested_key = "analyzer_row" if side == "analyzer" else "oracle_row"
        row = entry.get(nested_key)
        if side not in {"analyzer", "oracle"} or not isinstance(row, dict):
            continue
        identity = canonical_edge_identity(row)
        occurrence = physical_edge_occurrence(row)
        if (
            str(entry.get("verdict") or "") == "correct"
            and str(entry.get("identity") or "") == identity
            and str(entry.get("physical_occurrence") or "") == occurrence
        ):
            rows_by_occurrence[occurrence][side] = row
    return {
        _stable_edge_anchor(rows["oracle"])
        for rows in rows_by_occurrence.values()
        if set(rows) == {"analyzer", "oracle"}
    }


def artifact_verification_mode(manifest: dict) -> str:
    """Return the declared artifact identity policy for a pinned fixture."""
    materialization = manifest.get("materialization") or {}
    kind = str(materialization.get("kind") or "").strip()
    declared = str(materialization.get("artifact_verification") or "").strip()
    if kind == "published_artifact":
        return "sha256"
    if kind == "source_build" and declared == "runtime":
        return "runtime"
    return "sha256"


def _expected_physical_occurrence(edge: dict) -> str:
    identity = canonical_edge_identity(edge)
    entry = str((edge or {}).get("artifact_entry") or "").strip()
    explicit = str((edge or {}).get("physical_occurrence") or "").strip()
    prefix = f"{identity}|{entry}|"
    if explicit.startswith(prefix) and len(explicit) > len(prefix):
        return explicit
    offset = normalize_instruction_offset(edge)
    return physical_edge_occurrence(edge) if identity and entry and offset else ""


def evaluate_pinned_guard_contract(manifest: dict, result: dict) -> dict:
    errors: list[str] = []
    summary = result.get("summary") or {}
    conclusion_rows = []
    for bucket in ("reachable_apis", "uncertain_apis", "not_analyzed_apis", "not_found_apis"):
        conclusion_rows.extend(summary.get(bucket) or [])
    if any(str(item.get("reason_code") or "") == "SOURCE_BYTECODE_EDGE_CONFLICT"
           for item in conclusion_rows):
        errors.append("SOURCE_BYTECODE_EDGE_CONFLICT")

    expected_apis = list(manifest.get("apis") or [])
    if not expected_apis and manifest.get("api"):
        expected_apis = [{
            **(manifest.get("api") or {}),
            "expected_conclusion": manifest.get("expected_conclusion"),
            "expected_chain": manifest.get("expected_chain"),
        }]
    for expected_api in expected_apis:
        expected_name = ".".join(
            item for item in (
                str(expected_api.get("owner") or ""),
                str(expected_api.get("member") or ""),
            ) if item
        )
        expected_conclusion = str(
            expected_api.get("expected_conclusion")
            or manifest.get("expected_conclusion")
            or ""
        )
        expected_kind = str(expected_api.get("symbol_kind") or "").strip().lower()
        expected_coord = str(expected_api.get("coord") or "").strip()
        expected_descriptor = str(expected_api.get("descriptor") or "").strip()
        try:
            expected_signature = _source_signature(expected_descriptor)
        except (IndexError, ValueError):
            expected_signature = ""
        matching_rows = [
            row for row in conclusion_rows
            if str(row.get("api") or row.get("api_name") or "") == expected_name
            and str(row.get("analysis_status") or "") == expected_conclusion
            and (
                not expected_coord
                or str(row.get("coord") or "").strip() == expected_coord
            )
            and (
                not expected_kind
                or str(row.get("symbol_kind") or "").strip().lower() == expected_kind
            )
            and (
                expected_kind in {"field", "class"}
                or (
                    bool(expected_signature)
                    and signatures_match_identity(
                        str(row.get("api_signature") or ""), expected_signature
                    )
                )
            )
        ]
        if not matching_rows:
            if "expected_conclusion_missing" not in errors:
                errors.append("expected_conclusion_missing")
            continue
        expected_chain = [str(item) for item in (expected_api.get("expected_chain") or [])]
        if expected_chain:
            call_paths = [path for row in matching_rows for path in _reachable_call_paths(row)]
            if not any(
                _matches_expected_call_chain(path, expected_chain, expected_api)
                for path in call_paths
            ) and "expected_chain_missing" not in errors:
                errors.append("expected_chain_missing")

    topology = result.get("topology_coverage") or {}
    required = set(manifest.get("required_topologies") or [])
    if not topology.get("complete") or not required.issubset(set(topology.get("observed") or [])):
        errors.append("required_topology_missing")

    edge_truth = result.get("edge_truth") or {}
    if not edge_truth.get("complete") or edge_truth.get("blocking"):
        errors.append("edge_truth_failed")
    runtime_artifact = artifact_verification_mode(manifest) == "runtime"
    ledger = edge_truth.get("ledger") or []
    correct_physical_edges = _correct_reconciled_physical_edges(ledger)
    expected_physical_edges = {
        _expected_physical_occurrence(row)
        for row in (manifest.get("canonical_edges") or [])
    } if not runtime_artifact else set()
    correct_edge_anchors = _correct_reconciled_edge_anchors(ledger)
    expected_edge_anchors = {
        _stable_edge_anchor(row) for row in (manifest.get("canonical_edges") or [])
    } if runtime_artifact else set()
    expected_semantic = list(manifest.get("canonical_semantic_references") or [])
    actual_semantic = list(edge_truth.get("semantic_references") or [])
    semantic_fields = (
        "api_identity", "target_class", "artifact_entry", "authority",
    ) if runtime_artifact else (
        "api_identity", "target_class", "artifact_sha256", "artifact_entry", "authority",
    )
    actual_semantic_identities = {
        tuple(str(row.get(field) or "") for field in semantic_fields)
        for row in actual_semantic
    }
    expected_semantic_identities = {
        tuple(str(row.get(field) or "") for field in semantic_fields)
        for row in expected_semantic
    }
    if expected_physical_edges and (
        "" in expected_physical_edges
        or not expected_physical_edges.issubset(correct_physical_edges)
    ):
        errors.append("expected_physical_edge_missing")
    if expected_edge_anchors and not expected_edge_anchors.issubset(correct_edge_anchors):
        errors.append("expected_semantic_edge_missing")
    if expected_semantic_identities and not expected_semantic_identities.issubset(
        actual_semantic_identities
    ):
        errors.append("expected_semantic_reference_missing")
    if actual_semantic_identities - expected_semantic_identities:
        errors.append("unexpected_semantic_reference")
    if not expected_physical_edges and not expected_edge_anchors and not expected_semantic_identities:
        errors.append("expected_physical_edge_missing")
    return {
        "passed": not errors,
        "errors": errors,
        "api_count": len(expected_apis),
        "expected_physical_edge_count": len(expected_physical_edges),
        "expected_semantic_edge_count": len(expected_edge_anchors),
        "expected_semantic_reference_count": len(expected_semantic_identities),
        "artifact_verification": artifact_verification_mode(manifest),
    }


def validate_pinned_asset(manifest: dict, project_root: Path) -> dict:
    errors: list[str] = validate_reproducible_asset_contract(manifest)
    expected_revision = str(manifest.get("git_revision") or "")
    expected_sha = str(manifest.get("artifact_sha256") or "")
    verification_mode = artifact_verification_mode(manifest)
    artifact = project_root / str(manifest.get("artifact_path") or "")
    actual_revision = ""
    actual_sha = ""
    if not re.fullmatch(r"[0-9a-f]{40}", expected_revision):
        errors.append("git_revision_pin_invalid")
    if verification_mode == "sha256" and not _valid_sha256(expected_sha):
        errors.append("final_artifact_sha256_pin_invalid")
    if not project_root.is_dir():
        errors.append("project_checkout_missing")
    else:
        completed = subprocess.run(
            ["git", "-C", str(project_root), "rev-parse", "HEAD"],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if completed.returncode == 0:
            actual_revision = completed.stdout.strip()
        if actual_revision != expected_revision:
            errors.append("git_revision_mismatch")
    if not artifact.is_file():
        errors.append("final_artifact_missing")
    else:
        actual_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if verification_mode == "sha256" and actual_sha != expected_sha:
            errors.append("final_artifact_sha256_mismatch")
        try:
            with zipfile.ZipFile(artifact) as archive:
                if not any(name.endswith(".class") for name in archive.namelist()):
                    errors.append("final_artifact_has_no_classes")
        except zipfile.BadZipFile:
            errors.append("final_artifact_invalid_zip")
    return {
        "name": "asset",
        "passed": not errors,
        "errors": errors,
        "expected_git_revision": expected_revision,
        "actual_git_revision": actual_revision,
        "artifact_path": str(artifact),
        "expected_artifact_sha256": expected_sha,
        "actual_artifact_sha256": actual_sha,
        "artifact_verification": verification_mode,
    }


def validate_reproducible_asset_contract(manifest: dict) -> list[str]:
    errors: list[str] = []
    materialization = manifest.get("materialization")
    if not isinstance(materialization, dict):
        return ["materialization_contract_missing"]
    kind = str(materialization.get("kind") or "").strip()
    schema = str(manifest.get("schema") or "").strip()
    verification = str(materialization.get("artifact_verification") or "").strip()
    if schema == "java-upgrade-analyzer.real-project-guard.v4":
        lifecycle = str(manifest.get("guard_lifecycle") or "").strip()
        capabilities = manifest.get("capability_ids")
        if lifecycle not in GUARD_LIFECYCLES:
            errors.append("guard_lifecycle_invalid")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or any(not isinstance(item, str) or not item.strip() for item in capabilities)
            or len(capabilities) != len(set(capabilities or []))
        ):
            errors.append("guard_capability_ids_invalid")
        elif set(capabilities) != set(manifest.get("required_topologies") or []):
            errors.append("guard_capability_matrix_mismatch")
    if kind == "source_build":
        if schema == "java-upgrade-analyzer.real-project-guard.v4" and verification not in {
            "runtime", "sha256",
        }:
            errors.append("source_build_artifact_verification_invalid")
        if (
            schema == "java-upgrade-analyzer.real-project-guard.v4"
            and verification == "runtime"
            and manifest.get("canonical_edge_binding") != "semantic"
        ):
            errors.append("source_build_canonical_edge_binding_invalid")
        reference_sha = str(manifest.get("reference_artifact_sha256") or "")
        if reference_sha and not _valid_sha256(reference_sha):
            errors.append("source_build_reference_artifact_sha256_invalid")
        repository_url = str(materialization.get("repository_url") or "").strip()
        if not re.fullmatch(r"https://github\.com/[^/]+/[^/]+(?:\.git)?", repository_url):
            errors.append("source_build_repository_url_invalid")
        working_directory = Path(str(materialization.get("working_directory") or ""))
        if (
            not str(working_directory)
            or working_directory.is_absolute()
            or ".." in working_directory.parts
        ):
            errors.append("source_build_working_directory_not_relative")
        command = materialization.get("command")
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(item, str) or not item.strip() for item in command)
        ):
            errors.append("source_build_command_invalid")
        artifacts = list(materialization.get("artifacts") or [])
        if not artifacts:
            artifacts = [{
                "revision": manifest.get("git_revision"),
                "artifact_path": materialization.get("artifact_path"),
                "artifact_sha256": manifest.get("artifact_sha256"),
            }]
        for index, artifact in enumerate(artifacts):
            prefix = f"source_build_artifact_{index}"
            if not isinstance(artifact, dict):
                errors.append(f"{prefix}_invalid")
                continue
            revision = str(artifact.get("revision") or "")
            artifact_path = Path(str(artifact.get("artifact_path") or ""))
            digest = str(artifact.get("artifact_sha256") or "")
            if not re.fullmatch(r"[0-9a-f]{40}", revision):
                errors.append(f"{prefix}_revision_invalid")
            if not str(artifact_path) or artifact_path.is_absolute() or ".." in artifact_path.parts:
                errors.append("source_build_artifact_path_not_relative")
            if artifact_verification_mode(manifest) == "sha256" and not _valid_sha256(digest):
                errors.append(f"{prefix}_sha256_invalid")
    elif kind == "published_artifact":
        if schema == "java-upgrade-analyzer.real-project-guard.v4" and verification != "sha256":
            errors.append("published_artifact_verification_invalid")
        url = str(materialization.get("url") or "").strip()
        coordinate = str(materialization.get("coordinate") or "").strip()
        sha1 = str(materialization.get("sha1") or "").strip()
        sha256 = str(materialization.get("sha256") or "").strip()
        if not url.startswith("https://") or not url.endswith(".jar"):
            errors.append("published_artifact_url_invalid")
        if len(coordinate.split(":")) != 3 or any(
            not item for item in coordinate.split(":")
        ):
            errors.append("published_artifact_coordinate_invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", sha1):
            errors.append("published_artifact_sha1_invalid")
        if not _valid_sha256(sha256):
            errors.append("published_artifact_sha256_invalid")
        if sha1 != str(manifest.get("artifact_sha1") or ""):
            errors.append("published_artifact_sha1_mismatch")
        if sha256 != str(manifest.get("artifact_sha256") or ""):
            errors.append("published_artifact_sha256_mismatch")
    else:
        errors.append("materialization_kind_invalid")
    return sorted(set(errors))


def _fixture_debt_id(signal: dict) -> str:
    explicit = str(signal.get("fixture_debt_id") or "").strip()
    if explicit:
        return explicit
    return ":".join(filter(None, (
        str(signal.get("signal_type") or ""),
        str(signal.get("reason_code") or ""),
        str(signal.get("symbol") or ""),
    )))


def _resolves_to_unittest(reference: str) -> bool:
    root_entry = str(ROOT_DIR)
    added_root = root_entry not in sys.path
    if added_root:
        sys.path.insert(0, root_entry)
    try:
        module_name, class_name, method_name = str(reference or "").rsplit(".", 2)
        module = importlib.import_module(module_name)
        case_class = getattr(module, class_name)
    except (ImportError, AttributeError, ValueError):
        return False
    finally:
        if added_root and root_entry in sys.path:
            sys.path.remove(root_entry)
    return bool(
        isinstance(case_class, type)
        and issubclass(case_class, unittest.TestCase)
        and method_name in unittest.defaultTestLoader.getTestCaseNames(case_class)
    )


def evaluate_finding_lifecycle(
    signals: list[dict], declarations: list[dict], *, today: str | None = None
) -> dict:
    current_date = date.fromisoformat(today) if today else date.today()
    declarations_by_id = {
        str(row.get("finding_id") or ""): dict(row)
        for row in declarations
        if str(row.get("finding_id") or "")
    }
    active = {
        _fixture_debt_id(signal): signal
        for signal in signals
        if str(signal.get("severity") or "") in {"P0", "P1"}
    }
    rows = [dict(row) for row in declarations]
    errors: list[str] = []
    for finding_id in sorted(active):
        if finding_id not in declarations_by_id:
            rows.append({
                "finding_id": finding_id,
                "state": "missing",
                "lifecycle_result": "untriaged",
            })
            errors.append(f"{finding_id}:missing_state")
    for row in rows:
        finding_id = str(row.get("finding_id") or "")
        state = str(row.get("state") or "")
        row["lifecycle_result"] = "satisfied"
        if state not in {"fixed", "planned", "waived_until"}:
            row["lifecycle_result"] = "invalid"
            if state != "missing":
                errors.append(f"{finding_id}:invalid_state")
            continue
        if state == "fixed":
            fixture = str(row.get("fixture") or "")
            if not fixture:
                row["lifecycle_result"] = "invalid"
                errors.append(f"{finding_id}:fixed_fixture_missing")
            elif not _resolves_to_unittest(fixture):
                row["lifecycle_result"] = "invalid"
                errors.append(f"{finding_id}:fixed_fixture_not_unittest")
            if finding_id in active:
                row["lifecycle_result"] = "recurred"
                errors.append(f"{finding_id}:finding_recurred_after_fixed")
        elif state == "planned":
            if not str(row.get("target_fixture") or ""):
                row["lifecycle_result"] = "invalid"
                errors.append(f"{finding_id}:planned_target_missing")
        elif state == "waived_until":
            if not str(row.get("reason") or ""):
                row["lifecycle_result"] = "invalid"
                errors.append(f"{finding_id}:waiver_reason_missing")
            try:
                expires = date.fromisoformat(str(row.get("expires") or ""))
            except ValueError:
                row["lifecycle_result"] = "invalid"
                errors.append(f"{finding_id}:waiver_expiry_missing")
            else:
                if expires < current_date:
                    row["lifecycle_result"] = "expired"
                    errors.append(f"{finding_id}:waiver_expired")
    return {"passed": not errors, "blocking": bool(errors), "errors": errors, "rows": rows}


def evaluate_fixture_debt(lifecycle: dict, gate_states: dict[str, bool]) -> dict:
    rows = [dict(row) for row in (lifecycle.get("rows") or [])]
    errors = list(lifecycle.get("errors") or [])
    missing_gates = [name for name in V3_GATE_NAMES if name not in gate_states]
    failed_gates = [name for name in V3_GATE_NAMES if not bool(gate_states.get(name))]
    for row in rows:
        if str(row.get("state") or "") != "fixed":
            continue
        finding_id = str(row.get("finding_id") or "")
        if missing_gates:
            errors.append(f"{finding_id}:fixed_gate_state_missing:{','.join(missing_gates)}")
        elif failed_gates:
            errors.append(f"{finding_id}:fixed_gates_incomplete:{','.join(failed_gates)}")
    errors = list(dict.fromkeys(errors))
    return {"passed": not errors, "blocking": bool(errors), "errors": errors, "rows": rows}


def build_v3_gates(
    manifest: dict, result: dict, asset_gate: dict, fixture_debt: dict
) -> dict[str, dict]:
    topology = result.get("topology_coverage") or {}
    edge_truth = result.get("edge_truth") or {}
    contract = evaluate_pinned_guard_contract(manifest, result)
    contract_errors = set(contract.get("errors") or [])
    edge_errors = sorted(contract_errors & {
        "edge_truth_failed",
        "expected_physical_edge_missing",
        "expected_semantic_edge_missing",
        "expected_semantic_reference_missing",
        "unexpected_semantic_reference",
    })
    conclusion_errors = sorted(contract_errors & {
        "SOURCE_BYTECODE_EDGE_CONFLICT", "expected_conclusion_missing", "expected_chain_missing",
    })
    oracle_audit = result.get("oracle_audit")
    oracle_errors: list[str] = []
    if not isinstance(oracle_audit, dict) or "selected" not in oracle_audit:
        oracle_errors.append("oracle_audit_missing")
    else:
        selected = int(oracle_audit.get("selected") or 0)
        verified = int(oracle_audit.get("verified") or 0)
        if oracle_audit.get("blocking"):
            oracle_errors.append("oracle_reconciliation_blocking")
        if verified != selected:
            oracle_errors.append(
                f"oracle_coverage_incomplete:{verified}/{selected}"
            )
    performance_errors = [
        str(signal.get("message") or signal.get("signal_type") or "performance_regression")
        for signal in (result.get("quality_signals") or [])
        if signal.get("blocking") and signal.get("signal_type") == "performance_regression"
    ]
    api_complete = bool(result.get("api_coverage_complete", result.get("complete", False)))
    topology_errors: list[str] = []
    required_topologies = set(manifest.get("required_topologies") or [])
    observed_topologies = set(topology.get("observed") or [])
    missing_topologies = sorted(required_topologies - observed_topologies)
    if "required_topology_missing" in contract_errors:
        topology_errors.append("required_topology_missing")
    if not topology.get("complete"):
        topology_errors.append("topology_coverage_incomplete")
    topology_errors.extend(missing_topologies)
    return {
        "asset": dict(asset_gate),
        "api_coverage": {
            "name": "api_coverage", "passed": api_complete,
            "errors": [] if api_complete else ["api_coverage_incomplete"],
        },
        "topology_coverage": {
            "name": "topology_coverage", "passed": not topology_errors,
            "errors": topology_errors,
        },
        "edge_truth": {
            "name": "edge_truth", "passed": not edge_errors, "errors": edge_errors,
        },
        "conclusion": {
            "name": "conclusion", "passed": not conclusion_errors, "errors": conclusion_errors,
        },
        "oracle_accuracy": {
            "name": "oracle_accuracy", "passed": not oracle_errors,
            "errors": oracle_errors,
        },
        "performance": {
            "name": "performance", "passed": not performance_errors, "errors": performance_errors,
        },
        "fixture_debt": {
            "name": "fixture_debt", "passed": bool(fixture_debt.get("passed")),
            "errors": list(fixture_debt.get("errors") or []),
        },
    }


def write_v3_guard_outputs(
    report_dir: Path, gates: dict[str, dict], fixture_debt: dict
) -> dict[str, str]:
    quality_dir = report_dir / "evidence" / "quality"
    quality_dir.mkdir(parents=True, exist_ok=True)
    gates_path = quality_dir / "v3_gates.json"
    debt_json_path = quality_dir / "fixture_debt.json"
    debt_csv_path = quality_dir / "fixture_debt.csv"
    gates_path.write_text(json.dumps(gates, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    debt_json_path.write_text(
        json.dumps(fixture_debt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    fields = ("finding_id", "state", "fixture", "target_fixture", "reason", "expires")
    with open_csv_write(debt_csv_path) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(fixture_debt.get("rows") or [])
    return {
        "gates": str(gates_path),
        "fixture_debt_json": str(debt_json_path),
        "fixture_debt_csv": str(debt_csv_path),
    }


def load_pinned_guard_manifest(case: RealProjectCase) -> dict:
    if case.fixture_manifest is None:
        return {}
    return json.loads(case.fixture_manifest.read_text(encoding="utf-8"))


def infer_final_artifact_java_version(artifact_path: Path) -> str:
    versions: list[int] = []
    try:
        with zipfile.ZipFile(artifact_path) as archive:
            try:
                manifest = archive.read("META-INF/MANIFEST.MF").decode(
                    "utf-8", errors="replace"
                )
            except KeyError:
                manifest = ""
            declared = re.search(r"(?im)^Java-Version\s*:\s*([^\s]+)\s*$", manifest)
            if declared:
                return declared.group(1).strip()
            for name in archive.namelist():
                if not name.startswith(("BOOT-INF/classes/", "WEB-INF/classes/")):
                    continue
                if not name.endswith(".class"):
                    continue
                content = archive.read(name)
                if len(content) >= 8 and content[:4] == b"\xca\xfe\xba\xbe":
                    major = int.from_bytes(content[6:8], byteorder="big")
                    if major >= 45:
                        versions.append(major - 44)
    except (OSError, zipfile.BadZipFile):
        return ""
    return str(max(versions)) if versions else ""


def _load_matching_build_provenance(
    provenance_path: Path, artifact_sha256: str
) -> dict | None:
    try:
        raw = provenance_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeError(
            f"EXISTING_BUILD_PROVENANCE_INVALID:{provenance_path}:"
            f"{type(error).__name__}:{error}"
        ) from error
    try:
        existing = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"EXISTING_BUILD_PROVENANCE_INVALID:{provenance_path}:"
            f"{type(error).__name__}:{error}"
        ) from error
    if not isinstance(existing, dict):
        raise RuntimeError(
            f"EXISTING_BUILD_PROVENANCE_INVALID:{provenance_path}:root_not_object"
        )
    sides = existing.get("sides")
    if (
        not isinstance(sides, list)
        or not sides
        or any(not isinstance(side, dict) for side in sides)
    ):
        raise RuntimeError(
            f"EXISTING_BUILD_PROVENANCE_INVALID:{provenance_path}:invalid_sides"
        )
    current_sides = [
        side for side in sides if str(side.get("side") or "") == "current"
    ]
    if len(current_sides) != 1:
        raise RuntimeError(
            f"EXISTING_BUILD_PROVENANCE_INVALID:{provenance_path}:"
            f"current_side_count={len(current_sides)}"
        )
    current = current_sides[0]
    existing_sha = str(
        current.get("artifact_sha256")
        or current.get("actual_artifact_sha256")
        or ""
    ).strip()
    if not existing_sha:
        raise RuntimeError(
            f"EXISTING_BUILD_PROVENANCE_INVALID:{provenance_path}:"
            "current_artifact_sha256_missing"
        )
    if existing_sha != artifact_sha256:
        raise RuntimeError(
            f"EXISTING_BUILD_PROVENANCE_ARTIFACT_MISMATCH:{provenance_path}:"
            f"existing={existing_sha}:actual={artifact_sha256}"
        )
    return existing


def write_pinned_final_artifact_provenance(
    report_dir: Path,
    asset_gate: dict,
    case: RealProjectCase,
    *,
    authority: str = "pinned-real-project-manifest",
) -> Path:
    output = report_dir / "evidence" / "dependencies" / "build_provenance.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact_path = Path(str(asset_gate.get("artifact_path") or ""))
    artifact_sha256 = (
        asset_gate.get("actual_artifact_sha256")
        or asset_gate.get("artifact_sha256")
        or ""
    )
    revision = str(
        asset_gate.get("actual_git_revision")
        or asset_gate.get("expected_git_revision")
        or ""
    ).strip()
    source_mode = str(asset_gate.get("source_mode") or "").strip()
    current_side = {
        "side": "current",
        "artifact_path": str(artifact_path),
        "artifact_sha256": artifact_sha256,
        "authority": authority,
    }
    if revision:
        current_side["revision"] = revision
    if source_mode:
        current_side["source_mode"] = source_mode
    source_project = Path(
        case.current_source_project or case.default_project
    ).resolve()
    if source_mode == "checkout_build":
        scope = build_project_scope(
            source_project,
            case.target_module or ".",
            active_profiles=set(case.active_maven_profiles or ()),
        )
        if (
            scope.get("status") != "insufficient"
            and str(scope.get("source_revision") or "") == revision
        ):
            current_side.update(project_scope_provenance_fields(scope))
    provenance = {"sides": [current_side]}
    existing = _load_matching_build_provenance(output, artifact_sha256)
    if existing is not None:
        existing_sides = existing["sides"]
        existing_current = next(
            side for side in existing_sides
            if str(side.get("side") or "") == "current"
        )
        merged_current = {**existing_current, **current_side}
        provenance = dict(existing)
        provenance["sides"] = [
            merged_current
            if str(side.get("side") or "") == "current"
            else side
            for side in existing_sides
        ]
    output.write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    context_path = report_dir / "evidence" / "context" / "context.json"
    context_path.parent.mkdir(parents=True, exist_ok=True)
    context_path.write_text(json.dumps({
        "jdk_current": infer_final_artifact_java_version(artifact_path) or "unknown",
    }, indent=2) + "\n", encoding="utf-8")
    coordinate = str(case.bytecode_coord or "").strip()
    artifact_id = coordinate.split(":", 1)[-1] if ":" in coordinate else ""
    resolved_output = output.parent / "deps_current_resolved.csv"
    preserve_resolved_output = bool(
        resolved_output.is_file() and resolved_output.stat().st_size
    )
    nested_entry = ""
    runtime_entries: list[dict[str, str]] = []
    if not preserve_resolved_output and artifact_id and artifact_path.is_file():
        try:
            with zipfile.ZipFile(artifact_path) as archive:
                candidates = [
                    name for name in archive.namelist()
                    if name.startswith("BOOT-INF/lib/")
                    and name.endswith(".jar")
                    and Path(name).name.startswith(f"{artifact_id}-")
                ]
                if len(candidates) == 1:
                    nested_entry = candidates[0]
                for name in sorted(
                    item for item in archive.namelist()
                    if item.startswith("BOOT-INF/lib/") and item.endswith(".jar")
                ):
                    properties_rows = []
                    try:
                        with zipfile.ZipFile(io.BytesIO(archive.read(name))) as nested:
                            for metadata_name in nested.namelist():
                                if not re.fullmatch(
                                    r"META-INF/maven/[^/]+/[^/]+/pom\.properties",
                                    metadata_name,
                                ):
                                    continue
                                properties = {}
                                for line in nested.read(metadata_name).decode(
                                    "utf-8", errors="replace"
                                ).splitlines():
                                    key, separator, value = line.strip().partition("=")
                                    if separator:
                                        properties[key.strip()] = value.strip()
                                if all(properties.get(key) for key in (
                                    "groupId", "artifactId", "version"
                                )):
                                    properties_rows.append(properties)
                    except (KeyError, OSError, zipfile.BadZipFile):
                        properties_rows = []
                    if len(properties_rows) == 1:
                        properties = properties_rows[0]
                        runtime_entries.append({
                            "coord": f"{properties['groupId']}:{properties['artifactId']}",
                            "version": properties["version"],
                            "lib_entry": name,
                        })
                    else:
                        runtime_entries.append({
                            "coord": f"runtime:{Path(name).stem}",
                            "version": "runtime",
                            "lib_entry": name,
                        })
        except (OSError, zipfile.BadZipFile) as error:
            raise RuntimeError(
                f"REAL_PROJECT_ARTIFACT_SCAN_FAILED:{artifact_path}:"
                f"{type(error).__name__}:{error}"
            ) from error
    version = next(
        (
            str(row.get("old_version") or "").strip()
            for row in case.changed_api_rows
            if str(row.get("old_version") or "").strip() not in {"", "-"}
        ),
        "pinned",
    )
    if not preserve_resolved_output:
        with open_csv_write(resolved_output) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["coord", "version", "scope", "lib_entry", "resolution_status"],
            )
            writer.writeheader()
            if nested_entry:
                writer.writerow({
                    "coord": coordinate,
                    "version": version,
                    "scope": "compile",
                    "lib_entry": nested_entry,
                    "resolution_status": "resolved",
                })
            for runtime_item in runtime_entries:
                if runtime_item["lib_entry"] == nested_entry:
                    continue
                writer.writerow({
                    "coord": runtime_item["coord"],
                    "version": runtime_item["version"],
                    "scope": "runtime",
                    "lib_entry": runtime_item["lib_entry"],
                    "resolution_status": "resolved",
                })
    return output


def pinned_source_mode(manifest: dict) -> str:
    materialization = manifest.get("materialization") or {}
    return (
        "checkout_build"
        if str(materialization.get("kind") or "") == "source_build"
        else "provided_artifact"
    )


def write_declared_final_artifact_provenance(
    report_dir: Path, case: RealProjectCase
) -> Path:
    artifact = case.final_artifact
    if artifact is None or not artifact.is_file():
        raise ValueError("declared current final artifact is missing")
    artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
    dependencies_dir = Path(report_dir) / "evidence" / "dependencies"
    provenance_path = dependencies_dir / "build_provenance.json"
    resolved_path = dependencies_dir / "deps_current_resolved.csv"
    existing = _load_matching_build_provenance(
        provenance_path, artifact_sha256
    )
    if (
        existing is not None
        and resolved_path.is_file()
        and resolved_path.stat().st_size
    ):
        return provenance_path
    return write_pinned_final_artifact_provenance(
        report_dir,
        {
            "artifact_path": str(artifact),
            "actual_artifact_sha256": artifact_sha256,
        },
        case,
        authority="local-final-artifact",
    )


def _resolve_fixture_debt(
    manifest: dict,
    result: dict,
    asset_gate: dict,
    signals: list[dict],
) -> tuple[dict, dict[str, dict]]:
    lifecycle = evaluate_finding_lifecycle(
        signals, list(manifest.get("fixture_debt") or [])
    )
    provisional_gates = build_v3_gates(manifest, result, asset_gate, lifecycle)
    gate_states = {
        name: bool(provisional_gates[name].get("passed"))
        for name in V3_GATE_NAMES
    }
    fixture_debt = evaluate_fixture_debt(lifecycle, gate_states)
    return fixture_debt, build_v3_gates(manifest, result, asset_gate, fixture_debt)


def finalize_pinned_guard(
    manifest: dict, result: dict, asset_gate: dict, report_dir: Path
) -> dict:
    debt_signals = [
        *list(result.get("quality_signals") or []),
        *list(result.get("finding_lifecycle") or []),
    ]
    fixture_debt, gates = _resolve_fixture_debt(
        manifest, result, asset_gate, debt_signals
    )
    output_files = write_v3_guard_outputs(report_dir, gates, fixture_debt)
    result.update({
        "asset": asset_gate,
        "gates": gates,
        "guard_contract": evaluate_pinned_guard_contract(manifest, result),
        "fixture_debt": fixture_debt,
        "v3_output_files": output_files,
    })
    if any(not gate.get("passed") for gate in gates.values()):
        result["status"] = "failed"
    return result


def is_test_source(path: Path) -> bool:
    normalized = path.as_posix()
    return "/src/test/" in normalized or "/test/" in normalized


def iter_java_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*.java"):
        if path.is_file():
            yield path


def strip_java_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/|//[^\n\r]*", "", text, flags=re.DOTALL)


def collect_baseline_files(project_root: Path, spec: BaselineSpec) -> tuple[set[str], set[str], int]:
    production_files: set[str] = set()
    test_files: set[str] = set()
    occurrence_count = 0
    import_re = re.compile(spec.import_pattern)
    call_re = re.compile(spec.pattern)
    file_re = re.compile(spec.file_path_pattern) if spec.file_path_pattern else None
    for java_file in iter_java_files(project_root):
        rel_path = java_file.relative_to(project_root).as_posix()
        if file_re and not file_re.search(rel_path):
            continue
        try:
            text = java_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        text = strip_java_comments(text)
        if not import_re.search(text):
            continue
        matches = list(call_re.finditer(text))
        if not matches:
            continue
        occurrence_count += len(matches)
        resolved = str(java_file.resolve())
        if is_test_source(java_file):
            test_files.add(resolved)
        else:
            production_files.add(resolved)
    return production_files, test_files, occurrence_count


def collect_alert_files(
    alerts_csv: Path, symbol: str, project_root: Path | None = None
) -> set[str]:
    if not alerts_csv.exists():
        return set()
    files: set[str] = set()
    with open_csv_read(alerts_csv) as fh:
        for row in csv.DictReader(fh):
            if _api_identity_from_alert_row(row)[0] != symbol:
                continue
            for item in re.split(r"[|;]", row.get("evidence_files") or ""):
                item = item.strip()
                if item and Path(item).suffix == ".java":
                    files.add(str((alerts_csv.parent / item).resolve()))
            consumer_class = str(row.get("consumer_class") or "").strip().split("$", 1)[0]
            if project_root is not None and consumer_class:
                relative_source = Path(*consumer_class.split(".")).with_suffix(".java")
                candidates = [
                    path for path in project_root.rglob(relative_source.name)
                    if path.is_file() and path.as_posix().endswith(relative_source.as_posix())
                ]
                if len(candidates) == 1:
                    files.add(str(candidates[0].resolve()))
    return files


def validate_alert_partition_contract(report_dir: Path, summary: dict) -> list[str]:
    call_chain_dir = report_dir / "evidence" / "call_chain"
    main_fields, main_rows = _csv_rows(call_chain_dir / "alerts.csv")
    if not main_fields:
        return ["alerts.csv missing_or_headerless"]
    required_partitions = {
        "reachable": {"reachable"},
        "uncertain": {"uncertain"},
        "not_impacted": {"not_impacted"},
        "not_found_in_static_analysis": {
            "not_found_in_static_analysis", "not_reachable",
        },
        "not_analyzed": {"not_analyzed"},
    }
    errors = []
    known_path_statuses = set().union(*required_partitions.values())
    unknown_statuses = sorted({
        str(row.get("path_status") or "") for row in main_rows
        if str(row.get("path_status") or "") not in known_path_statuses
    })
    if unknown_statuses:
        errors.append(
            "alerts.csv:unknown_or_missing_path_status:" + ",".join(unknown_statuses)
        )
    for status, path_statuses in required_partitions.items():
        try:
            int(summary.get(status) or 0)
        except (TypeError, ValueError):
            errors.append(f"summary_{status}_invalid")
            continue
        stem = f"alerts_{status}"
        base = call_chain_dir / f"{stem}.csv"
        shards = sorted(
            path for path in call_chain_dir.glob(f"{stem}_*.csv")
            if re.fullmatch(rf"{re.escape(stem)}_\d{{3}}\.csv", path.name)
        )
        expected_rows = [
            row for row in main_rows
            if str(row.get("path_status") or "") in path_statuses
        ]
        files = ([base] if base.is_file() else []) + shards
        # Summary buckets classify each API once, while alert partitions retain
        # every path. A reachable API may therefore also have uncertain paths
        # through dependencies that lack a confirmed business entry.
        if expected_rows and not files:
            errors.append(f"{base.name} missing")
            continue
        if base.is_file() and shards:
            errors.append(f"{stem}:base_and_shards_both_present")
        if shards:
            expected_names = [
                f"{stem}_{index:03d}.csv"
                for index in range(1, len(shards) + 1)
            ]
            if [path.name for path in shards] != expected_names:
                errors.append(f"{stem}:non_contiguous_shards")
        actual_rows = []
        for path in files:
            fields, rows = _csv_rows(path)
            if fields != main_fields:
                errors.append(f"{path.name}:header_mismatch")
            actual_rows.extend(rows)
        if actual_rows != expected_rows:
            errors.append(
                f"{stem}:row_reconciliation_mismatch:"
                f"{len(actual_rows)}!={len(expected_rows)}"
            )
    return sorted(set(errors))


def missing_alert_partition_warnings(report_dir: Path, summary: dict) -> list[str]:
    """Compatibility alias; partition defects are now blocking contract errors."""
    return validate_alert_partition_contract(report_dir, summary)


def _csv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.exists():
        return [], []
    with open_csv_read(path) as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def _api_identity_from_changed_row(row: dict[str, str]) -> tuple[str, str, str]:
    signature = str(row.get("api_signature") or "").strip()
    if signature.startswith("("):
        signature = normalize_signature_for_lookup(signature)
    return (
        str(row.get("api_name") or "").strip(),
        signature,
        str(row.get("symbol_kind") or "").strip(),
    )


def _api_identity_from_alert_row(row: dict[str, str]) -> tuple[str, str, str]:
    changed_symbol = str(row.get("changed_symbol") or "").strip()
    signature = str(row.get("api_signature") or "").strip()
    if signature.startswith("("):
        signature = normalize_signature_for_lookup(signature)
        rendered_offset = changed_symbol.rfind("(")
        if rendered_offset >= 0:
            rendered_signature = normalize_signature_for_lookup(changed_symbol[rendered_offset:])
            if rendered_signature == signature:
                changed_symbol = changed_symbol[:rendered_offset].rstrip()
    return (
        changed_symbol,
        signature,
        str(row.get("symbol_kind") or "").strip(),
    )


def _canonical_identity_from_changed_row(row: dict[str, str]) -> str:
    return serialized_api_identity(row)


def _canonical_identity_from_alert_row(row: dict[str, str]) -> str:
    recorded = str(row.get("api_identity") or "").strip()
    if recorded:
        return recorded
    api_name, signature, symbol_kind = _api_identity_from_alert_row(row)
    target_coord = str(row.get("target_coord") or "").strip()
    if "（" in target_coord:
        target_coord = target_coord.split("（", 1)[0].strip()
    return canonical_api_identity({
        "coord": target_coord,
        "api_name": api_name,
        "api_signature": signature,
        "symbol_kind": symbol_kind,
        "change_type": str(row.get("change_type") or "").strip(),
    })


def _chain_target_matches_alert_api(row: dict[str, str]) -> bool:
    api_name, api_signature, symbol_kind = _api_identity_from_alert_row(row)
    chain_target = str(row.get("chain_target") or "").strip()
    if not api_name or not chain_target:
        return False
    if symbol_kind.lower() == "field" or not api_signature.startswith("("):
        return chain_target == api_name
    target_match = re.fullmatch(r"(.+?)(\(.*\))", chain_target)
    if not target_match or target_match.group(1).strip() != api_name:
        return False
    return (
        normalize_signature_for_lookup(target_match.group(2))
        == normalize_signature_for_lookup(api_signature)
    )


def audit_analysis_outputs(changed_apis: Path, alerts_csv: Path, summary: dict) -> dict:
    """Audit full real-project outputs for correctness signals, not just completion."""
    changed_fields, changed_rows = _csv_rows(changed_apis)
    alert_fields, alert_rows = _csv_rows(alerts_csv)
    failures: list[str] = []
    warnings: list[str] = []
    required_alert_fields = {
        "conclusion",
        "change_summary",
        "review_reason",
        "chain_summary",
        "chain_target",
        "changed_symbol",
        "api_signature",
        "symbol_kind",
        "path_status",
    }
    missing_alert_fields = sorted(required_alert_fields - set(alert_fields))
    if missing_alert_fields:
        failures.append(f"alerts_missing_readable_fields:{','.join(missing_alert_fields)}")

    changed_identity_rows = [
        (_canonical_identity_from_changed_row(row), row)
        for row in changed_rows
        if str(row.get("api_name") or "").strip()
    ]
    changed_identity_counts = Counter(identity for identity, _row in changed_identity_rows)
    changed_identities = set(changed_identity_counts)
    duplicate_changed_identities = sorted(
        identity for identity, count in changed_identity_counts.items() if count > 1
    )
    if duplicate_changed_identities:
        failures.append(
            f"changed_duplicate_api_identities:{len(duplicate_changed_identities)}"
        )
    alert_identities = {
        _canonical_identity_from_alert_row(row)
        for row in alert_rows
        if _api_identity_from_alert_row(row)[0]
    }
    missing_alert_identities = sorted(changed_identities - alert_identities)
    if missing_alert_identities:
        failures.append(f"alerts_missing_api_rows:{len(missing_alert_identities)}")
    extra_alert_identities = sorted(alert_identities - changed_identities)
    if extra_alert_identities:
        failures.append(f"alerts_extra_api_rows:{len(extra_alert_identities)}")

    summary_rows = load_analyzer_rows(summary)
    summary_identity_counts = Counter(
        serialized_api_identity(row) for row in summary_rows
    )
    summary_identities = set(summary_identity_counts)
    missing_summary_identities = sorted(changed_identities - summary_identities)
    extra_summary_identities = sorted(summary_identities - changed_identities)
    duplicate_summary_identities = sorted(
        identity for identity, count in summary_identity_counts.items() if count > 1
    )
    if missing_summary_identities:
        failures.append(f"summary_missing_api_rows:{len(missing_summary_identities)}")
    if extra_summary_identities:
        failures.append(f"summary_extra_api_rows:{len(extra_summary_identities)}")
    if duplicate_summary_identities:
        failures.append(
            f"summary_duplicate_api_identities:{len(duplicate_summary_identities)}"
        )

    total_apis = summary.get("total_apis")
    if total_apis is not None and int(total_apis or 0) != len(changed_rows):
        failures.append(f"summary_total_mismatch:summary={total_apis}:changed_rows={len(changed_rows)}")
    if alert_rows and len(alert_rows) < len(changed_identities):
        failures.append(f"alerts_rows_less_than_changed_apis:alerts={len(alert_rows)}:apis={len(changed_identities)}")

    readable_blank = []
    unreadable_markers = []
    unexplained_reachable = []
    suspicious_reachable = []
    source_edges_in_final_paths = []
    human_fields = (
        "conclusion", "change_summary", "review_reason", "chain_summary",
        "chain_entry", "chain_target", "chain_detail", "path_text",
    )
    forbidden_human_markers = (
        "__business__", "**business**", "<class>", "<clinit>",
        "源码图存在目标调用", "revision/profile", "fallback simple key",
    )
    for index, row in enumerate(alert_rows, 1):
        if any(not str(row.get(field) or "").strip() for field in ("conclusion", "change_summary", "review_reason")):
            readable_blank.append(index)
        human_text = " ".join(str(row.get(field) or "") for field in human_fields)
        matched_markers = [marker for marker in forbidden_human_markers if marker in human_text]
        if matched_markers:
            unreadable_markers.append({"row": index, "markers": matched_markers})
        path_status = str(row.get("path_status") or "").strip()
        changed_symbol = str(row.get("changed_symbol") or "").strip()
        if path_status == "reachable" and str(row.get("conclusion") or "").strip() == "已确认影响":
            unexplained_reachable.append(index)
        if path_status == "reachable" and changed_symbol:
            if not _chain_target_matches_alert_api(row):
                suspicious_reachable.append({
                    "row": index,
                    "changed_symbol": changed_symbol,
                    "chain_target": row.get("chain_target") or "",
                    "path_text": row.get("path_text") or "",
                })
    if readable_blank:
        failures.append(f"alerts_readable_fields_blank_rows:{len(readable_blank)}")
    if unreadable_markers:
        failures.append(f"alerts_internal_markers_in_human_fields:{len(unreadable_markers)}")
    if unexplained_reachable:
        failures.append(f"alerts_reachable_conclusion_without_explanation:{len(unexplained_reachable)}")
    if suspicious_reachable:
        failures.append(f"reachable_chain_missing_target_symbol:{len(suspicious_reachable)}")

    source_edge_types = {
        "ast_method_invocation", "instance_call", "lambda_call", "method_reference",
        "constructor_invocation", "field_access", "static_import",
    }
    for api_row in summary.get("reachable_apis") or []:
        for path in api_row.get("evidence_paths") or []:
            for edge in path or []:
                evidence_source = str(edge.get("evidence_source") or "").strip()
                if (
                    evidence_source and evidence_source != "current_final_artifact"
                ) or str(edge.get("evidence_type") or "") in source_edge_types:
                    source_edges_in_final_paths.append(edge)
    if source_edges_in_final_paths:
        failures.append(f"source_edges_in_final_artifact_paths:{len(source_edges_in_final_paths)}")

    status_counts: dict[str, int] = {}
    for row in alert_rows:
        status = str(row.get("path_status") or "<blank>").strip() or "<blank>"
        status_counts[status] = status_counts.get(status, 0) + 1
    if not alert_rows:
        failures.append("alerts_no_rows")
    if not changed_rows:
        failures.append("changed_apis_no_rows")
    if len(missing_alert_identities) > 50:
        warnings.append("large_missing_alert_identity_sample_truncated")
    if len(suspicious_reachable) > 50:
        warnings.append("suspicious_reachable_sample_truncated")

    return {
        "changed_api_rows": len(changed_rows),
        "changed_api_unique_identities": len(changed_identities),
        "alert_rows": len(alert_rows),
        "alert_unique_identities": len(alert_identities),
        "alert_status_counts": status_counts,
        "missing_alert_identities": missing_alert_identities[:50],
        "duplicate_changed_identities": duplicate_changed_identities[:50],
        "missing_summary_identities": missing_summary_identities[:50],
        "extra_summary_identities": extra_summary_identities[:50],
        "duplicate_summary_identities": duplicate_summary_identities[:50],
        "suspicious_reachable": suspicious_reachable[:50],
        "unreadable_markers": unreadable_markers[:50],
        "unexplained_reachable": unexplained_reachable[:50],
        "failures": failures,
        "warnings": warnings,
    }


def collect_source_shape_metrics(project_root: Path, patterns: dict[str, str]) -> dict[str, dict[str, int]]:
    compiled = {name: re.compile(pattern) for name, pattern in (patterns or {}).items()}
    metrics = {
        name: {"files": 0, "occurrences": 0}
        for name in compiled.keys()
    }
    if not compiled:
        return metrics
    for java_file in iter_java_files(project_root):
        try:
            text = java_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, regex in compiled.items():
            matches = list(regex.finditer(text))
            if not matches:
                continue
            metrics[name]["files"] += 1
            metrics[name]["occurrences"] += len(matches)
    return metrics


def extract_graph_stats(summary: dict) -> dict:
    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    graph_stats = meta.get("graph_stats") if isinstance(meta.get("graph_stats"), dict) else {}
    parser_usage = graph_stats.get("parser_usage") if isinstance(graph_stats.get("parser_usage"), dict) else {}
    return {
        "methods_indexed": int(graph_stats.get("methods_indexed") or 0),
        "reverse_edges_indexed": int(graph_stats.get("reverse_edges_indexed") or 0),
        "initializer_methods_indexed": int(graph_stats.get("initializer_methods_indexed") or 0),
        "initializer_edges_indexed": int(graph_stats.get("initializer_edges_indexed") or 0),
        "tree_sitter_files": int(parser_usage.get("tree_sitter") or 0),
        "regex_files": int(parser_usage.get("regex") or 0),
        "truncated": bool(graph_stats.get("truncated")),
        "edge_cap_hits": int(graph_stats.get("edge_cap_hits") or 0),
    }


def compute_api_coverage(case_mode: str, population: int, selected: int, output_total: int) -> dict:
    population = int(population or 0)
    selected = int(selected or 0)
    output_total = int(output_total or 0)
    full_scope = case_mode in {"discovery", "convergence"}
    ratio = selected / population if population else (1.0 if selected == 0 else 0.0)
    return {
        "case_mode": case_mode,
        "coverage_scope": "full" if full_scope else "declared_probes",
        "api_population": population,
        "apis_selected": selected,
        "apis_accounted": output_total,
        "coverage_ratio": ratio,
        "complete": output_total == selected and (not full_scope or ratio == 1.0),
    }


def extend_coordinate_entries_for_runtime_provider_sets(
    report_dir: Path, coordinate_entries: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Map logical upgraded coordinates to every packaged provider entry."""
    expanded = {
        str(coord): list(dict.fromkeys(str(entry) for entry in entries))
        for coord, entries in coordinate_entries.items()
    }
    path = Path(report_dir) / "evidence" / "api_changes" / "artifact_replacements.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return expanded
    for item in payload.get("items") or []:
        providers = [
            str(coord).strip() for coord in (item.get("current_provider_coords") or [])
            if str(coord).strip()
        ]
        if len(providers) < 2:
            continue
        provider_entries = list(dict.fromkeys(
            entry for coord in providers for entry in expanded.get(coord, [])
        ))
        aliases = {
            str(item.get("base_coord") or "").strip(),
            str(item.get("current_coord") or "").strip(),
        }
        for coord in aliases - {""}:
            expanded[coord] = list(dict.fromkeys([
                *expanded.get(coord, []), *provider_entries,
            ]))
    return expanded


def extract_case_topology_evidence(
    case: RealProjectCase,
    report_dir: Path,
    selected_rows: list[dict],
    project_root: Path,
    oracle_scan: dict | None = None,
) -> dict:
    errors: list[str] = []
    provenance_path = report_dir / "evidence" / "dependencies" / "build_provenance.json"
    artifact = None
    expected_sha256 = ""
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        current = next(item for item in provenance.get("sides") or [] if item.get("side") == "current")
        artifact = Path(str(current.get("artifact_path") or ""))
        expected_sha256 = str(current.get("artifact_sha256") or "")
        actual_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if len(expected_sha256) != 64 or actual_sha256 != expected_sha256:
            raise ValueError("current final artifact SHA-256 is missing or mismatched")
    except (OSError, StopIteration, ValueError, json.JSONDecodeError) as error:
        errors.append(f"verified current final artifact unavailable: {error}")

    coordinate_entries: dict[str, list[str]] = {}
    _, dependency_rows = _csv_rows(
        report_dir / "evidence" / "dependencies" / "deps_current_resolved.csv"
    )
    for row in dependency_rows:
        coordinate = str(row.get("coord") or "").strip()
        entry = str(row.get("lib_entry") or "").strip()
        if coordinate and entry:
            coordinate_entries.setdefault(coordinate, []).append(entry)
    coordinate_entries = extend_coordinate_entries_for_runtime_provider_sets(
        report_dir, coordinate_entries
    )

    if artifact is None or errors:
        evidence = {
            "complete": False,
            "errors": errors,
            "edges": [],
            "artifact_layout": {
                "authority": "final_artifact_edge_oracle", "complete": False,
                "errors": errors, "target_apis": [], "entry_layout": [],
            },
        }
    else:
        source_root = project_root if {
            "source_bytecode_agree", "source_bytecode_true_conflict"
        } & set(case.required_topologies) else None
        evidence = extract_artifact_topology_evidence(
            artifact,
            selected_rows,
            coordinate_entries,
            source_root=source_root,
            source_attestation=case.source_attestation,
            target_owner_entries={
                owner: list(entries) for owner, entries in case.target_owner_entries.items()
            },
            oracle_scan=oracle_scan,
        )
        if evidence.get("artifact_layout", {}).get("artifact_sha256") != expected_sha256:
            evidence["complete"] = False
            evidence.setdefault("errors", []).append("oracle artifact SHA-256 differs from verified provenance")
            evidence["artifact_layout"]["complete"] = False
            evidence["artifact_layout"].setdefault("errors", []).append(
                "oracle artifact SHA-256 differs from verified provenance"
            )
    output = report_dir / "evidence" / "quality" / "topology_artifact_layout.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(evidence["artifact_layout"], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    evidence["layout_path"] = str(output)
    return evidence


def _prior_topology_matrix_path(report_root: Path) -> Path:
    return Path(report_root) / "topology_prior_matrix.json"


def _topology_matrix_digest(topology_ids: Iterable[str]) -> str:
    covered = sorted(set(str(item) for item in topology_ids))
    return hashlib.sha256("".join(f"{item}\n" for item in covered).encode()).hexdigest()


def load_pinned_prior_topology_matrix(path: Path | None) -> dict:
    if path is None:
        return {"valid": False, "covered_ids": [], "errors": ["pinned prior matrix missing"]}
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        covered = sorted(set(payload.get("covered_ids") or []))
        digest = _topology_matrix_digest(covered)
        valid = bool(
            payload.get("authority")
            and payload.get("authority_version")
            and payload.get("procedure")
            and covered
            and payload.get("evidence_sha256") == digest
        )
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "covered_ids": [], "errors": ["pinned prior matrix unreadable"]}
    return {**payload, "covered_ids": covered if valid else [], "valid": valid,
            "errors": [] if valid else ["pinned prior matrix evidence invalid"]}


def load_prior_topology_matrix(report_root: Path) -> dict:
    path = _prior_topology_matrix_path(report_root)
    if not path.exists():
        return {"converged_guard_union": [], "cases": {}, "valid": False,
                "errors": ["persisted prior matrix missing"]}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"converged_guard_union": [], "cases": {}, "valid": False,
                "errors": ["persisted prior matrix unreadable"]}
    cases = payload.get("cases")
    if not isinstance(cases, dict):
        return {"converged_guard_union": [], "cases": {}, "valid": False,
                "errors": ["persisted prior matrix cases malformed"]}
    normalized_cases = {}
    union = set()
    for case_name, item in cases.items():
        if not isinstance(item, dict) or item.get("case_mode") not in {"guard", "convergence"}:
            return {"converged_guard_union": [], "cases": {}, "valid": False,
                    "errors": ["persisted prior matrix case malformed"]}
        observed = item.get("observed")
        if not isinstance(observed, list) or not all(isinstance(value, str) and value for value in observed):
            return {"converged_guard_union": [], "cases": {}, "valid": False,
                    "errors": ["persisted prior matrix observations malformed"]}
        normalized_cases[str(case_name)] = {
            "case_mode": item["case_mode"], "observed": sorted(set(observed)),
        }
        union.update(observed)
    covered = sorted(union)
    declared = sorted(set(payload.get("converged_guard_union") or []))
    valid = bool(
        payload.get("authority")
        and payload.get("authority_version")
        and payload.get("procedure")
        and declared == covered
        and payload.get("evidence_sha256") == _topology_matrix_digest(covered)
    )
    return {
        "converged_guard_union": covered if valid else [],
        "cases": normalized_cases if valid else {},
        "valid": valid,
        "errors": [] if valid else ["persisted prior matrix evidence invalid"],
    }


def update_prior_topology_matrix(
    report_root: Path, case_name: str, case_mode: str, observed: set[str]
) -> dict:
    matrix = load_prior_topology_matrix(report_root)
    if case_mode not in {"guard", "convergence"}:
        return matrix
    matrix["cases"][case_name] = {"case_mode": case_mode, "observed": sorted(observed)}
    union = set()
    for item in matrix["cases"].values():
        if item.get("case_mode") in {"guard", "convergence"}:
            union.update(item.get("observed") or [])
    matrix["converged_guard_union"] = sorted(union)
    matrix.update({
        "authority": "converged-guard-runner",
        "authority_version": "1",
        "procedure": "union of topology IDs from passing guard and convergence cases",
        "evidence_sha256": _topology_matrix_digest(matrix["converged_guard_union"]),
    })
    path = _prior_topology_matrix_path(report_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return matrix


def resolve_discovery_prior_coverage(case: RealProjectCase, report_root: Path) -> dict:
    pinned = load_pinned_prior_topology_matrix(case.prior_topology_matrix)
    accumulated = load_prior_topology_matrix(report_root)
    accumulated_exists = _prior_topology_matrix_path(report_root).exists()
    accumulated_acceptable = bool(accumulated.get("valid") or not accumulated_exists)
    covered = set(pinned.get("covered_ids") or [])
    if accumulated.get("valid"):
        covered.update(accumulated.get("converged_guard_union") or [])
    valid = bool(pinned.get("valid") and accumulated_acceptable)
    return {
        "valid": valid,
        "covered_ids": sorted(covered) if valid else [],
        "pinned": pinned,
        "accumulated": accumulated,
    }


def write_topology_coverage(report_dir: Path, coverage: dict) -> dict[str, str]:
    output_dir = report_dir / "evidence" / "quality"
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "topology_coverage.json"
    csv_path = output_dir / "topology_coverage.csv"
    json_path.write_text(
        json.dumps(coverage, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    required = set(coverage.get("required") or [])
    observed = set(coverage.get("observed") or [])
    missing = set(coverage.get("missing") or [])
    with open_csv_write(csv_path) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("topology_id", "required", "observed", "missing"),
        )
        writer.writeheader()
        for topology_id in sorted(required | observed):
            writer.writerow({
                "topology_id": topology_id,
                "required": str(topology_id in required).lower(),
                "observed": str(topology_id in observed).lower(),
                "missing": str(topology_id in missing).lower(),
            })
    return {"json": str(json_path), "csv": str(csv_path)}


def group_conclusion_gaps(summary: dict) -> list[dict]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for item in summary.get("not_analyzed_apis") or []:
        reason_code = str(item.get("reason_code") or "UNKNOWN")
        symbol_kind = str(item.get("symbol_kind") or "unknown")
        symbol = str(item.get("api") or item.get("api_name") or "")
        grouped.setdefault((reason_code, symbol_kind), []).append(symbol)
    return [
        {
            "reason_code": reason_code,
            "symbol_kind": symbol_kind,
            "count": len(symbols),
            "sample_symbols": sorted(set(symbols))[:5],
        }
        for (reason_code, symbol_kind), symbols in sorted(grouped.items())
    ]


def derive_case_status(executed: bool, signals: list[dict], ground_truth_status: str) -> str:
    if not executed:
        return "skipped"
    semantic_blockers = [
        signal for signal in signals
        if signal.get("blocking") and signal.get("signal_type") != "ground_truth_insufficient"
    ]
    if semantic_blockers:
        return "failed"
    if ground_truth_status != "reviewed":
        return "observed"
    return "passed"


def derive_run_status(results: list[dict]) -> str:
    statuses = [str(item.get("status") or "") for item in results]
    if any(status == "failed" for status in statuses):
        return "failed"
    if statuses and all(status == "passed" for status in statuses):
        return "passed"
    return "incomplete"


def collect_stage_performance(report_dir: Path) -> dict:
    observability = Path(report_dir) / ".runtime" / "observability"
    stage_specs = {
        "step1_elapsed_seconds": ("step1_timing.csv", "step1_total"),
        "step4_elapsed_seconds": ("step4_timing.csv", "step4.total"),
    }
    metrics = {}
    for metric, (filename, total_phase) in stage_specs.items():
        value = 0.0
        try:
            with (observability / filename).open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                for row in csv.DictReader(handle):
                    if str(row.get("phase") or "").strip() == total_phase:
                        value = float(row.get("elapsed_sec") or 0.0)
                        break
        except (OSError, TypeError, ValueError):
            value = 0.0
        metrics[metric] = value
    return metrics


def collect_performance_envelope(
    summary: dict,
    elapsed: float,
    selected: int,
    oracle_metrics: dict | None = None,
) -> dict:
    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    graph_stats = meta.get("graph_stats") if isinstance(meta.get("graph_stats"), dict) else {}
    step5_perf = graph_stats.get("step5_perf") if isinstance(graph_stats.get("step5_perf"), dict) else {}
    perf_main = step5_perf.get("main") if isinstance(step5_perf.get("main"), dict) else {}
    bytecode_scan = step5_perf.get("bytecode_scan") if isinstance(step5_perf.get("bytecode_scan"), dict) else {}
    bytecode_expand = step5_perf.get("bytecode_expand") if isinstance(step5_perf.get("bytecode_expand"), dict) else {}
    trace_perf = step5_perf.get("trace") if isinstance(step5_perf.get("trace"), dict) else {}
    pairs = int(perf_main.get("indirect_usage_potential_legacy_method_target_pairs") or 0)
    owner_scans = int(perf_main.get("indirect_usage_owner_presence_scans") or 0)
    selected = int(selected or 0)
    oracle_metrics = oracle_metrics or {}
    class_count = int(bytecode_scan.get("class_entries_scoped") or bytecode_scan.get("visited_classes") or 0)
    scan_seconds = float(bytecode_scan.get("elapsed_sec") or 0.0)
    per_api_timings = [
        dict(item) for item in (trace_perf.get("api_trace_timings") or [])
        if isinstance(item, dict)
    ]
    return {
        "elapsed_seconds": float(elapsed or 0.0),
        "elapsed_seconds_per_api": float(elapsed or 0.0) / selected if selected else 0.0,
        "elapsed_seconds_per_1000_apis": float(elapsed or 0.0) / (selected / 1000.0) if selected else 0.0,
        "potential_method_target_pairs": pairs,
        "selected_api_count": selected,
        "accounted_api_count": int(summary.get("total_apis") or 0),
        "potential_pairs_per_api": pairs / selected if selected else 0.0,
        "owner_presence_scans": owner_scans,
        "artifact_bytes": int(bytecode_scan.get("artifact_bytes") or 0),
        "artifact_count": int(bytecode_scan.get("artifact_count") or 0),
        "class_count": class_count,
        "scan_seconds_per_1000_classes": scan_seconds * 1000.0 / class_count if class_count else 0.0,
        "parsed_class_count": int(bytecode_scan.get("class_entries_parsed") or 0),
        "parse_seconds": float(bytecode_scan.get("class_parse_elapsed_sec") or 0.0),
        "artifact_cache_hits": int(bytecode_scan.get("artifact_cache_hits") or 0),
        "javap_fallbacks": int(bytecode_scan.get("javap_fallbacks") or 0),
        "javap_invocations": (
            int(bytecode_scan.get("javap_fallbacks") or 0)
        ),
        "duplicate_jar_scans": int(bytecode_scan.get("duplicate_jar_scans") or 0),
        "duplicate_class_scans": int(bytecode_scan.get("duplicate_class_scans") or 0),
        "peak_rss_mb": float(perf_main.get("peak_rss_mb") or 0.0),
        "per_api_timings": per_api_timings,
        "per_api_timing_count": len(per_api_timings),
        "per_api_timing_complete": len(per_api_timings) == selected,
        "max_api_elapsed_seconds": max(
            (float(item.get("elapsed_sec") or 0.0) for item in per_api_timings),
            default=0.0,
        ),
        "oracle_class_count": int(oracle_metrics.get("class_count") or 0),
        "oracle_completed_class_count": int(oracle_metrics.get("completed_class_count") or 0),
        "oracle_parsed_class_count": int(oracle_metrics.get("parsed_class_count") or 0),
        "oracle_cached_class_count": int(oracle_metrics.get("cached_class_count") or 0),
        "oracle_parse_failure_count": int(oracle_metrics.get("parse_failure_count") or 0),
        "oracle_parse_seconds": float(oracle_metrics.get("parse_seconds") or 0.0),
        "oracle_elapsed_seconds": float(oracle_metrics.get("elapsed_seconds") or 0.0),
        "oracle_worker_count": int(oracle_metrics.get("worker_count") or 0),
        "oracle_cache_hits": int(oracle_metrics.get("cache_hits") or 0),
        "oracle_cache_misses": int(oracle_metrics.get("cache_misses") or 0),
        "oracle_timed_out": bool(oracle_metrics.get("timed_out")),
        "oracle_interrupted": bool(oracle_metrics.get("interrupted")),
        "jdeps_invocations": int(oracle_metrics.get("jdeps_invocations") or 0),
        "jdeps_class_count": int(oracle_metrics.get("jdeps_class_count") or 0),
        "jdeps_elapsed_seconds": float(oracle_metrics.get("jdeps_elapsed_seconds") or 0.0),
        "javap_class_invocations": int(oracle_metrics.get("javap_class_invocations") or 0),
        "javap_class_elapsed_seconds": float(
            oracle_metrics.get("javap_class_elapsed_seconds") or 0.0
        ),
    }


def finalize_performance_envelope(envelope: dict) -> dict:
    """Derive normalized rates after exhaustive edge reconciliation adds its counts."""
    parsed_class_count = int(envelope.get("parsed_class_count") or 0)
    parse_seconds = float(envelope.get("parse_seconds") or 0.0)
    oracle_edges = int(envelope.get("oracle_edge_count") or 0)
    analyzer_edges = int(envelope.get("analyzer_edge_count") or 0)
    semantic_references = int(envelope.get("semantic_reference_count") or 0)
    edge_count = max(oracle_edges, analyzer_edges) + semantic_references
    reconcile_seconds = float(envelope.get("reconcile_seconds") or 0.0)
    elapsed_seconds = float(envelope.get("elapsed_seconds") or 0.0)
    envelope["parse_rate_available"] = parsed_class_count > 0 and parse_seconds > 0
    envelope["parse_classes_per_second"] = (
        parsed_class_count / parse_seconds if envelope["parse_rate_available"] else None
    )
    envelope["edge_rate_available"] = edge_count > 0
    envelope["audit_evidence_count"] = edge_count
    envelope["reconcile_edges_per_second"] = (
        edge_count / reconcile_seconds if edge_count and reconcile_seconds else None
    )
    envelope["elapsed_seconds_per_100k_edges"] = (
        elapsed_seconds * 100000.0 / edge_count if edge_count else None
    )
    return envelope


PERFORMANCE_SCOPE_FIELDS = (
    "selected_api_count",
    "accounted_api_count",
    "artifact_count",
    "class_count",
    "analyzer_edge_count",
    "oracle_edge_count",
    "fault_injection_detected_count",
)


def evaluate_performance_scope_preservation(baseline: dict, current: dict) -> dict:
    errors: list[str] = []
    regressions: dict[str, dict] = {}
    comparisons: dict[str, dict] = {}
    for field in PERFORMANCE_SCOPE_FIELDS:
        if field not in baseline:
            errors.append(f"performance_scope_baseline_missing:{field}")
            continue
        if field not in current:
            errors.append(f"performance_scope_current_missing:{field}")
            continue
        expected = int(baseline.get(field) or 0)
        actual = int(current.get(field) or 0)
        comparisons[field] = {"baseline": expected, "actual": actual}
        if actual < expected:
            regressions[field] = {
                "baseline": expected,
                "actual": actual,
                "missing": expected - actual,
            }
    return {
        "passed": not errors and not regressions,
        "errors": errors,
        "regressions": regressions,
        "comparisons": comparisons,
    }


def evaluate_relative_performance_baseline(
    case: RealProjectCase,
    pinned_manifest: dict | None,
    performance: dict,
) -> dict:
    if not case.require_relative_performance_baseline:
        return {"required": False, "passed": True, "errors": [], "regressions": {}, "comparisons": {}}
    manifest = dict(pinned_manifest or {})
    baseline = dict(manifest.get("performance_baseline") or {})
    errors = []
    if not baseline:
        errors.append("performance_baseline_missing")
    if baseline.get("git_revision") != manifest.get("git_revision"):
        errors.append("performance_baseline_git_revision_mismatch")
    if (
        artifact_verification_mode(manifest) == "sha256"
        and baseline.get("artifact_sha256") != manifest.get("artifact_sha256")
    ):
        errors.append("performance_baseline_artifact_sha_mismatch")
    metrics = baseline.get("metrics") if isinstance(baseline.get("metrics"), dict) else {}
    if not metrics:
        errors.append("performance_baseline_metrics_missing")
    if not performance.get("per_api_timing_complete"):
        errors.append("performance_per_api_timings_incomplete")
    regressions = {}
    comparisons = {}
    scope_baseline = baseline.get("scope")
    if isinstance(scope_baseline, dict):
        scope_result = evaluate_performance_scope_preservation(
            scope_baseline, performance
        )
        errors.extend(scope_result["errors"])
        regressions.update({
            f"scope:{name}": details
            for name, details in scope_result["regressions"].items()
        })
    else:
        scope_result = {
            "passed": False,
            "errors": ["performance_scope_baseline_missing"],
            "regressions": {},
            "comparisons": {},
        }
        errors.extend(scope_result["errors"])
    for name, policy in metrics.items():
        if not isinstance(policy, dict) or "value" not in policy:
            errors.append(f"performance_baseline_metric_invalid:{name}")
            continue
        if name not in performance:
            errors.append(f"performance_metric_missing:{name}")
            continue
        baseline_value = float(policy.get("value") or 0.0)
        actual_value = float(performance.get(name) or 0.0)
        zero_is_valid = name in {
            "javap_invocations", "duplicate_jar_scans",
            "duplicate_class_scans",
        }
        if baseline_value > 0 and (
            not math.isfinite(actual_value)
            or actual_value < 0
            or (actual_value == 0 and not zero_is_valid)
        ):
            errors.append(f"performance_metric_nonpositive:{name}")
            continue
        max_absolute = policy.get("max_absolute")
        max_ratio = float(policy.get("max_ratio") or 0.0)
        limit = (
            float(max_absolute)
            if max_absolute is not None
            else baseline_value * max_ratio
        )
        if max_absolute is None and max_ratio <= 0:
            errors.append(f"performance_baseline_threshold_missing:{name}")
            continue
        comparisons[name] = {
            "baseline": baseline_value,
            "actual": actual_value,
            "limit": limit,
        }
        if actual_value > limit:
            regressions[name] = comparisons[name]
    return {
        "required": True,
        "passed": not errors and not regressions,
        "errors": sorted(set(errors)),
        "regressions": regressions,
        "comparisons": comparisons,
        "scope": scope_result,
    }


def build_relative_performance_signals(
    case: RealProjectCase,
    relative_performance: dict,
    report_dir: Path,
) -> list[dict]:
    if not relative_performance.get("required") or relative_performance.get("passed"):
        return []
    return [make_signal(
        "performance_regression",
        "P1",
        case.name,
        step="real-project-gate",
        message="revision/artifact-bound relative performance baseline failed",
        count=(
            len(relative_performance.get("errors") or [])
            + len(relative_performance.get("regressions") or {})
        ),
        expected="all performance metrics present and within their pinned relative thresholds",
        actual=json.dumps({
            "errors": relative_performance.get("errors") or [],
            "regressions": relative_performance.get("regressions") or {},
        }, sort_keys=True),
        evidence=[Path(report_dir) / "evidence" / "call_chain" / "summary.json"],
        blocking=True,
    )]


def build_cache_equivalence_signals(
    case: RealProjectCase, cache_equivalence: dict, report_dir: Path
) -> list[dict]:
    if cache_equivalence.get("passed"):
        return []
    return [make_signal(
        "cache_semantic_equivalence_failure",
        "P0",
        case.name,
        step="step5-cache-equivalence",
        message="Step5 cold/warm execution did not preserve the same semantic result",
        expected="both runs succeed and canonical semantic fingerprints are identical",
        actual=json.dumps({
            "errors": cache_equivalence.get("errors") or [],
            "cold_returncode": cache_equivalence.get("cold_returncode"),
            "warm_returncode": cache_equivalence.get("warm_returncode"),
            "cold_fingerprint": cache_equivalence.get("cold_fingerprint") or "",
            "warm_fingerprint": cache_equivalence.get("warm_fingerprint") or "",
        }, sort_keys=True),
        evidence=[Path(report_dir) / "evidence" / "call_chain" / "summary.json"],
        blocking=True,
    )]


def serialized_api_identity(api_row: dict) -> str:
    """Use the shared analyzer/Oracle API identity."""
    return canonical_api_identity(api_row)


def _constructor_owner_from_api_name(api_name: str) -> str:
    value = str(api_name or "").strip()
    if value.endswith(".<init>"):
        return value[:-len(".<init>")]
    possible_owner, separator, repeated_name = value.rpartition(".")
    owner_simple_name = possible_owner.rpartition(".")[2]
    if separator and repeated_name == owner_simple_name:
        return possible_owner
    return value


def _api_target_matches(api_row: dict, edge: dict) -> bool:
    api_name = str((api_row or {}).get("api_name") or "").strip()
    symbol_kind = str((api_row or {}).get("symbol_kind") or "method").strip().lower()
    if symbol_kind == "constructor" and not api_name.endswith(".<init>"):
        owner = _constructor_owner_from_api_name(api_name)
        separator = "."
        member = "<init>"
    else:
        owner, separator, member = api_name.rpartition(".")
    if not separator or not owner or not member:
        return False
    if symbol_kind == "constructor":
        member = "<init>"
    if (
        str(edge.get("callee_owner") or "").strip() != owner
        or str(edge.get("callee_member") or "").strip() != member
    ):
        return False
    if symbol_kind == "field":
        opcode = str(edge.get("opcode_family") or "").strip().lower()
        return (
            opcode in {"getfield", "putfield", "getstatic", "putstatic"}
            and not str(edge.get("callee_descriptor") or "").strip().startswith("(")
        )
    opcode = str(edge.get("opcode_family") or "").strip().lower()
    if symbol_kind == "constructor":
        if opcode != "invokespecial":
            return False
    elif symbol_kind == "method":
        if not opcode.startswith("invoke"):
            return False
    descriptor = str(edge.get("callee_descriptor") or "").strip()
    if not descriptor.startswith("("):
        return False
    try:
        actual = normalize_signature_for_lookup(_source_signature(descriptor))
    except (IndexError, ValueError):
        return False
    expected = normalize_signature_for_lookup(str(api_row.get("api_signature") or ""))
    return bool(expected) and actual == expected


def _caller_identity(edge: dict) -> tuple[str, str, str]:
    return tuple(str(edge.get(field) or "").strip() for field in (
        "caller_owner", "caller_member", "caller_descriptor",
    ))


def _callee_identity(edge: dict) -> tuple[str, str, str]:
    return tuple(str(edge.get(field) or "").strip() for field in (
        "callee_owner", "callee_member", "callee_descriptor",
    ))


def _business_artifact_entry(
    entry: str, application_owned_nested_jars: set[str] | None = None
) -> bool:
    value = str(entry or "").strip()
    nested_jar = _nested_jar_entry(value)
    return bool(
        value.startswith(("BOOT-INF/classes/", "WEB-INF/classes/"))
        or (value.endswith(".class") and "!/" not in value)
        or (
            nested_jar
            and nested_jar in set(application_owned_nested_jars or set())
        )
    )


def _nested_jar_entry(artifact_entry: str) -> str:
    value = str(artifact_entry or "").strip()
    return value.split("!/", 1)[0] if "!/" in value else ""


def _is_external_provider_for_api(
    artifact_entry: str,
    api_row: dict,
    provider_nested_jars_by_coord: dict[str, set[str]] | None,
    provider_nested_jars_by_api_identity: dict[str, set[str]] | None = None,
) -> bool:
    coord = str((api_row or {}).get("coord") or "").strip()
    identity = serialized_api_identity(api_row or {})
    nested_jar = _nested_jar_entry(artifact_entry)
    provider_match = bool(
        nested_jar
        and (
            nested_jar in (provider_nested_jars_by_api_identity or {}).get(
                identity, set()
            )
            or (
                coord
                and nested_jar
                in (provider_nested_jars_by_coord or {}).get(coord, set())
            )
        )
    )
    if not provider_match:
        return False
    caller_owner = _artifact_entry_class_owner(artifact_entry).replace("$", ".")
    target_owner = _selected_api_owner(api_row).replace("$", ".")
    return bool(caller_owner and target_owner and caller_owner == target_owner)


def _artifact_entry_class_owner(entry: str) -> str:
    value = str(entry or "").strip()
    if "!/" in value:
        value = value.rsplit("!/", 1)[1]
    for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    value = re.sub(r"^META-INF/versions/\d+/", "", value)
    if not value.endswith(".class"):
        return ""
    return value[:-6].replace("/", ".")


def _duplicate_artifact_class_owners(entries) -> set[str]:
    """Return class owners whose physical implementation is ambiguous in one artifact."""
    owner_entries: dict[str, set[str]] = defaultdict(set)
    for raw_entry in entries or ():
        entry = str(raw_entry or "").strip()
        owner = _artifact_entry_class_owner(entry)
        if owner:
            owner_entries[owner].add(entry)
    return {
        owner for owner, physical_entries in owner_entries.items()
        if len(physical_entries) > 1
    }


def _oracle_edge_identity_errors(rows: list[dict]) -> list[str]:
    errors = set()
    for row in rows:
        entry = str(row.get("artifact_entry") or "").strip()
        expected_owner = _artifact_entry_class_owner(entry)
        actual_owner = str(row.get("caller_owner") or "").strip()
        if not expected_owner or actual_owner != expected_owner:
            errors.add(
                "oracle_caller_owner_artifact_entry_mismatch:"
                f"entry={entry}:expected={expected_owner or '<class-entry-required>'}:"
                f"actual={actual_owner or '<missing>'}"
            )
    return sorted(errors)


def normalize_instruction_offset(edge: dict | None) -> str:
    offset = (edge or {}).get("instruction_offset")
    return "" if offset is None else str(offset).strip()


def physical_edge_occurrence(edge: dict) -> str:
    """Identify one bytecode instruction without changing canonical edge identity."""
    return "|".join((
        canonical_edge_identity(edge),
        str((edge or {}).get("artifact_entry") or "").strip(),
        normalize_instruction_offset(edge),
    ))


def _retain_path_to_business_boundary(
    identity: str,
    direct_edges: list[dict],
    upstream_edges,
    application_owned_nested_jars: set[str] | None = None,
    ambiguous_class_owners: set[str] | None = None,
) -> tuple[dict[tuple[str, str], dict], bool]:
    direct_keys = {
        (identity, physical_edge_occurrence(edge)) for edge in direct_edges
    }
    discovered: dict[tuple[str, str], dict] = {}
    pending = deque(direct_edges)
    reached_boundary = False
    while pending:
        edge = pending.popleft()
        physical_key = (identity, physical_edge_occurrence(edge))
        if physical_key in discovered:
            continue
        discovered[physical_key] = {**edge, "api_identity": identity}
        if {
            str(edge.get("caller_owner") or "").strip(),
            str(edge.get("callee_owner") or "").strip(),
        } & set(ambiguous_class_owners or set()):
            continue
        if _business_artifact_entry(
            str(edge.get("artifact_entry") or ""),
            application_owned_nested_jars,
        ):
            reached_boundary = True
            continue
        pending.extend(
            upstream for upstream in upstream_edges(edge)
            if _caller_identity(upstream) != _callee_identity(upstream)
        )
    if reached_boundary:
        return discovered, True
    return {
        key: row for key, row in discovered.items() if key in direct_keys
    }, False


def _retain_authoritative_api_path(
    selected_rows: list[dict], oracle_rows: list[dict],
    semantic_targets: set[str] | None = None,
    *,
    absence_is_authoritative: bool = False,
    class_reachability: dict[str, str] | None = None,
    application_owned_nested_jars: set[str] | None = None,
    provider_nested_jars_by_coord: dict[str, set[str]] | None = None,
    provider_nested_jars_by_api_identity: dict[str, set[str]] | None = None,
    ambiguous_class_owners: set[str] | None = None,
) -> tuple[list[dict], dict[str, str], list[str]]:
    """Keep every physical path and classify whether it reaches packaged business code."""
    incoming: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for edge in oracle_rows:
        incoming[_callee_identity(edge)].append(edge)
    selected: dict[str, list[dict]] = {}
    api_reachability: dict[str, str] = {}
    errors: list[str] = []
    for api_row in selected_rows:
        identity = serialized_api_identity(api_row)
        direct = [
            edge for edge in oracle_rows
            if _api_target_matches(api_row, edge)
            and not (
                _nested_jar_entry(str(edge.get("artifact_entry") or ""))
                not in set(application_owned_nested_jars or set())
                and _is_external_provider_for_api(
                    str(edge.get("artifact_entry") or ""),
                    api_row,
                    provider_nested_jars_by_coord,
                    provider_nested_jars_by_api_identity,
                )
            )
        ]
        if not direct:
            if identity in (semantic_targets or set()):
                api_reachability[identity] = "uncertain"
                continue
            if identity in (class_reachability or {}):
                api_reachability[identity] = str(class_reachability[identity])
                continue
            if absence_is_authoritative:
                api_reachability[identity] = "not_found_in_static_analysis"
                continue
            errors.append(f"selected_api_unresolved:{identity}")
            api_reachability[identity] = "not_analyzed"
            continue
        selected[identity] = direct

    retained: dict[tuple[str, str], dict] = {}
    for identity, direct_edges in selected.items():
        path_rows, reached_boundary = _retain_path_to_business_boundary(
            identity,
            direct_edges,
            lambda edge: incoming.get(_caller_identity(edge), []),
            application_owned_nested_jars,
            ambiguous_class_owners,
        )
        retained.update(path_rows)
        api_reachability[identity] = "reachable" if reached_boundary else "uncertain"
    return sorted(retained.values(), key=lambda row: (
        str(row.get("api_identity") or ""), canonical_edge_identity(row),
        str(row.get("artifact_entry") or ""), normalize_instruction_offset(row),
    )), api_reachability, sorted(errors)


def _retain_analyzer_api_path(
    selected_rows: list[dict],
    analyzer_rows: list[dict],
    application_owned_nested_jars: set[str] | None = None,
    provider_nested_jars_by_coord: dict[str, set[str]] | None = None,
    provider_nested_jars_by_api_identity: dict[str, set[str]] | None = None,
    ambiguous_class_owners: set[str] | None = None,
) -> list[dict]:
    """Associate upstream analyzer edges by bytecode graph path from a labeled target edge."""
    incoming: dict[tuple[str, tuple[str, str, str]], list[dict]] = defaultdict(list)
    for edge in analyzer_rows:
        incoming[(str(edge.get("api_identity") or ""), _callee_identity(edge))].append(edge)

    retained: dict[tuple[str, str], dict] = {}
    for api_row in selected_rows:
        identity = serialized_api_identity(api_row)
        direct_edges = list(
            edge for edge in analyzer_rows
            if str(edge.get("api_identity") or "") == identity
            and _api_target_matches(api_row, edge)
            and not (
                _nested_jar_entry(str(edge.get("artifact_entry") or ""))
                not in set(application_owned_nested_jars or set())
                and _is_external_provider_for_api(
                    str(edge.get("artifact_entry") or ""),
                    api_row,
                    provider_nested_jars_by_coord,
                    provider_nested_jars_by_api_identity,
                )
            )
        )
        def upstream(edge):
            caller = _caller_identity(edge)
            return (
                list(incoming.get((identity, caller), []))
                + list(incoming.get(("", caller), []))
            )
        path_rows, _reached_boundary = _retain_path_to_business_boundary(
            identity,
            direct_edges,
            upstream,
            application_owned_nested_jars,
            ambiguous_class_owners,
        )
        retained.update(path_rows)
    return sorted(retained.values(), key=lambda row: (
        str(row.get("api_identity") or ""), physical_edge_occurrence(row),
    ))


def _reconcile_physical_edge_occurrences(
    analyzer_rows: list[dict],
    oracle_rows: list[dict],
    trusted_artifact_sha: str,
    artifact_entries: set[str],
) -> dict:
    """Use the shared canonical contract inside each explicitly associated occurrence."""
    grouped: dict[tuple[str, str], dict[str, list[dict]]] = defaultdict(
        lambda: {"analyzer": [], "oracle": []}
    )
    for side, rows in (("analyzer", analyzer_rows), ("oracle", oracle_rows)):
        for row in rows:
            key = (str(row.get("api_identity") or ""), physical_edge_occurrence(row))
            grouped[key][side].append(row)

    ledger: list[dict] = []
    verdict_counts = {verdict: 0 for verdict in EDGE_RECONCILIATION_VERDICTS}
    for api_identity, occurrence in sorted(grouped):
        rows = grouped[(api_identity, occurrence)]
        result = reconcile_edges(
            rows["analyzer"],
            rows["oracle"],
            trusted_artifact_sha=trusted_artifact_sha,
            valid_artifact_entries=artifact_entries,
        )
        for row in result["ledger"]:
            ledger.append({
                **row,
                "api_identity": api_identity,
                "physical_occurrence": occurrence,
            })
        for verdict, count in result["verdict_counts"].items():
            verdict_counts[verdict] += int(count)
    return {
        "ledger": ledger,
        "verdict_counts": verdict_counts,
        "blocking": any(verdict_counts[verdict] for verdict in verdict_counts if verdict != "correct"),
    }


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(path) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return str(path)


def _verified_framework_semantic_targets(
    report_dir: Path, selected_rows: list[dict]
) -> set[str]:
    path = Path(report_dir) / "evidence" / "call_chain" / "framework_adapters.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    verified_targets = set()
    for adapter in payload.get("adapters") or []:
        for edge in adapter.get("edges") or []:
            provenance = edge.get("provenance") or edge.get("evidence") or {}
            if (
                edge.get("edge_kind") == "spring_transaction_proxy_dispatch"
                and provenance.get("authority") == "final_artifact_javap"
                and _valid_sha256(str(provenance.get("artifact_sha256") or ""))
                and _valid_sha256(str(provenance.get("business_artifact_sha256") or ""))
            ):
                verified_targets.add(str(edge.get("target") or ""))
    identities = set()
    for row in selected_rows:
        target = f"{row.get('api_name') or ''}{row.get('api_signature') or ''}"
        if target in verified_targets:
            identities.add(serialized_api_identity(row))
    return identities


def _classfile_utf8_constants(content: bytes) -> set[bytes]:
    if len(content) < 10 or content[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("not a classfile")
    constant_count = struct.unpack_from(">H", content, 8)[0]
    constants: set[bytes] = set()
    index = 10
    slot = 1
    while slot < constant_count:
        if index >= len(content):
            raise ValueError("truncated constant pool")
        tag = content[index]
        index += 1
        if tag == 1:
            if index + 2 > len(content):
                raise ValueError("truncated UTF8 constant length")
            length = struct.unpack_from(">H", content, index)[0]
            index += 2
            if index + length > len(content):
                raise ValueError("truncated UTF8 constant")
            constants.add(content[index:index + length])
            index += length
        elif tag in {3, 4}:
            index += 4
        elif tag in {5, 6}:
            index += 8
            slot += 1
        elif tag in {7, 8, 16, 19, 20}:
            index += 2
        elif tag in {9, 10, 11, 12, 17, 18}:
            index += 4
        elif tag == 15:
            index += 3
        else:
            raise ValueError(f"unsupported constant-pool tag {tag}")
        if index > len(content):
            raise ValueError("truncated constant-pool payload")
        slot += 1
    return constants


def _classfile_member_references(content: bytes) -> list[dict]:
    """Parse exact field/method reference constants without using analyzer code."""
    if len(content) < 10 or content[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("not a classfile")
    constant_count = struct.unpack_from(">H", content, 8)[0]
    constants: list[object | None] = [None] * constant_count
    index = 10
    slot = 1
    while slot < constant_count:
        if index >= len(content):
            raise ValueError("truncated constant pool")
        tag = content[index]
        index += 1
        if tag == 1:
            if index + 2 > len(content):
                raise ValueError("truncated UTF8 constant length")
            length = struct.unpack_from(">H", content, index)[0]
            index += 2
            if index + length > len(content):
                raise ValueError("truncated UTF8 constant")
            constants[slot] = ("utf8", content[index:index + length])
            index += length
        elif tag in {3, 4}:
            index += 4
        elif tag in {5, 6}:
            index += 8
            slot += 1
        elif tag == 7:
            constants[slot] = ("class", struct.unpack_from(">H", content, index)[0])
            index += 2
        elif tag in {8, 16, 19, 20}:
            index += 2
        elif tag in {9, 10, 11}:
            class_index, name_type_index = struct.unpack_from(">HH", content, index)
            constants[slot] = ("reference", tag, class_index, name_type_index)
            index += 4
        elif tag == 12:
            name_index, descriptor_index = struct.unpack_from(">HH", content, index)
            constants[slot] = ("name_type", name_index, descriptor_index)
            index += 4
        elif tag in {17, 18}:
            index += 4
        elif tag == 15:
            index += 3
        else:
            raise ValueError(f"unsupported constant-pool tag {tag}")
        if index > len(content):
            raise ValueError("truncated constant-pool payload")
        slot += 1

    def utf8(constant_index: int) -> str:
        value = constants[constant_index]
        if not isinstance(value, tuple) or value[0] != "utf8":
            raise ValueError("invalid UTF8 constant reference")
        return value[1].decode("utf-8", errors="replace")

    references = []
    for value in constants:
        if not isinstance(value, tuple) or value[0] != "reference":
            continue
        _kind, tag, class_index, name_type_index = value
        class_value = constants[class_index]
        name_type = constants[name_type_index]
        if (
            not isinstance(class_value, tuple) or class_value[0] != "class"
            or not isinstance(name_type, tuple) or name_type[0] != "name_type"
        ):
            raise ValueError("invalid member reference")
        references.append({
            "callee_owner": utf8(class_value[1]).replace("/", "."),
            "callee_member": utf8(name_type[1]),
            "callee_descriptor": utf8(name_type[2]),
            "reference_kind": {9: "field", 10: "method", 11: "interface_method"}[tag],
            "opcode_family": (
                "getfield" if tag == 9
                else "invokespecial" if utf8(name_type[1]) == "<init>"
                else "invokeinterface" if tag == 11
                else "invokevirtual"
            ),
        })
    return references


def scan_final_artifact_member_references(
    artifact: Path,
    selected_rows: list[dict],
    *,
    excluded_nested_jars: set[str] | None = None,
    application_owned_nested_jars: set[str] | None = None,
    provider_nested_jars_by_coord: dict[str, set[str]] | None = None,
    provider_nested_jars_by_api_identity: dict[str, set[str]] | None = None,
    time_budget_seconds: float | None = None,
) -> dict:
    """Independently account for exact member refs in a packaged artifact."""
    targets = [
        row for row in selected_rows
        if str(row.get("symbol_kind") or "").strip().lower() != "class"
    ]
    reachability = {
        serialized_api_identity(row): "not_found_in_static_analysis"
        for row in targets
    }
    if not targets:
        return {"complete": True, "api_reachability": reachability, "references": [], "errors": []}
    targets_by_member: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in targets:
        api_name = str(row.get("api_name") or "").strip()
        symbol_kind = str(row.get("symbol_kind") or "").strip().lower()
        if symbol_kind == "constructor":
            owner = _constructor_owner_from_api_name(api_name)
            member = "<init>"
        else:
            owner, separator, member = api_name.rpartition(".")
            if not separator:
                continue
        targets_by_member[(owner, member)].append(row)

    excluded = set(excluded_nested_jars or set())
    references: list[dict] = []
    errors: list[str] = []
    deadline = (
        time.perf_counter() + max(0.0, float(time_budget_seconds))
        if time_budget_seconds is not None else None
    )
    timed_out = False
    snapshot = Path(artifact).read_bytes()
    artifact_sha256 = hashlib.sha256(snapshot).hexdigest()

    def inspect(content: bytes, artifact_entry: str, business_owned: bool) -> None:
        try:
            member_references = _classfile_member_references(content)
        except ValueError as error:
            errors.append(f"{artifact_entry}:{error}")
            return
        for reference in member_references:
            candidates = targets_by_member.get((
                reference["callee_owner"], reference["callee_member"]
            )) or []
            for row in candidates:
                if not _api_target_matches(row, reference):
                    continue
                if _is_external_provider_for_api(
                    artifact_entry, row, provider_nested_jars_by_coord,
                    provider_nested_jars_by_api_identity,
                ):
                    continue
                identity = serialized_api_identity(row)
                if business_owned:
                    reachability[identity] = "reachable"
                elif reachability[identity] != "reachable":
                    reachability[identity] = "uncertain"
                references.append({
                    "api_identity": identity,
                    **reference,
                    "artifact_sha256": artifact_sha256,
                    "artifact_entry": artifact_entry,
                    "business_owned": business_owned,
                    "authority": "raw-classfile-constant-pool",
                    "authority_version": "1",
                })

    with zipfile.ZipFile(io.BytesIO(snapshot)) as archive:
        names = archive.namelist()
        application_prefix = next((
            prefix for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/")
            if any(name.startswith(prefix) and name.endswith(".class") for name in names)
        ), "")
        for name in sorted(names):
            if deadline is not None and time.perf_counter() >= deadline:
                timed_out = True
                break
            if name.endswith(".class") and not name.startswith("META-INF/"):
                is_business = not application_prefix or name.startswith(application_prefix)
                if is_business:
                    inspect(archive.read(name), name, True)
                continue
            if (
                not name.endswith(".jar")
                or not name.startswith(("BOOT-INF/lib/", "WEB-INF/lib/"))
                or name in excluded
            ):
                continue
            try:
                with zipfile.ZipFile(io.BytesIO(archive.read(name))) as nested:
                    for nested_name in sorted(nested.namelist()):
                        if deadline is not None and time.perf_counter() >= deadline:
                            timed_out = True
                            break
                        if nested_name.endswith(".class") and not nested_name.startswith("META-INF/"):
                            artifact_entry = f"{name}!/{nested_name}"
                            inspect(
                                nested.read(nested_name),
                                artifact_entry,
                                _business_artifact_entry(
                                    artifact_entry,
                                    application_owned_nested_jars,
                                ),
                            )
            except (KeyError, OSError, ValueError, zipfile.BadZipFile) as error:
                errors.append(f"{name}:{type(error).__name__}:{error}")
    if timed_out:
        errors.append("oracle_time_budget_exceeded")
    return {
        "artifact_sha256": artifact_sha256,
        "complete": not errors,
        "api_reachability": reachability,
        "references": references,
        "errors": sorted(errors),
        "timed_out": timed_out,
    }


def scan_final_artifact_dynamic_class_references(
    artifact: Path, selected_rows: list[dict],
    *, time_budget_seconds: float | None = None,
) -> list[dict]:
    """Independently identify exact class-name constants coupled to a loader API.

    This is intentionally weaker than an executable edge oracle. It can prove a
    packaged dynamic class reference exists, but its semantic ceiling is
    ``uncertain`` because activation and successful loading remain runtime facts.
    """
    class_targets = [
        row for row in selected_rows
        if str((row or {}).get("symbol_kind") or "").strip().lower() == "class"
        and str((row or {}).get("api_name") or "").strip()
    ]
    if not class_targets:
        return []
    snapshot = Path(artifact).read_bytes()
    artifact_sha256 = hashlib.sha256(snapshot).hexdigest()
    deadline = (
        time.perf_counter() + max(0.0, float(time_budget_seconds))
        if time_budget_seconds is not None else None
    )
    references = []
    with zipfile.ZipFile(io.BytesIO(snapshot)) as archive:
        names = archive.namelist()
        business_prefix = next(
            (
                prefix for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/")
                if any(name.startswith(prefix) and name.endswith(".class") for name in names)
            ),
            "",
        )
        for name in sorted(names):
            if deadline is not None and time.perf_counter() >= deadline:
                raise TimeoutError("oracle_time_budget_exceeded")
            if not name.endswith(".class") or name.startswith("META-INF/"):
                continue
            if business_prefix and not name.startswith(business_prefix):
                continue
            content = archive.read(name)
            try:
                constants = _classfile_utf8_constants(content)
            except ValueError:
                continue
            has_loader = (
                (b"java/lang/Class" in constants and b"forName" in constants)
                or (
                    b"forName" in constants
                    and any(value == b"ClassUtils" or value.endswith(b"/ClassUtils") for value in constants)
                )
                or (b"java/lang/ClassLoader" in constants and b"loadClass" in constants)
            )
            if not has_loader:
                continue
            for row in class_targets:
                api_name = str(row.get("api_name") or "").strip()
                if api_name.encode("utf-8") not in constants:
                    continue
                references.append({
                    "api_identity": serialized_api_identity(row),
                    "target_class": api_name,
                    "artifact_sha256": artifact_sha256,
                    "artifact_entry": name,
                    "authority": "final-artifact-classfile-constants",
                    "authority_version": "1",
                    "procedure": (
                        "SHA-verified business class contains the exact FQCN UTF8 constant "
                        "and a Class.forName, ClassUtils.forName, or ClassLoader.loadClass marker"
                    ),
                })
    return references


def _constant_pool_references_class(constants: set[bytes], internal_name: bytes) -> bool:
    return any(
        value == internal_name
        or value == b"L" + internal_name + b";"
        or (value.startswith(b"[") and value.endswith(b"L" + internal_name + b";"))
        for value in constants
    )


def _class_reference_target_index(targets: dict[str, str]) -> dict[bytes, set[str]]:
    index: dict[bytes, set[str]] = defaultdict(set)
    for identity, owner in targets.items():
        parts = [part for part in owner.split(".") if part]
        class_boundaries = [
            offset for offset, part in enumerate(parts)
            if part[:1].isupper()
        ] or ([len(parts) - 1] if parts else [])
        internal_names = {owner.replace(".", "/")}
        for boundary in class_boundaries:
            package = "/".join(parts[:boundary])
            binary_name = "$".join(parts[boundary:])
            internal_names.add(f"{package}/{binary_name}" if package else binary_name)
        for value in internal_names:
            internal_name = value.encode("utf-8")
            index[internal_name].add(identity)
            index[b"L" + internal_name + b";"].add(identity)
    return index


def _class_internal_name_candidates(owner: str) -> set[str]:
    parts = [part for part in str(owner or "").split(".") if part]
    class_boundaries = [
        offset for offset, part in enumerate(parts) if part[:1].isupper()
    ] or ([len(parts) - 1] if parts else [])
    names = {str(owner or "").replace(".", "/")}
    for boundary in class_boundaries:
        package = "/".join(parts[:boundary])
        binary_name = "$".join(parts[boundary:])
        names.add(f"{package}/{binary_name}" if package else binary_name)
    return {name for name in names if name}


def _javap_verbose_matched_class_targets(
    output: str, targets: dict[str, str]
) -> set[str]:
    matched = set()
    lines = str(output or "").splitlines()
    for identity, owner in targets.items():
        for internal_name in _class_internal_name_candidates(owner):
            escaped = re.escape(internal_name)
            if any(
                re.search(rf"=\s+Class\b.*//\s*{escaped}\s*$", line)
                or re.search(rf"=\s+Utf8\s+(?:\[*)L{escaped};\s*$", line)
                for line in lines
            ):
                matched.add(identity)
                break
    return matched


def _javap_verbose_sections_by_class_path(text: str) -> dict[str, str]:
    """Split one batched javap response without losing physical class identity."""
    matches = list(re.finditer(r"(?m)^Classfile (.+?)\s*$", str(text or "")))
    sections = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        class_path = str(Path(match.group(1).strip()).resolve())
        sections[class_path] = str(text)[match.start():end]
    return sections


def scan_final_artifact_javap_class_references(
    artifact: Path,
    selected_rows: list[dict],
    *,
    application_owned_nested_jars: set[str] | None = None,
    provider_nested_jars_by_coord: dict[str, set[str]] | None = None,
    provider_nested_jars_by_api_identity: dict[str, set[str]] | None = None,
    javap: str = "javap",
    max_workers: int = 4,
    batch_size: int = 32,
    time_budget_seconds: float | None = None,
) -> dict:
    """Use JDK javap verbose metadata as a second complete class authority."""
    target_rows = {
        serialized_api_identity(row): row
        for row in selected_rows
        if str(row.get("symbol_kind") or "").strip().lower() == "class"
        and str(row.get("api_name") or "").strip()
    }
    targets = {
        identity: str(row.get("api_name") or "").strip()
        for identity, row in target_rows.items()
    }
    reachability = {
        identity: "not_found_in_static_analysis" for identity in targets
    }
    if not targets:
        return {
            "complete": True, "api_reachability": reachability,
            "references": [], "errors": [], "metrics": {"javap_invocations": 0},
        }
    started = time.perf_counter()
    deadline = (
        started + max(0.0, float(time_budget_seconds))
        if time_budget_seconds is not None else None
    )
    snapshot = Path(artifact).read_bytes()
    artifact_sha256 = hashlib.sha256(snapshot).hexdigest()
    application_owned = set(application_owned_nested_jars or set())
    needles = {
        identity: {
            value.encode("utf-8")
            for value in _class_internal_name_candidates(owner)
        }
        for identity, owner in targets.items()
    }
    candidates = []
    errors = []
    timed_out = False

    def collect(content: bytes, artifact_entry: str, business_owned: bool) -> None:
        matched = set()
        class_owner = _artifact_entry_class_owner(artifact_entry).replace("$", ".")
        for identity, values in needles.items():
            if class_owner == targets[identity].replace("$", "."):
                continue
            if _is_external_provider_for_api(
                artifact_entry, target_rows[identity],
                provider_nested_jars_by_coord,
                provider_nested_jars_by_api_identity,
            ):
                continue
            if any(value in content for value in values):
                matched.add(identity)
        if matched:
            candidates.append((content, artifact_entry, business_owned, matched))

    with zipfile.ZipFile(io.BytesIO(snapshot)) as archive:
        names = archive.namelist()
        application_prefix = next((
            prefix for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/")
            if any(name.startswith(prefix) and name.endswith(".class") for name in names)
        ), "")
        for name in sorted(names):
            if deadline is not None and time.perf_counter() >= deadline:
                timed_out = True
                break
            if name.endswith(".class") and not name.startswith("META-INF/"):
                is_business = not application_prefix or name.startswith(application_prefix)
                if is_business:
                    collect(archive.read(name), name, True)
                continue
            if not name.endswith(".jar") or not name.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")):
                continue
            try:
                with zipfile.ZipFile(io.BytesIO(archive.read(name))) as nested:
                    for nested_name in sorted(nested.namelist()):
                        if deadline is not None and time.perf_counter() >= deadline:
                            timed_out = True
                            break
                        if not nested_name.endswith(".class") or nested_name.startswith("META-INF/"):
                            continue
                        artifact_entry = f"{name}!/{nested_name}"
                        collect(
                            nested.read(nested_name),
                            artifact_entry,
                            _business_artifact_entry(
                                artifact_entry,
                                application_owned_nested_jars,
                            ),
                        )
            except (KeyError, OSError, ValueError, zipfile.BadZipFile) as error:
                errors.append(f"{name}:{type(error).__name__}:{error}")

    references = []
    with tempfile.TemporaryDirectory(prefix="jua-javap-class-oracle-") as tmp:
        root = Path(tmp)
        jobs = []
        for index, (content, entry, business_owned, identities) in enumerate(candidates):
            class_path = root / f"class-{index:06d}.class"
            class_path.write_bytes(content)
            jobs.append((class_path, entry, business_owned, identities))

        batches = [
            jobs[offset:offset + max(1, int(batch_size))]
            for offset in range(0, len(jobs), max(1, int(batch_size)))
        ]

        def run_batch(batch):
            timeout = 30.0
            if deadline is not None:
                timeout = max(0.001, min(timeout, deadline - time.perf_counter()))
            try:
                proc = subprocess.run(
                    [javap, "-verbose", *[str(job[0]) for job in batch]],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    check=False, timeout=timeout,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                message = f"{type(error).__name__}:{error}"
                return [], [(job[1], message) for job in batch]
            sections = _javap_verbose_sections_by_class_path(proc.stdout)
            results = []
            batch_errors = []
            for class_path, entry, business_owned, identities in batch:
                section = sections.get(str(class_path.resolve()))
                if section is None:
                    batch_errors.append((entry, "javap_class_section_missing"))
                    continue
                subset = {identity: targets[identity] for identity in identities}
                results.append((
                    entry,
                    business_owned,
                    _javap_verbose_matched_class_targets(section, subset),
                ))
            if proc.returncode != 0:
                batch_errors.append((
                    ",".join(job[1] for job in batch),
                    f"returncode={proc.returncode}",
                ))
            return results, batch_errors

        with ThreadPoolExecutor(max_workers=max(1, int(max_workers))) as executor:
            futures = [executor.submit(run_batch, batch) for batch in batches]
            for future in as_completed(futures):
                results, batch_errors = future.result()
                errors.extend(f"{entry}:{error}" for entry, error in batch_errors)
                for entry, business_owned, identities in results:
                    for identity in identities:
                        references.append({
                            "api_identity": identity,
                            "target_class": targets[identity],
                            "artifact_entry": entry,
                            "artifact_sha256": artifact_sha256,
                            "business_owned": business_owned,
                            "authority": "jdk-javap-verbose",
                            "authority_version": "1",
                        })
                        if business_owned:
                            reachability[identity] = "reachable"
                        elif reachability[identity] != "reachable":
                            reachability[identity] = "uncertain"
    if timed_out:
        errors.append("oracle_time_budget_exceeded")
    return {
        "artifact_sha256": artifact_sha256,
        "complete": not errors,
        "api_reachability": reachability,
        "references": references,
        "errors": sorted(errors),
        "metrics": {
            "candidate_class_count": len(candidates),
            "javap_invocations": len(batches),
            "javap_batch_size": max(1, int(batch_size)),
            "elapsed_seconds": time.perf_counter() - started,
            "timed_out": timed_out,
        },
    }


def _matched_class_reference_targets(
    constants: set[bytes], target_index: dict[bytes, set[str]]
) -> set[str]:
    matches = set()
    for value in constants:
        matches.update(target_index.get(value) or set())
        if value.startswith(b"["):
            matches.update(target_index.get(value.lstrip(b"[")) or set())
    return matches


def scan_final_artifact_class_references(
    artifact: Path,
    selected_rows: list[dict],
    *,
    excluded_nested_jars: set[str] | None = None,
    application_owned_nested_jars: set[str] | None = None,
    provider_nested_jars_by_coord: dict[str, set[str]] | None = None,
    provider_nested_jars_by_api_identity: dict[str, set[str]] | None = None,
    time_budget_seconds: float | None = None,
) -> dict:
    """Account for every class-level API using exact packaged class constants."""
    targets = {
        serialized_api_identity(row): str(row.get("api_name") or "").strip()
        for row in selected_rows
        if str(row.get("symbol_kind") or "").strip().lower() == "class"
        and str(row.get("api_name") or "").strip()
    }
    target_rows = {
        serialized_api_identity(row): row
        for row in selected_rows
        if serialized_api_identity(row) in targets
    }
    if not targets:
        return {"complete": True, "api_reachability": {}, "references": [], "errors": []}
    excluded = set(excluded_nested_jars or set())
    application_owned = set(application_owned_nested_jars or set())
    target_index = _class_reference_target_index(targets)
    references: list[dict] = []
    class_records: list[dict] = []
    errors: list[str] = []
    deadline = (
        time.perf_counter() + max(0.0, float(time_budget_seconds))
        if time_budget_seconds is not None else None
    )
    timed_out = False
    snapshot = Path(artifact).read_bytes()
    artifact_sha256 = hashlib.sha256(snapshot).hexdigest()

    def inspect(
        content: bytes, artifact_entry: str, location: str,
    ) -> None:
        try:
            constants = _classfile_utf8_constants(content)
        except ValueError as error:
            errors.append(f"{artifact_entry}:{error}")
            return
        class_records.append({
            "owner": _artifact_entry_class_owner(artifact_entry),
            "artifact_entry": artifact_entry,
            "location": location,
            "constants": constants,
        })

    def target_references(record: dict, reachable_paths: dict[str, list[str]]) -> None:
        owner_path = (
            reachable_paths.get(record["owner"])
            if record["location"] != "external" else None
        )
        for identity in sorted(_matched_class_reference_targets(
            record["constants"], target_index
        )):
            owner = targets[identity]
            if record["owner"] == owner:
                continue
            if _is_external_provider_for_api(
                record["artifact_entry"],
                target_rows[identity],
                provider_nested_jars_by_coord,
                provider_nested_jars_by_api_identity,
            ):
                continue
            references.append({
                "api_identity": identity,
                "target_class": owner,
                "artifact_sha256": artifact_sha256,
                "artifact_entry": record["artifact_entry"],
                "business_owned": owner_path is not None,
                "business_path": list(owner_path or []),
                "authority": "final-artifact-classfile-constants",
                "authority_version": "1",
                "procedure": "exact CONSTANT_Class or JVM type descriptor in SHA-verified final artifact",
            })

    with zipfile.ZipFile(io.BytesIO(snapshot)) as archive:
        names = archive.namelist()
        application_prefix = next(
            (
                prefix for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/")
                if any(name.startswith(prefix) and name.endswith(".class") for name in names)
            ),
            "",
        )
        for name in sorted(names):
            if deadline is not None and time.perf_counter() >= deadline:
                timed_out = True
                break
            if name.endswith(".class") and not name.startswith("META-INF/"):
                is_business = not application_prefix or name.startswith(application_prefix)
                if is_business:
                    inspect(archive.read(name), name, "business_root")
                continue
            if not name.endswith(".jar") or not name.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")):
                continue
            if name in excluded:
                continue
            try:
                with zipfile.ZipFile(io.BytesIO(archive.read(name))) as nested:
                    for nested_name in sorted(nested.namelist()):
                        if deadline is not None and time.perf_counter() >= deadline:
                            timed_out = True
                            break
                        if not nested_name.endswith(".class") or nested_name.startswith("META-INF/"):
                            continue
                        inspect(
                            nested.read(nested_name),
                            f"{name}!/{nested_name}",
                            "internal_module" if name in application_owned else "external",
                        )
            except (KeyError, OSError, ValueError, zipfile.BadZipFile) as error:
                errors.append(f"{name}:{type(error).__name__}:{error}")

    if timed_out:
        errors.append("oracle_time_budget_exceeded")

    duplicate_owners = _duplicate_artifact_class_owners(
        record["artifact_entry"] for record in class_records
    )
    traversable_records = [
        record for record in class_records
        if record["location"] in {"business_root", "internal_module"}
        and record["owner"] not in duplicate_owners
    ]
    traversable_owners = {record["owner"] for record in traversable_records}
    owner_index = _class_reference_target_index({
        owner: owner for owner in traversable_owners
    })
    adjacency: dict[str, set[str]] = defaultdict(set)
    for record in traversable_records:
        adjacency[record["owner"]].update(
            matched_owner for matched_owner in _matched_class_reference_targets(
                record["constants"], owner_index
            )
            if matched_owner != record["owner"]
        )
    reachable_paths = {
        record["owner"]: [record["owner"]]
        for record in traversable_records
    }
    frontier = deque(reachable_paths)
    while frontier:
        caller = frontier.popleft()
        for callee in sorted(adjacency.get(caller) or set()):
            if callee in reachable_paths:
                continue
            reachable_paths[callee] = reachable_paths[caller] + [callee]
            frontier.append(callee)
    for record in class_records:
        target_references(record, reachable_paths)

    by_identity: dict[str, list[dict]] = defaultdict(list)
    for reference in references:
        by_identity[str(reference["api_identity"])].append(reference)
    reachability = {}
    for identity in targets:
        matched = by_identity.get(identity) or []
        if any(item.get("business_owned") for item in matched):
            reachability[identity] = "reachable"
        elif matched:
            reachability[identity] = "uncertain"
        else:
            reachability[identity] = "not_found_in_static_analysis"
    return {
        "artifact_sha256": artifact_sha256,
        "complete": not errors,
        "api_reachability": reachability,
        "references": references,
        "errors": sorted(errors),
        "timed_out": timed_out,
    }


MYBATIS_SEMANTIC_APIS = {
    "org.apache.ibatis.binding.MapperProxy.invoke": {
        "signature": "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])",
        "class_entry": "org/apache/ibatis/binding/MapperProxy.class",
    },
    "org.apache.ibatis.binding.MapperMethod.execute": {
        "signature": "(org.apache.ibatis.session.SqlSession,java.lang.Object[])",
        "class_entry": "org/apache/ibatis/binding/MapperMethod.class",
    },
    "org.apache.ibatis.session.SqlSession.selectOne": {
        "signature": "(java.lang.String,java.lang.Object)",
        "class_entry": "org/apache/ibatis/session/SqlSession.class",
    },
}


def build_mybatis_semantic_references(
    selected_rows: list[dict],
    mapper_oracle: dict,
    runtime_activation: dict,
    artifact_sha256: str,
) -> list[dict]:
    """Bind reviewed runtime activation to independently proven mapper dispatch."""
    links = list(mapper_oracle.get("proxy_dispatch_links") or [])
    if (
        not mapper_oracle.get("complete")
        or not runtime_activation.get("active")
        or not _valid_sha256(artifact_sha256)
        or not _valid_sha256(str(runtime_activation.get("output_sha256") or ""))
        or not links
    ):
        return []
    dispatch_count = min(
        len(link.get("physical_dispatch_edges") or []) for link in links
    )
    if dispatch_count < 2:
        return []
    runtime_prefixes = {
        str(edge.get("artifact_entry") or "").split("!/", 1)[0] + "!/"
        for edge in (mapper_oracle.get("physical_edges") or [])
        if str(edge.get("artifact_entry") or "").startswith((
            "BOOT-INF/lib/", "WEB-INF/lib/",
        ))
        and "!/org/apache/ibatis/" in str(edge.get("artifact_entry") or "")
    }
    if len(runtime_prefixes) != 1:
        return []
    runtime_prefix = next(iter(runtime_prefixes))
    references = []
    framework_api_evidence = dict(mapper_oracle.get("framework_api_evidence") or {})
    for row in selected_rows:
        api_name = str(row.get("api_name") or "").strip()
        expected = MYBATIS_SEMANTIC_APIS.get(api_name)
        if (
            expected is None
            or str(row.get("coord") or "").strip() != "org.mybatis:mybatis"
            or normalize_signature_for_lookup(str(row.get("api_signature") or ""))
            != normalize_signature_for_lookup(expected["signature"])
        ):
            continue
        physical_evidence = list(framework_api_evidence.get(api_name) or [])
        if not physical_evidence:
            continue
        references.append({
            "api_identity": serialized_api_identity(row),
            "target_class": api_name,
            "artifact_sha256": artifact_sha256,
            "artifact_entry": runtime_prefix + expected["class_entry"],
            "authority": "final-artifact-mybatis-proxy-runtime",
            "authority_version": "1",
            "runtime_output_sha256": runtime_activation["output_sha256"],
            "proxy_dispatch_edge_count": dispatch_count,
            "physical_evidence_count": len(physical_evidence),
            "mapper_contract_count": len(mapper_oracle.get("mapper_contracts") or []),
            "procedure": (
                "SHA-bound mapper registration and statement binding; packaged javap "
                "proxy dispatch; successful pinned runtime query"
            ),
        })
    return references


def reconcile_selected_api_edges(
    report_dir: Path,
    selected_rows: list[dict],
    analyzer_rows: list[dict],
    oracle_scan: dict,
) -> dict:
    """Reconcile all selected API runtime edges, never a sampled subset."""
    reconcile_started_at = time.perf_counter()
    report_dir = Path(report_dir)
    oracle_rows = [dict(row) for row in (oracle_scan.get("edges") or [])]
    semantic_references = list(oracle_scan.get("semantic_references") or [])
    semantic_targets = _verified_framework_semantic_targets(report_dir, selected_rows)
    semantic_targets.update(
        str(item.get("api_identity") or "") for item in semantic_references
        if str(item.get("api_identity") or "")
    )
    application_owned_nested_jars = {
        str(item or "").strip()
        for item in (oracle_scan.get("application_owned_nested_jars") or [])
        if str(item or "").strip()
    }
    artifact_entries = {
        str(entry).strip() for entry in (oracle_scan.get("artifact_entries") or [])
        if str(entry).strip()
    }
    if not artifact_entries:
        artifact_entries = {
            str(row.get("artifact_entry") or "").strip() for row in oracle_rows
            if str(row.get("artifact_entry") or "").strip()
        }
    ambiguous_class_owners = _duplicate_artifact_class_owners(artifact_entries)
    retained_oracle_rows, api_reachability, path_errors = _retain_authoritative_api_path(
        selected_rows,
        oracle_rows,
        semantic_targets,
        absence_is_authoritative=bool(oracle_scan.get("complete")),
        class_reachability=dict(oracle_scan.get("class_reachability") or {}),
        application_owned_nested_jars=application_owned_nested_jars,
        provider_nested_jars_by_coord={
            str(coord): {str(entry) for entry in entries}
            for coord, entries in dict(
                oracle_scan.get("provider_nested_jars_by_coord") or {}
            ).items()
        },
        provider_nested_jars_by_api_identity={
            str(identity): {str(entry) for entry in entries}
            for identity, entries in dict(
                oracle_scan.get("provider_nested_jars_by_api_identity") or {}
            ).items()
        },
        ambiguous_class_owners=ambiguous_class_owners,
    )
    path_errors.extend(_oracle_edge_identity_errors(oracle_rows))
    retained_analyzer_rows = _retain_analyzer_api_path(
        selected_rows,
        [dict(row) for row in (analyzer_rows or [])],
        application_owned_nested_jars=application_owned_nested_jars,
        provider_nested_jars_by_coord={
            str(coord): {str(entry) for entry in entries}
            for coord, entries in dict(
                oracle_scan.get("provider_nested_jars_by_coord") or {}
            ).items()
        },
        provider_nested_jars_by_api_identity={
            str(identity): {str(entry) for entry in entries}
            for identity, entries in dict(
                oracle_scan.get("provider_nested_jars_by_api_identity") or {}
            ).items()
        },
        ambiguous_class_owners=ambiguous_class_owners,
    )
    complete = bool(oracle_scan.get("complete")) and not path_errors
    reconciliation = {
        "ledger": [],
        "verdict_counts": {verdict: 0 for verdict in EDGE_RECONCILIATION_VERDICTS},
        "blocking": False,
    }
    if artifact_entries and str(oracle_scan.get("artifact_sha256") or ""):
        reconciliation = _reconcile_physical_edge_occurrences(
            retained_analyzer_rows,
            retained_oracle_rows,
            str(oracle_scan.get("artifact_sha256") or ""),
            artifact_entries,
        )
    elif not artifact_entries:
        path_errors.append("oracle_artifact_entries_unavailable")
        complete = False
    oracle_path = _write_csv(
        report_dir / "evidence" / "call_chain" / "oracle_edges.csv",
        ("api_identity",) + ORACLE_EDGE_FIELDS,
        retained_oracle_rows,
    )
    reconciliation_path = _write_csv(
        report_dir / "evidence" / "call_chain" / "edge_reconciliation.csv",
        EDGE_RECONCILIATION_FIELDS,
        reconciliation["ledger"],
    )
    semantic_path = report_dir / "evidence" / "call_chain" / "oracle_semantic_references.json"
    semantic_path.write_text(
        json.dumps(semantic_references, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    class_reference_path = (
        report_dir / "evidence" / "call_chain" / "oracle_class_references.json"
    )
    class_reference_path.write_text(
        json.dumps(
            oracle_scan.get("class_references") or [],
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    member_reference_path = (
        report_dir / "evidence" / "call_chain" / "oracle_member_references.json"
    )
    member_reference_path.write_text(
        json.dumps(
            oracle_scan.get("member_references") or [],
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    jdeps_reference_path = (
        report_dir / "evidence" / "call_chain" / "oracle_jdeps_class_references.json"
    )
    jdeps_reference_path.write_text(
        json.dumps(
            oracle_scan.get("jdeps_class_references") or [],
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    javap_class_reference_path = (
        report_dir / "evidence" / "call_chain" / "oracle_javap_class_references.json"
    )
    javap_class_reference_path.write_text(
        json.dumps(
            oracle_scan.get("javap_class_references") or [],
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    counts = {
        "oracle_edge_count": len(retained_oracle_rows),
        "analyzer_edge_count": len(retained_analyzer_rows),
        "edge_reconciliation_row_count": len(reconciliation["ledger"]),
        "semantic_reference_count": len(semantic_references),
        "reconcile_seconds": time.perf_counter() - reconcile_started_at,
        **{f"edge_truth_{verdict}_count": int(count) for verdict, count in reconciliation["verdict_counts"].items()},
    }
    oracle_metrics = {
        key: oracle_scan.get(key)
        for key in (
            "class_count", "completed_class_count", "parsed_class_count",
            "cached_class_count", "parse_failure_count", "parse_seconds",
            "elapsed_seconds", "worker_count", "cache_hits", "cache_misses",
            "timed_out", "interrupted",
        )
    }
    jdeps_metrics = dict(oracle_scan.get("jdeps_metrics") or {})
    javap_class_metrics = dict(oracle_scan.get("javap_class_metrics") or {})
    oracle_metrics.update({
        "jdeps_invocations": int(jdeps_metrics.get("jdeps_invocations") or 0),
        "jdeps_class_count": int(jdeps_metrics.get("class_count") or 0),
        "jdeps_elapsed_seconds": float(jdeps_metrics.get("elapsed_seconds") or 0.0),
        "javap_class_invocations": int(
            javap_class_metrics.get("javap_invocations") or 0
        ),
        "javap_class_elapsed_seconds": float(
            javap_class_metrics.get("elapsed_seconds") or 0.0
        ),
    })
    return {
        "complete": complete,
        "errors": sorted(path_errors + [str(item) for item in (oracle_scan.get("failures") or [])]),
        "blocking": not complete or bool(reconciliation.get("blocking")),
        "reconciliation": reconciliation,
        "counts": counts,
        "oracle_edges": oracle_path,
        "edge_reconciliation": reconciliation_path,
        "semantic_references": semantic_references,
        "semantic_reference_evidence": str(semantic_path),
        "class_reference_evidence": str(class_reference_path),
        "member_reference_evidence": str(member_reference_path),
        "member_reference_reachability": dict(
            oracle_scan.get("member_reference_reachability") or {}
        ),
        "jdeps_class_reference_evidence": str(jdeps_reference_path),
        "jdeps_class_reachability": dict(
            oracle_scan.get("jdeps_class_reachability") or {}
        ),
        "javap_class_reference_evidence": str(javap_class_reference_path),
        "javap_class_reachability": dict(
            oracle_scan.get("javap_class_reachability") or {}
        ),
        "trusted_artifact_sha": str(oracle_scan.get("artifact_sha256") or ""),
        "oracle_metrics": oracle_metrics,
        "oracle_physical_occurrences": [
            physical_edge_occurrence(row) for row in retained_oracle_rows
        ],
        "oracle_scan": oracle_scan,
        "api_reachability": api_reachability,
    }


def _artifact_class_entries(
    artifact: Path, *, time_budget_seconds: float | None = None,
) -> set[str]:
    entries: set[str] = set()
    deadline = (
        time.perf_counter() + max(0.0, float(time_budget_seconds))
        if time_budget_seconds is not None else None
    )
    with zipfile.ZipFile(artifact) as archive:
        for info in archive.infolist():
            if deadline is not None and time.perf_counter() >= deadline:
                raise TimeoutError("oracle_time_budget_exceeded")
            if not info.is_dir() and info.filename.endswith(".class"):
                entries.add(info.filename)
            elif not info.is_dir() and info.filename.endswith(".jar") and info.filename.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")):
                with zipfile.ZipFile(io.BytesIO(archive.read(info))) as nested:
                    for nested_info in nested.infolist():
                        if deadline is not None and time.perf_counter() >= deadline:
                            raise TimeoutError("oracle_time_budget_exceeded")
                        if not nested_info.is_dir() and nested_info.filename.endswith(".class"):
                            entries.add(f"{info.filename}!/{nested_info.filename}")
    return entries


def validate_oracle_scan(oracle_scan: dict, expected_artifact_sha256: str) -> tuple[dict, str]:
    """Apply the production Oracle trust boundary before reconciliation."""
    validated = dict(oracle_scan or {})
    failures = list(validated.get("failures") or [])
    signal = ""
    declared_payload_sha = str(validated.get("oracle_payload_sha256") or "")
    if not declared_payload_sha or declared_payload_sha != oracle_payload_sha256(validated):
        failures.append("oracle_payload_sha_mismatch")
        signal = "oracle_invalid"
    elif str(validated.get("artifact_sha256") or "") != str(expected_artifact_sha256 or ""):
        failures.append("oracle_artifact_sha_mismatch")
        signal = "oracle_invalid"
    elif validated.get("complete") is not True:
        failures.append("oracle_scan_incomplete")
        signal = "oracle_incomplete"
    validated["failures"] = sorted(set(str(item) for item in failures if str(item)))
    validated["complete"] = validated.get("complete") is True and not signal
    return validated, signal


def _verified_current_final_artifact(report_dir: Path) -> tuple[Path | None, str, list[str]]:
    provenance_path = Path(report_dir) / "evidence" / "dependencies" / "build_provenance.json"
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        current = next(item for item in provenance.get("sides") or [] if item.get("side") == "current")
        artifact = Path(str(current.get("artifact_path") or ""))
        expected_sha = str(current.get("artifact_sha256") or "")
        safety = inspect_archive(artifact)
        if not safety.safe:
            raise ValueError(
                "current final artifact safety violation:" + ",".join(safety.reason_codes)
            )
        actual_sha = _file_sha256(artifact)
        if len(expected_sha) != 64 or actual_sha != expected_sha:
            raise ValueError("current final artifact SHA-256 is missing or mismatched")
        return artifact, expected_sha, []
    except (OSError, StopIteration, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        return None, "", [f"verified_current_final_artifact_unavailable:{error}"]


def _oracle_selected_targets(selected_rows: list[dict]) -> list[dict]:
    targets = set()
    for row in selected_rows or []:
        api_name = str((row or {}).get("api_name") or "").strip()
        symbol_kind = str((row or {}).get("symbol_kind") or "method").strip().lower()
        if symbol_kind == "class":
            continue
        if symbol_kind == "constructor" and not api_name.endswith(".<init>"):
            owner, member = _constructor_owner_from_api_name(api_name), "<init>"
        else:
            owner, separator, member = api_name.rpartition(".")
            if not separator:
                continue
            if symbol_kind == "constructor":
                member = "<init>"
        if owner and member:
            targets.add((owner, member, ""))
    return [
        {"owner": owner, "member": member, "descriptor": descriptor}
        for owner, member, descriptor in sorted(targets)
    ]


def _materialize_verified_oracle_snapshot(
    report_dir: Path, artifact: Path, expected_sha256: str
) -> tuple[Path | None, list[str]]:
    try:
        snapshot = Path(artifact).read_bytes()
    except OSError as error:
        return None, [f"final_artifact_snapshot:{type(error).__name__}:{error}"]
    actual_sha256 = hashlib.sha256(snapshot).hexdigest()
    if expected_sha256 and actual_sha256 != expected_sha256:
        return None, ["final_artifact_sha256_mismatch"]
    snapshot_dir = Path(report_dir) / ".runtime" / "oracle" / "input"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = snapshot_dir / f"{actual_sha256}.jar"
    if snapshot_path.exists():
        try:
            if hashlib.sha256(snapshot_path.read_bytes()).hexdigest() == actual_sha256:
                return snapshot_path, []
        except OSError as error:
            return None, [
                f"final_artifact_snapshot_read:{type(error).__name__}:{error}"
            ]
    temporary = snapshot_path.with_suffix(".tmp")
    try:
        temporary.write_bytes(snapshot)
        os.replace(temporary, snapshot_path)
        snapshot_path.chmod(0o444)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        return None, [f"final_artifact_snapshot_write:{type(error).__name__}:{error}"]
    return snapshot_path, []


def _oracle_provider_entries(
    artifact: Path, selected_rows: list[dict], expected_sha256: str = "",
    *, time_budget_seconds: float | None = None,
) -> tuple[dict[str, set[str]], dict[str, set[str]], list[str]]:
    """Rebuild target-provider identity directly from the verified final artifact."""
    identities_by_owner: dict[str, set[str]] = defaultdict(set)
    coordinate_by_identity: dict[str, str] = {}
    for row in selected_rows or []:
        owner = _selected_api_owner(row)
        if owner:
            identity = serialized_api_identity(row)
            identities_by_owner[owner].add(identity)
            coordinate_by_identity[identity] = str(row.get("coord") or "").strip()
    providers_by_coord: dict[str, set[str]] = defaultdict(set)
    providers_by_identity: dict[str, set[str]] = defaultdict(set)
    errors: list[str] = []
    deadline = (
        time.perf_counter() + max(0.0, float(time_budget_seconds))
        if time_budget_seconds is not None else None
    )

    def budget_exceeded() -> bool:
        if deadline is None or time.perf_counter() < deadline:
            return False
        if "oracle_time_budget_exceeded" not in errors:
            errors.append("oracle_time_budget_exceeded")
        return True

    try:
        snapshot = Path(artifact).read_bytes()
        if expected_sha256 and hashlib.sha256(snapshot).hexdigest() != expected_sha256:
            return {}, {}, ["final_artifact_sha256_mismatch"]
        with zipfile.ZipFile(io.BytesIO(snapshot)) as outer:
            for artifact_entry in sorted(outer.namelist()):
                if budget_exceeded():
                    break
                if (
                    not artifact_entry.startswith(("BOOT-INF/lib/", "WEB-INF/lib/"))
                    or not artifact_entry.endswith(".jar")
                ):
                    continue
                try:
                    with zipfile.ZipFile(io.BytesIO(outer.read(artifact_entry))) as nested:
                        names = nested.namelist()
                        coords = set()
                        for name in names:
                            if budget_exceeded():
                                break
                            if not (
                                name.startswith("META-INF/maven/")
                                and name.endswith("/pom.properties")
                            ):
                                continue
                            properties = {}
                            try:
                                metadata_text = nested.read(name).decode("utf-8")
                            except UnicodeDecodeError as error:
                                errors.append(
                                    f"{artifact_entry}!/{name}:UnicodeDecodeError:{error}"
                                )
                                continue
                            for line in metadata_text.splitlines():
                                line = line.strip()
                                if not line or line.startswith(("#", "!")):
                                    continue
                                key, separator, value = line.partition("=")
                                if not separator:
                                    key, separator, value = line.partition(":")
                                if separator:
                                    properties[key.strip()] = value.strip()
                            group_id = properties.get("groupId", "")
                            artifact_id = properties.get("artifactId", "")
                            if group_id and artifact_id:
                                coords.add(f"{group_id}:{artifact_id}")
                            else:
                                errors.append(
                                    f"{artifact_entry}!/{name}:"
                                    "pom_properties_coordinate_missing"
                                )
                        matched_owners = set()
                        for name in names:
                            if budget_exceeded():
                                break
                            logical_name = re.sub(r"^META-INF/versions/\d+/", "", name)
                            if not logical_name.endswith(".class"):
                                continue
                            owner = logical_name[:-6].replace("/", ".").replace("$", ".")
                            if owner in identities_by_owner:
                                matched_owners.add(owner)
                        for owner in sorted(matched_owners):
                            candidates = identities_by_owner[owner]
                            for identity in candidates:
                                providers_by_identity[identity].add(artifact_entry)
                            candidate_coords = {
                                coordinate_by_identity.get(identity, "")
                                for identity in candidates
                                if coordinate_by_identity.get(identity, "")
                            }
                            resolved = set(candidates)
                            if len(candidate_coords) > 1:
                                metadata_matches = candidate_coords & coords
                                if metadata_matches == candidate_coords:
                                    resolved = set(candidates)
                                elif len(metadata_matches) == 1:
                                    selected_coord = next(iter(metadata_matches))
                                    resolved = {
                                        identity for identity in candidates
                                        if coordinate_by_identity.get(identity) == selected_coord
                                    }
                                else:
                                    errors.append(
                                        f"{artifact_entry}:provider_identity_ambiguous:"
                                        f"{owner}:" f"{','.join(sorted(candidate_coords))}"
                                    )
                                    continue
                            for identity in resolved:
                                coord = coordinate_by_identity.get(identity, "")
                                if coord:
                                    providers_by_coord[coord].add(artifact_entry)
                except (KeyError, OSError, ValueError, zipfile.BadZipFile) as error:
                    errors.append(
                        f"{artifact_entry}:{type(error).__name__}:{error}"
                    )
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        errors.append(f"final_artifact:{type(error).__name__}:{error}")
    return dict(providers_by_coord), dict(providers_by_identity), sorted(errors)


def _oracle_application_owned_nested_jars(
    report_dir: Path, artifact: Path, expected_sha256: str,
    *, time_budget_seconds: float | None = None,
) -> tuple[set[str], list[str]]:
    """Bind reactor-owned dependency entries to the locked final artifact."""
    try:
        snapshot = Path(artifact).read_bytes()
    except OSError as error:
        return set(), [f"internal_module_artifact_unreadable:{error}"]
    if hashlib.sha256(snapshot).hexdigest() != expected_sha256:
        return set(), ["internal_module_artifact_sha_mismatch"]
    deadline = (
        time.perf_counter() + max(0.0, float(time_budget_seconds))
        if time_budget_seconds is not None else None
    )

    def budget_exceeded() -> bool:
        return deadline is not None and time.perf_counter() >= deadline

    if budget_exceeded():
        return set(), ["oracle_time_budget_exceeded"]

    state_path = Path(report_dir) / ".runtime" / "state" / "main_state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set(), []
    current_scope = {}
    for step in ("step5", "step4", "step3", "step2", "step1"):
        candidate = (((state.get(step) or {}).get("input") or {}).get(
            "project_scope"
        ) or {})
        if candidate:
            current_scope = candidate
            break
    declared_scope_hash = str(current_scope.get("scope_hash") or "").strip()
    scope_payload = dict(current_scope)
    scope_payload.pop("scope_hash", None)
    actual_scope_hash = hashlib.sha256(json.dumps(
        scope_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    if not declared_scope_hash or declared_scope_hash != actual_scope_hash:
        return set(), ["internal_module_project_scope_hash_invalid"]
    provenance_path = (
        Path(report_dir) / "evidence" / "dependencies" /
        "build_provenance.json"
    )
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        current_provenance = next(
            item for item in (provenance.get("sides") or [])
            if str(item.get("side") or "") == "current"
        )
    except (OSError, StopIteration, json.JSONDecodeError):
        return set(), ["internal_module_build_provenance_unavailable"]
    if str(current_provenance.get("artifact_sha256") or "") != expected_sha256:
        return set(), ["internal_module_build_artifact_sha_mismatch"]
    scope_revision = str(current_scope.get("source_revision") or "").strip()
    build_revision = str(
        current_provenance.get("revision")
        or current_provenance.get("ref")
        or ""
    ).strip()
    if not scope_revision or not build_revision:
        return set(), ["internal_module_project_revision_missing"]
    if scope_revision != build_revision:
        return set(), ["internal_module_project_revision_mismatch"]
    scope_binding_errors = project_scope_provenance_errors(
        current_scope, current_provenance,
    )
    if scope_binding_errors:
        return set(), [
            f"internal_module_{reason}" for reason in scope_binding_errors
        ]
    included_coords = {
        str(coord).strip()
        for coord in (current_scope.get("included_module_coords") or [])
        if str(coord).strip()
    }
    if not included_coords:
        return set(), []

    dependencies_path = (
        Path(report_dir) / "evidence" / "dependencies" /
        "deps_current_resolved.csv"
    )
    try:
        with open_csv_read(dependencies_path) as handle:
            rows = list(csv.DictReader(handle))
        with zipfile.ZipFile(io.BytesIO(snapshot)) as archive:
            artifact_entries = set(archive.namelist())
    except (OSError, csv.Error, zipfile.BadZipFile) as error:
        return set(), [f"internal_module_inventory_unreadable:{error}"]

    entries = set()
    errors = []
    for row in rows:
        if budget_exceeded():
            errors.append("oracle_time_budget_exceeded")
            break
        coord = str(row.get("coord") or "").strip()
        if coord not in included_coords:
            continue
        entry = str(row.get("lib_entry") or "").strip()
        if str(row.get("resolution_status") or "").strip() == "unresolved":
            errors.append(f"internal_module_unresolved:{coord}")
        elif not entry:
            errors.append(f"internal_module_entry_missing:{coord}")
        elif (
            not entry.startswith(("BOOT-INF/lib/", "WEB-INF/lib/"))
            or not entry.endswith(".jar")
            or entry not in artifact_entries
        ):
            errors.append(f"internal_module_entry_invalid:{coord}:{entry}")
        else:
            try:
                with zipfile.ZipFile(io.BytesIO(snapshot)) as outer_archive:
                    nested_bytes = outer_archive.read(entry)
                with zipfile.ZipFile(
                    io.BytesIO(nested_bytes)
                ) as nested_archive:
                    declared_coords = set()
                    for name in nested_archive.namelist():
                        if not (
                            name.startswith("META-INF/maven/")
                            and name.endswith("/pom.properties")
                        ):
                            continue
                        properties = {}
                        text_value = nested_archive.read(name).decode("utf-8")
                        for line in text_value.splitlines():
                            key, separator, value = line.strip().partition("=")
                            if separator:
                                properties[key.strip()] = value.strip()
                        if properties.get("groupId") and properties.get("artifactId"):
                            declared_coords.add(
                                f'{properties["groupId"]}:{properties["artifactId"]}'
                            )
            except (KeyError, OSError, UnicodeDecodeError, zipfile.BadZipFile) as error:
                errors.append(
                    f"internal_module_metadata_unreadable:{coord}:{entry}:"
                    f"{type(error).__name__}"
                )
                continue
            if len(declared_coords) != 1:
                errors.append(
                    f"internal_module_coordinate_ambiguous:{coord}:{entry}:"
                    f"{','.join(sorted(declared_coords)) or '<missing>'}"
                )
                continue
            if coord not in declared_coords:
                errors.append(
                    f"internal_module_coordinate_mismatch:{coord}:{entry}:"
                    f"{','.join(sorted(declared_coords)) or '<missing>'}"
                )
                continue
            entries.add(entry)
    return entries, sorted(set(errors))


def _selected_api_owner(api_row: dict) -> str:
    api_name = str((api_row or {}).get("api_name") or "").strip()
    symbol_kind = str((api_row or {}).get("symbol_kind") or "method").strip().lower()
    if symbol_kind == "class":
        return api_name.replace("$", ".")
    if symbol_kind == "constructor":
        return _constructor_owner_from_api_name(api_name).replace("$", ".")
    owner, separator, _member = api_name.rpartition(".")
    return owner.replace("$", ".") if separator else ""


def merge_positive_only_jdeps_evidence(scan: dict, jdeps_scan: dict) -> None:
    """Keep jdeps positives without treating its missing coverage as absence proof."""
    scan["jdeps_class_reachability"] = dict(
        jdeps_scan.get("api_reachability") or {}
    )
    scan["jdeps_class_references"] = list(jdeps_scan.get("references") or [])
    scan["jdeps_metrics"] = dict(jdeps_scan.get("metrics") or {})
    if not jdeps_scan.get("complete"):
        scan.setdefault("advisories", []).extend(
            f"jdeps_class_scan:{item}" for item in (jdeps_scan.get("errors") or [])
        )


def requires_positive_only_jdeps(scan: dict) -> bool:
    return not bool(scan.get("javap_class_authority_complete"))


def _oracle_component_provenance_errors(
    component, label: str, expected_sha256: str, artifact: Path,
    *, require_declaration: bool = False,
) -> list[str]:
    """Reject child evidence that is not tied to the locked artifact snapshot."""
    errors = []
    actual_sha256 = _file_sha256(artifact)
    if actual_sha256 != expected_sha256:
        errors.append(
            f"{label}:snapshot_sha_mismatch:{actual_sha256 or '<unreadable>'}"
        )
    declared = []
    evidence_markers = {
        "api_identity", "artifact_entry", "caller_owner", "callee_owner",
        "target_class", "identity", "physical_occurrence",
    }

    def collect(value, path: str = "") -> None:
        if isinstance(value, dict):
            digest = str(value.get("artifact_sha256") or "").strip()
            if digest:
                declared.append(digest)
            if path and evidence_markers.intersection(value) and not digest:
                errors.append(f"{label}:child_artifact_sha_missing:{path}")
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                collect(child, child_path)
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                collect(child, f"{path}[{index}]")

    collect(component)
    invalid = sorted({digest for digest in declared if digest != expected_sha256})
    if invalid:
        errors.append(f"{label}:component_sha_mismatch:{','.join(invalid)}")
    if require_declaration and expected_sha256 not in declared:
        errors.append(f"{label}:artifact_sha_missing")
    return errors


def _record_oracle_component_provenance(
    scan: dict, component, label: str, expected_sha256: str, artifact: Path,
    *, require_declaration: bool = False,
) -> None:
    errors = _oracle_component_provenance_errors(
        component, label, expected_sha256, artifact,
        require_declaration=require_declaration,
    )
    if errors:
        scan["complete"] = False
        scan.setdefault("failures", []).extend(errors)


def reconcile_final_artifact_edges(
    report_dir: Path,
    selected_rows: list[dict],
    oracle_time_budget_seconds: float | None = None,
    pinned_manifest: dict | None = None,
) -> dict:
    oracle_deadline = (
        time.perf_counter() + max(0.0, float(oracle_time_budget_seconds))
        if oracle_time_budget_seconds is not None else None
    )

    def remaining_oracle_budget() -> float | None:
        if oracle_deadline is None:
            return None
        return max(0.0, oracle_deadline - time.perf_counter())

    def oracle_budget_available(component: str) -> bool:
        if oracle_deadline is None or remaining_oracle_budget() > 0:
            return True
        failure = f"{component}:oracle_time_budget_exceeded"
        scan["complete"] = False
        failures = scan.setdefault("failures", [])
        if failure not in failures:
            failures.append(failure)
        return False

    artifact, expected_sha, errors = _verified_current_final_artifact(report_dir)
    if artifact is not None:
        artifact, snapshot_errors = _materialize_verified_oracle_snapshot(
            report_dir, artifact, expected_sha
        )
        errors.extend(snapshot_errors)
    analyzer_path = Path(report_dir) / "evidence" / "call_chain" / "analyzer_edges.csv"
    _fields, analyzer_rows = _csv_rows(analyzer_path)
    if artifact is None:
        scan = {"artifact_sha256": "", "complete": False, "edges": [], "failures": errors,
                "artifact_entries": []}
    else:
        mybatis_selected = any(
            str(row.get("coord") or "").strip() == "org.mybatis:mybatis"
            and str(row.get("api_name") or "").strip() in MYBATIS_SEMANTIC_APIS
            for row in selected_rows
        )
        mapper_oracle = None
        runtime_activation = None
        if mybatis_selected:
            mapper_oracle = inspect_mybatis_artifact(
                artifact,
                timeout_seconds=max(
                    0.001,
                    float(remaining_oracle_budget() or 0.001)
                    if oracle_deadline is not None else 120.0,
                ),
            )
            scan = dict(mapper_oracle.get("physical_scan") or {})
            runtime_spec = dict((pinned_manifest or {}).get("runtime_verification") or {})
            required_output = [
                str(item) for item in (runtime_spec.get("required_output") or [])
                if str(item)
            ]
            scan.setdefault("failures", [])
            if oracle_budget_available("mybatis_oracle"):
                runtime_activation = verify_runtime_activation(
                    artifact,
                    required_output,
                    timeout_seconds=max(
                        0.001,
                        min(30.0, float(remaining_oracle_budget() or 0.001)),
                    ),
                )
                oracle_budget_available("mybatis_runtime")
            else:
                runtime_activation = {
                    "active": False,
                    "failures": ["oracle_time_budget_exceeded"],
                    "elapsed_seconds": 0.0,
                }
            if not mapper_oracle.get("complete"):
                scan["complete"] = False
                scan["failures"].extend(
                    f"mybatis_oracle:{item}"
                    for item in (mapper_oracle.get("failures") or [])
                )
            if not runtime_activation.get("active"):
                scan["complete"] = False
                scan["failures"].extend(
                    f"mybatis_runtime:{item}"
                    for item in (runtime_activation.get("failures") or [])
                )
            scan["elapsed_seconds"] = (
                float((mapper_oracle.get("metrics") or {}).get("elapsed_seconds") or 0.0)
                + float(runtime_activation.get("elapsed_seconds") or 0.0)
            )
            scan["mybatis_oracle"] = {
                key: value for key, value in mapper_oracle.items()
                if key != "physical_scan"
            }
            scan["mybatis_runtime_activation"] = runtime_activation
        else:
            scan_kwargs = {
                "time_budget_seconds": oracle_time_budget_seconds,
                "selected_targets": _oracle_selected_targets(selected_rows),
            }
            scan = scan_final_artifact(artifact, **scan_kwargs)
        _record_oracle_component_provenance(
            scan, scan, "primary_edge_scan", expected_sha, artifact,
            require_declaration=True,
        )
        oracle_budget_available("primary_edge_scan")
        (
            provider_entries_by_coord,
            provider_entries_by_api_identity,
            provider_inventory_errors,
        ) = _oracle_provider_entries(
            artifact, selected_rows, expected_sha,
            time_budget_seconds=remaining_oracle_budget(),
        )
        oracle_budget_available("oracle_provider_inventory")
        if provider_inventory_errors:
            scan["complete"] = False
            scan.setdefault("failures", []).extend(
                f"oracle_provider_inventory:{item}"
                for item in provider_inventory_errors
            )
        (
            application_owned_provider_entries,
            internal_module_inventory_errors,
        ) = _oracle_application_owned_nested_jars(
            report_dir, artifact, expected_sha,
            time_budget_seconds=remaining_oracle_budget(),
        )
        oracle_budget_available("oracle_internal_module_inventory")
        if internal_module_inventory_errors:
            scan["complete"] = False
            scan.setdefault("failures", []).extend(
                f"oracle_internal_module_inventory:{item}"
                for item in internal_module_inventory_errors
            )
        scan["application_owned_nested_jars"] = sorted(
            application_owned_provider_entries
        )
        try:
            class_reference_scan = scan_final_artifact_class_references(
                artifact,
                selected_rows,
                application_owned_nested_jars=application_owned_provider_entries,
                provider_nested_jars_by_coord=provider_entries_by_coord,
                provider_nested_jars_by_api_identity=provider_entries_by_api_identity,
                time_budget_seconds=remaining_oracle_budget(),
            )
            _record_oracle_component_provenance(
                scan, class_reference_scan, "class_reference_scan",
                expected_sha, artifact,
                require_declaration=any(
                    str(row.get("symbol_kind") or "").strip().lower() == "class"
                    for row in selected_rows
                ),
            )
            scan["class_reachability"] = class_reference_scan["api_reachability"]
            scan["class_references"] = class_reference_scan["references"]
            if not class_reference_scan["complete"]:
                scan["complete"] = False
                scan.setdefault("failures", []).extend(
                    f"class_reference_scan:{item}"
                    for item in class_reference_scan["errors"]
                )
            oracle_budget_available("class_reference_scan")
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            scan["complete"] = False
            scan.setdefault("failures", []).append(
                f"class_reference_scan_failed:{error}"
            )
        try:
            javap_class_scan = scan_final_artifact_javap_class_references(
                artifact,
                selected_rows,
                application_owned_nested_jars=application_owned_provider_entries,
                provider_nested_jars_by_coord=provider_entries_by_coord,
                provider_nested_jars_by_api_identity=provider_entries_by_api_identity,
                time_budget_seconds=remaining_oracle_budget(),
            )
            _record_oracle_component_provenance(
                scan, javap_class_scan, "javap_class_scan",
                expected_sha, artifact,
                require_declaration=any(
                    str(row.get("symbol_kind") or "").strip().lower() == "class"
                    for row in selected_rows
                ),
            )
            scan["javap_class_reachability"] = javap_class_scan["api_reachability"]
            scan["javap_class_references"] = javap_class_scan["references"]
            scan["javap_class_metrics"] = javap_class_scan["metrics"]
            scan["javap_class_authority_complete"] = bool(
                javap_class_scan["complete"]
            )
            if not javap_class_scan["complete"]:
                scan["complete"] = False
                scan.setdefault("failures", []).extend(
                    f"javap_class_scan:{item}" for item in javap_class_scan["errors"]
                )
            oracle_budget_available("javap_class_scan")
        except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
            scan["javap_class_authority_complete"] = False
            scan["complete"] = False
            scan.setdefault("failures", []).append(
                f"javap_class_scan_failed:{error}"
            )
        try:
            member_reference_scan = scan_final_artifact_member_references(
                artifact,
                selected_rows,
                application_owned_nested_jars=application_owned_provider_entries,
                provider_nested_jars_by_coord=provider_entries_by_coord,
                provider_nested_jars_by_api_identity=provider_entries_by_api_identity,
                time_budget_seconds=remaining_oracle_budget(),
            )
            _record_oracle_component_provenance(
                scan, member_reference_scan, "member_reference_scan",
                expected_sha, artifact,
                require_declaration=any(
                    str(row.get("symbol_kind") or "").strip().lower() != "class"
                    for row in selected_rows
                ),
            )
            scan["member_reference_reachability"] = member_reference_scan["api_reachability"]
            scan["member_references"] = member_reference_scan["references"]
            if not member_reference_scan["complete"]:
                scan["complete"] = False
                scan.setdefault("failures", []).extend(
                    f"member_reference_scan:{item}"
                    for item in member_reference_scan["errors"]
                )
            oracle_budget_available("member_reference_scan")
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            scan["complete"] = False
            scan.setdefault("failures", []).append(
                f"member_reference_scan_failed:{error}"
            )
        try:
            if oracle_deadline is not None and remaining_oracle_budget() <= 0:
                scan["complete"] = False
                scan.setdefault("failures", []).append(
                    "dynamic_class_reference_scan:oracle_time_budget_exceeded"
                )
                scan["semantic_references"] = []
            else:
                scan["semantic_references"] = scan_final_artifact_dynamic_class_references(
                    artifact, selected_rows,
                    time_budget_seconds=remaining_oracle_budget(),
                )
                _record_oracle_component_provenance(
                    scan, scan["semantic_references"], "dynamic_class_reference_scan",
                    expected_sha, artifact,
                )
                oracle_budget_available("dynamic_class_reference_scan")
        except (OSError, TimeoutError, ValueError, zipfile.BadZipFile) as error:
            scan["complete"] = False
            reason = (
                "dynamic_class_reference_scan:oracle_time_budget_exceeded"
                if isinstance(error, TimeoutError)
                else f"dynamic_class_reference_scan_failed:{error}"
            )
            scan.setdefault("failures", []).append(reason)
        if requires_positive_only_jdeps(scan):
            try:
                jdeps_class_scan = scan_jdeps_class_references(
                    artifact,
                    selected_rows,
                    application_owned_nested_jars=application_owned_provider_entries,
                    provider_nested_jars_by_coord=provider_entries_by_coord,
                    provider_nested_jars_by_api_identity=provider_entries_by_api_identity,
                    timeout_seconds=min(60.0, remaining_oracle_budget() or 0.001)
                    if oracle_deadline is not None else 60.0,
                    time_budget_seconds=remaining_oracle_budget(),
                )
                _record_oracle_component_provenance(
                    scan, jdeps_class_scan, "jdeps_class_scan",
                    expected_sha, artifact,
                )
                merge_positive_only_jdeps_evidence(scan, jdeps_class_scan)
                oracle_budget_available("jdeps_class_scan")
            except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
                scan.setdefault("advisories", []).append(
                    f"jdeps_class_scan_failed:{error}"
                )
        else:
            scan["jdeps_class_reachability"] = {}
            scan["jdeps_class_references"] = []
            scan["jdeps_metrics"] = {
                "skipped": True,
                "skip_reason": "complete_javap_class_authority",
                "jdeps_invocations": 0,
                "class_count": 0,
                "elapsed_seconds": 0.0,
            }
        if mapper_oracle is not None and runtime_activation is not None:
            scan.setdefault("semantic_references", []).extend(
                build_mybatis_semantic_references(
                    selected_rows,
                    mapper_oracle,
                    runtime_activation,
                    str(scan.get("artifact_sha256") or ""),
                )
            )
        try:
            if not oracle_budget_available("artifact_class_inventory"):
                scan["artifact_entries"] = []
            else:
                scan["artifact_entries"] = sorted(_artifact_class_entries(
                    artifact, time_budget_seconds=remaining_oracle_budget(),
                ))
                oracle_budget_available("artifact_class_inventory")
        except (OSError, TimeoutError, zipfile.BadZipFile) as error:
            scan["complete"] = False
            reason = (
                "artifact_class_inventory:oracle_time_budget_exceeded"
                if isinstance(error, TimeoutError)
                else f"artifact_class_inventory_failed:{error}"
            )
            scan.setdefault("failures", []).append(reason)
            scan["artifact_entries"] = []
        scan["provider_nested_jars_by_coord"] = {
            coord: sorted(entries)
            for coord, entries in provider_entries_by_coord.items()
        }
        scan["provider_nested_jars_by_api_identity"] = {
            identity: sorted(entries)
            for identity, entries in provider_entries_by_api_identity.items()
        }
        scan = seal_oracle_scan(scan)
        scan, _validation_signal = validate_oracle_scan(scan, expected_sha)
    return reconcile_selected_api_edges(report_dir, selected_rows, analyzer_rows, scan)


def _file_sha256(path: str | Path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def evaluate_required_fault_injections(
    case: RealProjectCase,
    report_dir: Path,
    selected_rows: list[dict],
    clean_edge_truth: dict,
    *,
    analyzer_rows: list[dict] | None = None,
) -> dict:
    """Prove the real-project gate detects a deliberately omitted analyzer edge."""
    report_dir = Path(report_dir)
    root = report_dir / "evidence" / "quality" / "fault_injection"
    root.mkdir(parents=True, exist_ok=True)
    if analyzer_rows is None:
        _fields, analyzer_rows = _csv_rows(
            report_dir / "evidence" / "call_chain" / "analyzer_edges.csv"
        )
    analyzer_rows = [dict(row) for row in (analyzer_rows or [])]
    clean_ledger = list((clean_edge_truth.get("reconciliation") or {}).get("ledger") or [])
    oracle_scan = dict(clean_edge_truth.get("oracle_scan") or {})
    clean_ready = bool(clean_edge_truth.get("complete")) and not bool(
        clean_edge_truth.get("blocking")
    )
    runs = []
    for mode in case.required_fault_injections:
        run = {
            "mode": mode,
            "passed": False,
            "error": "",
            "removed_occurrence": "",
            "removed_api_identity": "",
            "verdict_counts": {},
            "clean_oracle_sha256": _file_sha256(clean_edge_truth.get("oracle_edges") or ""),
            "injected_oracle_sha256": "",
            "edge_reconciliation": "",
        }
        if not clean_ready:
            run["error"] = "clean_edge_truth_not_ready"
            runs.append(run)
            continue
        candidate = next(
            (
                row for row in clean_ledger
                if row.get("side") == "analyzer"
                and row.get("verdict") == "correct"
                and str(row.get("physical_occurrence") or "")
            ),
            None,
        )
        occurrence = str((candidate or {}).get("physical_occurrence") or "")
        api_identity = str((candidate or {}).get("api_identity") or "")
        ordered_rows = list(analyzer_rows)
        if candidate is not None:
            for index, row in enumerate(ordered_rows):
                if physical_edge_occurrence(row) == occurrence:
                    ordered_rows.insert(0, ordered_rows.pop(index))
                    break
        try:
            mutation = apply_fault_injection(mode, ordered_rows, oracle_scan)
        except ValueError as error:
            message = str(error)
            if message.startswith("injectable_analyzer_edge_missing"):
                message = "injectable_analyzer_edge_missing"
            run["error"] = message
            runs.append(run)
            continue

        if mutation.oracle_mutated:
            validated_scan, detected = validate_oracle_scan(
                mutation.oracle_scan,
                str(oracle_scan.get("artifact_sha256") or ""),
            )
            injected = reconcile_selected_api_edges(
                root / mode,
                selected_rows,
                analyzer_rows,
                validated_scan,
            )
            run.update({
                "removed_occurrence": occurrence,
                "removed_api_identity": api_identity,
                "detected_signal": detected,
                "injected_oracle_sha256": "",
                "edge_reconciliation": str(injected.get("edge_reconciliation") or ""),
            })
            run["passed"] = bool(
                detected == mutation.expected_signal
                and injected.get("blocking")
                and not injected.get("complete")
            )
            if not run["passed"]:
                run["error"] = "injected_oracle_mutation_was_not_rejected"
            runs.append(run)
            continue

        injected = reconcile_selected_api_edges(
            root / mode,
            selected_rows,
            list(mutation.analyzer_rows),
            mutation.oracle_scan,
        )
        counts = dict((injected.get("reconciliation") or {}).get("verdict_counts") or {})
        run.update({
            "removed_occurrence": occurrence,
            "removed_api_identity": api_identity,
            "verdict_counts": counts,
            "injected_oracle_sha256": _file_sha256(injected.get("oracle_edges") or ""),
            "edge_reconciliation": str(injected.get("edge_reconciliation") or ""),
        })
        oracle_unchanged = bool(run["clean_oracle_sha256"]) and (
            run["clean_oracle_sha256"] == run["injected_oracle_sha256"]
        )
        expected_count = int(counts.get(mutation.expected_verdict) or 0)
        run["detected_signal"] = "edge_reconciliation"
        run["passed"] = bool(
            injected.get("complete")
            and injected.get("blocking")
            and expected_count > 0
            and oracle_unchanged
        )
        if not run["passed"]:
            run["error"] = "injected_false_negative_did_not_fail_closed"
        runs.append(run)
    payload = {
        "case": case.name,
        "required": list(case.required_fault_injections),
        "passed": all(run.get("passed") for run in runs),
        "runs": runs,
    }
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return {**payload, "manifest": str(manifest)}


def _is_compile_time_constant_candidate(row: dict) -> bool:
    return bool(
        str(row.get("symbol_kind") or "").strip().lower() == "field"
        and (
            str(row.get("change_type") or "").strip() == "CONSTANT_VALUE_CHANGED"
            or "CONSTANT" in str(row.get("compatibility_flags") or "").upper()
            or str(row.get("reason_code") or "").strip().lower()
            == "constant_value_changed"
        )
    )


def _constant_aware_oracle_conclusion(row: dict, conclusion: str) -> str:
    if (
        conclusion == "not_found_in_static_analysis"
        and _is_compile_time_constant_candidate(row)
    ):
        return "uncertain"
    return conclusion


def _constant_impact_record(row: dict, conclusion: str) -> dict:
    if not _is_compile_time_constant_candidate(row):
        return {}
    required_evidence = (
        "old_field_has_constant_value",
        "source_reference_present",
        "source_artifact_aligned",
    )
    evidence_complete = all(key in row for key in required_evidence)
    def evidence_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value == 1
        return str(value or "").strip().lower() in {"1", "true", "yes", "on"}

    impact = classify_constant_impact(
        change_type=row.get("change_type") or row.get("reason_code"),
        old_field_has_constant_value=evidence_bool(row.get("old_field_has_constant_value")),
        source_reference_present=evidence_bool(row.get("source_reference_present")),
        runtime_field_edge_present=conclusion == "reachable",
        source_artifact_aligned=(
            evidence_bool(row.get("source_artifact_aligned")) if evidence_complete else False
        ),
    )
    payload = impact.to_dict()
    return {
        "compile_impact": payload.pop("compile_impact"),
        "runtime_link_impact": payload.pop("runtime_link_impact"),
        "constant_impact_evidence": payload,
    }


def build_final_artifact_api_oracle_records(
    selected_rows: list[dict], edge_truth: dict
) -> list[dict]:
    """Convert the independent classfile graph into per-API semantic verdicts."""
    if not edge_truth.get("complete"):
        return []
    reachability = edge_truth.get("api_reachability") or {}
    records = []
    trusted_artifact_sha = str(edge_truth.get("trusted_artifact_sha") or "")
    if not _valid_sha256(trusted_artifact_sha):
        return records
    for row in selected_rows:
        conclusion = str(reachability.get(serialized_api_identity(row)) or "")
        conclusion = _constant_aware_oracle_conclusion(row, conclusion)
        if conclusion not in {
            "reachable", "uncertain", "not_found_in_static_analysis"
        }:
            continue
        is_class = str(row.get("symbol_kind") or "").strip().lower() == "class"
        evidence_path = Path(str(
            edge_truth.get("class_reference_evidence")
            if is_class else edge_truth.get("oracle_edges") or ""
        ))
        try:
            evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        except OSError:
            continue
        records.append({
            **{
                key: str(row.get(key) or "")
                for key in (
                    "coord", "api_name", "api_signature", "symbol_kind",
                    "change_type",
                )
            },
            "oracle_conclusion": conclusion,
            "authority": "final-artifact-classfile" if is_class else "jdk-javap",
            "authority_version": "1",
            "procedure": (
                "SHA-verified final artifact classfile graph; exact target edge; "
                "reverse traversal to packaged business class boundary; compile-time constant "
                "absence remains uncertain because javac may inline the value"
                if _is_compile_time_constant_candidate(row)
                else "SHA-verified final artifact classfile graph; exact target edge; "
                "reverse traversal to packaged business class boundary"
            ),
            "evidence_path": str(evidence_path),
            "evidence_sha256": evidence_sha256,
            "generated_at": date.today().isoformat(),
            "evidence_mode": "bytecode",
            "conclusion_scope": "static_analysis",
            "artifact_sha256": trusted_artifact_sha,
            "capabilities": (
                "artifact_bound;closed_world_static;metadata_references"
                if is_class else
                "artifact_bound;closed_world_static;executable_edges"
            ),
            **_constant_impact_record(row, conclusion),
        })
    return records


def build_jdeps_api_oracle_records(
    selected_rows: list[dict], edge_truth: dict
) -> list[dict]:
    """Produce an independent class-level authority from the JDK jdeps tool."""
    if not edge_truth.get("complete"):
        return []
    evidence_path = Path(str(edge_truth.get("jdeps_class_reference_evidence") or ""))
    try:
        evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    except OSError:
        return []
    reachability = edge_truth.get("jdeps_class_reachability") or {}
    trusted_artifact_sha = str(edge_truth.get("trusted_artifact_sha") or "")
    if not _valid_sha256(trusted_artifact_sha):
        return []
    records = []
    for row in selected_rows:
        if str(row.get("symbol_kind") or "").strip().lower() != "class":
            continue
        conclusion = str(reachability.get(serialized_api_identity(row)) or "")
        if conclusion not in {"reachable", "uncertain"}:
            continue
        records.append({
            **{
                key: str(row.get(key) or "")
                for key in (
                    "coord", "api_name", "api_signature", "symbol_kind",
                    "change_type",
                )
            },
            "oracle_conclusion": conclusion,
            "authority": "jdk-jdeps",
            "authority_version": "1",
            "procedure": (
                "Positive-only JDK jdeps -verbose:class reference over effective classes "
                "in every non-target container of the SHA-verified final artifact; absence "
                "is not authoritative because jdeps omits some annotation metadata"
            ),
            "evidence_path": str(evidence_path),
            "evidence_sha256": evidence_sha256,
            "generated_at": date.today().isoformat(),
            "evidence_mode": "bytecode",
            "artifact_sha256": trusted_artifact_sha,
            "capabilities": "artifact_bound;metadata_references;positive_only",
        })
    return records


def build_javap_verbose_api_oracle_records(
    selected_rows: list[dict], edge_truth: dict
) -> list[dict]:
    """Produce a complete class-metadata authority from JDK javap verbose."""
    if not edge_truth.get("complete"):
        return []
    evidence_path = Path(str(edge_truth.get("javap_class_reference_evidence") or ""))
    try:
        evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    except OSError:
        return []
    reachability = edge_truth.get("javap_class_reachability") or {}
    trusted_artifact_sha = str(edge_truth.get("trusted_artifact_sha") or "")
    if not _valid_sha256(trusted_artifact_sha):
        return []
    records = []
    for row in selected_rows:
        if str(row.get("symbol_kind") or "").strip().lower() != "class":
            continue
        conclusion = str(reachability.get(serialized_api_identity(row)) or "")
        if conclusion not in {
            "reachable", "uncertain", "not_found_in_static_analysis",
        }:
            continue
        records.append({
            **{
                key: str(row.get(key) or "")
                for key in (
                    "coord", "api_name", "api_signature", "symbol_kind",
                    "change_type",
                )
            },
            "oracle_conclusion": conclusion,
            "authority": "jdk-javap-verbose",
            "authority_version": "1",
            "procedure": (
                "Exhaustive class-byte candidate inventory followed by exact JDK javap "
                "-verbose CONSTANT_Class and JVM descriptor confirmation"
            ),
            "evidence_path": str(evidence_path),
            "evidence_sha256": evidence_sha256,
            "generated_at": date.today().isoformat(),
            "evidence_mode": "bytecode",
            "conclusion_scope": "static_analysis",
            "artifact_sha256": trusted_artifact_sha,
            "capabilities": (
                "artifact_bound;closed_world_static;metadata_references"
            ),
        })
    return records


def build_semantic_api_oracle_records(
    selected_rows: list[dict], edge_truth: dict
) -> list[dict]:
    """Turn independently generated semantic evidence into API verdicts."""
    if not edge_truth.get("complete"):
        return []
    trusted_artifact_sha = str(edge_truth.get("trusted_artifact_sha") or "")
    if not _valid_sha256(trusted_artifact_sha):
        return []
    evidence_path = Path(str(edge_truth.get("semantic_reference_evidence") or ""))
    try:
        evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    except OSError:
        return []
    references_by_identity: dict[str, list[dict]] = defaultdict(list)
    for reference in edge_truth.get("semantic_references") or []:
        if str(reference.get("artifact_sha256") or "") != trusted_artifact_sha:
            continue
        identity = str(reference.get("api_identity") or "")
        if identity:
            references_by_identity[identity].append(reference)

    records = []
    for row in selected_rows:
        identity = serialized_api_identity(row)
        for reference in references_by_identity.get(identity) or []:
            authority = str(reference.get("authority") or "").strip()
            if authority == "final-artifact-classfile-constants":
                conclusion = "uncertain"
                conclusion_scope = "dynamic_resolution"
                evidence_mode = "bytecode"
                capabilities = "artifact_bound;positive_only;metadata_references"
            elif (
                authority == "final-artifact-mybatis-proxy-runtime"
                and _valid_sha256(str(reference.get("runtime_output_sha256") or ""))
                and int(reference.get("proxy_dispatch_edge_count") or 0) >= 2
                and int(reference.get("physical_evidence_count") or 0) >= 1
                and int(reference.get("mapper_contract_count") or 0) >= 1
            ):
                conclusion = "reachable"
                conclusion_scope = "runtime_analysis"
                evidence_mode = "project_test"
                capabilities = "artifact_bound;executable_runtime"
            else:
                continue
            records.append({
                **{
                    key: str(row.get(key) or "")
                    for key in (
                        "coord", "api_name", "api_signature", "symbol_kind",
                        "change_type",
                    )
                },
                "oracle_conclusion": conclusion,
                "authority": authority,
                "authority_version": str(
                    reference.get("authority_version") or "1"
                ),
                "procedure": str(reference.get("procedure") or "").strip(),
                "evidence_path": str(evidence_path),
                "evidence_sha256": evidence_sha256,
                "generated_at": date.today().isoformat(),
                "evidence_mode": evidence_mode,
                "conclusion_scope": conclusion_scope,
                "artifact_sha256": trusted_artifact_sha,
                "capabilities": capabilities,
            })
    return records


def build_automatic_oracle_records(
    selected_rows: list[dict], edge_truth: dict
) -> list[dict]:
    """Build verdict authorities; diagnostic constant-pool candidates are excluded."""
    records = build_final_artifact_api_oracle_records(selected_rows, edge_truth)
    records.extend(build_jdeps_api_oracle_records(selected_rows, edge_truth))
    records.extend(build_javap_verbose_api_oracle_records(selected_rows, edge_truth))
    records.extend(build_semantic_api_oracle_records(selected_rows, edge_truth))
    return records


def _artifact_entry_bytes(artifact: Path, artifact_entry: str) -> bytes:
    outer_entry, separator, inner_entry = str(artifact_entry or "").partition("!/")
    with zipfile.ZipFile(artifact) as archive:
        if not separator:
            return archive.read(outer_entry)
        nested_bytes = archive.read(outer_entry)
    with zipfile.ZipFile(io.BytesIO(nested_bytes)) as nested:
        return nested.read(inner_entry)


def build_runtime_bound_oracle_records(
    case: RealProjectCase,
    selected_rows: list[dict],
    manifest_rows: list[dict],
    edge_truth: dict,
    report_dir: Path,
    pinned_manifest: dict | None,
) -> tuple[list[dict], list[str]]:
    """Regenerate reviewed runtime Oracle evidence for a runtime-bound build."""
    manifest = dict(pinned_manifest or {})
    runtime_spec = dict(manifest.get("runtime_verification") or {})
    if (
        artifact_verification_mode(manifest) != "runtime"
        or not runtime_spec.get("oracle_rebinding")
    ):
        return [], []
    artifact = Path(case.final_artifact or "")
    trusted_artifact_sha = str(edge_truth.get("trusted_artifact_sha") or "")
    reference_artifact_sha = str(manifest.get("reference_artifact_sha256") or "")
    required_output = [
        str(item) for item in (runtime_spec.get("required_output") or [])
        if str(item)
    ]
    warnings = []
    if (
        not artifact.is_file()
        or not _valid_sha256(trusted_artifact_sha)
        or hashlib.sha256(artifact.read_bytes()).hexdigest() != trusted_artifact_sha
        or not _valid_sha256(reference_artifact_sha)
        or not required_output
    ):
        return [], ["runtime_oracle_rebinding_input_invalid"]

    timeout_seconds = max(0.1, float(runtime_spec.get("timeout_seconds") or 30.0))
    try:
        completed = subprocess.run(
            ["java", "-jar", str(artifact)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return [], [f"runtime_oracle_execution_failed:{type(error).__name__}:{error}"]
    runtime_output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
    missing_output = [item for item in required_output if item not in runtime_output]
    if completed.returncode != 0 or missing_output:
        return [], [
            "runtime_oracle_verification_failed:"
            f"exit={completed.returncode}:missing={','.join(missing_output)}"
        ]

    manifest_apis = {
        (str(item.get("owner") or ""), str(item.get("member") or "")): item
        for item in (manifest.get("apis") or [])
    }
    declaration_checks = []
    for row in selected_rows:
        api_name = str(row.get("api_name") or "")
        owner, separator, member = api_name.rpartition(".")
        expected = manifest_apis.get((owner, member))
        entries = tuple(case.target_owner_entries.get(owner) or ())
        if not separator or expected is None or len(entries) != 1:
            return [], [f"runtime_oracle_declaration_contract_missing:{api_name}"]
        descriptor = str(expected.get("descriptor") or "")
        try:
            content = _artifact_entry_bytes(artifact, entries[0])
            with tempfile.TemporaryDirectory(prefix="runtime-oracle-javap-") as temporary:
                class_file = Path(temporary) / "target.class"
                class_file.write_bytes(content)
                javap = subprocess.run(
                    ["javap", "-p", "-s", str(class_file)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout_seconds,
                    check=False,
                )
        except (KeyError, OSError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
            return [], [
                f"runtime_oracle_declaration_failed:{api_name}:"
                f"{type(error).__name__}:{error}"
            ]
        declaration_output = f"{javap.stdout or ''}\n{javap.stderr or ''}"
        passed = bool(
            javap.returncode == 0
            and member in declaration_output
            and descriptor
            and f"descriptor: {descriptor}" in declaration_output
        )
        declaration_checks.append({
            "api_identity": serialized_api_identity(row),
            "artifact_entry": entries[0],
            "member": member,
            "descriptor": descriptor,
            "passed": passed,
            "javap_output_sha256": hashlib.sha256(
                declaration_output.encode("utf-8")
            ).hexdigest(),
        })
    if not declaration_checks or not all(item["passed"] for item in declaration_checks):
        return [], ["runtime_oracle_declaration_verification_failed"]

    quality_dir = Path(report_dir) / "evidence" / "quality"
    quality_dir.mkdir(parents=True, exist_ok=True)
    runtime_path = quality_dir / "runtime_oracle_output.txt"
    runtime_path.write_text(runtime_output, encoding="utf-8")
    evidence_path = quality_dir / "runtime_oracle_evidence.json"
    evidence_payload = {
        "artifact_sha256": trusted_artifact_sha,
        "reference_artifact_sha256": reference_artifact_sha,
        "git_revision": str(manifest.get("git_revision") or ""),
        "runtime_exit_code": completed.returncode,
        "runtime_output": str(runtime_path),
        "runtime_output_sha256": hashlib.sha256(
            runtime_output.encode("utf-8")
        ).hexdigest(),
        "required_output": required_output,
        "declaration_checks": declaration_checks,
    }
    evidence_path.write_text(
        json.dumps(evidence_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()

    reviewed_by_identity = {
        serialized_api_identity(row): row for row in manifest_rows
        if str(row.get("oracle_conclusion") or "") == "reachable"
        and str(row.get("artifact_sha256") or "") == reference_artifact_sha
        and str(row.get("authority_version") or "")
        == str(manifest.get("git_revision") or "")
    }
    records = []
    for row in selected_rows:
        identity = serialized_api_identity(row)
        if identity not in reviewed_by_identity:
            warnings.append(f"runtime_oracle_review_record_missing:{identity}")
            continue
        records.append({
            **{
                key: str(row.get(key) or "")
                for key in (
                    "coord", "api_name", "api_signature", "symbol_kind",
                    "change_type",
                )
            },
            "oracle_conclusion": "reachable",
            "authority": "project-runtime",
            "authority_version": str(manifest.get("git_revision") or ""),
            "procedure": (
                "Execute the current runtime-bound artifact, verify reviewed rollback "
                "outputs, and confirm each exact target declaration with JDK javap"
            ),
            "evidence_path": str(evidence_path),
            "evidence_sha256": evidence_sha256,
            "generated_at": date.today().isoformat(),
            "evidence_mode": "project_test",
            "conclusion_scope": "runtime_analysis",
            "artifact_sha256": trusted_artifact_sha,
            "capabilities": "artifact_bound;executable_runtime",
        })
    if len(records) != len(selected_rows):
        return [], warnings
    return records, warnings


def run_dual_line_accuracy_audit(
    case: RealProjectCase,
    selected_rows: list[dict],
    summary: dict,
    edge_truth: dict,
    report_dir: Path,
    *,
    oracle_manifest: Path | None = None,
    pinned_manifest: dict | None = None,
) -> tuple[dict, list[str]]:
    """Build the independent line, then reconcile it with analyzer output."""
    warnings: list[str] = []
    oracle_rows = load_oracle_manifest(oracle_manifest or case.oracle_manifest)
    runtime_oracle_rows, runtime_warnings = build_runtime_bound_oracle_records(
        case, selected_rows, oracle_rows, edge_truth, report_dir, pinned_manifest
    )
    warnings.extend(runtime_warnings)
    if runtime_oracle_rows:
        rebound_identities = {
            serialized_api_identity(row) for row in runtime_oracle_rows
        }
        oracle_rows = [
            row for row in oracle_rows
            if serialized_api_identity(row) not in rebound_identities
        ]
        oracle_rows.extend(runtime_oracle_rows)
    automatic_oracle_rows = build_automatic_oracle_records(
        selected_rows, edge_truth
    )
    oracle_rows.extend(automatic_oracle_rows)
    trusted_capability_records = list(automatic_oracle_rows) + list(
        runtime_oracle_rows
    )
    automatic_identities = {
        serialized_api_identity(row) for row in automatic_oracle_rows
    }
    jdk_selected_rows = [
        row for row in selected_rows
        if serialized_api_identity(row) not in automatic_identities
    ]
    if case.enable_jdk_oracle and jdk_selected_rows:
        try:
            class_files = (
                load_materialized_class_inventory(report_dir, case.final_artifact)
                if case.final_artifact else []
            )
            jdk_rows = scan_class_files(
                jdk_selected_rows,
                class_files,
                report_dir / "evidence" / "quality" / "jdk-javap",
                business_class_files=[
                    path for path in class_files if "nested" not in path.parts
                ],
            )
            oracle_rows.extend(jdk_rows)
            trusted_capability_records.extend(jdk_rows)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            warnings.append(
                f"jdk_oracle_unavailable:{type(error).__name__}:{error}"
            )
    analyzer_rows = load_analyzer_rows(summary)
    expected_artifact_sha256 = str(
        edge_truth.get("trusted_artifact_sha") or ""
    )
    result = reconcile_accuracy_lines(
        selected_rows,
        analyzer_rows,
        oracle_rows,
        expected_artifact_sha256=expected_artifact_sha256,
        trusted_capability_records=trusted_capability_records,
    )
    result["oracle_authorities"] = sorted({
        str(row.get("authority") or "") for row in oracle_rows
        if str(row.get("authority") or "")
    })
    quality_dir = Path(report_dir) / "evidence" / "quality"
    analyzer_line = write_line_payload(
        quality_dir / "analyzer_api_line.json", "analyzer", analyzer_rows
    )
    oracle_line = write_line_payload(
        quality_dir / "oracle_api_line.json", "oracle", oracle_rows
    )
    ledger_path = quality_dir / "exhaustive_api_oracle.csv"
    write_oracle_ledger(ledger_path, result)
    result_path = quality_dir / "dual_line_accuracy.json"
    result["line_outputs"] = {
        "analyzer": analyzer_line,
        "oracle": oracle_line,
        "reconciliation": str(result_path),
        "ledger": str(ledger_path),
    }
    write_accuracy_result(result_path, result)
    return result, warnings


def requires_dual_line_accuracy(
    case: RealProjectCase, *, oracle_manifest: Path | None = None
) -> bool:
    return bool(
        case.fixture_manifest
        or case.oracle_manifest
        or oracle_manifest
        or case.case_mode in {"discovery", "convergence"}
    )


def _valid_sha256(value: str) -> bool:
    value = str(value or "").strip()
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def validate_source_bytecode_conflicts(summary: dict, edge_truth: dict | None = None) -> dict:
    conflicts = [
        item for item in (summary.get("uncertain_apis") or [])
        if str(item.get("reason_code") or "") == "SOURCE_BYTECODE_EDGE_CONFLICT"
    ]
    edge_truth = edge_truth or {}
    trusted_artifact_sha = str(edge_truth.get("trusted_artifact_sha") or "")
    oracle_occurrences = set(edge_truth.get("oracle_physical_occurrences") or [])
    final_artifact_bound = bool(
        edge_truth.get("complete")
        and _valid_sha256(trusted_artifact_sha)
        and oracle_occurrences
    )
    errors: list[str] = []
    for index, conflict in enumerate(conflicts):
        provenance = conflict.get("source_revision_provenance") or conflict.get("source_provenance") or {}
        source_edge = conflict.get("normalized_source_edge") or conflict.get("source_edge") or {}
        final_edge = conflict.get("normalized_final_artifact_edge") or conflict.get("final_artifact_edge") or {}
        prefix = f"source_bytecode_conflict[{index}]"
        if not isinstance(provenance, dict) or not provenance.get("valid") or not provenance.get("git_revision"):
            errors.append(f"{prefix}:source_revision_provenance_missing")
        if not isinstance(source_edge, dict) or not all(str(source_edge.get(field) or "").strip() for field in EDGE_COMPARISON_FIELDS):
            errors.append(f"{prefix}:normalized_source_edge_missing")
        if not isinstance(final_edge, dict) or not all(str(final_edge.get(field) or "").strip() for field in EDGE_IDENTITY_FIELDS):
            errors.append(f"{prefix}:normalized_final_artifact_edge_missing")
            continue
        if not normalize_instruction_offset(final_edge):
            errors.append(f"{prefix}:final_artifact_instruction_offset_missing")
        final_sha = str(final_edge.get("artifact_sha256") or "")
        if not _valid_sha256(final_sha):
            errors.append(f"{prefix}:final_artifact_sha_invalid")
        elif not final_artifact_bound:
            errors.append(f"{prefix}:final_artifact_oracle_binding_unavailable")
        elif final_sha != trusted_artifact_sha:
            errors.append(f"{prefix}:final_artifact_sha_mismatch")
        elif physical_edge_occurrence(final_edge) not in oracle_occurrences:
            errors.append(f"{prefix}:final_artifact_oracle_identity_missing")
    return {"conflict_count": len(conflicts), "invalid_count": len({item.split(":", 1)[0] for item in errors}),
            "valid": not errors, "errors": errors}


def build_edge_truth_signals(case: RealProjectCase, edge_truth: dict, source_conflicts: dict) -> list[dict]:
    signals: list[dict] = []
    evidence = [edge_truth.get("oracle_edges", ""), edge_truth.get("edge_reconciliation", "")]
    if not edge_truth.get("complete"):
        signals.append(make_signal(
            "oracle_incomplete", "P0", case.name, step="step5",
            message="final-artifact edge oracle is incomplete",
            count=len(edge_truth.get("errors") or []),
            expected="complete SHA-verified final-artifact edge oracle for every selected API",
            actual="; ".join((edge_truth.get("errors") or [])[:10]), evidence=evidence,
        ))
    if edge_truth.get("reconciliation", {}).get("blocking"):
        counts = edge_truth["reconciliation"].get("verdict_counts") or {}
        samples = [
            row.get("identity", "") for row in edge_truth["reconciliation"].get("ledger") or []
            if row.get("verdict") != "correct"
        ][:10]
        signals.append(make_signal(
            "edge_truth_failure", "P0", case.name, step="step5",
            message="final-artifact edge reconciliation found blocking edge truth differences",
            count=sum(int(value or 0) for key, value in counts.items() if key != "correct"),
            expected="every selected API runtime edge matches the final-artifact oracle",
            actual=json.dumps(counts, sort_keys=True), evidence=evidence, sample_symbols=samples,
        ))
    if not source_conflicts.get("valid"):
        signals.append(make_signal(
            "source_bytecode_conflict_invalid", "P0", case.name, step="step5",
            message="SOURCE_BYTECODE_EDGE_CONFLICT lacks authoritative normalized source/final evidence",
            count=int(source_conflicts.get("invalid_count") or 0),
            expected="normalized source and final-artifact edge identities with known source revision provenance",
            actual="; ".join((source_conflicts.get("errors") or [])[:10]), evidence=evidence,
        ))
    return signals


def build_fault_injection_signals(case: RealProjectCase, fault_injection: dict) -> list[dict]:
    if not case.required_fault_injections or fault_injection.get("passed"):
        return []
    failed = [
        run for run in (fault_injection.get("runs") or [])
        if not run.get("passed")
    ]
    return [make_signal(
        "fault_injection_failure",
        "P0",
        case.name,
        step="real-project-gate",
        message="required fault injection did not prove that the gate detects a false negative",
        count=len(failed),
        expected="clean run passes and every injected analyzer-edge omission fails with a missing verdict",
        actual="; ".join(
            f"{run.get('mode')}:{run.get('error') or 'not_blocking'}"
            for run in failed
        ),
        evidence=[fault_injection.get("manifest") or ""],
        blocking=True,
    )]


def build_constant_evidence_signals(case: RealProjectCase, evidence: dict) -> list[dict]:
    if not evidence.get("required") or not evidence.get("blocking"):
        return []
    return [make_signal(
        "constant_evidence_reconciliation_failure",
        "P0",
        case.name,
        step="step4-step5",
        message="constant evidence was incomplete or disagreed with the independent javap Oracle",
        expected="exact descriptor, ConstantValue, runtime link, artifact SHA, and conclusion agreement",
        actual=json.dumps({
            "errors": evidence.get("errors") or [],
            "audit": evidence.get("audit") or {},
        }, sort_keys=True),
        evidence=[evidence.get("manifest") or evidence.get("provider_artifact") or ""],
        blocking=True,
    )]


def ensure_changed_apis(case: RealProjectCase, changed_apis: Path, materialized_path: Path | None = None) -> Path:
    if case.prefer_embedded_changed_api_rows and case.changed_api_rows:
        changed_apis = materialized_path or changed_apis
    elif changed_apis.exists() or not case.changed_api_rows:
        return changed_apis
    changed_apis.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(changed_apis) as fh:
        writer = csv.DictWriter(fh, fieldnames=ALL_CHANGED_APIS_FIELDS)
        writer.writeheader()
        writer.writerows(case.changed_api_rows)
    return changed_apis


def resolve_constant_oracle_provider(
    manifest: dict, *, project_root: Path | None = None,
    maven_repository: Path | None = None,
) -> Path:
    provider = dict((manifest.get("constant_oracle") or {}).get("provider") or {})
    coordinate = str(provider.get("coordinate") or "").strip()
    parts = coordinate.split(":")
    if len(parts) != 3 or any(not part for part in parts):
        raise ValueError("constant_oracle_provider_coordinate_invalid")
    expected_sha = str(provider.get("sha256") or "").strip()
    if not _valid_sha256(expected_sha):
        raise ValueError("constant_oracle_provider_sha256_invalid")
    artifact_path = str(provider.get("artifact_path") or "").strip()
    if artifact_path:
        if project_root is None:
            raise ValueError("constant_oracle_provider_project_root_required")
        root = Path(project_root).resolve()
        artifact = (root / artifact_path).resolve()
        if artifact != root and root not in artifact.parents:
            raise ValueError("constant_oracle_provider_path_outside_project")
    else:
        group_id, artifact_id, version = parts
        repository = Path(
            maven_repository
            or os.environ.get("JUA_MAVEN_REPOSITORY")
            or (Path.home() / ".m2" / "repository")
        )
        artifact = (
            repository / Path(*group_id.split(".")) / artifact_id / version
            / f"{artifact_id}-{version}.jar"
        )
    if not artifact.is_file():
        raise ValueError(f"constant_oracle_provider_missing:{artifact}")
    actual_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual_sha != expected_sha:
        raise ValueError("constant_oracle_provider_sha256_mismatch")
    return artifact


def _manifest_constant_descriptor(manifest: dict, row: dict) -> str:
    api_name = str(row.get("api_name") or "")
    owner, separator, member = api_name.rpartition(".")
    matches = [
        str(item.get("descriptor") or "").strip()
        for item in (manifest.get("apis") or [])
        if str(item.get("coord") or "") == str(row.get("coord") or "")
        and str(item.get("owner") or "") == owner
        and str(item.get("member") or "") == member
        and str(item.get("symbol_kind") or "").lower() == "field"
    ]
    if not separator or len(matches) != 1 or not matches[0]:
        raise ValueError(f"constant_oracle_descriptor_not_unique:{api_name}")
    return matches[0]


def materialize_constant_evidence_input(
    changed_apis: Path,
    provider_artifact: Path,
    manifest: dict,
    output_path: Path,
) -> dict:
    _fields, rows = _csv_rows(changed_apis)
    candidate_indexes = [
        index for index, row in enumerate(rows)
        if _is_compile_time_constant_candidate(row)
    ]
    for index in candidate_indexes:
        rows[index]["field_descriptor"] = _manifest_constant_descriptor(
            manifest, rows[index]
        )
    enriched = attach_constant_field_evidence(rows, provider_artifact)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(output_path) as handle:
        writer = csv.DictWriter(
            handle, fieldnames=ALL_CHANGED_APIS_FIELDS, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(enriched)
    return {
        "path": str(output_path),
        "selected_count": len(candidate_indexes),
        "provider_artifact": str(provider_artifact),
    }


def prepare_constant_project_input(
    manifest: dict, changed_apis: Path, report_dir: Path,
    project_root: Path | None = None,
) -> dict:
    if not manifest.get("constant_oracle"):
        return {
            "required": False, "complete": True, "blocking": False,
            "changed_apis": str(changed_apis), "provider_artifact": "",
            "errors": [],
        }
    try:
        provider = resolve_constant_oracle_provider(
            manifest, project_root=project_root
        )
        output = (
            Path(report_dir) / "evidence" / "api_changes"
            / "constant_evidence_apis.csv"
        )
        materialized = materialize_constant_evidence_input(
            changed_apis, provider, manifest, output
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {
            "required": True, "complete": False, "blocking": True,
            "changed_apis": str(changed_apis), "provider_artifact": "",
            "errors": [str(error)],
        }
    return {
        "required": True, "complete": True, "blocking": False,
        "changed_apis": str(materialized["path"]),
        "provider_artifact": str(provider),
        "selected_count": int(materialized.get("selected_count") or 0),
        "errors": [],
    }


def reconcile_constant_project_evidence(
    provider_artifact: Path,
    consumer_artifact: Path,
    selected_rows: list[dict],
    summary: dict,
    output_path: Path,
    required_faults: Iterable[str] = (),
    analyzer_edge_rows: Iterable[dict] = (),
    consumer_artifact_sha256: str = "",
) -> dict:
    constant_rows = [
        dict(row) for row in selected_rows
        if _is_compile_time_constant_candidate(row)
    ]
    oracle_ledger = run_constant_oracle(
        provider_artifact, [consumer_artifact], constant_rows
    )
    oracle_rows = []
    for record in oracle_ledger.records:
        row = record.to_dict()
        row["expected_conclusion"] = (
            "reachable" if row.get("runtime_links") else
            "uncertain" if row.get("has_constant_value") else
            "not_found_in_static_analysis"
        )
        oracle_rows.append(row)

    selected_by_identity = defaultdict(list)
    for row in constant_rows:
        selected_by_identity[serialized_api_identity(row)].append(row)
    analyzer_rows = []
    analyzer_edge_rows = list(analyzer_edge_rows or ())
    artifact_scan_complete = str(
        (((summary.get("meta") or {}).get("graph_stats") or {}).get(
            "artifact_bytecode"
        ) or {}).get("status") or ""
    ) == "complete"
    for summary_row in load_analyzer_rows(summary):
        identity = serialized_api_identity(summary_row)
        candidates = selected_by_identity.get(identity) or []
        for _selected in candidates:
            impact = summary_row.get("constant_impact_evidence")
            impact = dict(impact) if isinstance(impact, dict) else {}
            old_field = impact.get("old_field")
            old_field = dict(old_field) if isinstance(old_field, dict) else {}
            runtime_flag = impact.get("runtime_field_edge_present")
            exact_links = []
            for edge in analyzer_edge_rows:
                if str(edge.get("api_identity") or "") != identity:
                    continue
                exact_links.append({
                    "consumer_owner": str(edge.get("caller_owner") or ""),
                    "consumer_method": str(edge.get("caller_member") or ""),
                    "consumer_descriptor": str(edge.get("caller_descriptor") or ""),
                    "target_owner": str(edge.get("callee_owner") or ""),
                    "target_field": str(edge.get("callee_member") or ""),
                    "target_descriptor": str(edge.get("callee_descriptor") or ""),
                    "opcode": str(edge.get("opcode_family") or ""),
                    "instruction_offset": int(edge.get("instruction_offset")),
                    "artifact_sha256": str(edge.get("artifact_sha256") or ""),
                    "artifact_entry": str(edge.get("artifact_entry") or ""),
                })
            exact_links.sort(key=lambda item: tuple(str(item.get(key) or "") for key in (
                "artifact_sha256", "artifact_entry", "consumer_owner", "consumer_method",
                "consumer_descriptor", "instruction_offset",
            )))
            evidence_complete = bool(
                artifact_scan_complete
                and old_field.get("status") == "complete"
                and str(old_field.get("descriptor") or "")
                and _valid_sha256(str(old_field.get("artifact_sha256") or ""))
                and isinstance(runtime_flag, bool)
                and bool(str(summary_row.get("compile_impact") or ""))
                and bool(str(summary_row.get("runtime_link_impact") or ""))
                and _valid_sha256(consumer_artifact_sha256)
                and runtime_flag == bool(exact_links)
            )
            analyzer_rows.append({
                "identity": identity,
                "descriptor": str(old_field.get("descriptor") or ""),
                "has_constant_value": old_field.get("has_constant_value") is True,
                "constant_value": old_field.get("constant_value"),
                "runtime_links": exact_links,
                "consumer_artifact_sha256s": [consumer_artifact_sha256],
                "old_artifact_sha256": str(old_field.get("artifact_sha256") or ""),
                "conclusion": str(summary_row.get("analysis_status") or ""),
                "compile_impact": str(summary_row.get("compile_impact") or ""),
                "runtime_link_impact": str(
                    summary_row.get("runtime_link_impact") or ""
                ),
                "evidence_status": "complete" if evidence_complete else "incomplete",
            })
    audit = audit_constant_evidence(analyzer_rows, oracle_rows)
    incomplete_analyzer = sorted(
        row["identity"] for row in analyzer_rows
        if row.get("evidence_status") != "complete"
    )
    complete = bool(
        oracle_ledger.complete and not audit.get("blocking") and not incomplete_analyzer
    )
    payload = {
        "complete": complete,
        "blocking": not complete,
        "provider_artifact": str(provider_artifact),
        "consumer_artifact": str(consumer_artifact),
        "oracle": oracle_ledger.to_dict() if hasattr(oracle_ledger, "to_dict") else {
            "complete": oracle_ledger.complete,
            "records": oracle_rows,
            "failures": list(oracle_ledger.failures),
        },
        "analyzer_records": analyzer_rows,
        "audit": audit,
        "incomplete_analyzer_identities": incomplete_analyzer,
    }
    fault_injection = evaluate_constant_evidence_fault_injections(
        payload, required_faults
    )
    payload["fault_injection"] = fault_injection
    if not fault_injection.get("passed"):
        payload["complete"] = False
        payload["blocking"] = True
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    payload["manifest"] = str(output_path)
    return payload


def evaluate_constant_evidence_fault_injections(
    clean_evidence: dict, required_modes: Iterable[str]
) -> dict:
    required_modes = list(required_modes or ())
    oracle_base = copy.deepcopy(
        list((clean_evidence.get("oracle") or {}).get("records") or [])
    )
    analyzer_base = copy.deepcopy(clean_evidence.get("analyzer_records") or [])
    for row in oracle_base:
        row["expected_conclusion"] = (
            "reachable" if row.get("runtime_links") else
            "uncertain" if row.get("has_constant_value") else
            "not_found_in_static_analysis"
        )
    clean_oracle = clean_evidence.get("oracle") or {}
    clean_audit = audit_constant_evidence(analyzer_base, oracle_base)
    clean_baseline_blocking = bool(
        not clean_evidence.get("complete")
        or clean_evidence.get("blocking")
        or not clean_oracle.get("complete")
        or clean_oracle.get("failures")
        or not oracle_base
        or not analyzer_base
        or clean_audit.get("blocking")
    )
    runs = []
    expected_fields = {
        "wrong_constant_value": ["constant_value"],
        "removed_field_link": ["runtime_links"],
        "extra_field_link": ["runtime_links"],
        "wrong_descriptor": ["descriptor"],
        "stale_provider_sha256": ["old_artifact_sha256"],
    }
    for mode in required_modes:
        oracle_rows = copy.deepcopy(oracle_base)
        analyzer_rows = copy.deepcopy(analyzer_base)
        if clean_baseline_blocking:
            runs.append({
                "mode": mode, "passed": False, "blocking": False,
                "detected_fields": [], "error": "clean_baseline_blocking",
                "clean_audit": clean_audit,
            })
            continue
        if mode == "wrong_constant_value":
            analyzer_rows[0]["constant_value"] = "__fault_wrong_constant__"
        elif mode == "removed_field_link":
            target = next(
                (row for row in analyzer_rows if row.get("runtime_links")), None
            )
            if target is None:
                runs.append({
                    "mode": mode, "passed": False, "blocking": False,
                    "detected_fields": [], "error": "fault_not_applicable",
                })
                continue
            target["runtime_links"] = list(target["runtime_links"])[1:]
        elif mode == "extra_field_link":
            target = next(
                (row for row in analyzer_rows if not row.get("runtime_links")), None
            )
            if target is None:
                runs.append({
                    "mode": mode, "passed": False, "blocking": False,
                    "detected_fields": [], "error": "fault_not_applicable",
                })
                continue
            target["runtime_links"] = [{
                "consumer_owner": "fault.Consumer",
                "consumer_method": "read",
                "consumer_descriptor": "()V",
                "target_owner": "fault.Provider",
                "target_field": "VALUE",
                "target_descriptor": "I",
                "opcode": "getstatic",
                "instruction_offset": -1,
                "artifact_sha256": "f" * 64,
                "artifact_entry": "fault/Consumer.class",
            }]
        elif mode == "wrong_descriptor":
            analyzer_rows[0]["descriptor"] = "__fault_descriptor__"
        elif mode == "stale_provider_sha256":
            analyzer_rows[0]["old_artifact_sha256"] = "0" * 64
        else:
            runs.append({
                "mode": mode, "passed": False, "blocking": False,
                "detected_fields": [], "error": "unknown_constant_fault_mode",
            })
            continue
        audit = audit_constant_evidence(analyzer_rows, oracle_rows)
        detected_fields = sorted({
            field
            for fields in (audit.get("incorrect_fields") or {}).values()
            for field in fields
        })
        runs.append({
            "mode": mode,
            "passed": bool(
                audit.get("blocking")
                and detected_fields == expected_fields[mode]
            ),
            "blocking": bool(audit.get("blocking")),
            "detected_fields": detected_fields,
            "audit": audit,
        })
    return {
        "required": required_modes,
        "passed": all(run.get("passed") for run in runs),
        "runs": runs,
    }


def materialize_bytecode_changed_apis(
    case: RealProjectCase,
    project_root: Path,
    report_dir: Path,
    selected_changed_apis: Path | None = None,
) -> Path:
    artifact = case.final_artifact
    if artifact is None or not artifact.is_file():
        raise ValueError("current final artifact is required for bytecode discovery")
    artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
    extracted_root = report_dir / ".runtime" / "final-artifact-classes" / artifact_sha256[:16]
    extracted_root.mkdir(parents=True, exist_ok=True)
    target_lib_entry = ""
    target_lib_candidates: list[str] = []
    target_filename_candidates: list[str] = []
    runtime_lib_entries: list[dict[str, str]] = []
    artifact_java_version = infer_final_artifact_java_version(artifact)
    owner_prefix_bytes = tuple(prefix.encode("utf-8") for prefix in case.bytecode_owner_prefixes)
    artifact_id = case.bytecode_coord.split(":", 1)[-1].strip()
    class_files: list[Path] = []
    with zipfile.ZipFile(artifact) as source:
        names = source.namelist()
        target_filename_candidates = [
            name
            for name in names
            if name.startswith("BOOT-INF/lib/")
            and name.endswith(".jar")
            and artifact_id
            and re.fullmatch(
                rf"{re.escape(artifact_id)}(?:-.+)?\.jar",
                Path(name).name,
            )
        ]
        application_prefix = next(
            (
                prefix for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/")
                if any(name.startswith(prefix) and name.endswith(".class") for name in names)
            ),
            "",
        )
        business_entries: dict[str, str] = {}
        for name in sorted(names):
            if application_prefix:
                is_business_class = name.startswith(application_prefix) and name.endswith(".class")
                relative = name[len(application_prefix):] if is_business_class else ""
            else:
                is_business_class = bool(
                    name.endswith(".class")
                    and not name.startswith("META-INF/")
                    and name != "module-info.class"
                )
                relative = name if is_business_class else ""
            if is_business_class:
                relative_path = PurePosixPath(relative)
                if relative_path.is_absolute() or ".." in relative_path.parts:
                    raise ValueError(f"unsafe business class entry: {name}")
                logical_name = relative_path.as_posix()
                if logical_name in business_entries:
                    raise ValueError(f"duplicate business class entry: {logical_name}")
                business_entries[logical_name] = name
                destination = extracted_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                class_bytes = source.read(name)
                destination.write_bytes(class_bytes)
                class_files.append(destination)
            if (
                name.startswith("BOOT-INF/lib/")
                and name.endswith(".jar")
            ):
                nested_filename = Path(name).name
                is_target_provider = (
                    len(target_filename_candidates) == 1
                    and name == target_filename_candidates[0]
                )
                try:
                    nested_blob = source.read(name)
                    with zipfile.ZipFile(io.BytesIO(nested_blob)) as nested:
                        nested_coordinates = []
                        for metadata_name in nested.namelist():
                            if not re.fullmatch(
                                r"META-INF/maven/[^/]+/[^/]+/pom\.properties",
                                metadata_name,
                            ):
                                continue
                            properties = {}
                            for line in nested.read(metadata_name).decode(
                                "utf-8", errors="replace"
                            ).splitlines():
                                key, separator, value = line.strip().partition("=")
                                if separator:
                                    properties[key.strip()] = value.strip()
                            if all(properties.get(key) for key in ("groupId", "artifactId", "version")):
                                nested_coordinates.append(properties)
                        if len(nested_coordinates) == 1:
                            coordinate = nested_coordinates[0]
                            nested_coord = (
                                f"{coordinate['groupId']}:{coordinate['artifactId']}"
                            )
                            is_target_provider = nested_coord == case.bytecode_coord
                            runtime_lib_entries.append({
                                "coord": nested_coord,
                                "version": coordinate["version"],
                                "lib_entry": name,
                            })
                        else:
                            runtime_lib_entries.append({
                                "coord": f"runtime:{Path(name).stem}",
                                "version": "runtime",
                                "lib_entry": name,
                            })
                        if is_target_provider and name not in target_lib_candidates:
                            target_lib_candidates.append(name)
                        nested_root = (
                            extracted_root / "nested" /
                            f"{hashlib.sha256(name.encode('utf-8')).hexdigest()[:12]}-{Path(name).stem}"
                        )
                        for class_entry in sorted(nested.namelist()):
                            if not class_entry.endswith(".class") or class_entry.startswith("META-INF/"):
                                continue
                            if is_target_provider:
                                continue
                            class_bytes = nested.read(class_entry)
                            if owner_prefix_bytes and not any(
                                prefix in class_bytes for prefix in owner_prefix_bytes
                            ):
                                continue
                            destination = nested_root / class_entry
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            destination.write_bytes(class_bytes)
                            class_files.append(destination)
                except (KeyError, OSError, ValueError, zipfile.BadZipFile) as error:
                    raise RuntimeError(
                        f"FINAL_ARTIFACT_NESTED_CLASS_MATERIALIZATION_FAILED:"
                        f"{name}:{type(error).__name__}:{error}"
                    ) from error
    if not target_lib_candidates and len(target_filename_candidates) == 1:
        target_lib_candidates = target_filename_candidates
    if len(target_lib_candidates) == 1:
        target_lib_entry = target_lib_candidates[0]
    target_resolution_ambiguous = bool(
        not target_lib_entry
        and (len(target_lib_candidates) > 1 or len(target_filename_candidates) > 1)
    )
    class_files = sorted(set(class_files))
    if not class_files:
        raise ValueError("current final artifact contains no business class files")
    inventory_path = report_dir / ".runtime" / "final-artifact-class-inventory.json"
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_path.write_text(
        json.dumps({
            "schema_version": 1,
            "artifact_sha256": artifact_sha256,
            "extracted_root": str(extracted_root.resolve()),
            "class_files": [
                path.relative_to(extracted_root).as_posix() for path in class_files
            ],
        }, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    dependencies_dir = report_dir / "evidence" / "dependencies"
    dependencies_dir.mkdir(parents=True, exist_ok=True)
    context_dir = report_dir / "evidence" / "context"
    context_dir.mkdir(parents=True, exist_ok=True)
    (context_dir / "context.json").write_text(
        json.dumps({"jdk_current": artifact_java_version or "unknown"}, indent=2) + "\n",
        encoding="utf-8",
    )
    (dependencies_dir / "build_provenance.json").write_text(json.dumps({
        "sides": [{
            "side": "current",
            "artifact_path": str(artifact),
            "artifact_sha256": artifact_sha256,
        }],
    }, indent=2) + "\n", encoding="utf-8")
    with open_csv_write(dependencies_dir / "deps_current_resolved.csv") as fh:
        fields = ["coord", "version", "scope", "lib_entry", "resolution_status"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        if target_lib_entry:
            filename = Path(target_lib_entry).name
            target_version = filename[len(artifact_id) + 1:-4] or "runtime"
            writer.writerow({
                "coord": case.bytecode_coord,
                "version": target_version,
                "scope": "compile",
                "lib_entry": target_lib_entry,
                "resolution_status": "resolved",
            })
        elif target_resolution_ambiguous:
            writer.writerow({
                "coord": case.bytecode_coord,
                "version": "runtime",
                "scope": "compile",
                "lib_entry": "",
                "resolution_status": "unresolved",
            })
        for runtime_item in runtime_lib_entries:
            if runtime_item["lib_entry"] == target_lib_entry:
                continue
            writer.writerow({
                "coord": runtime_item["coord"],
                "version": runtime_item["version"],
                "scope": "runtime",
                "lib_entry": runtime_item["lib_entry"],
                "resolution_status": "resolved",
            })
    if selected_changed_apis is not None and selected_changed_apis.is_file():
        return selected_changed_apis
    discovered = discover_calls(
        class_files,
        owner_prefixes=case.bytecode_owner_prefixes,
        coord=case.bytecode_coord,
        evidence_dir=report_dir / "evidence" / "quality" / "jdk-javap-discovery",
    )
    rows = []
    for row in discovered:
        rows.append({
            "coord": row["coord"],
            "old_version": "bytecode-observed",
            "new_version": "-",
            "change_type": "REMOVED",
            "api_name": row["api_name"],
            "api_simple": row["api_name"].rsplit(".", 1)[-1],
            "symbol_kind": row["symbol_kind"],
            "api_signature": row["api_signature"],
            "confirmed": "true",
            "severity": "P1",
            "source": "third_party_jdk_bytecode_discovery",
        })
    generated_case = replace(case, changed_api_rows=tuple(rows), prefer_embedded_changed_api_rows=True)
    generated_changed_apis = ensure_changed_apis(
        generated_case,
        Path(""),
        report_dir / "evidence" / "api_changes" / "all_changed_apis.csv",
    )
    if selected_changed_apis is not None and selected_changed_apis.is_file():
        return selected_changed_apis
    return generated_changed_apis


def load_materialized_class_inventory(report_dir: Path, artifact: Path) -> list[Path]:
    """Load only class files materialized by the current artifact run."""
    inventory_path = Path(report_dir) / ".runtime" / "final-artifact-class-inventory.json"
    payload = json.loads(inventory_path.read_text(encoding="utf-8"))
    expected_sha = hashlib.sha256(Path(artifact).read_bytes()).hexdigest()
    if str(payload.get("artifact_sha256") or "") != expected_sha:
        raise ValueError("materialized class inventory artifact SHA mismatch")
    extracted_root = Path(str(payload.get("extracted_root") or "")).resolve()
    expected_root = (
        Path(report_dir) / ".runtime" / "final-artifact-classes" / expected_sha[:16]
    ).resolve()
    if extracted_root != expected_root:
        raise ValueError("materialized class inventory root mismatch")
    class_files = []
    for value in payload.get("class_files") or []:
        relative = PurePosixPath(str(value or ""))
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError(f"unsafe materialized class inventory entry: {value}")
        candidate = extracted_root.joinpath(*relative.parts).resolve()
        if candidate.parent != extracted_root and extracted_root not in candidate.parents:
            raise ValueError(f"materialized class inventory entry escaped root: {value}")
        if not candidate.is_file():
            raise ValueError(f"materialized class inventory entry missing: {value}")
        class_files.append(candidate)
    if not class_files:
        raise ValueError("materialized class inventory is empty")
    return sorted(set(class_files))


def materialize_step4_inputs(case: RealProjectCase, report_dir: Path) -> tuple[Path, Path]:
    runtime_dir = report_dir / ".runtime" / "real_project_regression"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    dep_changes = runtime_dir / "s1_dep_changes.csv"
    context = runtime_dir / "s2_context.json"
    fields = [
        "coord",
        "old_version",
        "new_version",
        "change_type",
        "scope",
        "base_coord",
        "current_coord",
        "base_lib_entry",
        "current_lib_entry",
    ]
    with open_csv_write(dep_changes) as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in case.step4_dep_rows:
            normalized = {field: str((row or {}).get(field) or "") for field in fields}
            if not normalized.get("scope"):
                normalized["scope"] = "compile"
            writer.writerow(normalized)
    context.write_text(
        json.dumps(
            {
                "changed_dependencies": [
                    {"coord": str((row or {}).get("coord") or "").strip()}
                    for row in case.step4_dep_rows
                    if str((row or {}).get("coord") or "").strip()
                ]
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return dep_changes, context


def validate_step4_population_contract(case: RealProjectCase) -> None:
    if not case.derive_step1_from_artifacts:
        return
    if case.step4_dep_rows:
        raise ValueError(
            "artifact-derived Step4 population cannot declare step4_dep_rows"
        )
    if case.base_final_artifact is None or case.final_artifact is None:
        raise ValueError(
            "artifact-derived Step4 population requires base and current final artifacts"
        )


def requires_full_step4_population(case: RealProjectCase, requested: bool) -> bool:
    return bool(requested or case.case_mode in {"discovery", "convergence"})


def derive_step4_inputs_from_artifacts(
    case: RealProjectCase, report_dir: Path
) -> tuple[Path, Path, list[dict]]:
    validate_step4_population_contract(case)
    dependency_dir = report_dir / "evidence" / "dependencies"
    context_dir = report_dir / "evidence" / "context"
    dependency_dir.mkdir(parents=True, exist_ok=True)
    context_dir.mkdir(parents=True, exist_ok=True)
    dep_changes = dependency_dir / "dep_changes.csv"
    context = context_dir / "s2_context.json"
    base_source = case.base_source_project or case.default_project
    current_source = case.current_source_project or case.default_project
    state_dir = report_dir / ".runtime" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    pinned_input = {}
    for side, revision in (("base", case.base_revision), ("current", case.current_revision)):
        if not revision:
            continue
        pinned_input.update({
            f"{side}_requested_ref": revision,
            f"{side}_resolved_ref": revision,
            f"{side}_resolved_commit": revision,
            f"{side}_ref_resolution_mode": "pinned_real_project_fixture",
            f"{side}_ref_source_status": "user_confirmed_local_source",
            f"{side}_allow_local_source": True,
        })
    if case.target_module:
        project_scope = build_project_scope(
            current_source,
            case.target_module,
            active_profiles=set(case.active_maven_profiles),
        )
        pinned_input.update({
            "target_module": case.target_module,
            "primary_module": case.target_module,
            "modules": [case.target_module],
            "active_maven_profiles": list(case.active_maven_profiles),
            "project_scope": project_scope,
        })
    (state_dir / "main_state.json").write_text(
        json.dumps({"step1": {"input": pinned_input}}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    step1_env = {
        **os.environ,
        "JUA_ORCHESTRATED": "1",
        "UPGRADE_REPORT_DIR": str(report_dir.resolve()),
    }
    step1_cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "s1_dep_diff.py"),
        "--base-artifact-path",
        str(case.base_final_artifact),
        "--current-artifact-path",
        str(case.final_artifact),
        "--base-source-project-dir",
        str(base_source),
        "--current-source-project-dir",
        str(current_source),
        "--output",
        str(dep_changes),
    ]
    if case.base_revision:
        step1_cmd.extend(("--base", case.base_revision))
    if case.current_revision:
        step1_cmd.extend(("--current", case.current_revision))
    if case.target_module:
        step1_cmd.extend(("--primary-module", case.target_module))
    for override in case.manual_coord_overrides:
        step1_cmd.extend(("--manual-coord-override", override))
    step1 = subprocess.run(
        step1_cmd, cwd=ROOT_DIR, env=step1_env, text=True,
        encoding="utf-8", errors="replace", timeout=900
    )
    runs = [{"step": "step1", "returncode": step1.returncode, "command": step1_cmd}]
    if step1.returncode != 0:
        return dep_changes, context, runs

    step2_cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "s2_context_from_deps.py"),
        "--dep-changes",
        str(dep_changes),
        "--work-dir",
        str(current_source),
        "--output",
        str(context),
    ]
    if case.base_revision:
        step2_cmd.extend(("--base", case.base_revision))
    if case.current_revision:
        step2_cmd.extend(("--current", case.current_revision))
    if case.source_dirs:
        step2_cmd.append("--source-dirs")
        step2_cmd.extend(str(current_source / source_dir) for source_dir in case.source_dirs)
    step2 = subprocess.run(
        step2_cmd, cwd=ROOT_DIR, text=True, encoding="utf-8", errors="replace", timeout=900
    )
    runs.append({"step": "step2", "returncode": step2.returncode, "command": step2_cmd})
    return dep_changes, context, runs


def run_step4(case: RealProjectCase, report_dir: Path) -> dict:
    output_dir = report_dir / "evidence" / "api_changes"
    output_dir.mkdir(parents=True, exist_ok=True)
    preparation_runs: list[dict] = []
    if case.derive_step1_from_artifacts:
        dep_changes, context, preparation_runs = derive_step4_inputs_from_artifacts(
            case, report_dir
        )
        preparation_returncode = next(
            (
                int(run["returncode"])
                for run in preparation_runs
                if int(run["returncode"]) != 0
            ),
            0,
        )
        if preparation_returncode:
            return {
                "returncode": preparation_returncode,
                "elapsed_seconds": 0.0,
                "dep_changes": str(dep_changes),
                "context": str(context),
                "output_dir": str(output_dir),
                "all_changed_apis": str(output_dir / "all_changed_apis.csv"),
                "population_source": "step1_final_artifacts",
                "preparation_runs": preparation_runs,
            }
    else:
        dep_changes, context = materialize_step4_inputs(case, report_dir)
    cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "s4_jar_compare.py"),
        "--dep-changes",
        str(dep_changes),
        "--context",
        str(context),
        "--output-dir",
        str(output_dir),
        "--allow-degraded",
        "--workers",
        "1",
        "--fetch-timeout",
        "30",
    ]
    start = time.time()
    proc = subprocess.run(cmd, cwd=ROOT_DIR, text=True, encoding="utf-8", errors="replace", timeout=900)
    elapsed = time.time() - start
    return {
        "returncode": proc.returncode,
        "elapsed_seconds": round(elapsed, 2),
        "dep_changes": str(dep_changes),
        "context": str(context),
        "output_dir": str(output_dir),
        "all_changed_apis": str(output_dir / "all_changed_apis.csv"),
        "population_source": (
            "step1_final_artifacts" if case.derive_step1_from_artifacts else "declared_dependency_rows"
        ),
        "preparation_runs": preparation_runs,
    }


def select_step4_changed_apis(step4_all_changed_apis: Path, selected_names: Iterable[str], output_path: Path) -> dict:
    selected_set = {str(name or "").strip() for name in selected_names if str(name or "").strip()}
    if not step4_all_changed_apis.exists():
        return {
            "status": "missing",
            "source": str(step4_all_changed_apis),
            "selected": str(output_path),
            "total_rows": 0,
            "selected_rows": 0,
            "missing_api_names": sorted(selected_set),
        }
    with open_csv_read(step4_all_changed_apis) as fh:
        reader = csv.DictReader(fh)
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    matched_names = {str(row.get("api_name") or "").strip() for row in rows if str(row.get("api_name") or "").strip() in selected_set}
    selected_rows = [row for row in rows if str(row.get("api_name") or "").strip() in selected_set]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(output_path) as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(selected_rows)
    return {
        "status": "ok",
        "source": str(step4_all_changed_apis),
        "selected": str(output_path),
        "total_rows": len(rows),
        "selected_rows": len(selected_rows),
        "matched_api_names": sorted(matched_names),
        "missing_api_names": sorted(selected_set - matched_names),
    }


def run_step5(case: RealProjectCase, project_root: Path, changed_apis: Path, report_dir: Path) -> tuple[int, float]:
    output_dir = report_dir / "evidence" / "call_chain"
    configured_source_dirs = case.source_dirs or (Path("."),)
    source_dirs = [
        source_dir if source_dir.is_absolute() else project_root / source_dir
        for source_dir in configured_source_dirs
    ]
    cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "s5_call_chain.py"),
        "--all-changed-apis",
        str(changed_apis),
        "--source-dirs",
        *(str(source_dir) for source_dir in source_dirs),
        "--report-dir",
        str(report_dir),
        "--output-dir",
        str(output_dir),
        "--max-depth",
        "5",
        "--allow-degraded",
    ]
    start = time.time()
    timeout_seconds = float(case.max_elapsed_seconds or 900.0)
    try:
        proc = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
        return proc.returncode, time.time() - start
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        timeout_path = report_dir / "evidence" / "quality" / "step5_timeout.json"
        timeout_path.parent.mkdir(parents=True, exist_ok=True)
        timeout_path.write_text(json.dumps({
            "reason": "STEP5_PERFORMANCE_BUDGET_EXCEEDED",
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": round(elapsed, 3),
            "command": cmd,
        }, indent=2) + "\n", encoding="utf-8")
        return 124, elapsed


def run_step5_cache_equivalence(
    case: RealProjectCase,
    project_root: Path,
    changed_apis: Path,
    report_dir: Path,
) -> dict:
    """Run a cache-cold Step5 and, when gated, prove a warm run is semantic-equivalent."""
    def clear_result_contract() -> None:
        call_chain_dir = Path(report_dir) / "evidence" / "call_chain"
        for path in call_chain_dir.glob("alerts*.csv"):
            path.unlink(missing_ok=True)
        (call_chain_dir / "summary.json").unlink(missing_ok=True)
        shutil.rmtree(call_chain_dir / "by_api", ignore_errors=True)
        (
            Path(report_dir) / ".runtime" / "indexes" / "s5_query_index.json"
        ).unlink(missing_ok=True)

    def result_contract_complete() -> bool:
        files_complete = all(path.is_file() for path in (
            Path(report_dir) / "evidence" / "call_chain" / "summary.json",
            Path(report_dir) / "evidence" / "call_chain" / "alerts.csv",
            Path(report_dir) / ".runtime" / "indexes" / "s5_query_index.json",
        ))
        if not files_complete:
            return False
        return not validate_alert_partition_contract(
            Path(report_dir), load_summary(Path(report_dir))
        )

    required = bool(case.require_relative_performance_baseline)
    if required:
        cache_dir = Path(report_dir) / ".runtime" / "cache"
        for cache_path in cache_dir.glob("s5_*"):
            if cache_path.is_dir():
                shutil.rmtree(cache_path, ignore_errors=True)
            else:
                cache_path.unlink(missing_ok=True)
    clear_result_contract()
    cold_returncode, cold_elapsed = run_step5(
        case, project_root, changed_apis, report_dir
    )
    result = {
        "required": required,
        "passed": cold_returncode == 0,
        "cold_returncode": cold_returncode,
        "cold_elapsed_seconds": cold_elapsed,
        "cold_fingerprint": "",
        "cold_summary": load_summary(report_dir),
        "cold_metrics": {},
        "warm_returncode": None,
        "warm_elapsed_seconds": None,
        "warm_fingerprint": "",
        "errors": [],
    }
    if (
        cold_returncode != 0
        or not result["cold_summary"]
        or not result_contract_complete()
    ):
        result["passed"] = False
        result["errors"].append("cold_step5_failed_or_summary_missing")
        return result
    result["cold_fingerprint"] = canonical_step5_result_fingerprint(report_dir)
    if not required:
        return result
    try:
        result["cold_metrics"] = cold_run_metrics(report_dir)
    except (OSError, ValueError) as error:
        result["passed"] = False
        result["errors"].append(
            f"cold_step5_timing_missing_or_invalid:{type(error).__name__}"
        )
        return result
    clear_result_contract()
    warm_returncode, warm_elapsed = run_step5(
        case, project_root, changed_apis, report_dir
    )
    result["warm_returncode"] = warm_returncode
    result["warm_elapsed_seconds"] = warm_elapsed
    if (
        warm_returncode != 0
        or not load_summary(report_dir)
        or not result_contract_complete()
    ):
        result["passed"] = False
        result["errors"].append("warm_step5_failed_or_summary_missing")
        return result
    result["warm_fingerprint"] = canonical_step5_result_fingerprint(report_dir)
    if result["warm_fingerprint"] != result["cold_fingerprint"]:
        result["passed"] = False
        result["errors"].append("cold_warm_semantic_fingerprint_mismatch")
    return result


def run_step6(report_dir: Path) -> dict:
    output_findings = report_dir / ".runtime" / "findings" / "s6_findings.json"
    output_report = report_dir / "deliverables" / "report.md"
    cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "s6_report.py"),
        "--report-dir",
        str(report_dir),
        "--output-findings",
        str(output_findings),
        "--output-report",
        str(output_report),
    ]
    start = time.time()
    proc = subprocess.run(
        cmd, cwd=ROOT_DIR, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=900,
    )
    elapsed = time.time() - start
    return {
        "returncode": proc.returncode,
        "elapsed_seconds": round(elapsed, 2),
        "findings": str(output_findings),
        "report": str(output_report),
        "stdout_tail": (proc.stdout or "")[-2000:],
        "stderr_tail": (proc.stderr or "")[-2000:],
    }


def query_step5(report_dir: Path, method: str) -> dict:
    cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "s5_query_call_chain.py"),
        "--report-dir",
        str(report_dir),
        "--method",
        method,
        "--limit",
        "5",
    ]
    proc = subprocess.run(
        cmd, cwd=ROOT_DIR, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=900,
    )
    return {
        "method": method,
        "returncode": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def load_summary(report_dir: Path) -> dict:
    summary_path = report_dir / "evidence" / "call_chain" / "summary.json"
    if not summary_path.exists():
        return {}
    return json.loads(summary_path.read_text(encoding="utf-8"))


def real_project_matrix_policy() -> dict:
    return {
        "role": "problem_finder",
        "lifecycle": ["exploration", "convergence", "guardian", "rotation"],
        "promotion_rules": [
            "fixture_debt",
            "convert_new_findings_to_l0_l1_l2_fixtures",
            "clear_p0_p1_fixture_debt_before_release",
            "keep_only_representative_guardian_probes_after_convergence",
            "rotate_to_new_project",
            "rotate_to_new_project_when_current_project_no_longer_finds_new_signals",
        ],
        "selection_bias": [
            "prefer_projects_with_uncovered_framework_or_build_shapes",
            "prefer_projects_that_exercise_current_capability_boundaries",
            "do_not_spend_discovery_budget_on_projects_whose_findings_are_already_fixtured",
        ],
    }


def collect_project_asset_health(project_root: Path) -> dict:
    java_files = list(iter_java_files(project_root)) if project_root.exists() else []
    main_java_files = [
        path for path in java_files
        if "/src/main/java/" in path.as_posix()
    ]
    generated_java_files = [
        path for path in java_files
        if "/target/generated-sources/" in path.as_posix()
        or "/generated-sources/" in path.as_posix()
    ]
    git_result = subprocess.run(
        ["git", "-C", str(project_root), "rev-parse", "--is-inside-work-tree"],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    valid_git_checkout = git_result.returncode == 0 and git_result.stdout.strip() == "true"
    revision = ""
    git_dirty = None
    extra_git_errors = []
    if valid_git_checkout:
        revision_result = subprocess.run(
            ["git", "-C", str(project_root), "rev-parse", "HEAD"],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if revision_result.returncode == 0:
            revision = revision_result.stdout.strip()
        else:
            extra_git_errors.append(
                (revision_result.stderr or revision_result.stdout or "git revision unavailable").strip()
            )
        dirty_result = subprocess.run(
            ["git", "-C", str(project_root), "status", "--porcelain"],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if dirty_result.returncode == 0:
            git_dirty = bool(dirty_result.stdout.strip())
        else:
            extra_git_errors.append(
                (dirty_result.stderr or dirty_result.stdout or "git status unavailable").strip()
            )
    generated_ratio = (len(generated_java_files) / len(java_files)) if java_files else 0.0
    initial_git_error = ""
    if not valid_git_checkout:
        initial_git_error = (git_result.stderr or git_result.stdout or "").strip()
    return {
        "valid_git_checkout": valid_git_checkout,
        "git_revision": revision,
        "git_dirty": git_dirty,
        "git_error": "; ".join(filter(None, [initial_git_error, *extra_git_errors])),
        "java_files": len(java_files),
        "main_java_files": len(main_java_files),
        "generated_java_files": len(generated_java_files),
        "generated_java_ratio": round(generated_ratio, 4),
    }


def project_asset_violations(case: RealProjectCase, health: dict) -> list[str]:
    violations: list[str] = []
    if case.require_valid_git and not health.get("valid_git_checkout"):
        violations.append("git_checkout_invalid")
    if case.min_project_java_files and int(health.get("java_files") or 0) < case.min_project_java_files:
        violations.append(
            f"java_files={int(health.get('java_files') or 0)} below_min={case.min_project_java_files}"
        )
    if case.min_main_java_files and int(health.get("main_java_files") or 0) < case.min_main_java_files:
        violations.append(
            f"main_java_files={int(health.get('main_java_files') or 0)} below_min={case.min_main_java_files}"
        )
    if (
        case.max_generated_java_ratio
        and float(health.get("generated_java_ratio") or 0.0) > case.max_generated_java_ratio
    ):
        violations.append(
            "generated_java_ratio="
            f"{float(health.get('generated_java_ratio') or 0.0):.4f} "
            f"over_max={case.max_generated_java_ratio:.4f}"
        )
    return violations


def make_signal(
    signal_type: str,
    severity: str,
    case: str,
    *,
    step: str = "",
    symbol: str = "",
    message: str = "",
    count: int = 0,
    expected: str = "",
    actual: str = "",
    evidence: Iterable[str] = (),
    fixture_status: str = "missing",
    notes: str = "",
    blocking: bool | None = None,
    reason_code: str = "",
    symbol_kind: str = "",
    sample_symbols: Iterable[str] = (),
) -> dict:
    if blocking is None:
        blocking = severity in {"P0", "P1"} and signal_type in {
            "correctness_failure",
            "capability_gap",
            "evidence_weakness",
            "performance_regression",
            "project_asset_invalid",
            "coverage_gap",
            "test_configuration_failure",
            "ground_truth_insufficient",
            "conclusion_gap",
            "topology_coverage_gap",
            "oracle_incomplete",
        }
    return {
        "signal_type": signal_type,
        "severity": severity,
        "blocking": bool(blocking),
        "case": case,
        "step": step,
        "symbol": symbol,
        "message": message,
        "count": int(count or 0),
        "expected": expected,
        "actual": actual,
        "evidence": [str(item) for item in evidence],
        "fixture_status": fixture_status,
        "notes": notes,
        "reason_code": reason_code,
        "symbol_kind": symbol_kind,
        "sample_symbols": [str(item) for item in sample_symbols],
    }


def build_topology_coverage_signals(
    case: RealProjectCase,
    coverage: dict,
    report_dir: Path,
) -> list[dict]:
    signals: list[dict] = []
    if case.case_mode in {"discovery", "convergence"} and not case.required_topologies:
        signals.append(make_signal(
            "topology_configuration_invalid", "P1", case.name, step="step5",
            message="discovery/convergence case has an empty required_topologies policy",
            expected="nonempty stable topology requirements", actual="[]", blocking=True,
        ))
        return signals
    if case.case_mode in {"discovery", "convergence"} and not coverage.get("prior_covered"):
        signals.append(make_signal(
            "topology_configuration_invalid", "P1", case.name, step="step5",
            message="discovery/convergence case has no persistent prior topology coverage",
            expected="nonempty configured or converged-guard prior set", actual="[]", blocking=True,
        ))
    if case.case_mode in {"discovery", "convergence"} and not coverage.get("prior_matrix_valid"):
        signals.append(make_signal(
            "topology_configuration_invalid", "P1", case.name, step="step5",
            message="pinned prior topology matrix is missing, corrupt, or invalid",
            expected="validated external prior matrix evidence", actual="invalid", blocking=True,
        ))
    if not coverage.get("evidence_complete"):
        signals.append(make_signal(
            "topology_evidence_invalid", "P1", case.name, step="step5",
            message="independent final-artifact topology evidence is missing or malformed",
            expected="complete final_artifact_edge_oracle extraction",
            actual="incomplete", evidence=[report_dir / "evidence" / "quality" / "topology_artifact_layout.json"],
            blocking=True,
        ))
    missing = list(coverage.get("missing") or [])
    if missing:
        signals.append(make_signal(
            "topology_coverage_gap", "P1", case.name, step="step5",
            message="Missing required stable topology IDs: " + ", ".join(missing),
            count=len(missing), expected=json.dumps(coverage.get("required") or []),
            actual=json.dumps(coverage.get("observed") or []),
            evidence=[report_dir / "evidence" / "quality" / "topology_coverage.json"],
            sample_symbols=missing, blocking=True,
        ))
    if coverage.get("rotation_required"):
        signals.append(make_signal(
            "topology_rotation_required", "P2", case.name, step="step5",
            message="discovery project observed no topology beyond prior coverage; rotate target",
            expected="nonempty observed minus prior_covered", actual="[]", blocking=False,
        ))
    return signals


def build_policy_signals(
    case: RealProjectCase,
    *,
    coverage: dict,
    performance: dict,
    report_dir: Path,
    oracle_audit: dict | None = None,
) -> list[dict]:
    signals: list[dict] = []
    if not coverage.get("complete"):
        signals.append(make_signal(
            "coverage_gap", "P1", case.name, step="step5",
            message=(
                f"API coverage incomplete: selected={coverage.get('apis_selected')} "
                f"population={coverage.get('api_population')} accounted={coverage.get('apis_accounted')}"
            ),
            expected="discovery and convergence cases analyze the complete Step4 API population",
            actual=json.dumps(coverage, sort_keys=True),
            evidence=[report_dir / "evidence" / "api_changes" / "all_changed_apis.csv"],
        ))
    needs_ground_truth = (
        bool(oracle_audit.get("blocking"))
        or int(oracle_audit.get("verified") or 0) != int(oracle_audit.get("selected") or 0)
        if oracle_audit is not None
        else case.ground_truth_status != "reviewed"
    )
    if needs_ground_truth and (
        oracle_audit is not None
        or case.case_mode in {"discovery", "convergence"}
    ):
        has_oracle_audit = oracle_audit is not None
        oracle_audit = oracle_audit or {}
        selected = int(oracle_audit.get("selected") or 0)
        verified = int(oracle_audit.get("verified") or 0)
        unverified = int(oracle_audit.get("unverified") or 0)
        incorrect = int(oracle_audit.get("incorrect") or 0)
        conflicts = int(oracle_audit.get("oracle_conflicts") or 0)
        if incorrect:
            signals.append(make_signal(
                "correctness_failure", "P0", case.name, step="step5",
                message=f"third-party oracle disagrees with {incorrect} analyzer conclusion(s)",
                count=incorrect,
                expected="analyzer conclusion equals independent third-party oracle conclusion",
                actual=f"incorrect={incorrect}",
                evidence=[report_dir / "evidence" / "quality" / "exhaustive_api_oracle.csv"],
            ))
        if conflicts:
            signals.append(make_signal(
                "ground_truth_insufficient", "P1", case.name, step="step5",
                message=f"third-party authorities conflict for {conflicts} API(s)",
                count=conflicts,
                expected="independent authorities agree without majority voting",
                actual=f"oracle_conflicts={conflicts}",
                evidence=[report_dir / "evidence" / "quality" / "exhaustive_api_oracle.csv"],
            ))
        if unverified or not has_oracle_audit:
            signals.append(make_signal(
                "ground_truth_insufficient", "P1", case.name, step="step5",
                message=(
                    f"exhaustive third-party oracle incomplete: verified={verified}/{selected}, "
                    f"unverified={unverified}, incorrect={incorrect}, conflicts={conflicts}"
                ),
                count=unverified,
                expected="one valid third-party oracle verdict for every selected API",
                actual=json.dumps({
                    "selected": selected, "verified": verified, "unverified": unverified,
                    "incorrect": incorrect, "oracle_conflicts": conflicts,
                }, sort_keys=True),
                evidence=[report_dir / "evidence" / "quality" / "exhaustive_api_oracle.csv"],
            ))
    oracle_timed_out = bool(performance.get("oracle_timed_out"))
    oracle_interrupted = bool(performance.get("oracle_interrupted"))
    if oracle_timed_out or oracle_interrupted:
        reason = "time budget exceeded" if oracle_timed_out else "scan interrupted"
        signals.append(make_signal(
            "performance_regression", "P1", case.name, step="step5",
            message=(
                f"final-artifact oracle {reason}: "
                f"elapsed={float(performance.get('oracle_elapsed_seconds') or 0.0):.3f}s "
                f"budget={case.max_oracle_seconds:.3f}s "
                f"completed={int(performance.get('oracle_completed_class_count') or 0)}/"
                f"{int(performance.get('oracle_class_count') or 0)} classes"
            ),
            expected="exhaustive final-artifact oracle completes within its per-case time budget",
            actual=json.dumps({
                "timed_out": oracle_timed_out,
                "interrupted": oracle_interrupted,
                "elapsed_seconds": float(performance.get("oracle_elapsed_seconds") or 0.0),
                "class_count": int(performance.get("oracle_class_count") or 0),
                "completed_class_count": int(performance.get("oracle_completed_class_count") or 0),
            }, sort_keys=True),
            evidence=[report_dir / "evidence" / "call_chain" / "oracle_edges.csv"],
        ))
    pairs_per_api = float(performance.get("potential_pairs_per_api") or 0.0)
    if case.max_potential_pairs_per_api and pairs_per_api > case.max_potential_pairs_per_api:
        signals.append(make_signal(
            "performance_regression", "P1", case.name, step="step5",
            message=(
                f"potential_pairs_per_api={pairs_per_api:.2f} "
                f"over_budget={case.max_potential_pairs_per_api:.2f}"
            ),
            expected="normalized candidate-pair metric stays within budget",
            actual=str(pairs_per_api),
            evidence=[report_dir / "evidence" / "call_chain" / "summary.json"],
        ))
    duplicate_class_scans = int(performance.get("duplicate_class_scans") or 0)
    if case.max_duplicate_class_scans >= 0 and duplicate_class_scans > case.max_duplicate_class_scans:
        signals.append(make_signal(
            "performance_regression", "P1", case.name, step="step5",
            message=(
                f"duplicate_class_scans={duplicate_class_scans} "
                f"over_budget={case.max_duplicate_class_scans}"
            ),
            expected="immutable artifact-hash cache prevents duplicate class parsing",
            actual=str(duplicate_class_scans),
            evidence=[report_dir / "evidence" / "call_chain" / "summary.json"],
        ))
    seconds_per_100k_edges = performance.get("elapsed_seconds_per_100k_edges")
    reconciled_edge_count = max(
        int(performance.get("oracle_edge_count") or 0),
        int(performance.get("analyzer_edge_count") or 0),
    ) + int(performance.get("semantic_reference_count") or 0)
    normalized_rate_eligible = (
        reconciled_edge_count >= int(case.min_edges_for_normalized_rate or 0)
    )
    edge_rate_available = performance.get("edge_rate_available")
    if edge_rate_available is None:
        edge_rate_available = seconds_per_100k_edges is not None
    edge_rate_available = bool(edge_rate_available)
    if case.max_seconds_per_100k_edges and not edge_rate_available:
        signals.append(make_signal(
            "performance_regression", "P1", case.name, step="step5",
            message=(
                "elapsed_seconds_per_100k_edges=unavailable because "
                "physical edge and semantic reference counts are all zero"
            ),
            expected="normalized analysis time has a nonzero independently audited evidence denominator",
            actual="unavailable",
            evidence=[report_dir / "evidence" / "call_chain" / "summary.json"],
        ))
    elif (
        case.max_seconds_per_100k_edges
        and normalized_rate_eligible
        and seconds_per_100k_edges is not None
        and float(seconds_per_100k_edges) > case.max_seconds_per_100k_edges
    ):
        signals.append(make_signal(
            "performance_regression", "P1", case.name, step="step5",
            message=(
                f"elapsed_seconds_per_100k_edges={float(seconds_per_100k_edges):.2f} "
                f"over_budget={case.max_seconds_per_100k_edges:.2f}"
            ),
            expected="normalized edge analysis time stays within budget",
            actual=str(seconds_per_100k_edges),
            evidence=[report_dir / "evidence" / "call_chain" / "summary.json"],
        ))
    classes_per_second = performance.get("parse_classes_per_second")
    parse_rate_available = performance.get("parse_rate_available")
    if parse_rate_available is None:
        parse_rate_available = classes_per_second is not None
    if case.min_classes_per_second and not parse_rate_available:
        signals.append(make_signal(
            "performance_regression", "P1", case.name, step="step5",
            message=(
                "parse_classes_per_second=unavailable because "
                "class_entries_parsed is zero or parse time is unavailable"
            ),
            expected="artifact parse throughput has parsed classes and measured parse time",
            actual="unavailable",
            evidence=[report_dir / "evidence" / "call_chain" / "summary.json"],
        ))
    elif (
        case.min_classes_per_second
        and float(classes_per_second) < case.min_classes_per_second
    ):
        signals.append(make_signal(
            "performance_regression", "P1", case.name, step="step5",
            message=(
                f"parse_classes_per_second={float(classes_per_second):.2f} "
                f"below_budget={case.min_classes_per_second:.2f}"
            ),
            expected="artifact parse throughput meets minimum classes per second",
            actual=str(classes_per_second),
            evidence=[report_dir / "evidence" / "call_chain" / "summary.json"],
        ))
    return signals


def build_quality_signals(
    case: RealProjectCase,
    *,
    summary: dict,
    checks: list[dict],
    failures: list[str],
    result_audit: dict,
    report_dir: Path,
    oracle_audit: dict | None = None,
    expected_uncertain: int = 0,
    expected_not_found: int = 0,
) -> list[dict]:
    signals: list[dict] = []
    conclusion_groups = group_conclusion_gaps(summary)
    for group in conclusion_groups:
        signals.append(make_signal(
            "conclusion_gap",
            "P1",
            case.name,
            step="step5",
            message=(
                f"{case.name} has {group['count']} not_analyzed {group['symbol_kind']} item(s): "
                f"{group['reason_code']}"
            ),
            count=group["count"],
            expected="every selected P0/P1 API has a reviewable conclusion",
            actual="not_analyzed",
            evidence=[report_dir / "evidence" / "call_chain" / "summary.json"],
            reason_code=group["reason_code"],
            symbol_kind=group["symbol_kind"],
            sample_symbols=group["sample_symbols"],
        ))
    verified_absence = sum(
        1 for row in ((oracle_audit or {}).get("ledger") or [])
        if row.get("analyzer_conclusion") == "not_found_in_static_analysis"
        and row.get("verdict") == "correct"
    )
    for field in ("not_analyzed", "not_found_in_static_analysis"):
        count = int(summary.get(field) or 0)
        if field == "not_found_in_static_analysis":
            count = max(
                0,
                count - max(verified_absence, max(0, int(expected_not_found or 0))),
            )
        if count and not (field == "not_analyzed" and conclusion_groups):
            signals.append(make_signal(
                "capability_gap",
                "P1",
                case.name,
                step="step5",
                message=f"{case.name} summary has {count} {field} item(s)",
                count=count,
                expected="available evidence should produce a reviewable conclusion",
                actual=field,
                evidence=[
                    report_dir / "evidence" / "call_chain" / "summary.json",
                    report_dir / "evidence" / "call_chain" / "alerts.csv",
                ],
            ))
    uncertain = max(
        0,
        int(summary.get("uncertain") or 0) - max(0, int(expected_uncertain or 0)),
    )
    if uncertain:
        signals.append(make_signal(
            "capability_gap",
            "P2",
            case.name,
            step="step5",
            message=f"{case.name} summary has {uncertain} uncertain item(s)",
            count=uncertain,
            expected="reduce uncertainty when source or bytecode evidence is sufficient",
            actual="uncertain",
            evidence=[report_dir / "evidence" / "call_chain" / "summary.json"],
            blocking=False,
        ))

    for check in checks:
        prod_missing = int(check.get("production_missing") or 0)
        if not prod_missing:
            continue
        symbol = str(check.get("symbol") or "")
        if check.get("gating"):
            signals.append(make_signal(
                "correctness_failure",
                "P1",
                case.name,
                step="step5",
                symbol=symbol,
                message=f"{symbol} missing {prod_missing} gated production baseline file(s)",
                count=prod_missing,
                expected="production baseline files represented in alerts.csv",
                actual="production baseline missing from alerts.csv",
                evidence=[report_dir / "evidence" / "call_chain" / "alerts.csv"],
                notes=str(check.get("notes") or ""),
            ))
        else:
            signals.append(make_signal(
                "capability_gap",
                "P2",
                case.name,
                step="step5",
                symbol=symbol,
                message=f"{symbol} has {prod_missing} non-gating production baseline miss(es)",
                count=prod_missing,
                expected="investigate whether the analyzer can distinguish this probe precisely",
                actual="non-gating baseline miss",
                evidence=[report_dir / "evidence" / "call_chain" / "alerts.csv"],
                notes=str(check.get("notes") or ""),
                blocking=False,
            ))

    for failure in result_audit.get("failures") or []:
        signals.append(make_signal(
            "evidence_weakness",
            "P1",
            case.name,
            step="step5",
            message=str(failure),
            expected="complete and reviewable evidence files",
            actual=str(failure),
            evidence=[report_dir / "evidence" / "call_chain" / "alerts.csv"],
        ))

    for failure in failures:
        text = str(failure)
        if text.startswith("performance:"):
            signals.append(make_signal(
                "performance_regression",
                "P1",
                case.name,
                step="step5",
                message=text,
                expected="real project performance stays within configured budget",
                actual=text,
                evidence=[
                    report_dir / "evidence" / "call_chain" / "summary.json",
                    report_dir / ".runtime" / "observability" / "step5_timing.csv",
                ],
            ))
        elif text.startswith(("graph_stats:", "source_shape:")):
            signals.append(make_signal(
                "capability_gap",
                "P1",
                case.name,
                step="step5",
                message=text,
                expected="real project scale and performance stay within configured thresholds",
                actual=text,
                evidence=[report_dir / "evidence" / "call_chain" / "summary.json"],
            ))
    return signals


def run_case(
    case: RealProjectCase,
    project_root: Path,
    changed_apis: Path,
    report_root: Path,
    *,
    full_step4_apis: bool = False,
    oracle_manifest: Path | None = None,
) -> dict:
    pinned_manifest: dict = {}
    pinned_asset_gate: dict = {}
    constant_input = {
        "required": False, "complete": True, "blocking": False,
        "changed_apis": str(changed_apis), "provider_artifact": "", "errors": [],
    }
    constant_reconciliation = dict(constant_input)
    if case.fixture_manifest is not None:
        report_dir = report_root / case.name
        report_dir.mkdir(parents=True, exist_ok=True)
        try:
            pinned_manifest = load_pinned_guard_manifest(case)
            pinned_asset_gate = validate_pinned_asset(pinned_manifest, project_root)
            pinned_asset_gate["source_mode"] = pinned_source_mode(pinned_manifest)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            pinned_asset_gate = {
                "name": "asset", "passed": False,
                "errors": [f"pinned_manifest_invalid:{error}"],
            }
        if not pinned_asset_gate.get("passed"):
            asset_signal = make_signal(
                "project_asset_invalid", "P1", case.name,
                message="; ".join(pinned_asset_gate.get("errors") or []),
                expected=(
                    "pinned Git revision and valid runtime-identified source artifact, "
                    "or exact SHA-verified published artifact"
                ),
                actual=json.dumps(pinned_asset_gate, sort_keys=True),
                evidence=[project_root, case.fixture_manifest],
                fixture_status="missing",
                blocking=True,
            )
            asset_signal["fixture_debt_id"] = "pinned_asset_unavailable"
            skeleton = {
                "api_coverage_complete": False,
                "summary": {},
                "topology_coverage": {
                    "complete": False,
                    "observed": [],
                    "missing": list(case.required_topologies),
                },
                "edge_truth": {"complete": False, "blocking": True, "ledger": []},
                "quality_signals": [asset_signal],
            }
            fixture_debt, gates = _resolve_fixture_debt(
                pinned_manifest, skeleton, pinned_asset_gate, [asset_signal]
            )
            output_files = write_v3_guard_outputs(report_dir, gates, fixture_debt)
            return {
                "case": case.name,
                "status": "failed",
                "reason": "pinned project asset invalid",
                "project_root": str(project_root),
                "report_dir": str(report_dir),
                "asset": pinned_asset_gate,
                "gates": gates,
                "fixture_debt": fixture_debt,
                "v3_output_files": output_files,
                "matrix_policy": real_project_matrix_policy(),
                "quality_signals": [asset_signal],
            }
        case = replace(case, final_artifact=Path(str(pinned_asset_gate["artifact_path"])))
        write_pinned_final_artifact_provenance(report_dir, pinned_asset_gate, case)
    if not project_root.exists():
        reason = f"project root missing: {project_root}"
        return {
            "case": case.name,
            "status": "failed",
            "reason": reason,
            "matrix_policy": real_project_matrix_policy(),
            "quality_signals": [
                make_signal(
                    "project_asset_invalid",
                    "P1",
                    case.name,
                    message=reason,
                    actual="real project checkout unavailable",
                    blocking=True,
                    fixture_status="",
                )
            ],
        }
    project_asset_health = collect_project_asset_health(project_root)
    asset_violations = project_asset_violations(case, project_asset_health)
    if asset_violations:
        return {
            "case": case.name,
            "status": "failed",
            "reason": "project asset invalid",
            "project_root": str(project_root),
            "project_asset_health": project_asset_health,
            "project_asset_violations": asset_violations,
            "matrix_policy": real_project_matrix_policy(),
            "quality_signals": [
                make_signal(
                    "project_asset_invalid",
                    "P1",
                    case.name,
                    message="; ".join(asset_violations),
                    expected="real project asset matches case scale and checkout assumptions",
                    actual=json.dumps(project_asset_health, ensure_ascii=False, sort_keys=True),
                    evidence=[project_root],
                    fixture_status="",
                )
            ],
        }
    report_dir = report_root / case.name
    report_dir.mkdir(parents=True, exist_ok=True)
    requires_final_artifact = bool(
        case.bytecode_owner_prefixes
        or case.enable_jdk_oracle
        or case.required_topologies
    )
    if requires_final_artifact and (
        case.final_artifact is None or not case.final_artifact.is_file()
    ):
        reason = "current final artifact unavailable"
        return {
            "case": case.name,
            "status": "failed",
            "reason": reason,
            "project_root": str(project_root),
            "report_dir": str(report_dir),
            "matrix_policy": real_project_matrix_policy(),
            "quality_signals": [make_signal(
                "project_asset_invalid",
                "P1",
                case.name,
                message=reason,
                expected="SHA-verifiable current final artifact for bytecode discovery",
                actual=str(case.final_artifact or ""),
                evidence=[project_root, case.final_artifact or report_dir],
                blocking=True,
                fixture_status="missing",
            )],
        }
    if case.bytecode_owner_prefixes:
        explicit_changed_apis = changed_apis if changed_apis.is_file() else None
        changed_apis = materialize_bytecode_changed_apis(
            case,
            project_root,
            report_dir,
            selected_changed_apis=explicit_changed_apis,
        )
    elif case.fixture_manifest is None and case.final_artifact is not None:
        write_declared_final_artifact_provenance(report_dir, case)
    step4_result = {}
    step4_selection = {}
    failures = []
    warnings = []
    if case.run_step4:
        step4_result = run_step4(case, report_dir)
        if pinned_asset_gate.get("passed"):
            write_pinned_final_artifact_provenance(
                report_dir, pinned_asset_gate, case
            )
        step4_all_changed_apis = Path(step4_result.get("all_changed_apis") or "")
        if step4_result.get("returncode") != 0:
            failures.append(f"step4_returncode={step4_result.get('returncode')}")
        if case.max_step4_elapsed_seconds and float(step4_result.get("elapsed_seconds") or 0.0) > case.max_step4_elapsed_seconds:
            failures.append(
                "step4_performance: "
                f"elapsed={float(step4_result.get('elapsed_seconds') or 0.0):.2f}s "
                f"over_budget={case.max_step4_elapsed_seconds:.2f}s"
            )
        use_full_step4_population = requires_full_step4_population(
            case, full_step4_apis
        )
        if use_full_step4_population:
            _, step4_rows = _csv_rows(step4_all_changed_apis)
            step4_api_names = {
                str(row.get("api_name") or "").strip()
                for row in step4_rows
                if str(row.get("api_name") or "").strip()
            }
            expected_names = {
                str(name or "").strip()
                for name in (case.expected_step4_api_names or ())
                if str(name or "").strip()
            }
            missing_expected = sorted(expected_names - step4_api_names)
            step4_selection = {
                "status": "full",
                "source": str(step4_all_changed_apis),
                "selected": str(step4_all_changed_apis),
                "total_rows": len(step4_rows),
                "selected_rows": len(step4_rows),
                "missing_api_names": missing_expected,
            }
            for missing in missing_expected:
                failures.append(f"step4_missing_expected_api:{missing}")
            if int(step4_selection.get("selected_rows") or 0) <= 0:
                failures.append("step4_full_changed_apis_empty")
            changed_apis = step4_all_changed_apis
        else:
            selected_names = case.expected_step4_api_names or tuple(
                str(row.get("api_name") or "").strip()
                for row in case.changed_api_rows
                if str(row.get("api_name") or "").strip()
            )
            step4_selection = select_step4_changed_apis(
                step4_all_changed_apis,
                selected_names,
                report_dir / "evidence" / "api_changes" / "selected_all_changed_apis.csv",
            )
            for missing in step4_selection.get("missing_api_names") or []:
                failures.append(f"step4_missing_expected_api:{missing}")
            if int(step4_selection.get("selected_rows") or 0) <= 0:
                failures.append("step4_selected_changed_apis_empty")
            changed_apis = Path(step4_selection.get("selected") or "")
    else:
        changed_apis = ensure_changed_apis(
            case,
            changed_apis,
            report_dir / "evidence" / "api_changes" / "all_changed_apis.csv",
        )
    performance_budget = (
        case.max_full_step4_api_elapsed_seconds
        if requires_full_step4_population(case, full_step4_apis)
        and case.max_full_step4_api_elapsed_seconds
        else case.max_elapsed_seconds
    )

    if not changed_apis.exists():
        if failures:
            missing_reason = f"changed APIs missing: {changed_apis}"
            return {
                "case": case.name,
                "status": "failed",
                "project_root": str(project_root),
                "changed_apis": str(changed_apis),
                "report_dir": str(report_dir),
                "elapsed_seconds": 0.0,
                "performance_budget_seconds": performance_budget,
                "step4": step4_result,
                "step4_selection": step4_selection,
                "step5_returncode": None,
                "summary": {},
                "graph_stats": {},
                "source_shape_metrics": {},
                "step6": {},
                "queries": [],
                "checks": [],
                "failures": failures + [missing_reason],
                "warnings": warnings,
                "matrix_policy": real_project_matrix_policy(),
                "quality_signals": [
                    make_signal(
                        "project_asset_invalid",
                        "P1",
                        case.name,
                        step="step4",
                        message=missing_reason,
                        actual="changed API input unavailable",
                        blocking=True,
                        fixture_status="",
                    )
                ],
            }
        reason = f"changed APIs missing: {changed_apis}"
        return {
            "case": case.name,
            "status": "failed",
            "reason": reason,
            "matrix_policy": real_project_matrix_policy(),
            "quality_signals": [
                make_signal(
                    "project_asset_invalid",
                    "P1",
                    case.name,
                    step="step4",
                    message=reason,
                    actual="changed API input unavailable",
                    blocking=True,
                    fixture_status="",
                )
            ],
        }

    constant_input = prepare_constant_project_input(
        pinned_manifest, changed_apis, report_dir, project_root=project_root
    )
    if constant_input.get("complete"):
        changed_apis = Path(str(constant_input.get("changed_apis") or changed_apis))

    execution_case = (
        replace(case, max_elapsed_seconds=performance_budget)
        if performance_budget != case.max_elapsed_seconds
        else case
    )
    cache_equivalence = run_step5_cache_equivalence(
        execution_case, project_root, changed_apis, report_dir
    )
    returncode = (
        cache_equivalence.get("warm_returncode")
        if cache_equivalence.get("warm_returncode") is not None
        else cache_equivalence.get("cold_returncode")
    )
    elapsed = float(cache_equivalence.get("cold_elapsed_seconds") or 0.0)
    if not cache_equivalence.get("passed"):
        failures.extend(cache_equivalence.get("errors") or [])
    summary = load_summary(report_dir)
    if returncode != 0 or not summary:
        execution_failures = list(failures)
        if returncode != 0:
            execution_failures.append(f"step5_returncode={returncode}")
        if not summary:
            execution_failures.append("step5_summary_missing")
        if performance_budget and elapsed > performance_budget:
            execution_failures.append(
                f"performance: elapsed={elapsed:.2f}s over_budget={performance_budget:.2f}s"
            )
        execution_signal = make_signal(
            "step5_execution_failure",
            "P0",
            case.name,
            step="step5",
            message="Step5 failed or did not produce a complete summary; edge truth audit was skipped",
            expected="returncode=0 and readable summary.json before edge reconciliation",
            actual="; ".join(execution_failures),
            evidence=[
                report_dir / "evidence" / "quality" / "step5_timeout.json",
                report_dir / "evidence" / "call_chain" / "summary.json",
            ],
            blocking=True,
        )
        return {
            "case": case.name,
            "status": "failed",
            "reason": "Step5 execution did not produce a complete summary",
            "project_root": str(project_root),
            "changed_apis": str(changed_apis),
            "report_dir": str(report_dir),
            "elapsed_seconds": round(elapsed, 3),
            "performance_budget_seconds": performance_budget,
            "step5_returncode": returncode,
            "cache_equivalence": cache_equivalence,
            "summary": summary,
            "failures": execution_failures,
            "warnings": [],
            "project_asset_health": project_asset_health,
            "matrix_policy": real_project_matrix_policy(),
            "quality_signals": [execution_signal] + build_cache_equivalence_signals(
                case, cache_equivalence, report_dir
            ),
        }
    graph_stats = extract_graph_stats(summary)
    source_shape_metrics = collect_source_shape_metrics(project_root, case.source_shape_patterns)
    alerts_csv = report_dir / "evidence" / "call_chain" / "alerts.csv"
    checks = []
    step6_result = {}
    query_results = []
    result_audit = {}

    for name, minimum_files in (case.min_source_shape_files or {}).items():
        actual_files = int((source_shape_metrics.get(name) or {}).get("files") or 0)
        if actual_files < int(minimum_files or 0):
            failures.append(f"source_shape:{name}: files={actual_files} below_min={minimum_files}")

    if case.min_methods_indexed and graph_stats["methods_indexed"] < case.min_methods_indexed:
        failures.append(
            f"graph_stats: methods_indexed={graph_stats['methods_indexed']} below_min={case.min_methods_indexed}"
        )
    if case.min_reverse_edges_indexed and graph_stats["reverse_edges_indexed"] < case.min_reverse_edges_indexed:
        failures.append(
            "graph_stats: reverse_edges_indexed="
            f"{graph_stats['reverse_edges_indexed']} below_min={case.min_reverse_edges_indexed}"
        )
    if graph_stats["truncated"] or graph_stats["edge_cap_hits"]:
        failures.append(
            f"graph_stats: truncated={graph_stats['truncated']} edge_cap_hits={graph_stats['edge_cap_hits']}"
        )
    if performance_budget and elapsed > performance_budget:
        failures.append(f"performance: elapsed={elapsed:.2f}s over_budget={performance_budget:.2f}s")
    if not alerts_csv.exists():
        failures.append("alerts.csv missing")
    elif alerts_csv.stat().st_size == 0:
        failures.append("alerts.csv empty")
    failures.extend(validate_alert_partition_contract(report_dir, summary))

    result_audit = audit_analysis_outputs(changed_apis, alerts_csv, summary)
    failures.extend(result_audit.get("failures") or [])
    warnings.extend(result_audit.get("warnings") or [])

    for spec in case.baseline_specs:
        production_baseline, test_baseline, occurrences = collect_baseline_files(project_root, spec)
        alert_files = collect_alert_files(alerts_csv, spec.symbol, project_root=project_root)
        production_missing = sorted(production_baseline - alert_files)
        test_missing = sorted(test_baseline - alert_files)
        extra = sorted(alert_files - production_baseline - test_baseline)
        project_root_resolved = project_root.resolve()
        check = {
            "symbol": spec.symbol,
            "gating": spec.require_zero_production_missing,
            "occurrences": occurrences,
            "baseline_production_files": len(production_baseline),
            "baseline_test_files": len(test_baseline),
            "alert_files": len(alert_files),
            "production_missing": len(production_missing),
            "test_missing": len(test_missing),
            "extra_alert_files": len(extra),
            "notes": spec.notes,
            "production_missing_files": [str(Path(item).resolve().relative_to(project_root_resolved)) for item in production_missing[:20]],
            "test_missing_files": [str(Path(item).resolve().relative_to(project_root_resolved)) for item in test_missing[:20]],
        }
        checks.append(check)
        if spec.require_zero_production_missing and production_missing:
            failures.append(f"{spec.symbol}: production_missing={len(production_missing)}")
        if spec.require_zero_production_missing and not production_baseline:
            failures.append(f"{spec.symbol}: production_baseline_empty")

    if case.run_step6_report and returncode == 0:
        step6_result = run_step6(report_dir)
        report_path = Path(step6_result.get("report") or "")
        findings_path = Path(step6_result.get("findings") or "")
        if step6_result.get("returncode") != 0:
            failures.append(f"step6_returncode={step6_result.get('returncode')}")
        if not report_path.exists() or report_path.stat().st_size == 0:
            failures.append("step6_report_missing_or_empty")
        else:
            report_text = report_path.read_text(encoding="utf-8", errors="ignore")
            for marker in (
                "__business__", "**business**", "<class>", "<clinit>",
                "源码图存在目标调用", "revision/profile", "fallback simple key",
            ):
                if marker in report_text:
                    failures.append(f"step6_report_internal_marker:{marker}")
            for expected in case.expected_report_texts:
                if expected not in report_text:
                    failures.append(f"step6_report_missing_text:{expected}")
        if not findings_path.exists() or findings_path.stat().st_size == 0:
            failures.append("step6_findings_missing_or_empty")

    for method in case.query_methods:
        query_result = query_step5(report_dir, method)
        query_results.append(query_result)
        output = query_result.get("stdout") or ""
        if query_result.get("returncode") != 0:
            failures.append(f"query_returncode:{method}={query_result.get('returncode')}")
        if "未找到调用链" in output or "找到" not in output:
            failures.append(f"query_no_chain:{method}")
        owner = method.split("(", 1)[0]
        if owner and owner not in output:
            failures.append(f"query_missing_method:{method}")

    if returncode != 0:
        failures.append(f"step5_returncode={returncode}")
    _, selected_rows = _csv_rows(changed_apis)
    if constant_input.get("required"):
        if constant_input.get("complete"):
            try:
                analyzer_edge_path = (
                    report_dir / "evidence" / "call_chain" / "analyzer_edges.csv"
                )
                _edge_fields, constant_analyzer_edges = (
                    _csv_rows(analyzer_edge_path)
                    if analyzer_edge_path.is_file() else ([], [])
                )
                consumer_sha256 = (
                    hashlib.sha256(Path(case.final_artifact).read_bytes()).hexdigest()
                    if analyzer_edge_path.is_file() and case.final_artifact else ""
                )
                constant_reconciliation = reconcile_constant_project_evidence(
                    Path(str(constant_input.get("provider_artifact") or "")),
                    Path(case.final_artifact or ""),
                    selected_rows,
                    summary,
                    report_dir / "evidence" / "quality" / "constant_oracle.json",
                    required_faults=(
                        (pinned_manifest.get("constant_oracle") or {}).get(
                            "required_fault_injections"
                        ) or ()
                    ),
                    analyzer_edge_rows=constant_analyzer_edges,
                    consumer_artifact_sha256=consumer_sha256,
                )
                constant_reconciliation["required"] = True
                constant_reconciliation["errors"] = list(
                    constant_reconciliation.get("oracle", {}).get("failures") or []
                )
            except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
                constant_reconciliation = {
                    **constant_input,
                    "complete": False,
                    "blocking": True,
                    "errors": [f"{type(error).__name__}:{error}"],
                }
        else:
            constant_reconciliation = dict(constant_input)
    selected_count = len(selected_rows)
    population_count = int(step4_selection.get("total_rows") or selected_count)
    coverage = compute_api_coverage(
        case.case_mode,
        population_count,
        selected_count,
        int(summary.get("total_apis") or 0),
    )
    edge_truth = reconcile_final_artifact_edges(
        report_dir,
        selected_rows,
        oracle_time_budget_seconds=case.max_oracle_seconds,
        pinned_manifest=pinned_manifest,
    )
    fault_injection = (
        evaluate_required_fault_injections(
            case, report_dir, selected_rows, edge_truth
        )
        if case.required_fault_injections
        else {"required": [], "passed": True, "runs": [], "manifest": ""}
    )
    source_conflicts = validate_source_bytecode_conflicts(summary, edge_truth)
    performance_envelope = collect_performance_envelope(
        cache_equivalence.get("cold_summary") or summary,
        elapsed,
        selected_count,
        oracle_metrics=edge_truth.get("oracle_metrics"),
    )
    performance_envelope.update(collect_stage_performance(report_dir))
    performance_envelope.update(edge_truth["counts"])
    performance_envelope["fault_injection_detected_count"] = sum(
        1 for run in (fault_injection.get("runs") or []) if run.get("passed")
    )
    finalize_performance_envelope(performance_envelope)
    performance_manifest = pinned_manifest
    if case.performance_manifest is not None:
        try:
            performance_manifest = json.loads(
                Path(case.performance_manifest).read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            performance_manifest = {}
    relative_performance = evaluate_relative_performance_baseline(
        case, performance_manifest, performance_envelope
    )
    oracle_audit = None
    oracle_ledger = ""
    effective_ground_truth_status = case.ground_truth_status
    if requires_dual_line_accuracy(case, oracle_manifest=oracle_manifest):
        oracle_audit, oracle_warnings = run_dual_line_accuracy_audit(
            case,
            selected_rows,
            summary,
            edge_truth,
            report_dir,
            oracle_manifest=oracle_manifest,
            pinned_manifest=pinned_manifest,
        )
        warnings.extend(oracle_warnings)
        oracle_ledger = str(
            (oracle_audit.get("line_outputs") or {}).get("ledger") or ""
        )
        effective_ground_truth_status = (
            "reviewed" if not oracle_audit.get("blocking") else "unreviewed"
        )
    topology_evidence = extract_case_topology_evidence(
        case, report_dir, selected_rows, project_root,
        oracle_scan=edge_truth.get("oracle_scan"),
    )
    observed_topologies = classify_topologies(
        topology_evidence["edges"], topology_evidence["artifact_layout"]
    )
    resolved_prior = resolve_discovery_prior_coverage(case, report_root)
    effective_prior = set(resolved_prior.get("covered_ids") or [])
    topology_coverage = compute_topology_coverage(
        case.required_topologies,
        observed_topologies,
        prior_covered=effective_prior,
        case_mode=case.case_mode,
        evidence_complete=bool(topology_evidence.get("complete")),
    )
    topology_coverage["prior_matrix_valid"] = bool(
        resolved_prior.get("valid") if case.case_mode in {"discovery", "convergence"} else True
    )
    topology_coverage["prior_matrix"] = str(case.prior_topology_matrix or "")
    topology_coverage["report_root_prior_matrix"] = str(_prior_topology_matrix_path(report_root))
    topology_coverage_files = write_topology_coverage(report_dir, topology_coverage)
    quality_signals = build_quality_signals(
        case,
        summary=summary,
        checks=checks,
        failures=failures,
        result_audit=result_audit,
        report_dir=report_dir,
        oracle_audit=oracle_audit,
        expected_uncertain=sum(
            1
            for item in (pinned_manifest.get("apis") or [])
            if str(item.get("expected_conclusion") or "") == "uncertain"
        ),
        expected_not_found=sum(
            1
            for item in (pinned_manifest.get("apis") or [])
            if str(item.get("expected_conclusion") or "")
            == "not_found_in_static_analysis"
        ),
    )
    quality_signals.extend(build_cache_equivalence_signals(
        case, cache_equivalence, report_dir
    ))
    quality_signals.extend(build_policy_signals(
        case,
        coverage=coverage,
        performance=performance_envelope,
        report_dir=report_dir,
        oracle_audit=oracle_audit,
    ))
    quality_signals.extend(build_topology_coverage_signals(
        case,
        topology_coverage,
        report_dir,
    ))
    quality_signals.extend(build_edge_truth_signals(case, edge_truth, source_conflicts))
    quality_signals.extend(build_fault_injection_signals(case, fault_injection))
    quality_signals.extend(build_constant_evidence_signals(
        case, constant_reconciliation
    ))
    quality_signals.extend(build_relative_performance_signals(
        case, relative_performance, report_dir
    ))
    performance_envelope["within_budget"] = not any(
        str(item.get("signal_type") or "") == "performance_regression"
        for item in quality_signals
    )
    if failures and not any(item.get("blocking") for item in quality_signals):
        quality_signals.append(make_signal(
            "correctness_failure", "P1", case.name,
            message="; ".join(str(item) for item in failures[:10]),
            expected="real project runner completes without gating failures",
            actual="runner failures present",
            evidence=[report_dir],
        ))
    status = derive_case_status(returncode == 0, quality_signals, effective_ground_truth_status)
    if status == "passed" and case.case_mode in {"guard", "convergence"}:
        update_prior_topology_matrix(report_root, case.name, case.case_mode, observed_topologies)

    result = {
        "case": case.name,
        "status": status,
        "project_root": str(project_root),
        "changed_apis": str(changed_apis),
        "report_dir": str(report_dir),
        "elapsed_seconds": round(elapsed, 2),
        "performance_budget_seconds": performance_budget,
        "performance_envelope": performance_envelope,
        "relative_performance": relative_performance,
        "cache_equivalence": cache_equivalence,
        "fault_injection": fault_injection,
        "constant_evidence": constant_reconciliation,
        "edge_truth": {
            "complete": edge_truth["complete"],
            "blocking": edge_truth["blocking"],
            "errors": edge_truth["errors"],
            "counts": edge_truth["counts"],
            "verdict_counts": edge_truth["reconciliation"]["verdict_counts"],
            "ledger": edge_truth["reconciliation"].get("ledger") or [],
            "oracle_edges": edge_truth["oracle_edges"],
            "edge_reconciliation": edge_truth["edge_reconciliation"],
            "semantic_references": edge_truth.get("semantic_references") or [],
            "semantic_reference_evidence": edge_truth.get(
                "semantic_reference_evidence"
            ) or "",
            "oracle_metrics": edge_truth.get("oracle_metrics") or {},
        },
        "ground_truth_status": effective_ground_truth_status,
        "oracle_audit": {
            key: value for key, value in (oracle_audit or {}).items()
            if key not in {
                "ledger", "missing_identities", "duplicate_identities",
                "extra_identities", "analyzer_extra_identities",
                "analyzer_duplicate_identities", "analyzer_conflict_identities",
                "invalid_provenance",
            }
        },
        "oracle_ledger": oracle_ledger,
        "third_party_authorities": list(
            (oracle_audit or {}).get("oracle_authorities") or []
        ),
        "topology_coverage": topology_coverage,
        "topology_coverage_files": topology_coverage_files,
        "topology_artifact_layout": topology_evidence.get("layout_path"),
        "topology_evidence_errors": topology_evidence.get("errors") or [],
        "topology_prior_matrix": str(_prior_topology_matrix_path(report_root)),
        **coverage,
        "step4": step4_result,
        "step4_selection": step4_selection,
        "step5_returncode": returncode,
        "summary": {
            "total_apis": summary.get("total_apis"),
            "reachable": summary.get("reachable"),
            "uncertain": summary.get("uncertain"),
            "not_analyzed": summary.get("not_analyzed"),
            "not_found_in_static_analysis": summary.get("not_found_in_static_analysis"),
            "reachable_apis": summary.get("reachable_apis") or [],
            "uncertain_apis": summary.get("uncertain_apis") or [],
            "not_analyzed_apis": summary.get("not_analyzed_apis") or [],
            "not_found_apis": summary.get("not_found_apis") or [],
        },
        "graph_stats": graph_stats,
        "source_shape_metrics": source_shape_metrics,
        "step6": step6_result,
        "queries": query_results,
        "checks": checks,
        "result_audit": result_audit,
        "failures": failures,
        "warnings": warnings,
        "project_asset_health": project_asset_health,
        "matrix_policy": real_project_matrix_policy(),
        "quality_signals": quality_signals,
    }
    if pinned_manifest:
        result["api_coverage_complete"] = bool(coverage.get("complete"))
        return finalize_pinned_guard(
            pinned_manifest, result, pinned_asset_gate, report_dir
        )
    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run real-project regression probes for Step5.")
    parser.add_argument(
        "--case", choices=sorted(CASES.keys()) + ["all", *GUARD_SELECTORS], default="all"
    )
    parser.add_argument("--project-root", help="Override project root for a single --case run.")
    parser.add_argument("--changed-apis", help="Override all_changed_apis.csv for a single --case run.")
    parser.add_argument(
        "--final-artifact",
        help="Bind a SHA-verified current final JAR/WAR for a single --case run.",
    )
    parser.add_argument(
        "--oracle-manifest",
        help="Override the independent per-API oracle CSV for a single --case run.",
    )
    parser.add_argument(
        "--required-topology",
        action="append",
        default=[],
        help="Override required topology IDs for a custom single-case probe; repeat as needed.",
    )
    parser.add_argument(
        "--full-step4-apis",
        action="store_true",
        help="For cases with Step4 enabled, feed the full Step4 all_changed_apis.csv into Step5 instead of probe selection.",
    )
    parser.add_argument(
        "--report-root",
        default="/private/tmp/java-upgrade-real-project-regression",
        help="Directory where per-case reports are written.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only.")
    parser.add_argument("--json-out", default="", help="Write machine-readable JSON result to this file.")
    return parser.parse_args(argv)


def select_case_names(selector: str) -> list[str]:
    if selector == "all":
        return sorted(CASES)
    if selector in GUARD_SELECTORS:
        lifecycle_by_selector = {
            "guard": {"core", "capability"},
            "guard-core": {"core"},
            "guard-capability": {"capability"},
            "guard-exploratory": {"exploratory"},
        }
        accepted = lifecycle_by_selector[selector]
        def selected(case: RealProjectCase) -> bool:
            try:
                manifest = json.loads(Path(case.fixture_manifest).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise ValueError(
                    f"guard manifest unavailable or invalid: {case.fixture_manifest}: {error}"
                ) from error
            lifecycle = str(manifest.get("guard_lifecycle") or "")
            if lifecycle not in GUARD_LIFECYCLES:
                raise ValueError(
                    f"guard lifecycle missing or invalid: {case.fixture_manifest}"
                )
            return lifecycle in accepted
        return sorted(
            name for name, case in CASES.items()
            if case.case_mode == "guard"
            and case.fixture_manifest is not None
            and selected(case)
        )
    return [selector]


def main(argv=None):
    args = parse_args(argv)
    case_names = select_case_names(args.case)
    report_root = Path(args.report_root)
    results = []
    for name in case_names:
        case = CASES[name]
        if args.case in {"all", *GUARD_SELECTORS} and (
            args.project_root
            or args.changed_apis
            or args.final_artifact
            or args.oracle_manifest
            or args.required_topology
        ):
            raise SystemExit(
                f"single-case overrides cannot be used with --case {args.case}"
            )
        if args.required_topology:
            case = replace(case, required_topologies=tuple(dict.fromkeys(args.required_topology)))
        artifact_override = args.final_artifact or os.environ.get("JUA_REAL_FINAL_ARTIFACT", "")
        if artifact_override:
            case = replace(case, final_artifact=Path(artifact_override))
        project_override = args.project_root or os.environ.get("JUA_REAL_PROJECT_ROOT", "")
        project_root = Path(project_override) if project_override else case.default_project
        changed_apis = Path(args.changed_apis) if args.changed_apis else case.default_changed_apis
        results.append(
            run_case(
                case,
                project_root,
                changed_apis,
                report_root,
                full_step4_apis=args.full_step4_apis,
                oracle_manifest=(Path(args.oracle_manifest) if args.oracle_manifest else None),
            )
        )

    run_status = derive_run_status(results)
    payload = {"status": run_status, "results": results}
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for item in results:
            print(f"\nREAL PROJECT {item['case']}: {item['status']}")
            for gate_name, gate in (item.get("gates") or {}).items():
                verdict = "passed" if gate.get("passed") else "failed"
                errors = "; ".join(str(error) for error in (gate.get("errors") or []))
                print(f"  gate {gate_name}: {verdict}" + (f" ({errors})" if errors else ""))
            if item.get("reason"):
                print(f"  reason: {item['reason']}")
                continue
            print(f"  elapsed: {item['elapsed_seconds']}s")
            if item.get("performance_budget_seconds"):
                print(f"  performance budget: {item['performance_budget_seconds']}s")
            print(f"  report: {item['report_dir']}")
            if item.get("step4"):
                step4 = item.get("step4") or {}
                selection = item.get("step4_selection") or {}
                print(
                    f"  step4: rc={step4.get('returncode')} elapsed={step4.get('elapsed_seconds')}s "
                    f"all_changed={step4.get('all_changed_apis')}"
                )
                print(
                    f"  step4_selection: selected_rows={selection.get('selected_rows')} "
                    f"total_rows={selection.get('total_rows')} missing={selection.get('missing_api_names')}"
                )
            print(f"  summary: {item['summary']}")
            if item.get("result_audit"):
                audit = item.get("result_audit") or {}
                print(
                    "  result_audit: changed_api_rows={changed_api_rows} "
                    "alert_rows={alert_rows} statuses={alert_status_counts}".format(**audit)
                )
            if item.get("graph_stats"):
                print(f"  graph_stats: {item['graph_stats']}")
            if item.get("step6"):
                step6 = item.get("step6") or {}
                print(
                    f"  step6: rc={step6.get('returncode')} "
                    f"elapsed={step6.get('elapsed_seconds')}s report={step6.get('report')}"
                )
            for query in item.get("queries") or []:
                first_line = (query.get("stdout") or "").strip().splitlines()
                print(
                    f"  query: {query.get('method')} rc={query.get('returncode')} "
                    f"result={first_line[0] if first_line else ''}"
                )
            for name, metric in sorted((item.get("source_shape_metrics") or {}).items()):
                print(
                    f"  source_shape: {name} files={metric.get('files', 0)} "
                    f"occurrences={metric.get('occurrences', 0)}"
                )
            for check in item.get("checks", []):
                print(
                    "  check: {symbol} production={baseline_production_files} "
                    "test={baseline_test_files} alerts={alert_files} "
                    "prod_missing={production_missing} test_missing={test_missing} extra={extra_alert_files} "
                    "gating={gating}".format(**check)
                )
                for missing in check.get("production_missing_files", []):
                    label = "PROD_MISSING" if check.get("gating") else "NON_GATING_PROD_MISSING"
                    print(f"    {label} {missing}")
            for failure in item.get("failures", []):
                print(f"  FAILURE {failure}")
            for warning in item.get("warnings", []):
                print(f"  WARNING {warning}")
    return 0 if run_status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
