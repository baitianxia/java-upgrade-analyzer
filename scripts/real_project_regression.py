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
import csv
import hashlib
import importlib
import io
import json
import re
import subprocess
import sys
import time
import unittest
import zipfile
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Iterable

from exhaustive_api_oracle import (
    audit_api_oracle,
    load_analyzer_rows,
    load_oracle_manifest,
    write_oracle_ledger,
)
from edge_truth import EDGE_IDENTITY_FIELDS, canonical_edge_identity, reconcile_edges
from final_artifact_edge_oracle import scan_final_artifact
from signature_utils import normalize_signature_for_lookup
from third_party_jdk_oracle import _source_signature
from third_party_jdk_oracle import discover_calls, scan_class_files
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
    "conclusion", "performance", "fixture_debt",
)


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
        default_project=Path("/private/tmp/jua-real-system-commons-text"),
        default_changed_apis=Path(""),
        required_topologies=("business_direct", "static_dispatch", "field_access"),
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
        prefer_embedded_changed_api_rows=True,
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

CASES = {
    name: apply_real_case_performance_budget(case)
    for name, case in CASES.items()
}


_CHANGE_API_MARKER_RE = re.compile(r"变更\s*API\s*[：:]")


def _expected_target_signature(expected_api: dict) -> str:
    descriptor = str((expected_api or {}).get("descriptor") or "").strip()
    if not descriptor.startswith("("):
        return ""
    try:
        return normalize_signature_for_lookup(_source_signature(descriptor))
    except (IndexError, ValueError):
        return ""


def _matches_expected_call_chain(path_text: str, expected_chain: list[str], expected_api: dict) -> bool:
    nodes = [node.strip() for node in re.split(r"\s*(?:->|→)\s*", str(path_text or "").strip())]
    if not nodes or any(not node for node in nodes) or len(nodes) != len(expected_chain):
        return False
    marker_indexes = [index for index, node in enumerate(nodes) if _CHANGE_API_MARKER_RE.search(node)]
    if any(index != len(nodes) - 1 for index in marker_indexes) or len(marker_indexes) > 1:
        return False
    if any(
        actual != expected
        and not (
            "(" not in expected
            and re.fullmatch(r"(.+?)(\(.*\))", actual)
            and re.fullmatch(r"(.+?)(\(.*\))", actual).group(1).strip() == expected
        )
        for actual, expected in zip(nodes[:-1], expected_chain[:-1])
    ):
        return False

    target_identity = ".".join(
        item for item in (
            str((expected_api or {}).get("owner") or "").strip(),
            str((expected_api or {}).get("member") or "").strip(),
        ) if item
    )
    expected_signature = _expected_target_signature(expected_api)
    if not target_identity or expected_chain[-1] != target_identity or not expected_signature:
        return False
    terminal = nodes[-1]
    if marker_indexes:
        terminal = _CHANGE_API_MARKER_RE.sub("", terminal, count=1).strip()
    terminal_match = re.fullmatch(r"(.+?)(\(.*\))", terminal)
    if not terminal_match or terminal_match.group(1).strip() != target_identity:
        return False
    return normalize_signature_for_lookup(terminal_match.group(2)) == expected_signature


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

    expected_api = manifest.get("api") or {}
    expected_name = ".".join(
        item for item in (str(expected_api.get("owner") or ""), str(expected_api.get("member") or ""))
        if item
    )
    reachable_rows = [
        row for row in (summary.get("reachable_apis") or [])
        if str(row.get("api") or row.get("api_name") or "") == expected_name
        and str(row.get("analysis_status") or "reachable") == str(manifest.get("expected_conclusion") or "")
    ]
    if not reachable_rows:
        errors.append("expected_conclusion_missing")
    expected_chain = [str(item) for item in (manifest.get("expected_chain") or [])]
    if reachable_rows and expected_chain:
        call_paths = [path for row in reachable_rows for path in _reachable_call_paths(row)]
        if not any(_matches_expected_call_chain(path, expected_chain, expected_api) for path in call_paths):
            errors.append("expected_chain_missing")

    topology = result.get("topology_coverage") or {}
    required = set(manifest.get("required_topologies") or [])
    if not topology.get("complete") or not required.issubset(set(topology.get("observed") or [])):
        errors.append("required_topology_missing")

    edge_truth = result.get("edge_truth") or {}
    if not edge_truth.get("complete") or edge_truth.get("blocking"):
        errors.append("edge_truth_failed")
    correct_physical_edges = _correct_reconciled_physical_edges(edge_truth.get("ledger") or [])
    expected_physical_edges = {
        _expected_physical_occurrence(row)
        for row in (manifest.get("canonical_edges") or [])
    }
    if not expected_physical_edges or "" in expected_physical_edges or not expected_physical_edges.issubset(correct_physical_edges):
        errors.append("expected_physical_edge_missing")
    return {"passed": not errors, "errors": errors}


def validate_pinned_asset(manifest: dict, project_root: Path) -> dict:
    errors: list[str] = []
    expected_revision = str(manifest.get("git_revision") or "")
    expected_sha = str(manifest.get("artifact_sha256") or "")
    artifact = project_root / str(manifest.get("artifact_path") or "")
    actual_revision = ""
    actual_sha = ""
    if not re.fullmatch(r"[0-9a-f]{40}", expected_revision):
        errors.append("git_revision_pin_invalid")
    if not _valid_sha256(expected_sha):
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
        if actual_sha != expected_sha:
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
    }


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
        if added_root:
            try:
                sys.path.remove(root_entry)
            except ValueError:
                pass
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
    edge_errors = sorted(contract_errors & {"edge_truth_failed", "expected_physical_edge_missing"})
    conclusion_errors = sorted(contract_errors & {
        "SOURCE_BYTECODE_EDGE_CONFLICT", "expected_conclusion_missing", "expected_chain_missing",
    })
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
    with debt_csv_path.open("w", newline="", encoding="utf-8") as handle:
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


def write_pinned_final_artifact_provenance(
    report_dir: Path, asset_gate: dict, case: RealProjectCase
) -> Path:
    output = report_dir / "evidence" / "dependencies" / "build_provenance.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact_path = Path(str(asset_gate.get("artifact_path") or ""))
    artifact_sha256 = (
        asset_gate.get("actual_artifact_sha256")
        or asset_gate.get("artifact_sha256")
        or ""
    )
    output.write_text(json.dumps({
        "sides": [{
            "side": "current",
            "artifact_path": str(artifact_path),
            "artifact_sha256": artifact_sha256,
            "authority": "pinned-real-project-manifest",
        }],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    coordinate = str(case.bytecode_coord or "").strip()
    artifact_id = coordinate.split(":", 1)[-1] if ":" in coordinate else ""
    nested_entry = ""
    if artifact_id and artifact_path.is_file():
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
        except (OSError, zipfile.BadZipFile):
            pass
    version = next(
        (
            str(row.get("old_version") or "").strip()
            for row in case.changed_api_rows
            if str(row.get("old_version") or "").strip() not in {"", "-"}
        ),
        "pinned",
    )
    with (output.parent / "deps_current_resolved.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["coord", "version", "scope", "lib_entry", "resolution_status"],
        )
        writer.writeheader()
        writer.writerow({
            "coord": coordinate,
            "version": version,
            "scope": "compile",
            "lib_entry": nested_entry,
            "resolution_status": "resolved" if nested_entry else "unresolved",
        })
    return output


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


def collect_alert_files(alerts_csv: Path, symbol: str) -> set[str]:
    if not alerts_csv.exists():
        return set()
    files: set[str] = set()
    with alerts_csv.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if _api_identity_from_alert_row(row)[0] != symbol:
                continue
            for item in re.split(r"[|;]", row.get("evidence_files") or ""):
                item = item.strip()
                if item:
                    files.add(str((alerts_csv.parent / item).resolve()))
    return files


def _csv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.exists():
        return [], []
    with path.open(newline="", encoding="utf-8") as fh:
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

    changed_identities = {
        identity for row in changed_rows
        if (identity := _api_identity_from_changed_row(row))[0]
    }
    alert_identities = {
        identity for row in alert_rows
        if (identity := _api_identity_from_alert_row(row))[0]
    }
    missing_alert_identities = sorted(changed_identities - alert_identities)
    if missing_alert_identities:
        failures.append(f"alerts_missing_api_rows:{len(missing_alert_identities)}")

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
        "missing_alert_identities": [
            {"api_name": api, "api_signature": sig, "symbol_kind": kind}
            for api, sig, kind in missing_alert_identities[:50]
        ],
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
    covered = set(pinned.get("covered_ids") or [])
    covered.update(accumulated.get("converged_guard_union") or [])
    return {
        "valid": bool(pinned.get("valid") and accumulated.get("valid")),
        "covered_ids": sorted(covered) if pinned.get("valid") and accumulated.get("valid") else [],
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
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
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
    pairs = int(perf_main.get("indirect_usage_potential_legacy_method_target_pairs") or 0)
    owner_scans = int(perf_main.get("indirect_usage_owner_presence_scans") or 0)
    selected = int(selected or 0)
    oracle_metrics = oracle_metrics or {}
    return {
        "elapsed_seconds": float(elapsed or 0.0),
        "elapsed_seconds_per_1000_apis": float(elapsed or 0.0) / (selected / 1000.0) if selected else 0.0,
        "potential_method_target_pairs": pairs,
        "potential_pairs_per_api": pairs / selected if selected else 0.0,
        "owner_presence_scans": owner_scans,
        "artifact_bytes": int(bytecode_scan.get("artifact_bytes") or 0),
        "class_count": int(bytecode_scan.get("class_entries_scoped") or bytecode_scan.get("visited_classes") or 0),
        "parsed_class_count": int(bytecode_scan.get("class_entries_parsed") or 0),
        "parse_seconds": float(bytecode_scan.get("class_parse_elapsed_sec") or 0.0),
        "artifact_cache_hits": int(bytecode_scan.get("artifact_cache_hits") or 0),
        "javap_fallbacks": int(bytecode_scan.get("javap_fallbacks") or 0),
        "duplicate_class_scans": int(bytecode_scan.get("duplicate_class_scans") or 0),
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
    }


def finalize_performance_envelope(envelope: dict) -> dict:
    """Derive normalized rates after exhaustive edge reconciliation adds its counts."""
    parsed_class_count = int(envelope.get("parsed_class_count") or 0)
    parse_seconds = float(envelope.get("parse_seconds") or 0.0)
    oracle_edges = int(envelope.get("oracle_edge_count") or 0)
    analyzer_edges = int(envelope.get("analyzer_edge_count") or 0)
    edge_count = max(oracle_edges, analyzer_edges)
    reconcile_seconds = float(envelope.get("reconcile_seconds") or 0.0)
    elapsed_seconds = float(envelope.get("elapsed_seconds") or 0.0)
    envelope["parse_rate_available"] = parsed_class_count > 0 and parse_seconds > 0
    envelope["parse_classes_per_second"] = (
        parsed_class_count / parse_seconds if envelope["parse_rate_available"] else None
    )
    envelope["edge_rate_available"] = edge_count > 0
    envelope["reconcile_edges_per_second"] = (
        edge_count / reconcile_seconds if edge_count and reconcile_seconds else None
    )
    envelope["elapsed_seconds_per_100k_edges"] = (
        elapsed_seconds * 100000.0 / edge_count if edge_count else None
    )
    return envelope


def serialized_api_identity(api_row: dict) -> str:
    """Match the Task 4 ledger's serialized API identity without importing its parser."""
    return str(tuple(str((api_row or {}).get(field) or "").strip() for field in (
        "coord", "api_name", "api_signature", "symbol_kind", "change_type",
    )))


def _api_target_matches(api_row: dict, edge: dict) -> bool:
    api_name = str((api_row or {}).get("api_name") or "").strip()
    symbol_kind = str((api_row or {}).get("symbol_kind") or "method").strip().lower()
    if symbol_kind == "constructor" and not api_name.endswith(".<init>"):
        owner, separator, member = api_name, ".", "<init>"
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
        return True
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


def _business_artifact_entry(entry: str) -> bool:
    value = str(entry or "").strip()
    return bool(
        value.startswith(("BOOT-INF/classes/", "WEB-INF/classes/"))
        or (value.endswith(".class") and "!/" not in value)
    )


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


def _retain_authoritative_api_path(selected_rows: list[dict], oracle_rows: list[dict]) -> tuple[list[dict], list[str]]:
    """Keep every oracle edge from a selected API back to a packaged business boundary."""
    incoming: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for edge in oracle_rows:
        incoming[_callee_identity(edge)].append(edge)
    selected: dict[str, list[dict]] = {}
    errors: list[str] = []
    for api_row in selected_rows:
        identity = serialized_api_identity(api_row)
        direct = [edge for edge in oracle_rows if _api_target_matches(api_row, edge)]
        if not direct:
            errors.append(f"selected_api_unresolved:{identity}")
            continue
        selected[identity] = direct

    retained: dict[tuple[str, str], dict] = {}
    for identity, direct_edges in selected.items():
        pending = deque(direct_edges)
        visited = set()
        reached_boundary = False
        while pending:
            edge = pending.popleft()
            physical_key = (identity, physical_edge_occurrence(edge))
            if physical_key in visited:
                continue
            visited.add(physical_key)
            retained[physical_key] = {**edge, "api_identity": identity}
            if _business_artifact_entry(str(edge.get("artifact_entry") or "")):
                reached_boundary = True
                continue
            for upstream in incoming.get(_caller_identity(edge), []):
                pending.append(upstream)
        if not reached_boundary:
            errors.append(f"selected_api_unreached_business_boundary:{identity}")
    return sorted(retained.values(), key=lambda row: (
        str(row.get("api_identity") or ""), canonical_edge_identity(row),
        str(row.get("artifact_entry") or ""), normalize_instruction_offset(row),
    )), sorted(errors)


def _retain_analyzer_api_path(selected_rows: list[dict], analyzer_rows: list[dict]) -> list[dict]:
    """Associate upstream analyzer edges by bytecode graph path from a labeled target edge."""
    incoming: dict[tuple[str, tuple[str, str, str]], list[dict]] = defaultdict(list)
    for edge in analyzer_rows:
        incoming[(str(edge.get("api_identity") or ""), _callee_identity(edge))].append(edge)

    retained: dict[tuple[str, str], dict] = {}
    for api_row in selected_rows:
        identity = serialized_api_identity(api_row)
        pending = deque(
            edge for edge in analyzer_rows
            if str(edge.get("api_identity") or "") == identity and _api_target_matches(api_row, edge)
        )
        visited: set[tuple[str, str]] = set()
        while pending:
            edge = pending.popleft()
            physical_key = (identity, physical_edge_occurrence(edge))
            if physical_key in visited:
                continue
            visited.add(physical_key)
            retained[physical_key] = {**edge, "api_identity": identity}
            if _business_artifact_entry(str(edge.get("artifact_entry") or "")):
                continue
            caller = _caller_identity(edge)
            pending.extend(incoming.get((identity, caller), []))
            pending.extend(incoming.get(("", caller), []))
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
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return str(path)


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
    retained_oracle_rows, path_errors = _retain_authoritative_api_path(selected_rows, oracle_rows)
    path_errors.extend(_oracle_edge_identity_errors(oracle_rows))
    retained_analyzer_rows = _retain_analyzer_api_path(selected_rows, [dict(row) for row in (analyzer_rows or [])])
    artifact_entries = {
        str(entry).strip() for entry in (oracle_scan.get("artifact_entries") or [])
        if str(entry).strip()
    }
    if not artifact_entries:
        artifact_entries = {
            str(row.get("artifact_entry") or "").strip() for row in oracle_rows
            if str(row.get("artifact_entry") or "").strip()
        }
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
    counts = {
        "oracle_edge_count": len(retained_oracle_rows),
        "analyzer_edge_count": len(retained_analyzer_rows),
        "edge_reconciliation_row_count": len(reconciliation["ledger"]),
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
    return {
        "complete": complete,
        "errors": sorted(path_errors + [str(item) for item in (oracle_scan.get("failures") or [])]),
        "blocking": not complete or bool(reconciliation.get("blocking")),
        "reconciliation": reconciliation,
        "counts": counts,
        "oracle_edges": oracle_path,
        "edge_reconciliation": reconciliation_path,
        "trusted_artifact_sha": str(oracle_scan.get("artifact_sha256") or ""),
        "oracle_metrics": oracle_metrics,
        "oracle_physical_occurrences": [
            physical_edge_occurrence(row) for row in retained_oracle_rows
        ],
        "oracle_scan": oracle_scan,
    }


def _artifact_class_entries(artifact: Path) -> set[str]:
    entries: set[str] = set()
    with zipfile.ZipFile(artifact) as archive:
        for info in archive.infolist():
            if not info.is_dir() and info.filename.endswith(".class"):
                entries.add(info.filename)
            elif not info.is_dir() and info.filename.endswith(".jar") and info.filename.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")):
                with zipfile.ZipFile(io.BytesIO(archive.read(info))) as nested:
                    entries.update(
                        f"{info.filename}!/{nested_info.filename}"
                        for nested_info in nested.infolist()
                        if not nested_info.is_dir() and nested_info.filename.endswith(".class")
                    )
    return entries


def _verified_current_final_artifact(report_dir: Path) -> tuple[Path | None, str, list[str]]:
    provenance_path = Path(report_dir) / "evidence" / "dependencies" / "build_provenance.json"
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        current = next(item for item in provenance.get("sides") or [] if item.get("side") == "current")
        artifact = Path(str(current.get("artifact_path") or ""))
        expected_sha = str(current.get("artifact_sha256") or "")
        actual_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
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
        if symbol_kind == "constructor" and not api_name.endswith(".<init>"):
            owner, member = api_name, "<init>"
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


def reconcile_final_artifact_edges(
    report_dir: Path,
    selected_rows: list[dict],
    oracle_time_budget_seconds: float | None = None,
) -> dict:
    artifact, expected_sha, errors = _verified_current_final_artifact(report_dir)
    analyzer_path = Path(report_dir) / "evidence" / "call_chain" / "analyzer_edges.csv"
    _fields, analyzer_rows = _csv_rows(analyzer_path)
    if artifact is None:
        scan = {"artifact_sha256": "", "complete": False, "edges": [], "failures": errors,
                "artifact_entries": []}
    else:
        scan = scan_final_artifact(
            artifact,
            time_budget_seconds=oracle_time_budget_seconds,
            selected_targets=_oracle_selected_targets(selected_rows),
        )
        try:
            scan["artifact_entries"] = sorted(_artifact_class_entries(artifact))
        except (OSError, zipfile.BadZipFile) as error:
            scan["complete"] = False
            scan.setdefault("failures", []).append(f"artifact_class_inventory_failed:{error}")
            scan["artifact_entries"] = []
        if scan.get("artifact_sha256") != expected_sha:
            scan["complete"] = False
            scan.setdefault("failures", []).append("oracle_artifact_sha_mismatch")
    return reconcile_selected_api_edges(report_dir, selected_rows, analyzer_rows, scan)


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


def ensure_changed_apis(case: RealProjectCase, changed_apis: Path, materialized_path: Path | None = None) -> Path:
    if case.prefer_embedded_changed_api_rows and case.changed_api_rows:
        changed_apis = materialized_path or changed_apis
    elif changed_apis.exists() or not case.changed_api_rows:
        return changed_apis
    changed_apis.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "coord", "old_version", "new_version", "change_type", "api_name",
        "api_simple", "symbol_kind", "api_signature", "confirmed", "severity", "source",
    ]
    with changed_apis.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(case.changed_api_rows)
    return changed_apis


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
    runtime_lib_entries: list[dict[str, str]] = []
    artifact_java_version = ""
    owner_prefix_bytes = tuple(prefix.encode("utf-8") for prefix in case.bytecode_owner_prefixes)
    artifact_id = case.bytecode_coord.split(":", 1)[-1].strip()
    with zipfile.ZipFile(artifact) as source:
        try:
            manifest = source.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
        except KeyError:
            manifest = ""
        java_version_match = re.search(r"(?im)^Java-Version\s*:\s*([^\s]+)\s*$", manifest)
        if java_version_match:
            artifact_java_version = java_version_match.group(1).strip()
        for name in sorted(source.namelist()):
            if name.startswith("BOOT-INF/classes/") and name.endswith(".class"):
                relative = name[len("BOOT-INF/classes/"):]
                destination = extracted_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.read(name))
            if (
                name.startswith("BOOT-INF/lib/")
                and name.endswith(".jar")
            ):
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
                            runtime_lib_entries.append({
                                "coord": f"{coordinate['groupId']}:{coordinate['artifactId']}",
                                "version": coordinate["version"],
                                "lib_entry": name,
                            })
                        else:
                            runtime_lib_entries.append({
                                "coord": f"runtime:{Path(name).stem}",
                                "version": "runtime",
                                "lib_entry": name,
                            })
                        nested_root = (
                            extracted_root / "nested" /
                            f"{hashlib.sha256(name.encode('utf-8')).hexdigest()[:12]}-{Path(name).stem}"
                        )
                        for class_entry in sorted(nested.namelist()):
                            if not class_entry.endswith(".class") or class_entry.startswith("META-INF/"):
                                continue
                            class_bytes = nested.read(class_entry)
                            if owner_prefix_bytes and not any(
                                prefix in class_bytes for prefix in owner_prefix_bytes
                            ):
                                continue
                            destination = nested_root / class_entry
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            destination.write_bytes(class_bytes)
                except (KeyError, OSError, ValueError, zipfile.BadZipFile):
                    pass
            if (
                artifact_id
                and name.startswith(f"BOOT-INF/lib/{artifact_id}-")
                and name.endswith(".jar")
            ):
                target_lib_candidates.append(name)
    if len(target_lib_candidates) == 1:
        target_lib_entry = target_lib_candidates[0]
    class_files = sorted(extracted_root.rglob("*.class"))
    if not class_files:
        raise ValueError("current final artifact contains no business class files")
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
    with (dependencies_dir / "deps_current_resolved.csv").open("w", newline="", encoding="utf-8") as fh:
        fields = ["coord", "version", "scope", "lib_entry", "resolution_status"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        target_version = "runtime"
        if target_lib_entry:
            filename = Path(target_lib_entry).name
            target_version = filename[len(artifact_id) + 1:-4] or target_version
        writer.writerow({
            "coord": case.bytecode_coord,
            "version": target_version,
            "scope": "compile",
            "lib_entry": target_lib_entry,
            "resolution_status": "resolved" if target_lib_entry else "unresolved",
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
    with dep_changes.open("w", newline="", encoding="utf-8") as fh:
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


def run_step4(case: RealProjectCase, report_dir: Path) -> dict:
    output_dir = report_dir / "evidence" / "api_changes"
    output_dir.mkdir(parents=True, exist_ok=True)
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
    with step4_all_changed_apis.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    matched_names = {str(row.get("api_name") or "").strip() for row in rows if str(row.get("api_name") or "").strip() in selected_set}
    selected_rows = [row for row in rows if str(row.get("api_name") or "").strip() in selected_set]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
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
    generated_ratio = (len(generated_java_files) / len(java_files)) if java_files else 0.0
    return {
        "valid_git_checkout": git_result.returncode == 0 and git_result.stdout.strip() == "true",
        "git_error": (git_result.stderr or git_result.stdout or "").strip(),
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
    if case.case_mode in {"discovery", "convergence"} and needs_ground_truth:
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
    )
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
                "oracle_edge_count and analyzer_edge_count are both zero"
            ),
            expected="normalized edge analysis time has a nonzero exhaustive edge denominator",
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
    for field in ("not_analyzed", "not_found_in_static_analysis"):
        count = int(summary.get(field) or 0)
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
    uncertain = int(summary.get("uncertain") or 0)
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
                    report_dir / "evidence" / "call_chain" / "step5_timing.csv",
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
) -> dict:
    pinned_manifest: dict = {}
    pinned_asset_gate: dict = {}
    if case.fixture_manifest is not None:
        report_dir = report_root / case.name
        report_dir.mkdir(parents=True, exist_ok=True)
        try:
            pinned_manifest = load_pinned_guard_manifest(case)
            pinned_asset_gate = validate_pinned_asset(pinned_manifest, project_root)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            pinned_asset_gate = {
                "name": "asset", "passed": False,
                "errors": [f"pinned_manifest_invalid:{error}"],
            }
        if not pinned_asset_gate.get("passed"):
            asset_signal = make_signal(
                "project_asset_invalid", "P1", case.name,
                message="; ".join(pinned_asset_gate.get("errors") or []),
                expected="pinned Git revision and SHA-verified final artifact",
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
            "status": "skipped",
            "reason": reason,
            "matrix_policy": real_project_matrix_policy(),
            "quality_signals": [
                make_signal(
                    "infra_skip",
                    "P1",
                    case.name,
                    message=reason,
                    actual="real project checkout unavailable",
                    blocking=False,
                    fixture_status="",
                )
            ],
        }
    project_asset_health = collect_project_asset_health(project_root)
    asset_violations = project_asset_violations(case, project_asset_health)
    if asset_violations:
        return {
            "case": case.name,
            "status": "skipped",
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
    if case.bytecode_owner_prefixes:
        explicit_changed_apis = changed_apis if changed_apis.is_file() else None
        changed_apis = materialize_bytecode_changed_apis(
            case,
            project_root,
            report_dir,
            selected_changed_apis=explicit_changed_apis,
        )
    step4_result = {}
    step4_selection = {}
    failures = []
    warnings = []
    if case.run_step4:
        step4_result = run_step4(case, report_dir)
        step4_all_changed_apis = Path(step4_result.get("all_changed_apis") or "")
        if step4_result.get("returncode") != 0:
            failures.append(f"step4_returncode={step4_result.get('returncode')}")
        if case.max_step4_elapsed_seconds and float(step4_result.get("elapsed_seconds") or 0.0) > case.max_step4_elapsed_seconds:
            failures.append(
                "step4_performance: "
                f"elapsed={float(step4_result.get('elapsed_seconds') or 0.0):.2f}s "
                f"over_budget={case.max_step4_elapsed_seconds:.2f}s"
            )
        if full_step4_apis:
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
        if full_step4_apis and case.max_full_step4_api_elapsed_seconds
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
                        "infra_skip",
                        "P1",
                        case.name,
                        step="step4",
                        message=missing_reason,
                        actual="changed API input unavailable",
                        blocking=False,
                        fixture_status="",
                    )
                ],
            }
        reason = f"changed APIs missing: {changed_apis}"
        return {
            "case": case.name,
            "status": "skipped",
            "reason": reason,
            "matrix_policy": real_project_matrix_policy(),
            "quality_signals": [
                make_signal(
                    "infra_skip",
                    "P1",
                    case.name,
                    step="step4",
                    message=reason,
                    actual="changed API input unavailable",
                    blocking=False,
                    fixture_status="",
                )
            ],
        }

    execution_case = (
        replace(case, max_elapsed_seconds=performance_budget)
        if performance_budget != case.max_elapsed_seconds
        else case
    )
    returncode, elapsed = run_step5(execution_case, project_root, changed_apis, report_dir)
    summary = load_summary(report_dir)
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
    if (report_dir / "evidence" / "call_chain" / "alerts_reachable.csv").exists() is False:
        warnings.append("alerts_reachable.csv missing")

    result_audit = audit_analysis_outputs(changed_apis, alerts_csv, summary)
    failures.extend(result_audit.get("failures") or [])
    warnings.extend(result_audit.get("warnings") or [])

    for spec in case.baseline_specs:
        production_baseline, test_baseline, occurrences = collect_baseline_files(project_root, spec)
        alert_files = collect_alert_files(alerts_csv, spec.symbol)
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
    selected_count = len(selected_rows)
    population_count = int(step4_selection.get("total_rows") or selected_count)
    coverage = compute_api_coverage(
        case.case_mode,
        population_count,
        selected_count,
        int(summary.get("total_apis") or 0),
    )
    edge_truth = reconcile_final_artifact_edges(
        report_dir, selected_rows, oracle_time_budget_seconds=case.max_oracle_seconds
    )
    source_conflicts = validate_source_bytecode_conflicts(summary, edge_truth)
    performance_envelope = collect_performance_envelope(
        summary,
        elapsed,
        selected_count,
        oracle_metrics=edge_truth.get("oracle_metrics"),
    )
    performance_envelope.update(edge_truth["counts"])
    finalize_performance_envelope(performance_envelope)
    oracle_audit = None
    oracle_ledger = ""
    effective_ground_truth_status = case.ground_truth_status
    if case.case_mode in {"discovery", "convergence"}:
        oracle_rows = load_oracle_manifest(case.oracle_manifest)
        if case.enable_jdk_oracle:
            if case.final_artifact:
                class_files = sorted(
                    (report_dir / ".runtime" / "final-artifact-classes").rglob("*.class")
                )
            else:
                class_files = []
            oracle_rows.extend(scan_class_files(
                selected_rows,
                class_files,
                report_dir / "evidence" / "quality" / "jdk-javap",
            ))
        oracle_audit = audit_api_oracle(
            selected_rows,
            load_analyzer_rows(summary),
            oracle_rows,
        )
        oracle_ledger_path = report_dir / "evidence" / "quality" / "exhaustive_api_oracle.csv"
        write_oracle_ledger(oracle_ledger_path, oracle_audit)
        oracle_ledger = str(oracle_ledger_path)
        effective_ground_truth_status = "reviewed" if not oracle_audit.get("blocking") else "unreviewed"
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
    )
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
        "edge_truth": {
            "complete": edge_truth["complete"],
            "blocking": edge_truth["blocking"],
            "errors": edge_truth["errors"],
            "counts": edge_truth["counts"],
            "verdict_counts": edge_truth["reconciliation"]["verdict_counts"],
            "ledger": edge_truth["reconciliation"].get("ledger") or [],
            "oracle_edges": edge_truth["oracle_edges"],
            "edge_reconciliation": edge_truth["edge_reconciliation"],
            "oracle_metrics": edge_truth.get("oracle_metrics") or {},
        },
        "ground_truth_status": effective_ground_truth_status,
        "oracle_audit": {
            key: value for key, value in (oracle_audit or {}).items()
            if key not in {
                "ledger", "missing_identities", "duplicate_identities",
                "extra_identities", "invalid_provenance",
            }
        },
        "oracle_ledger": oracle_ledger,
        "third_party_authorities": sorted({
            str(row.get("authority") or "") for row in oracle_rows
        }) if case.case_mode in {"discovery", "convergence"} else [],
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
    parser.add_argument("--case", choices=sorted(CASES.keys()) + ["all"], default="all")
    parser.add_argument("--project-root", help="Override project root for a single --case run.")
    parser.add_argument("--changed-apis", help="Override all_changed_apis.csv for a single --case run.")
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


def main(argv=None):
    args = parse_args(argv)
    case_names = sorted(CASES.keys()) if args.case == "all" else [args.case]
    report_root = Path(args.report_root)
    results = []
    for name in case_names:
        case = CASES[name]
        if args.case == "all" and (args.project_root or args.changed_apis):
            raise SystemExit("--project-root/--changed-apis can only be used with a single --case")
        project_root = Path(args.project_root) if args.project_root else case.default_project
        changed_apis = Path(args.changed_apis) if args.changed_apis else case.default_changed_apis
        results.append(
            run_case(
                case,
                project_root,
                changed_apis,
                report_root,
                full_step4_apis=args.full_step4_apis,
            )
        )

    failed = any(item.get("status") == "failed" for item in results)
    payload = {"status": "failed" if failed else "passed", "results": results}
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
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
