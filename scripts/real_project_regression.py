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
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


ROOT_DIR = Path(__file__).resolve().parents[1]


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


CASES = {
    "commons-text": RealProjectCase(
        name="commons-text",
        default_project=Path("/private/tmp/jua-real-system-commons-text"),
        default_changed_apis=Path(""),
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
    ),
    "commons-lang": RealProjectCase(
        name="commons-lang",
        default_project=Path("/private/tmp/jua-real-git-commons-lang"),
        default_changed_apis=Path(""),
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
            if (row.get("changed_symbol") or "").strip() != symbol:
                continue
            for item in re.split(r"[|;]", row.get("evidence_files") or ""):
                item = item.strip()
                if item:
                    files.add(str(Path(item).resolve()))
    return files


def _csv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.exists():
        return [], []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def _api_identity_from_changed_row(row: dict[str, str]) -> tuple[str, str, str]:
    return (
        str(row.get("api_name") or "").strip(),
        str(row.get("api_signature") or "").strip(),
        str(row.get("symbol_kind") or "").strip(),
    )


def _api_identity_from_alert_row(row: dict[str, str]) -> tuple[str, str, str]:
    return (
        str(row.get("changed_symbol") or "").strip(),
        str(row.get("api_signature") or "").strip(),
        str(row.get("symbol_kind") or "").strip(),
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
            chain_text = " ".join(
                str(row.get(field) or "")
                for field in ("chain_target", "chain_detail", "path_text")
            )
            if changed_symbol not in chain_text:
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
    proc = subprocess.run(cmd, cwd=ROOT_DIR, text=True)
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
    cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "s5_call_chain.py"),
        "--all-changed-apis",
        str(changed_apis),
        "--source-dirs",
        str(project_root),
        "--report-dir",
        str(report_dir),
        "--output-dir",
        str(output_dir),
        "--max-depth",
        "5",
        "--allow-degraded",
    ]
    start = time.time()
    proc = subprocess.run(cmd, cwd=ROOT_DIR, text=True)
    return proc.returncode, time.time() - start


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
    proc = subprocess.run(cmd, cwd=ROOT_DIR, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
    proc = subprocess.run(cmd, cwd=ROOT_DIR, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
) -> dict:
    if blocking is None:
        blocking = severity in {"P0", "P1"} and signal_type in {
            "correctness_failure",
            "capability_gap",
            "evidence_weakness",
            "performance_regression",
            "project_asset_invalid",
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
    }


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
    for field in ("not_analyzed", "not_found_in_static_analysis"):
        count = int(summary.get(field) or 0)
        if count:
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

    returncode, elapsed = run_step5(case, project_root, changed_apis, report_dir)
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

    status = "passed" if returncode == 0 and not failures else "failed"
    if returncode != 0:
        failures.append(f"step5_returncode={returncode}")
    quality_signals = build_quality_signals(
        case,
        summary=summary,
        checks=checks,
        failures=failures,
        result_audit=result_audit,
        report_dir=report_dir,
    )

    return {
        "case": case.name,
        "status": status,
        "project_root": str(project_root),
        "changed_apis": str(changed_apis),
        "report_dir": str(report_dir),
        "elapsed_seconds": round(elapsed, 2),
        "performance_budget_seconds": performance_budget,
        "step4": step4_result,
        "step4_selection": step4_selection,
        "step5_returncode": returncode,
        "summary": {
            "total_apis": summary.get("total_apis"),
            "reachable": summary.get("reachable"),
            "uncertain": summary.get("uncertain"),
            "not_analyzed": summary.get("not_analyzed"),
            "not_found_in_static_analysis": summary.get("not_found_in_static_analysis"),
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
