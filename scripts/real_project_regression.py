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


def load_summary(report_dir: Path) -> dict:
    summary_path = report_dir / "evidence" / "call_chain" / "summary.json"
    if not summary_path.exists():
        return {}
    return json.loads(summary_path.read_text(encoding="utf-8"))


def run_case(case: RealProjectCase, project_root: Path, changed_apis: Path, report_root: Path) -> dict:
    if not project_root.exists():
        return {"case": case.name, "status": "skipped", "reason": f"project root missing: {project_root}"}
    report_dir = report_root / case.name
    report_dir.mkdir(parents=True, exist_ok=True)
    changed_apis = ensure_changed_apis(
        case,
        changed_apis,
        report_dir / "evidence" / "api_changes" / "all_changed_apis.csv",
    )
    if not changed_apis.exists():
        return {"case": case.name, "status": "skipped", "reason": f"changed APIs missing: {changed_apis}"}

    returncode, elapsed = run_step5(case, project_root, changed_apis, report_dir)
    summary = load_summary(report_dir)
    graph_stats = extract_graph_stats(summary)
    source_shape_metrics = collect_source_shape_metrics(project_root, case.source_shape_patterns)
    alerts_csv = report_dir / "evidence" / "call_chain" / "alerts.csv"
    checks = []
    failures = []
    warnings = []

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
    if case.max_elapsed_seconds and elapsed > case.max_elapsed_seconds:
        failures.append(f"performance: elapsed={elapsed:.2f}s over_budget={case.max_elapsed_seconds:.2f}s")
    if not alerts_csv.exists():
        failures.append("alerts.csv missing")
    elif alerts_csv.stat().st_size == 0:
        failures.append("alerts.csv empty")
    if (report_dir / "evidence" / "call_chain" / "alerts_reachable.csv").exists() is False:
        warnings.append("alerts_reachable.csv missing")

    for spec in case.baseline_specs:
        production_baseline, test_baseline, occurrences = collect_baseline_files(project_root, spec)
        alert_files = collect_alert_files(alerts_csv, spec.symbol)
        production_missing = sorted(production_baseline - alert_files)
        test_missing = sorted(test_baseline - alert_files)
        extra = sorted(alert_files - production_baseline - test_baseline)
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
            "production_missing_files": [str(Path(item).relative_to(project_root)) for item in production_missing[:20]],
            "test_missing_files": [str(Path(item).relative_to(project_root)) for item in test_missing[:20]],
        }
        checks.append(check)
        if spec.require_zero_production_missing and production_missing:
            failures.append(f"{spec.symbol}: production_missing={len(production_missing)}")
        if spec.require_zero_production_missing and not production_baseline:
            failures.append(f"{spec.symbol}: production_baseline_empty")

    status = "passed" if returncode == 0 and not failures else "failed"
    if returncode != 0:
        failures.append(f"step5_returncode={returncode}")

    return {
        "case": case.name,
        "status": status,
        "project_root": str(project_root),
        "changed_apis": str(changed_apis),
        "report_dir": str(report_dir),
        "elapsed_seconds": round(elapsed, 2),
        "performance_budget_seconds": case.max_elapsed_seconds,
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
        "checks": checks,
        "failures": failures,
        "warnings": warnings,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run real-project regression probes for Step5.")
    parser.add_argument("--case", choices=sorted(CASES.keys()) + ["all"], default="all")
    parser.add_argument("--project-root", help="Override project root for a single --case run.")
    parser.add_argument("--changed-apis", help="Override all_changed_apis.csv for a single --case run.")
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
        results.append(run_case(case, project_root, changed_apis, report_root))

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
            print(f"  summary: {item['summary']}")
            if item.get("graph_stats"):
                print(f"  graph_stats: {item['graph_stats']}")
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
