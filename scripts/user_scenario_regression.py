#!/usr/bin/env python3
"""Generate and run fixed user-scenario regressions.

Unlike ``real_project_regression.py``, this runner does not require pre-cloned
external projects.  It creates small but ecosystem-shaped Java projects with
real ``javac`` output and real jars, then verifies the analyzer behavior that
has historically caused user-visible misses:

* business source -> dependency jar A -> dependency jar B -> removed API
* source diff is auxiliary, dependency jar bytecode is the primary API truth
* Step5 query index can answer a user's follow-up call-chain question

The scenarios are intentionally compact so they can be added to release gates
without turning every quality run into a long integration test.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT_DIR / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import s4_jar_compare as step4  # noqa: E402
import s1_dep_diff as step1  # noqa: E402
import run_step as orchestrator  # noqa: E402
from csv_io import open_csv_read, open_csv_write  # noqa: E402
from path_runtime import short_temp_root  # noqa: E402


CHANGED_API_FIELDS = [
    "coord",
    "old_version",
    "new_version",
    "change_type",
    "api_name",
    "api_simple",
    "symbol_kind",
    "api_signature",
    "confirmed",
    "severity",
    "source",
]

DEFAULT_WORKSPACE = short_temp_root() / "jua-user-scenarios"


@dataclass
class ScenarioResult:
    name: str
    status: str
    elapsed_seconds: float
    report_dir: str = ""
    failures: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd or ROOT_DIR),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _require_tool(name: str) -> None:
    result = _run([name, "--version"])
    if result.returncode != 0:
        raise RuntimeError(f"required tool missing or unusable: {name}: {result.stderr or result.stdout}")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _compile_java(source_root: Path, classes_dir: Path, classpath: list[Path] | None = None) -> None:
    java_files = sorted(str(path) for path in source_root.rglob("*.java"))
    if not java_files:
        raise RuntimeError(f"no java files under {source_root}")
    classes_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["javac", "-d", str(classes_dir)]
    if classpath:
        cmd.extend(["-cp", os.pathsep.join(str(item) for item in classpath)])
    cmd.extend(java_files)
    result = _run(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"javac failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")


def _jar_from_classes(jar_path: Path, classes_dir: Path) -> None:
    jar_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(jar_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(classes_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(classes_dir).as_posix())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_changed_apis(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(path) as fh:
        writer = csv.DictWriter(fh, fieldnames=CHANGED_API_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with open_csv_read(path) as fh:
        return list(csv.DictReader(fh))


def _prepare_transitive_deleted_dependency_workspace(workspace: Path) -> dict[str, Path]:
    """Create a user-like app and final artifact with dependency jars.

    Shape:
        business App.run
          -> dep-a FacadeA.entry
          -> dep-b BridgeB.call
          -> com.vendor.LegacyApi.removed(String)
    """
    scenario = workspace / "transitive_deleted_dependency"
    if scenario.exists():
        shutil.rmtree(scenario)
    scenario.mkdir(parents=True)

    vendor_src = scenario / "vendor-src"
    _write(
        vendor_src / "com/vendor/LegacyApi.java",
        """
        package com.vendor;
        public class LegacyApi {
            public static String removed(String value) { return value == null ? "" : value.trim(); }
        }
        """,
    )
    vendor_classes = scenario / "vendor-classes"
    _compile_java(vendor_src, vendor_classes)
    vendor_jar = scenario / "legacy-lib-1.0.0.jar"
    _jar_from_classes(vendor_jar, vendor_classes)

    dep_b_src = scenario / "dep-b-src"
    _write(
        dep_b_src / "com/depb/BridgeB.java",
        """
        package com.depb;
        import com.vendor.LegacyApi;
        public class BridgeB {
            public String call(String value) {
                return LegacyApi.removed(value);
            }
        }
        """,
    )
    dep_b_classes = scenario / "dep-b-classes"
    _compile_java(dep_b_src, dep_b_classes, [vendor_jar])
    dep_b_jar = scenario / "dep-b-1.0.0.jar"
    _jar_from_classes(dep_b_jar, dep_b_classes)

    dep_a_src = scenario / "dep-a-src"
    _write(
        dep_a_src / "com/depa/FacadeA.java",
        """
        package com.depa;
        import com.depb.BridgeB;
        public class FacadeA {
            public String entry(String value) {
                return new BridgeB().call(value);
            }
        }
        """,
    )
    dep_a_classes = scenario / "dep-a-classes"
    _compile_java(dep_a_src, dep_a_classes, [dep_b_jar, vendor_jar])
    dep_a_jar = scenario / "dep-a-1.0.0.jar"
    _jar_from_classes(dep_a_jar, dep_a_classes)

    project = scenario / "project"
    app_src = project / "src/main/java"
    _write(
        app_src / "com/app/App.java",
        """
        package com.app;
        import com.depa.FacadeA;
        public class App {
            public String run(String value) {
                return new FacadeA().entry(value);
            }
        }
        """,
    )
    app_classes = scenario / "app-classes"
    _compile_java(app_src, app_classes, [dep_a_jar, dep_b_jar, vendor_jar])

    final_artifact = scenario / "app-current.jar"
    with zipfile.ZipFile(final_artifact, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for source, entry in (
            (dep_a_jar, "BOOT-INF/lib/dep-a-1.0.0.jar"),
            (dep_b_jar, "BOOT-INF/lib/dep-b-1.0.0.jar"),
        ):
            zf.write(source, entry)
        for path in sorted(app_classes.rglob("*.class")):
            zf.write(path, f"BOOT-INF/classes/{path.relative_to(app_classes).as_posix()}")

    report_dir = project / ".upgrade-report"
    deps_dir = report_dir / "evidence" / "dependencies"
    deps_dir.mkdir(parents=True, exist_ok=True)
    current_entries = [
        {
            "coord": "com.example:dep-a",
            "version": "1.0.0",
            "scope": "compile",
            "lib_entry": "BOOT-INF/lib/dep-a-1.0.0.jar",
            "resolution_status": "resolved",
            "packaged_match_source": "user_scenario_final_artifact",
        },
        {
            "coord": "com.example:dep-b",
            "version": "1.0.0",
            "scope": "compile",
            "lib_entry": "BOOT-INF/lib/dep-b-1.0.0.jar",
            "resolution_status": "resolved",
            "packaged_match_source": "user_scenario_final_artifact",
        },
    ]
    with open_csv_write(deps_dir / "deps_current_resolved.csv") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "coord", "version", "scope", "lib_entry",
                "resolution_status",
            ],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(current_entries)
    final_artifact_sha256 = _sha256(final_artifact)
    step1.materialize_changed_dependency_jars(
        [],
        {
            "current": {
                "artifact_path": str(final_artifact),
                "artifact_sha256": final_artifact_sha256,
            }
        },
        deps_dir,
        current_entries=current_entries,
    )
    (deps_dir / "build_provenance.json").write_text(
        json.dumps(
            {
                "sides": [
                    {
                        "side": "current",
                        "artifact_path": str(final_artifact),
                        "artifact_sha256": final_artifact_sha256,
                    }
                ]
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    context_dir = report_dir / "evidence" / "context"
    context_dir.mkdir(parents=True, exist_ok=True)
    (context_dir / "context.json").write_text(json.dumps({"jdk_current": "17"}, ensure_ascii=False), encoding="utf-8")

    changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_apis.csv"
    _write_changed_apis(
        changed_apis,
        [
            {
                "coord": "com.vendor:legacy-lib",
                "old_version": "1.0.0",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "com.vendor.LegacyApi.removed",
                "api_simple": "removed",
                "symbol_kind": "method",
                "api_signature": "(String)",
                "confirmed": "true",
                "severity": "P1",
                "source": "user_scenario_regression",
            }
        ],
    )
    return {
        "scenario": scenario,
        "project": project,
        "source_dir": app_src,
        "report_dir": report_dir,
        "changed_apis": changed_apis,
        "vendor_jar": vendor_jar,
    }


def _run_step5(paths: dict[str, Path]) -> subprocess.CompletedProcess:
    return _run(
        [
            sys.executable,
            str(ROOT_DIR / "scripts" / "s5_call_chain.py"),
            "--all-changed-apis",
            str(paths["changed_apis"]),
            "--source-dirs",
            str(paths["source_dir"]),
            "--report-dir",
            str(paths["report_dir"]),
            "--output-dir",
            str(paths["report_dir"] / "evidence" / "call_chain"),
            "--max-depth",
            "5",
            "--allow-degraded",
        ]
    )


def _validate_transitive_deleted_dependency(paths: dict[str, Path]) -> tuple[list[str], dict]:
    failures: list[str] = []
    report_dir = paths["report_dir"]
    summary_path = report_dir / "evidence" / "call_chain" / "summary.json"
    alerts_path = report_dir / "evidence" / "call_chain" / "alerts.csv"
    if not summary_path.exists():
        failures.append("summary.json missing")
        summary = {}
    else:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    alerts = _read_csv(alerts_path)
    target_rows = [
        row for row in alerts
        if (row.get("changed_symbol") or "").strip().startswith("com.vendor.LegacyApi.removed")
    ]
    alert_text = json.dumps(target_rows, ensure_ascii=False)
    if summary.get("reachable") != 1:
        failures.append(f"reachable expected 1, actual={summary.get('reachable')}")
    if not target_rows:
        failures.append("alerts.csv has no row for com.vendor.LegacyApi.removed")
    for expected in ("com.app.App.run", "com.depa.FacadeA.entry", "com.depb.BridgeB.call"):
        if expected not in alert_text:
            failures.append(f"call chain missing {expected}")
    if "运行时依赖字节码仍引用被删除依赖" not in alert_text:
        failures.append("runtime dependency removed API explanation missing")
    return failures, {
        "summary": {
            "total_apis": summary.get("total_apis"),
            "reachable": summary.get("reachable"),
            "uncertain": summary.get("uncertain"),
            "not_analyzed": summary.get("not_analyzed"),
            "not_found_in_static_analysis": summary.get("not_found_in_static_analysis"),
        },
        "target_alert_rows": len(target_rows),
        "alerts_csv": str(alerts_path),
    }


def scenario_transitive_deleted_dependency(workspace: Path) -> ScenarioResult:
    started = time.perf_counter()
    failures: list[str] = []
    paths = _prepare_transitive_deleted_dependency_workspace(workspace)
    proc = _run_step5(paths)
    if proc.returncode != 0:
        failures.append(f"step5_returncode={proc.returncode}")
    validation_failures, details = _validate_transitive_deleted_dependency(paths)
    failures.extend(validation_failures)
    details.update({
        "stdout_tail": proc.stdout[-2000:],
        "stderr_tail": proc.stderr[-2000:],
    })
    return ScenarioResult(
        name="transitive_deleted_dependency",
        status="passed" if not failures else "failed",
        elapsed_seconds=round(time.perf_counter() - started, 3),
        report_dir=str(paths["report_dir"]),
        failures=failures,
        details=details,
    )


def scenario_query_after_step5(workspace: Path) -> ScenarioResult:
    started = time.perf_counter()
    failures: list[str] = []
    paths = _prepare_transitive_deleted_dependency_workspace(workspace / "query")
    step5_proc = _run_step5(paths)
    if step5_proc.returncode != 0:
        failures.append(f"step5_returncode={step5_proc.returncode}")
    query_proc = _run(
        [
            sys.executable,
            str(ROOT_DIR / "scripts" / "s5_query_call_chain.py"),
            "--report-dir",
            str(paths["report_dir"]),
            "--method",
            "com.vendor.LegacyApi.removed(String)",
            "--limit",
            "5",
        ]
    )
    if query_proc.returncode != 0:
        failures.append(f"query_returncode={query_proc.returncode}")
    query_text = query_proc.stdout
    for expected in ("com.app.App.run", "com.depa.FacadeA.entry", "com.depb.BridgeB.call", "com.vendor.LegacyApi.removed"):
        if expected not in query_text:
            failures.append(f"query output missing {expected}")
    return ScenarioResult(
        name="query_after_step5",
        status="passed" if not failures else "failed",
        elapsed_seconds=round(time.perf_counter() - started, 3),
        report_dir=str(paths["report_dir"]),
        failures=failures,
        details={
            "query_stdout": query_proc.stdout,
            "query_stderr": query_proc.stderr,
            "step5_stdout_tail": step5_proc.stdout[-1200:],
            "step5_stderr_tail": step5_proc.stderr[-1200:],
        },
    )


def scenario_jar_primary_source_auxiliary(workspace: Path) -> ScenarioResult:
    started = time.perf_counter()
    scenario = workspace / "jar_primary_source_auxiliary"
    if scenario.exists():
        shutil.rmtree(scenario)
    failures: list[str] = []
    src_root = scenario / "src"
    for version in ("old", "new"):
        root = src_root / version
        _write(
            root / "com/example/Dto.java",
            """
            package com.example;
            public class Dto {
                private String name;
                public String getName() { return name; }
            }
            """,
        )
        _write(
            root / "com/example/Service.java",
            """
            package com.example;
            public class Service {
                public String run(String value) { return value; }
            }
            """,
        )
        classes = scenario / f"{version}-classes"
        _compile_java(root, classes)
        _jar_from_classes(scenario / f"{version}.jar", classes)

    rows = [
        {
            "coord": "com.example:demo",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "change_type": "REMOVED",
            "api_name": "com.example.Dto.getName",
            "api_simple": "getName",
            "symbol_kind": "method",
            "api_signature": "()",
            "source": "gitdiff",
        },
        {
            "coord": "com.example:demo",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "change_type": "BEHAVIOR_CHANGED",
            "api_name": "com.example.Service.run",
            "api_simple": "run",
            "symbol_kind": "method",
            "api_signature": "(String)",
            "source": "gitdiff",
        },
    ]
    accepted, rejected = step4.filter_gitdiff_rows_with_jar_truth(
        rows,
        old_jar=str(scenario / "old.jar"),
        new_jar=str(scenario / "new.jar"),
        coord="com.example:demo",
        old_ver="1.0.0",
        new_ver="2.0.0",
    )
    accepted_names = [(row.get("api_name"), row.get("change_type")) for row in accepted]
    rejected_reasons = {row.get("api_name"): row.get("filter_reason") for row in rejected}
    if accepted_names != [("com.example.Service.run", "BEHAVIOR_CHANGED")]:
        failures.append(f"unexpected accepted rows: {accepted_names}")
    if rejected_reasons.get("com.example.Dto.getName") != "source_structural_change_not_promoted_japicmp_is_primary":
        failures.append(f"getter source diff was not auxiliary-only: {rejected_reasons}")
    return ScenarioResult(
        name="jar_primary_source_auxiliary",
        status="passed" if not failures else "failed",
        elapsed_seconds=round(time.perf_counter() - started, 3),
        report_dir="",
        failures=failures,
        details={
            "accepted": accepted_names,
            "rejected_reasons": rejected_reasons,
        },
    )


def _missing_local_markdown_links(markdown_path: Path) -> list[str]:
    missing = []
    text = markdown_path.read_text(encoding="utf-8", errors="replace")
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
        target = target.strip().split("#", 1)[0]
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        if not (markdown_path.parent / target).resolve().exists():
            missing.append(target)
    return sorted(set(missing))


def scenario_delivery_output_journey(workspace: Path) -> ScenarioResult:
    """Exercise Step5 -> final delivery and verify every human reading entry."""
    started = time.perf_counter()
    failures: list[str] = []
    paths = _prepare_transitive_deleted_dependency_workspace(workspace / "delivery")
    report_dir = paths["report_dir"]
    step5_proc = _run_step5(paths)
    if step5_proc.returncode != 0:
        failures.append(f"step5_returncode={step5_proc.returncode}")

    selection_path = report_dir / ".runtime" / "cache" / "step5_selection.json"
    selection_path.parent.mkdir(parents=True, exist_ok=True)
    selection_path.write_text(
        json.dumps(
            {
                "mode": "full",
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "included_dependency_coords": ["com.vendor:legacy-lib"],
                "excluded_dependency_coords": [],
                "analyzed_api_count": 1,
                "total_api_count": 1,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    report_path = report_dir / "deliverables" / "report.md"
    findings_path = report_dir / ".runtime" / "findings" / "s6_findings.json"
    step6_proc = _run(
        [
            sys.executable,
            str(ROOT_DIR / "scripts" / "s6_report.py"),
            "--report-dir",
            str(report_dir),
            "--output-findings",
            str(findings_path),
            "--output-report",
            str(report_path),
        ]
    )
    if step6_proc.returncode != 0:
        failures.append(f"step6_returncode={step6_proc.returncode}")

    state = orchestrator.new_main_state(report_dir)
    state["state"].update(
        {
            "current_step": "done",
            "completed_step": "step6",
            "status": "completed",
            "completion_summary": orchestrator.build_final_completion_summary(report_dir),
        }
    )
    orchestrator.save_main_state(report_dir, state)

    landing_path = report_dir / "README.md"
    scope_path = report_dir / "deliverables" / "analysis-scope.md"
    required_files = [report_path, scope_path, landing_path, findings_path]
    for path in required_files:
        if not path.is_file() or path.stat().st_size == 0:
            failures.append(f"missing_or_empty:{path.relative_to(report_dir)}")

    report_text = report_path.read_text(encoding="utf-8", errors="replace") if report_path.exists() else ""
    landing_text = landing_path.read_text(encoding="utf-8", errors="replace") if landing_path.exists() else ""
    for expected in (
        "## 一、核心结论",
        "## 二、结论限制",
        "## 三、下一步复核顺序",
        "## 四、分析结果总表",
        "严重级别不等于结论确定性",
        "已确认链路 3 条",
    ):
        if expected not in report_text:
            failures.append(f"report_missing:{expected}")
    if "已确认影响" in report_text and "发现 3 条依赖引用，尚未回溯到业务入口" in report_text:
        failures.append("confirmed_impact_uses_unresolved_evidence_summary")
    for forbidden in (
        "__business__",
        "<clinit>",
        "fallback simple key",
        "response_schema",
        "action_requirements",
    ):
        if forbidden in report_text or forbidden in landing_text:
            failures.append(f"internal_marker_visible:{forbidden}")
    if re.search(r"\b[Ss]tep\d+\b", landing_text):
        failures.append("landing_exposes_internal_step_id")
    for path in (report_path, scope_path, landing_path):
        if path.exists():
            for target in _missing_local_markdown_links(path):
                failures.append(
                    f"broken_link:{path.relative_to(report_dir)}->{target}"
                )

    return ScenarioResult(
        name="delivery_output_journey",
        status="passed" if not failures else "failed",
        elapsed_seconds=round(time.perf_counter() - started, 3),
        report_dir=str(report_dir),
        failures=failures,
        details={
            "report": str(report_path),
            "scope": str(scope_path),
            "landing": str(landing_path),
            "step5_stderr_tail": step5_proc.stderr[-1200:],
            "step6_stderr_tail": step6_proc.stderr[-1200:],
        },
    )


SCENARIOS = {
    "delivery_output_journey": scenario_delivery_output_journey,
    "transitive_deleted_dependency": scenario_transitive_deleted_dependency,
    "query_after_step5": scenario_query_after_step5,
    "jar_primary_source_auxiliary": scenario_jar_primary_source_auxiliary,
}


def run_scenarios(workspace: Path, scenario_name: str) -> dict:
    _require_tool("javac")
    workspace.mkdir(parents=True, exist_ok=True)
    names = sorted(SCENARIOS) if scenario_name == "all" else [scenario_name]
    results = [SCENARIOS[name](workspace) for name in names]
    return {
        "status": "failed" if any(item.status != "passed" for item in results) else "passed",
        "workspace": str(workspace),
        "results": [asdict(item) for item in results],
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run fixed generated user-scenario regressions.")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS) + ["all"], default="all")
    parser.add_argument(
        "--workspace",
        default=str(DEFAULT_WORKSPACE),
        help="Workspace for generated projects and reports.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON only.")
    parser.add_argument("--json-out", default="", help="Write structured result to this JSON file.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    payload = run_scenarios(Path(args.workspace), args.scenario)
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"USER SCENARIO REGRESSION: {payload['status']}")
        print(f"workspace: {payload['workspace']}")
        for item in payload["results"]:
            print(f"  {item['name']}: {item['status']} elapsed={item['elapsed_seconds']}s")
            if item.get("report_dir"):
                print(f"    report: {item['report_dir']}")
            for failure in item.get("failures") or []:
                print(f"    FAILURE {failure}")
    return 0 if payload["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
