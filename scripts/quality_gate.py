#!/usr/bin/env python3
"""Unified quality gate runner for java-upgrade-analyzer.

The gate is intentionally boring: it does not invent new checks, it gives the
existing semantic tests, smoke tests, real-project probes and packaging checks a
single repeatable entry point.
"""

import argparse
from dataclasses import dataclass, asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class GateTask:
    name: str
    command: list
    purpose: str
    heavy: bool = False
    real_project: bool = False


@dataclass
class GateResult:
    name: str
    command: list
    status: str
    elapsed_sec: float = 0.0
    returncode: int = 0
    purpose: str = ""


STEP5_TESTS = [
    "tests.test_step5_key_matching",
    "tests.test_business_bytecode_graph",
    "tests.test_artifact_bytecode_catalog",
    "tests.test_indirect_usage_analyzer",
]


CORE_SEMANTIC_TESTS = [
    "tests.test_artifact_bytecode_catalog",
    "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_business_to_transitive_packaged_hit",
    "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_three_hop_packaged_hit",
    "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_business_to_changed_field_hit",
]


def _python_files_under_scripts():
    return sorted(str(path.relative_to(ROOT)) for path in (ROOT / "scripts").glob("*.py"))


def _py_compile_task(python_exe):
    return GateTask(
        name="py_compile_scripts",
        command=[python_exe, "-m", "py_compile", *_python_files_under_scripts()],
        purpose="Python 语法和 import-time 编译检查",
    )


def _unittest_task(python_exe, name, modules, purpose, heavy=False):
    return GateTask(
        name=name,
        command=[python_exe, "-m", "unittest", *modules],
        purpose=purpose,
        heavy=heavy,
    )


def _unittest_discover_task(python_exe):
    return GateTask(
        name="unit_all",
        command=[python_exe, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        purpose="完整单元测试，防止跨步骤回归",
        heavy=True,
    )


def _smoke_task(python_exe, group):
    return GateTask(
        name=f"smoke_{group}",
        command=[python_exe, "scripts/smoke_regression.py", "--group", group],
        purpose=f"主流程 smoke 回归：{group}",
        heavy=group == "all",
    )


def _real_project_task(python_exe, case, report_root):
    command = [python_exe, "scripts/real_project_regression.py", "--case", case]
    if report_root:
        command.extend(["--report-root", report_root])
    return GateTask(
        name=f"real_project_{case}",
        command=command,
        purpose="真实项目矩阵，验证复杂源码、字节码、输出语义和性能边界",
        heavy=True,
        real_project=True,
    )


def _diff_check_task():
    return GateTask(
        name="git_diff_check",
        command=["git", "diff", "--check"],
        purpose="检查 whitespace/error markers，防止低级提交污染",
    )


def build_plan(profile, python_exe=None, skip_real=False, real_case="all", report_root=None):
    python_exe = python_exe or sys.executable
    tasks = [_py_compile_task(python_exe)]

    if profile == "quick":
        tasks.append(_unittest_task(
            python_exe,
            "unit_core_semantics",
            CORE_SEMANTIC_TESTS,
            "核心准确性契约：jdeps 对照、多依赖链路、字段链路",
        ))
        tasks.append(_smoke_task(python_exe, "core"))
    elif profile == "step5":
        tasks.append(_unittest_task(
            python_exe,
            "unit_step5_semantics",
            STEP5_TESTS,
            "Step5 语义回归：owner/signature/字节码/反射/间接引用",
            heavy=True,
        ))
        tasks.append(_smoke_task(python_exe, "core"))
        tasks.append(_smoke_task(python_exe, "step5"))
        if not skip_real:
            tasks.append(_real_project_task(python_exe, real_case, report_root))
    elif profile == "release":
        tasks.append(_unittest_discover_task(python_exe))
        tasks.append(_smoke_task(python_exe, "all"))
        if not skip_real:
            tasks.append(_real_project_task(python_exe, real_case, report_root))
        tasks.append(_diff_check_task())
    else:
        raise ValueError(f"unknown profile: {profile}")
    return tasks


def _run_task(task, env=None):
    started = time.perf_counter()
    print(f"[quality-gate] START {task.name}: {' '.join(task.command)}", flush=True)
    completed = subprocess.run(task.command, cwd=str(ROOT), env=env)
    elapsed = time.perf_counter() - started
    status = "passed" if completed.returncode == 0 else "failed"
    print(
        f"[quality-gate] {status.upper()} {task.name} "
        f"elapsed={elapsed:.2f}s rc={completed.returncode}",
        flush=True,
    )
    return GateResult(
        name=task.name,
        command=task.command,
        status=status,
        elapsed_sec=round(elapsed, 3),
        returncode=completed.returncode,
        purpose=task.purpose,
    )


def _write_json(path, payload):
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run java-upgrade-analyzer quality gates")
    parser.add_argument("--profile", choices=["quick", "step5", "release"], default="quick")
    parser.add_argument("--python", default=sys.executable, help="Python executable used by gate commands")
    parser.add_argument("--skip-real", action="store_true", help="Skip real project regression matrix")
    parser.add_argument("--real-case", default="all", help="real_project_regression.py case, default: all")
    parser.add_argument("--report-root", default="", help="Report root for real project regression")
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without executing")
    parser.add_argument("--continue-on-failure", action="store_true", help="Run remaining tasks after a failure")
    parser.add_argument("--json-out", default="", help="Write structured gate results to JSON")
    args = parser.parse_args(argv)

    tasks = build_plan(
        args.profile,
        python_exe=args.python,
        skip_real=args.skip_real,
        real_case=args.real_case,
        report_root=args.report_root,
    )

    if args.dry_run:
        payload = {
            "profile": args.profile,
            "dry_run": True,
            "tasks": [asdict(task) for task in tasks],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        _write_json(args.json_out, payload)
        return 0

    started = time.perf_counter()
    env = dict(os.environ)
    results = []
    overall = "passed"
    for task in tasks:
        result = _run_task(task, env=env)
        results.append(result)
        if result.status != "passed":
            overall = "failed"
            if not args.continue_on_failure:
                break

    payload = {
        "profile": args.profile,
        "status": overall,
        "elapsed_sec": round(time.perf_counter() - started, 3),
        "results": [asdict(result) for result in results],
        "skipped_tasks": [asdict(task) for task in tasks[len(results):]],
    }
    _write_json(args.json_out, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if overall == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
