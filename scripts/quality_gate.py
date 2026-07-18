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
import shutil
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
    run_after_failure: bool = False
    output_paths: tuple[str, ...] = ()


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
    "tests.test_s5_query_call_chain",
]


CORE_SEMANTIC_TESTS = [
    "tests.test_artifact_bytecode_catalog",
    "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_business_to_transitive_packaged_hit",
    "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_three_hop_packaged_hit",
    "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_business_to_changed_field_hit",
    "tests.test_s5_query_call_chain.S5QueryCallChainTest.test_query_respects_limit_on_many_business_callers",
    "tests.test_s5_query_call_chain.S5QueryCallChainTest.test_query_avoids_cycles_while_finding_business_chain",
]

REQUIRED_TOOLS = ("git", "java", "javac", "javap", "jdeps", "mvn")


def validate_required_tools(names=REQUIRED_TOOLS):
    """Return every mandatory executable missing from PATH."""
    return [name for name in names if shutil.which(name) is None]


def _required_tools_task(names=REQUIRED_TOOLS):
    return GateTask(
        name="required_tools",
        command=list(names),
        purpose="必需工具预检：" + ", ".join(names),
    )


def _run_required_tools_task(task):
    started = time.perf_counter()
    missing = validate_required_tools(tuple(task.command))
    status = "failed" if missing else "passed"
    purpose = task.purpose
    if missing:
        purpose = f"{purpose}；缺失：{', '.join(missing)}"
    result = GateResult(
        name=task.name,
        command=task.command,
        status=status,
        elapsed_sec=round(time.perf_counter() - started, 3),
        returncode=1 if missing else 0,
        purpose=purpose,
    )
    print(
        f"[quality-gate] {status.upper()} {task.name} "
        f"elapsed={result.elapsed_sec:.2f}s rc={result.returncode}",
        flush=True,
    )
    if missing:
        print(f"[quality-gate] missing required tools: {', '.join(missing)}", flush=True)
    return result


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


def _real_project_task(python_exe, case, report_root, json_out=""):
    command = [python_exe, "scripts/real_project_regression.py", "--case", case]
    if report_root:
        command.extend(["--report-root", report_root])
    if json_out:
        command.extend(["--json-out", json_out])
    return GateTask(
        name=f"real_project_{case}",
        command=command,
        purpose="真实项目矩阵，验证复杂源码、字节码、输出语义和性能边界",
        heavy=True,
        real_project=True,
        output_paths=(json_out,) if json_out else (),
    )


def _quality_signal_audit_task(python_exe, real_json, audit_json):
    return GateTask(
        name="quality_signal_audit",
        command=[
            python_exe,
            "scripts/quality_signal_audit.py",
            real_json,
            "--json-out",
            audit_json,
        ],
        purpose="审计真实项目质量信号，阻塞 P0/P1 correctness/capability/evidence 问题",
        real_project=True,
        run_after_failure=True,
        output_paths=(audit_json,),
    )


def _test_round_retrospective_task(python_exe, real_json, audit_json, audit_root):
    retrospective_json = str(audit_root / "test_round_retrospective.json")
    retrospective_markdown = str(audit_root / "test_round_retrospective.md")
    return GateTask(
        name="test_round_retrospective",
        command=[
            python_exe,
            "scripts/test_round_retrospective.py",
            real_json,
            audit_json,
            "--reviews",
            str(audit_root / "test_round_reviews.json"),
            "--history",
            str(audit_root / "test_round_history.json"),
            "--json-out",
            retrospective_json,
            "--markdown-out",
            retrospective_markdown,
        ],
        purpose="复盘本轮缺陷根因、逃逸原因、覆盖增量、性能和下一项目决策",
        real_project=True,
        run_after_failure=True,
        output_paths=(retrospective_json, retrospective_markdown),
    )


def _capability_family_closure_task(python_exe, real_json, audit_root):
    closure_json = str(audit_root / "capability_family_closure.json")
    return GateTask(
        name="capability_family_closure",
        command=[
            python_exe,
            "scripts/capability_family_closure.py",
            "tests/fixtures/capability_families.json",
            real_json,
            "--reviews",
            str(audit_root / "test_round_reviews.json"),
            "--history",
            str(audit_root / "test_round_history.json"),
            "--retrospective",
            str(audit_root / "test_round_retrospective.json"),
            "--json-out",
            closure_json,
        ],
        purpose="验证能力家族已完成全生产路径、广义回归、故障注入和跨项目闭环",
        real_project=True,
        run_after_failure=True,
        output_paths=(closure_json,),
    )


def _user_scenario_task(python_exe):
    return GateTask(
        name="user_scenario_regression",
        command=[
            python_exe,
            "scripts/user_scenario_regression.py",
            "--scenario",
            "all",
            "--workspace",
            "/private/tmp/java-upgrade-quality-user-scenarios",
        ],
        purpose="固定模拟用户场景：删除依赖跨 jar 链路、jar-primary 过滤、Step5 即时查询",
        heavy=True,
    )


def _accuracy_benchmark_task(python_exe, profile):
    return GateTask(
        name=f"accuracy_benchmark_{profile}",
        command=[python_exe, "scripts/accuracy_benchmark.py", "--profile", profile],
        purpose=f"准确性基准矩阵：{profile}",
        heavy=profile in {"step5", "all"},
    )


def _diff_check_task():
    return GateTask(
        name="git_diff_check",
        command=[sys.executable, "scripts/git_change_check.py"],
        purpose="检查工作区与分支已提交变更的 whitespace/error markers",
    )


def _oracle_independence_task(python_exe):
    return GateTask(
        name="oracle_independence",
        command=[
            python_exe,
            "scripts/oracle_independence.py",
            "tests/fixtures/oracle_boundary.json",
        ],
        purpose="第三方 Oracle 实现与分析器提取、过滤和裁决代码保持独立",
    )


def build_plan(profile, python_exe=None, skip_real=False, real_case="guard", report_root=None):
    python_exe = python_exe or sys.executable
    required_tools = REQUIRED_TOOLS if profile in {"step5", "release"} else REQUIRED_TOOLS[:-1]
    tasks = [
        _required_tools_task(required_tools),
        _py_compile_task(python_exe),
        _oracle_independence_task(python_exe),
    ]
    audit_root = Path(report_root or "/private/tmp/jua-quality-gate")
    real_json = str(audit_root / f"real_project_{real_case}.json")
    audit_json = str(audit_root / f"quality_signal_audit_{real_case}.json")

    if profile == "quick":
        tasks.append(_accuracy_benchmark_task(python_exe, "core"))
        tasks.append(_unittest_task(
            python_exe,
            "unit_core_semantics",
            CORE_SEMANTIC_TESTS,
            "核心准确性契约：jdeps 对照、多依赖链路、字段链路",
        ))
        tasks.append(_smoke_task(python_exe, "core"))
    elif profile == "step5":
        tasks.append(_accuracy_benchmark_task(python_exe, "step5"))
        tasks.append(_unittest_task(
            python_exe,
            "unit_step5_semantics",
            STEP5_TESTS,
            "Step5 语义回归：owner/signature/字节码/反射/间接引用",
            heavy=True,
        ))
        tasks.append(_smoke_task(python_exe, "core"))
        tasks.append(_smoke_task(python_exe, "step5"))
        tasks.append(_user_scenario_task(python_exe))
        if not skip_real:
            tasks.append(_real_project_task(python_exe, real_case, report_root, real_json))
            tasks.append(_quality_signal_audit_task(python_exe, real_json, audit_json))
            tasks.append(_test_round_retrospective_task(
                python_exe, real_json, audit_json, audit_root
            ))
            tasks.append(_capability_family_closure_task(
                python_exe, real_json, audit_root
            ))
    elif profile == "release":
        tasks.append(_accuracy_benchmark_task(python_exe, "all"))
        tasks.append(_unittest_discover_task(python_exe))
        tasks.append(_smoke_task(python_exe, "all"))
        tasks.append(_user_scenario_task(python_exe))
        if not skip_real:
            tasks.append(_real_project_task(python_exe, real_case, report_root, real_json))
            tasks.append(_quality_signal_audit_task(python_exe, real_json, audit_json))
            tasks.append(_test_round_retrospective_task(
                python_exe, real_json, audit_json, audit_root
            ))
            tasks.append(_capability_family_closure_task(
                python_exe, real_json, audit_root
            ))
        tasks.append(_diff_check_task())
    else:
        raise ValueError(f"unknown profile: {profile}")
    return tasks


def _run_task(task, env=None):
    if task.name == "required_tools":
        return _run_required_tools_task(task)
    for raw_path in task.output_paths:
        output = Path(raw_path)
        if output.is_file():
            output.unlink()
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


def _read_audit_summary(tasks):
    for task in tasks:
        if task.name != "quality_signal_audit":
            continue
        command = list(task.command)
        if "--json-out" not in command:
            return {}
        index = command.index("--json-out") + 1
        if index >= len(command):
            return {}
        path = Path(command[index])
        if not path.exists():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        summary = payload.get("summary")
        return summary if isinstance(summary, dict) else {}
    return {}


def _execute_tasks(tasks, env, continue_on_failure=False):
    results = []
    overall = "passed"
    failure_seen = False
    for task in tasks:
        if failure_seen and not continue_on_failure and not task.run_after_failure:
            break
        result = _run_task(task, env=env)
        results.append(result)
        if result.status != "passed":
            overall = "failed"
            failure_seen = True
    return results, overall


def ensure_round_input_files(tasks):
    defaults = {
        "--reviews": {"findings": []},
        "--history": [],
    }
    for task in tasks:
        command = list(task.command)
        for option, default in defaults.items():
            if option not in command:
                continue
            index = command.index(option) + 1
            if index >= len(command):
                continue
            path = Path(command[index])
            if path.exists():
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(default, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run java-upgrade-analyzer quality gates")
    parser.add_argument("--profile", choices=["quick", "step5", "release"], default="quick")
    parser.add_argument("--python", default=sys.executable, help="Python executable used by gate commands")
    parser.add_argument("--skip-real", action="store_true", help="Skip real project regression matrix")
    parser.add_argument(
        "--real-case", default="guard",
        help="real_project_regression.py selector; default: guard (reproducible guardian matrix)",
    )
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

    ensure_round_input_files(tasks)
    started = time.perf_counter()
    env = dict(os.environ)
    results, overall = _execute_tasks(
        tasks, env=env, continue_on_failure=args.continue_on_failure
    )

    audit_summary = _read_audit_summary(tasks)
    payload = {
        "profile": args.profile,
        "status": overall,
        "decision": "release_blocked" if overall == "failed" else "release_allowed",
        "elapsed_sec": round(time.perf_counter() - started, 3),
        "blocking_signals": int(audit_summary.get("blocking_signals") or 0),
        "non_blocking_signals": int(audit_summary.get("non_blocking_signals") or 0),
        "fixture_debt": int(audit_summary.get("fixture_debt") or 0),
        "real_project_skipped": int((audit_summary.get("by_type") or {}).get("infra_skip") or 0),
        "results": [asdict(result) for result in results],
        "skipped_tasks": [asdict(task) for task in tasks[len(results):]],
    }
    _write_json(args.json_out, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if overall == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
