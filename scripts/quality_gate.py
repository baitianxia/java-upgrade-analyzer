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

from compat import setup_utf8_io
from path_runtime import short_temp_root
from runtime_contract import contract_payload


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT_ROOT = short_temp_root() / "jua-quality-gate"

setup_utf8_io()


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
    "tests.test_persistent_artifact_fact_cache",
    "tests.test_business_bytecode_graph",
    "tests.test_artifact_bytecode_catalog",
    "tests.test_indirect_usage_analyzer",
    "tests.test_s5_query_call_chain",
]


CORE_SEMANTIC_TESTS = [
    "tests.test_artifact_bytecode_catalog",
    "tests.test_persistent_artifact_fact_cache",
    "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_business_to_transitive_packaged_hit",
    "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_three_hop_packaged_hit",
    "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_business_to_changed_field_hit",
    "tests.test_s5_query_call_chain.S5QueryCallChainTest.test_query_respects_limit_on_many_business_callers",
    "tests.test_s5_query_call_chain.S5QueryCallChainTest.test_query_avoids_cycles_while_finding_business_chain",
]

PLATFORM_CONTRACT_TESTS = [
    "tests.test_platform_contract",
    (
        "tests.test_step5_memory_equivalence.Step5MemoryObserverTest."
        "test_imports_and_runs_when_resource_module_is_unavailable"
    ),
    (
        "tests.test_user_scenario_regression.UserScenarioRegressionTest."
        "test_java_classpath_uses_platform_separator"
    ),
    (
        "tests.test_user_scenario_regression.UserScenarioRegressionTest."
        "test_default_workspace_uses_platform_temp_directory"
    ),
    "tests.test_build_tool_selection",
    (
        "tests.test_execution_faults.ExecutionFaultTest."
        "test_permission_fault_uses_portable_owner_write_boundary"
    ),
    (
        "tests.test_run_step_main_state.RunStepMainStateTest."
        "test_resume_command_uses_powershell_safe_argument_quoting"
    ),
    (
        "tests.test_quality_gate.QualityGateTest."
        "test_user_scenario_workspace_follows_portable_report_root"
    ),
    (
        "tests.test_quality_gate.QualityGateTest."
        "test_every_profile_runs_shared_script_boundary_regressions"
    ),
    (
        "tests.test_real_project_regression.RealProjectRegressionTest."
        "test_default_report_root_uses_platform_temp_directory"
    ),
]

SHARED_SCRIPT_BOUNDARY_TESTS = [
    (
        "tests.test_step1_packaged_deps.Step1PackagedDepsTest."
        "test_merge_runtime_artifact_record_ignores_blank_identity"
    ),
    (
        "tests.test_step1_packaged_deps.Step1PackagedDepsTest."
        "test_merge_runtime_artifact_record_initializes_without_mutating_input"
    ),
    (
        "tests.test_step1_packaged_deps.Step1PackagedDepsTest."
        "test_merge_runtime_artifact_record_preserves_and_deduplicates_evidence"
    ),
    (
        "tests.test_artifact_safety.ArtifactSafetyTest."
        "test_inspect_archive_rejects_missing_and_non_file_paths_without_scanning"
    ),
    (
        "tests.test_artifact_safety.ArtifactSafetyTest."
        "test_inspect_archive_distinguishes_read_failure_from_invalid_format"
    ),
    (
        "tests.test_artifact_safety.ArtifactSafetyTest."
        "test_inspect_archive_forwards_explicit_limits"
    ),
]

RELEASE_REAL_PROJECT_SCOPES = frozenset({"guard", "all"})


def _environment_contract_task(require_maven=True):
    return GateTask(
        name="environment_contract",
        command=["with_maven" if require_maven else "without_maven"],
        purpose="运行契约预检：分析器固定依赖及当前测试 profile 所需命令",
    )


def _run_environment_contract_task(task):
    started = time.perf_counter()
    payload = contract_payload(
        require_java_tools=True,
        require_maven=task.command == ["with_maven"],
    )
    failures = [item for item in payload["checks"] if item["status"] != "passed"]
    status = payload["status"]
    purpose = task.purpose + (
        "；失败：" + ", ".join(item["component"] for item in failures)
        if failures else ""
    )
    result = GateResult(
        name=task.name,
        command=task.command,
        status=status,
        elapsed_sec=round(time.perf_counter() - started, 3),
        returncode=1 if failures else 0,
        purpose=purpose,
    )
    print(
        f"[quality-gate] {status.upper()} {task.name} "
        f"elapsed={result.elapsed_sec:.2f}s rc={result.returncode}",
        flush=True,
    )
    for failure in failures:
        print(
            "[quality-gate] environment contract failure: "
            f"{failure['component']} observed={failure['observed']} "
            f"expected={failure['expected']} reason={failure['reason']}",
            flush=True,
        )
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


def _platform_contract_task(python_exe):
    return _unittest_task(
        python_exe,
        "platform_compatibility",
        PLATFORM_CONTRACT_TESTS,
        "Linux、macOS、Windows 的导入、路径、命令、权限及临时目录契约",
    )


def _shared_script_boundary_task(python_exe):
    return _unittest_task(
        python_exe,
        "shared_script_boundaries",
        SHARED_SCRIPT_BOUNDARY_TESTS,
        "全局共享脚本的运行时依赖合并与归档读取边界回归",
    )


def _smoke_task(python_exe, group, json_out=""):
    command = [python_exe, "scripts/smoke_regression.py", "--group", group]
    if json_out:
        command.extend(["--json-out", json_out])
    return GateTask(
        name=f"smoke_{group}",
        command=command,
        purpose=f"主流程 smoke 回归：{group}",
        heavy=group == "all",
        output_paths=(json_out,) if json_out else (),
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
            "--fail-on-blocking",
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


def _user_scenario_task(python_exe, audit_root):
    return GateTask(
        name="user_scenario_regression",
        command=[
            python_exe,
            "scripts/user_scenario_regression.py",
            "--scenario",
            "all",
            "--workspace",
            str(Path(audit_root) / "user_scenarios"),
        ],
        purpose="固定模拟用户场景：删除依赖跨 jar 链路、jar-primary 过滤、Step5 即时查询",
        heavy=True,
    )


def _accuracy_benchmark_task(python_exe, profile, json_out=""):
    command = [
        python_exe,
        "scripts/accuracy_benchmark.py",
        "--profile",
        profile,
        "--continue-on-failure",
    ]
    if json_out:
        command.extend(["--json-out", json_out])
    return GateTask(
        name=f"accuracy_benchmark_{profile}",
        command=command,
        purpose=f"准确性基准矩阵：{profile}",
        heavy=profile in {"step5", "all"},
        output_paths=(json_out,) if json_out else (),
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


def _production_mutation_task(python_exe):
    return _unittest_task(
        python_exe,
        "production_mutations",
        [
            "tests.test_production_mutation.ProductionMutationTest."
            "test_registered_production_mutants_are_all_killed"
        ],
        "生产代码 AST 变异矩阵必须全部被广义回归杀死",
        heavy=True,
    )


def _capability_profile_task(python_exe, name, profile, audit_root, *, validate_only=False, heavy=False):
    json_out = str(audit_root / f"{name}.json")
    command = [
        python_exe,
        "scripts/capability_test_catalog.py",
        "--profile",
        profile,
        "--json-out",
        json_out,
    ]
    if validate_only:
        command.append("--validate-only")
    return GateTask(
        name=name,
        command=command,
        purpose=(
            f"声明式 capability-family 测试目录：{profile}；"
            "自动校验引用、稳定分片、重复结果与时长排行"
        ),
        heavy=heavy,
        output_paths=(json_out,),
    )


def _branch_coverage_task(python_exe, audit_root):
    json_out = str(audit_root / "branch_coverage_core.json")
    return GateTask(
        name="branch_coverage_core",
        command=[
            python_exe,
            "scripts/branch_coverage_gate.py",
            "--profile",
            "branch_core",
            "--json-out",
            json_out,
        ],
        purpose="核心身份规范化与五态结论策略的 decision branch 覆盖门槛",
        heavy=True,
        output_paths=(json_out,),
    )


def _determinism_task(python_exe, profile):
    method = (
        "test_generated_core_matrix_is_semantically_identical"
        if profile == "core"
        else "test_generated_production_matrix_is_semantically_identical"
    )
    return _unittest_task(
        python_exe,
        f"determinism_{profile}",
        [f"tests.test_determinism_gate.DeterminismGateTest.{method}"],
        f"跨进程语义确定性矩阵：{profile}",
        heavy=profile == "full",
    )


def _execution_fault_task(python_exe):
    return _unittest_task(
        python_exe,
        "execution_faults",
        ["tests.test_tool_execution", "tests.test_execution_faults"],
        "执行超时、退出、截断、替换、权限、编码、中断与缓存竞态必须失败关闭",
    )


def _generated_complexity_task(python_exe):
    return _unittest_task(
        python_exe,
        "generated_complexity",
        [
            "tests.test_complexity_gate.ComplexityGateTest."
            "test_real_generated_collector_produces_valid_1x_2x_4x_tiers"
        ],
        "生成项目生产字节码收集路径的正确性优先缩放预算",
        heavy=True,
    )


def _claude_skill_contract_task(python_exe):
    return _unittest_task(
        python_exe,
        "claude_skill_contract",
        ["tests.test_claude_skill_contract"],
        "从无用户状态和缓存的干净副本验证 Claude Code 公共 Skill 工作流",
        heavy=True,
    )


def build_plan(profile, python_exe=None, skip_real=True, real_case="guard", report_root=None):
    python_exe = python_exe or sys.executable
    tasks = [
        _environment_contract_task(require_maven=profile in {"step5", "release"}),
        _py_compile_task(python_exe),
        _platform_contract_task(python_exe),
        _shared_script_boundary_task(python_exe),
        _oracle_independence_task(python_exe),
    ]
    audit_root = Path(report_root) if report_root else DEFAULT_AUDIT_ROOT
    real_json = str(audit_root / f"real_project_{real_case}.json")
    audit_json = str(audit_root / f"quality_signal_audit_{real_case}.json")

    if profile == "quick":
        tasks.append(_determinism_task(python_exe, "core"))
        tasks.append(_accuracy_benchmark_task(
            python_exe,
            "core",
            str(audit_root / "accuracy_benchmark_core.json"),
        ))
        tasks.append(_capability_profile_task(
            python_exe, "unit_core_semantics", "quick", audit_root
        ))
        tasks.append(_smoke_task(python_exe, "core", str(audit_root / "smoke_core.json")))
    elif profile == "step5":
        tasks.append(_accuracy_benchmark_task(
            python_exe,
            "step5",
            str(audit_root / "accuracy_benchmark_step5.json"),
        ))
        tasks.append(_capability_profile_task(
            python_exe, "unit_step5_semantics", "step5", audit_root, heavy=True
        ))
        tasks.append(_smoke_task(python_exe, "core", str(audit_root / "smoke_core.json")))
        tasks.append(_smoke_task(python_exe, "step5", str(audit_root / "smoke_step5.json")))
        tasks.append(_user_scenario_task(python_exe, audit_root))
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
        tasks.append(_capability_profile_task(
            python_exe,
            "capability_test_catalog",
            "quick",
            audit_root,
            validate_only=True,
        ))
        tasks.append(_branch_coverage_task(python_exe, audit_root))
        tasks.append(_capability_profile_task(
            python_exe, "test_health", "health", audit_root
        ))
        tasks.append(_production_mutation_task(python_exe))
        tasks.append(_execution_fault_task(python_exe))
        tasks.append(_determinism_task(python_exe, "full"))
        tasks.append(_generated_complexity_task(python_exe))
        tasks.append(_claude_skill_contract_task(python_exe))
        tasks.append(_accuracy_benchmark_task(
            python_exe,
            "all",
            str(audit_root / "accuracy_benchmark_all.json"),
        ))
        tasks.append(_unittest_discover_task(python_exe))
        tasks.append(_smoke_task(python_exe, "all", str(audit_root / "smoke_all.json")))
        tasks.append(_user_scenario_task(python_exe, audit_root))
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
    if task.name == "environment_contract":
        return _run_environment_contract_task(task)
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


def _read_audit_summary(tasks, results=None):
    if results is not None:
        result_by_name = {result.name: result for result in results}
        audit_result = result_by_name.get("quality_signal_audit")
        if audit_result is None or audit_result.status != "passed":
            return {}
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


def _task_group_status(tasks, results, *, real_project):
    planned = [task for task in tasks if task.real_project is real_project]
    if not planned:
        return "not_evaluated"
    result_by_name = {result.name: result for result in results}
    observed = [result_by_name.get(task.name) for task in planned]
    if any(result is not None and result.status != "passed" for result in observed):
        return "failed"
    if any(result is None for result in observed):
        return "not_evaluated"
    return "passed"


def build_gate_decision_summary(
    profile,
    tasks,
    results,
    *,
    real_scope_mode,
    real_case,
    audit_summary=None,
    dry_run=False,
):
    """Build the release contract without conflating regression success with approval."""
    audit_summary = audit_summary if isinstance(audit_summary, dict) else {}
    real_tasks = [task for task in tasks if task.real_project]
    real_scope = {
        "mode": real_scope_mode,
        "selector": real_case if real_scope_mode == "included" else "",
        "planned_task_count": len(real_tasks),
        "release_required_selectors": sorted(RELEASE_REAL_PROJECT_SCOPES),
    }
    if dry_run:
        local_status = "not_evaluated"
        real_status = "skipped" if real_scope_mode == "explicitly_skipped" else "not_evaluated"
    else:
        local_status = _task_group_status(tasks, results, real_project=False)
        if real_scope_mode == "explicitly_skipped":
            real_status = "skipped"
        elif real_scope_mode != "included":
            real_status = "not_evaluated"
        else:
            real_status = _task_group_status(tasks, results, real_project=True)

    infra_skips = int((audit_summary.get("by_type") or {}).get("infra_skip") or 0)
    blocking_signals = int(audit_summary.get("blocking_signals") or 0)
    fixture_debt = int(audit_summary.get("fixture_debt") or 0)
    if real_scope_mode == "included" and infra_skips:
        real_status = "skipped"

    release_decision = "not_evaluated"
    if not dry_run and profile == "release" and real_scope_mode == "included":
        audit_complete = bool(audit_summary) and "blocking_signals" in audit_summary
        release_decision = (
            "release_allowed"
            if (
                local_status == "passed"
                and real_status == "passed"
                and real_case in RELEASE_REAL_PROJECT_SCOPES
                and audit_complete
                and blocking_signals == 0
                and fixture_debt == 0
                and infra_skips == 0
            )
            else "release_blocked"
        )

    return {
        "local_regression_status": local_status,
        "real_project_scope": real_scope,
        "real_project_status": real_status,
        "release_decision": release_decision,
    }


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
    real_project_group = parser.add_mutually_exclusive_group()
    real_project_group.add_argument(
        "--include-real",
        dest="skip_real",
        action="store_false",
        help="Explicitly include the real project regression matrix",
    )
    real_project_group.add_argument(
        "--skip-real",
        dest="skip_real",
        action="store_true",
        help="Skip the real project regression matrix (default)",
    )
    parser.set_defaults(skip_real=None)
    parser.add_argument(
        "--real-case", default="guard",
        help="real_project_regression.py selector; default: guard (reproducible guardian matrix)",
    )
    parser.add_argument("--report-root", default="", help="Report root for real project regression")
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without executing")
    parser.add_argument("--continue-on-failure", action="store_true", help="Run remaining tasks after a failure")
    parser.add_argument("--json-out", default="", help="Write structured gate results to JSON")
    args = parser.parse_args(argv)

    skip_real = args.skip_real is not False
    real_scope_mode = (
        "included"
        if args.skip_real is False
        else ("explicitly_skipped" if args.skip_real is True else "not_planned")
    )
    tasks = build_plan(
        args.profile,
        python_exe=args.python,
        skip_real=skip_real,
        real_case=args.real_case,
        report_root=args.report_root,
    )

    if args.dry_run:
        payload = {
            "profile": args.profile,
            "dry_run": True,
            "tasks": [asdict(task) for task in tasks],
        }
        payload.update(build_gate_decision_summary(
            args.profile,
            tasks,
            [],
            real_scope_mode=real_scope_mode,
            real_case=args.real_case,
            dry_run=True,
        ))
        payload["decision"] = payload["release_decision"]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        _write_json(args.json_out, payload)
        return 0

    ensure_round_input_files(tasks)
    started = time.perf_counter()
    env = dict(os.environ)
    results, overall = _execute_tasks(
        tasks, env=env, continue_on_failure=args.continue_on_failure
    )

    audit_summary = _read_audit_summary(tasks, results)
    decision_summary = build_gate_decision_summary(
        args.profile,
        tasks,
        results,
        real_scope_mode=real_scope_mode,
        real_case=args.real_case,
        audit_summary=audit_summary,
    )
    payload = {
        "profile": args.profile,
        "status": overall,
        "decision": decision_summary["release_decision"],
        "elapsed_sec": round(time.perf_counter() - started, 3),
        "blocking_signals": int(audit_summary.get("blocking_signals") or 0),
        "non_blocking_signals": int(audit_summary.get("non_blocking_signals") or 0),
        "fixture_debt": int(audit_summary.get("fixture_debt") or 0),
        "real_project_skipped": int((audit_summary.get("by_type") or {}).get("infra_skip") or 0),
        "results": [asdict(result) for result in results],
        "skipped_tasks": [asdict(task) for task in tasks[len(results):]],
    }
    payload.update(decision_summary)
    _write_json(args.json_out, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if (
        overall == "passed"
        and decision_summary["release_decision"] != "release_blocked"
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
