#!/usr/bin/env python3
"""统一调度入口：执行单个 Step，并负责门控与主状态持久化。"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from compat import (
    infer_maven_coord_locations,
    infer_maven_coords,
    open_text,
    resolve_repo_input_path,
    run_cmd,
)
from compat import git_cmd
from csv_io import open_csv_read, open_csv_write
from analysis_contract import build_project_scope, discover_project_modules, write_coverage_report
from pipeline_constants import (
    DELIVERABLES_DIRNAME,
    EVIDENCE_API_CHANGES_DIRNAME,
    EVIDENCE_CALL_CHAIN_DIRNAME,
    EVIDENCE_CONTEXT_DIRNAME,
    EVIDENCE_DEPENDENCIES_DIRNAME,
    EVIDENCE_DIRNAME,
    EVIDENCE_STATIC_SCAN_DIRNAME,
    INTERACTIVE_STATUS,
    RUNTIME_COVERAGE_DIRNAME,
    RUNTIME_CACHE_DIRNAME,
    RUNTIME_DIRNAME,
    RUNTIME_FINDINGS_DIRNAME,
    RUNTIME_INDEXES_DIRNAME,
    RUNTIME_OBSERVABILITY_DIRNAME,
    RUNTIME_STATE_DIRNAME,
    STEP1_ARTIFACTS_DIRNAME,
    STEP1_DEPENDENCY_JARS_DIRNAME,
    STEP1_DEPENDENCY_JARS_MANIFEST_FILE,
    STEP5_ARTIFACT_BYTECODE_CATALOG_FILE,
    STEP5_ARTIFACT_BYTECODE_DIRNAME,
    STEP5_ARTIFACT_BYTECODE_INDEX_FILE,
    STEP5_QUERY_INDEX_FILE,
    STEP_SEQUENCE,
)
from s4_contract import (
    ALL_CHANGED_APIS_FIELDS,
    PER_DEPENDENCY_CANDIDATE_HITS_FILE,
    PER_DEPENDENCY_DIRNAME,
    PER_DEPENDENCY_SUMMARY_FILE,
    STEP3_RISK_CANDIDATES_FILE,
)
from step1_ref_resolution import resolve_step1_ref
from runtime_contract import contract_payload
from progress_logging import emit_progress


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
DEFAULT_MANIFEST = SCRIPT_DIR / "step_manifest.json"
CHECKPOINT_RULES_FILE = SKILL_DIR / "CHECKPOINT_RULES.md"
EXIT_AWAITING_USER = 4
EXIT_INTERRUPTED = 130
MAIN_STATE_FILE_NAME = "main_state.json"
USER_TASK_NAMES = {
    "step1": "分析对象与依赖范围",
    "step2": "升级上下文",
    "step3": "兼容性线索",
    "step4": "依赖 API 变化",
    "step5": "系统触达证据",
    "step6": "分析报告",
}
USER_ACTION_LABELS = {
    "continue": "接受当前结果并继续",
    "rerun_current_step": "补充信息后重新分析",
    "restart_from_step": "从指定任务重新分析",
    "cancel": "暂时停止分析",
    "confirm_local_source": "确认使用本地源码兜底",
}
SCRIPT_STEP_IDS = {
    "s1_dep_diff.py": "step1",
    "s2_context_from_deps.py": "step2",
    "s3_scan.py": "step3",
    "s4_jar_compare.py": "step4",
    "s5_call_chain_engine_integrated.py": "step5",
    "s6_report.py": "step6",
}
STEP1_MAVEN_MODULE_SEP = re.compile(r"\[INFO\]\s*---.*@\s*(\S+)\s*---")
INTENT_PATCH_ALLOWED_SET_FIELDS = {
    "allow_degraded",
    "accept_suggested_mappings",
    "analysis_mode",
    "active_maven_profiles",
    "base_artifact_path",
    "base_branch",
    "base_allow_local_source",
    "base_allow_dirty_local_source",
    "base_jdk_home",
    "base_source_project_dir",
    "current_artifact_path",
    "current_branch",
    "current_allow_local_source",
    "current_allow_dirty_local_source",
    "base_expected_commit",
    "current_expected_commit",
    "current_jdk_home",
    "current_source_project_dir",
    "jdk_base",
    "jdk_current",
    "dependency_git_ref_overrides",
    "dependency_git_ref_selections",
    "source_ref_selections",
    "dependency_source_dirs",
    "retry_remote_fetch",
    "manual_coord_overrides",
    "max_depth",
    "modules",
    "primary_module",
    "source_dirs",
    "source_repo_hints",
    "springboot_base",
    "springboot_current",
    "selected_targets",
    "step4_fetch_timeout",
    "step4_tool_install_timeout",
    "step4_git_diff_timeout",
    "step4_japicmp_timeout",
    "step4_workers",
    "step5_selected_coords",
    "step5_selected_names",
    "step5_timeout",
    "tree_sitter_installed",
    "strict_risk_gate",
    "target_module",
    "tool",
}
INTENT_PATCH_RESERVED_TOP_LEVEL_FIELDS = {"action", "intent_patch", "notes", "restart_step_id"}


class StepError(RuntimeError):
    def __init__(self, message, reason_codes=None):
        super().__init__(message)
        self.reason_codes = list(dict.fromkeys(
            str(code).strip()
            for code in (reason_codes or [])
            if str(code).strip()
        ))


class StepInteractionRequired(StepError):
    def __init__(self, interaction):
        self.interaction = interaction
        super().__init__(str((interaction or {}).get("question") or (interaction or {}).get("title") or "需要用户补充信息"))


def deliverables_dir(report_dir):
    return Path(report_dir) / DELIVERABLES_DIRNAME


def evidence_dir(report_dir):
    return Path(report_dir) / EVIDENCE_DIRNAME


def runtime_dir(report_dir):
    return Path(report_dir) / RUNTIME_DIRNAME


def evidence_dependencies_dir(report_dir):
    return evidence_dir(report_dir) / EVIDENCE_DEPENDENCIES_DIRNAME


def evidence_context_dir(report_dir):
    return evidence_dir(report_dir) / EVIDENCE_CONTEXT_DIRNAME


def evidence_static_scan_dir(report_dir):
    return evidence_dir(report_dir) / EVIDENCE_STATIC_SCAN_DIRNAME


def evidence_api_changes_dir(report_dir):
    return evidence_dir(report_dir) / EVIDENCE_API_CHANGES_DIRNAME


def evidence_call_chain_dir(report_dir):
    return evidence_dir(report_dir) / EVIDENCE_CALL_CHAIN_DIRNAME


def runtime_state_dir(report_dir):
    return runtime_dir(report_dir) / RUNTIME_STATE_DIRNAME


def runtime_coverage_dir(report_dir):
    return runtime_dir(report_dir) / RUNTIME_COVERAGE_DIRNAME


def runtime_indexes_dir(report_dir):
    return runtime_dir(report_dir) / RUNTIME_INDEXES_DIRNAME


def runtime_findings_dir(report_dir):
    return runtime_dir(report_dir) / RUNTIME_FINDINGS_DIRNAME


def runtime_cache_dir(report_dir):
    return runtime_dir(report_dir) / RUNTIME_CACHE_DIRNAME


def runtime_observability_dir(report_dir):
    return runtime_dir(report_dir) / RUNTIME_OBSERVABILITY_DIRNAME


def step1_dep_changes_path(report_dir):
    return evidence_dependencies_dir(report_dir) / "dep_changes.csv"


def step1_dep_alerts_path(report_dir):
    return evidence_dependencies_dir(report_dir) / "dep_alerts.csv"


def step1_dep_summary_path(report_dir):
    return evidence_dependencies_dir(report_dir) / "dep_summary.txt"


def step1_current_resolved_path(report_dir):
    return evidence_dependencies_dir(report_dir) / "deps_current_resolved.csv"


def build_provenance_path(report_dir):
    return evidence_dependencies_dir(report_dir) / "build_provenance.json"


def step1_artifacts_dir(report_dir):
    return evidence_dependencies_dir(report_dir) / STEP1_ARTIFACTS_DIRNAME


def step1_dependency_jars_dir(report_dir):
    return evidence_dependencies_dir(report_dir) / STEP1_DEPENDENCY_JARS_DIRNAME


def step1_dependency_jars_manifest_path(report_dir):
    return (
        evidence_dependencies_dir(report_dir)
        / STEP1_DEPENDENCY_JARS_MANIFEST_FILE
    )


def step2_context_path(report_dir):
    return evidence_context_dir(report_dir) / "context.json"


def step2_dep_graph_path(report_dir):
    return evidence_context_dir(report_dir) / "dep_graph.json"


def step2_source_mapping_summary_path(report_dir):
    return evidence_context_dir(report_dir) / "source_mapping_summary.json"


def step4_api_changes_dir(report_dir):
    return evidence_api_changes_dir(report_dir)


def step5_call_chain_dir(report_dir):
    return evidence_call_chain_dir(report_dir)


def step5_query_index_path(report_dir):
    return runtime_indexes_dir(report_dir) / STEP5_QUERY_INDEX_FILE


def s6_findings_path(report_dir):
    return runtime_findings_dir(report_dir) / "s6_findings.json"


def s6_report_path(report_dir):
    return deliverables_dir(report_dir) / "report.md"


def artifact_path(report_dir, rel_path):
    report_dir = Path(report_dir)
    text = str(rel_path or "").strip()
    trailing_slash = text.endswith("/")
    text = text.rstrip("/")
    if Path(text).is_absolute():
        return Path(text)
    path = report_dir / text
    return path if not trailing_slash else Path(str(path))


def read_json(path):
    with open_text(path) as f:
        return json.load(f)


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _write_text_file(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _resume_boundary_lines(current_step, completed_step):
    current_step = str(current_step or "").strip()
    completed_step = str(completed_step or "").strip()
    lines = []
    if completed_step in STEP_SEQUENCE:
        lines.append(
            f"已保留：{USER_TASK_NAMES.get(completed_step, completed_step)}及之前的正式产物。"
        )
    if current_step in STEP_SEQUENCE:
        lines.append(
            f"恢复后：从{USER_TASK_NAMES.get(current_step, current_step)}继续，不重复已完成任务。"
        )
    return lines


def _landing_status_lines(state):
    state_view = dict((state or {}).get("state") or {})
    status = str(state_view.get("status") or "idle").strip()
    current_step = str(state_view.get("current_step") or "step1").strip()
    completed_step = str(state_view.get("completed_step") or "").strip()
    completion_summary = dict(state_view.get("completion_summary") or {})
    task_name = USER_TASK_NAMES.get(current_step, "准备分析")
    reason = _humanize_interaction_text(state_view.get("blocking_reason") or "").strip()

    if current_step == "done":
        if status == "completed_with_limits":
            lines = [
                "当前状态：分析已完成，但存在结论限制",
                "",
                "请先阅读最终报告的“结论限制”，并以本轮分析范围为解释边界。",
            ]
        else:
            lines = ["当前状态：分析已完成"]
        if completion_summary:
            scope_mode = str(completion_summary.get("scope_mode") or "").strip()
            if scope_mode == "partial":
                scope_text = (
                    f"部分依赖（{int(completion_summary.get('included_dependency_count') or 0)}/"
                    f"{int(completion_summary.get('available_dependency_count') or 0)}）"
                )
            elif scope_mode == "full":
                scope_text = "全部变化依赖"
            else:
                scope_text = "未记录（不得按全量结论解释）"
            lines.extend([
                "",
                f"分析范围：{scope_text}",
                (
                    "结果计数：已确认影响 {confirmed}（其中高风险 {high_risk}），可能影响 {probable}，"
                    "需人工复核 {uncertain}，本次未完成 {not_analyzed}。"
                ).format(
                    confirmed=int(completion_summary.get("confirmed_count") or 0),
                    high_risk=int(completion_summary.get("high_risk_count") or 0),
                    probable=int(completion_summary.get("probable_count") or 0),
                    uncertain=int(completion_summary.get("uncertain_count") or 0),
                    not_analyzed=int(completion_summary.get("not_analyzed_count") or 0),
                ),
            ])
            limitations = list(completion_summary.get("limitations") or [])
            if limitations:
                lines.append("主要限制：" + "；".join(limitations[:5]) + "。")
        return lines
    if status in INTERACTIVE_STATUS or status.startswith("awaiting_"):
        lines = ["当前状态：等待你确认", f"当前任务：{task_name}"]
        if reason:
            lines.extend(["", f"暂停原因：{reason}"])
        lines.extend(["", *_resume_boundary_lines(current_step, completed_step)])
        lines.extend(["", "下一步：查看下方确认项并直接回复；系统会根据回复继续或重新分析。"])
        return lines
    if status == "paused_by_user":
        has_pending_confirmation = bool(state_view.get("pending_interaction"))
        lines = [
            "当前状态：已暂停",
            f"当前任务：{task_name}",
            "",
            *_resume_boundary_lines(current_step, completed_step),
            "",
            (
                "下一步：再次运行分析时，会回到当前确认任务。"
                if has_pending_confirmation
                else "下一步：再次运行分析即可从当前任务安全重试。"
            ),
        ]
        return lines
    if status == "blocked_by_system":
        lines = ["当前状态：分析未完成", f"当前任务：{task_name}"]
        if reason:
            lines.extend(["", f"未完成原因：{reason}"])
        lines.extend(
            [
                "",
                "系统已停止当前任务，避免把不完整执行包装成可靠结论；这不是业务确认项。",
                *_resume_boundary_lines(current_step, completed_step),
                "阻塞条件恢复后重新运行即可；无需重新选择已经确认的业务输入或分析范围。",
            ]
        )
        return lines
    if completed_step:
        completed_name = USER_TASK_NAMES.get(completed_step, completed_step)
        return [
            f"当前状态：{completed_name}已完成",
            f"下一项：{task_name}",
        ]
    return ["当前状态：尚未开始", "当前任务：准备分析对象与版本范围。"]


def _landing_existing_artifact_rows(report_dir):
    candidates = [
        ("最终分析结论", "deliverables/report.md"),
        ("本轮实际分析范围与结论边界", "deliverables/analysis-scope.md"),
        ("发生 API 变化的依赖及范围候选", "evidence/api_changes/changed_dependencies.md"),
        ("完整变化 API 结构化清单", "evidence/api_changes/all_changed_apis.csv"),
        ("变化 API 的系统触达台账", "evidence/call_chain/alerts.csv"),
        ("升级上下文人工阅读页", "evidence/context/review.md"),
        ("依赖变化清单", "evidence/dependencies/dep_changes.csv"),
        ("构建来源与制品身份", "evidence/dependencies/build_provenance.json"),
    ]
    root = Path(report_dir)
    return [
        (question, relative_path)
        for question, relative_path in candidates
        if (root / relative_path).is_file()
    ]


def _landing_review_file_link(report_dir, raw_path):
    raw_path = str(raw_path or "").strip()
    if not raw_path:
        return ""
    path = Path(raw_path)
    if not path.is_absolute():
        path = Path(report_dir) / path
    if not path.is_file():
        return ""
    try:
        relative_path = path.resolve().relative_to(Path(report_dir).resolve()).as_posix()
    except (OSError, ValueError):
        return f"`{path}`"
    return f"[{relative_path}]({relative_path})"


def _landing_pending_interaction_lines(report_dir, state):
    interaction = dict(((state or {}).get("state") or {}).get("pending_interaction") or {})
    if not interaction:
        return []
    question = _humanize_interaction_text(
        interaction.get("question") or interaction.get("title") or "请确认后继续。"
    ).strip()
    lines = ["## 当前需要你决定", "", question, ""]
    scope_preview = dict(interaction.get("scope_preview") or {})
    if scope_preview:
        lines.extend(
            [
                "本次范围影响：",
                "",
                (
                    f"- 全量将覆盖 {int(scope_preview.get('available_dependency_count') or 0)} 个变化依赖、"
                    f"{int(scope_preview.get('total_api_count') or 0)} 个变化 API，"
                    f"其中高风险 API {int(scope_preview.get('high_risk_api_count') or 0)} 个。"
                ),
                f"- {scope_preview.get('partial_scope_effect') or '部分分析会缩小最终报告的适用范围。'}",
                "",
            ]
        )
    options = list(interaction.get("options") or [])
    if options:
        lines.extend(["可选处理方式：", ""])
        for item in [
            option for option in options
            if str((option or {}).get("id") or "").strip() != "restart_from_step"
        ]:
            option_id = str((item or {}).get("id") or "").strip()
            label = str((item or {}).get("label") or USER_ACTION_LABELS.get(option_id) or option_id).strip()
            description = _humanize_interaction_text((item or {}).get("description") or "").strip()
            lines.append(f"- {label}" + (f"：{description}" if description else ""))
        lines.append("")
        restart_options = [
            option for option in options
            if str((option or {}).get("id") or "").strip() == "restart_from_step"
        ]
        if restart_options:
            lines.extend(["需要修正更早输入时：", ""])
            for item in restart_options:
                label = str((item or {}).get("label") or USER_ACTION_LABELS["restart_from_step"]).strip()
                description = _humanize_interaction_text((item or {}).get("description") or "").strip()
                lines.append(f"- {label}" + (f"：{description}" if description else ""))
            lines.append("")
    examples = _decision_card_reply_examples(
        interaction,
        list(interaction.get("selection_options") or []),
        options,
    )
    if examples:
        lines.extend(["可以直接这样回复：", ""])
        lines.extend(f"- `{example}`" for example in examples)
        lines.append("")
    review_links = [
        _landing_review_file_link(report_dir, path)
        for path in (interaction.get("files_to_review") or [])
    ]
    review_links = [item for item in review_links if item]
    if review_links:
        lines.extend(["确认前可核对：", ""])
        lines.extend(f"- {item}" for item in review_links)
        lines.append("")
    return lines


def write_report_landing_docs(report_dir, state=None):
    report_dir = Path(report_dir)
    for path in (report_dir, deliverables_dir(report_dir), evidence_dir(report_dir), runtime_dir(report_dir)):
        path.mkdir(parents=True, exist_ok=True)

    artifact_rows = _landing_existing_artifact_rows(report_dir)
    lines = [
        "# 升级分析",
        "",
        *_landing_status_lines(state),
        "",
        *_landing_pending_interaction_lines(report_dir, state),
    ]
    if artifact_rows:
        lines.extend([
            "## 按问题找文件",
            "",
            "| 想确认的问题 | 打开文件 |",
            "|---|---|",
        ])
        for question, relative_path in artifact_rows:
            lines.append(f"| {question} | [{relative_path}]({relative_path}) |")
        lines.append("")
    else:
        lines.extend(["## 当前产物", "", "分析产物尚未生成；文件会随流程进度出现在这里。", ""])
    lines.append("`.runtime/` 仅供程序恢复、缓存和索引使用，不是人工阅读入口。")
    _write_text_file(report_dir / "README.md", "\n".join(lines))


def build_user_runtime_message(event, step_id, reason="", completion_summary=None):
    task_name = USER_TASK_NAMES.get(str(step_id or "").strip(), "当前分析")
    if event == "start":
        return [f"正在分析：{task_name}"]
    if event == "failed":
        lines = [f"{task_name}未完成"]
        if str(reason or "").strip():
            lines.append(f"原因：{_humanize_interaction_text(reason)}")
        lines.extend(
            [
                "系统已停止当前任务，以避免输出不可靠结论；无需确认降级或修改分析范围。",
                "已完成步骤和已有证据会保留。外部环境恢复后重新运行，系统会从当前任务重试。",
            ]
        )
        return lines
    if str(step_id or "").strip() == "step6":
        summary = dict(completion_summary or {})
        limited = summary.get("status") == "completed_with_limits"
        lines = ["分析已完成，但存在结论限制。" if limited else "分析已完成。"]
        scope_mode = str(summary.get("scope_mode") or "").strip()
        if scope_mode == "partial":
            lines.append(
                f"分析范围：部分依赖（{int(summary.get('included_dependency_count') or 0)}/"
                f"{int(summary.get('available_dependency_count') or 0)}）。"
            )
        elif scope_mode == "full":
            lines.append("分析范围：依赖 API 变化分析识别出的全部变化依赖。")
        else:
            lines.append("分析范围：未记录，结果不得按全量结论解释。")
        if summary:
            lines.append(
                "结果：已确认影响 {confirmed}（其中高风险 {high_risk}），可能影响 {probable}，需人工复核 {uncertain}，"
                "本次未完成 {not_analyzed}。".format(
                    confirmed=int(summary.get("confirmed_count") or 0),
                    high_risk=int(summary.get("high_risk_count") or 0),
                    probable=int(summary.get("probable_count") or 0),
                    uncertain=int(summary.get("uncertain_count") or 0),
                    not_analyzed=int(summary.get("not_analyzed_count") or 0),
                )
            )
        limitations = list(summary.get("limitations") or [])
        if limitations:
            lines.append("主要限制：" + "；".join(limitations[:3]) + "。")
        lines.extend([
            "最终报告：deliverables/report.md",
            "分析范围：deliverables/analysis-scope.md",
        ])
        return lines
    next_step = next_step_id_for(step_id)
    lines = [f"{task_name}已完成。"]
    if next_step:
        lines.append(f"接下来：{USER_TASK_NAMES.get(next_step, next_step)}")
    return lines


def build_environment_block_message(environment):
    labels = {
        "python": "Python 运行时",
        "platform": "操作系统",
    }
    failed = [
        item for item in (environment or {}).get("checks") or []
        if item.get("status") != "passed"
    ]
    lines = [
        "分析尚未开始：运行环境预检未通过。",
        "系统没有修改宿主机的 Python 环境；安装或修复运行依赖需要外部条件或授权。",
        "未满足的条件：",
    ]
    if not failed:
        lines.append("- 预检结果缺少可识别的失败明细；请先核对运行环境检查输出。")
    for item in failed:
        component = str(item.get("component") or "运行组件")
        if component.startswith("python_package:"):
            label = "Python 依赖 " + component.split(":", 1)[1]
        elif component.startswith("python_import:"):
            label = "Python 模块 " + component.split(":", 1)[1]
        elif component.startswith("tool:"):
            label = "命令行工具 " + component.split(":", 1)[1]
        else:
            label = labels.get(component, component)
        lines.append(
            f"- {label}：当前为 {item.get('observed') or '未检测到'}；需要 {item.get('expected') or '可正常使用'}。"
        )
    python_only = bool(failed) and all(
        str(item.get("component") or "").startswith(("python_package:", "python_import:"))
        for item in failed
    )
    if python_only:
        lines.append(
            f"下一步：授权准备产品运行依赖后，在 `{SKILL_DIR}` 使用 CPython 3.12–3.14 执行 "
            "`scripts/bootstrap_runtime.py`；完成后重新运行分析。"
        )
    else:
        lines.append("下一步：补齐上面列出的外部运行前提后重新运行；业务输入和分析范围无需修改。")
    return lines
def read_csv_rows(path):
    import csv

    path = Path(path)
    if not path.exists():
        return []
    with open_csv_read(path) as f:
        reader = csv.DictReader(f)
        return [{k: (v or "").strip() for k, v in row.items()} for row in reader if row]


def load_checkpoint_rules():
    if not CHECKPOINT_RULES_FILE.exists():
        return []
    rules = []
    for line in CHECKPOINT_RULES_FILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rules.append(stripped)
    return rules


CHECKPOINT_RULES = load_checkpoint_rules()


def main_state_path(report_dir):
    return runtime_state_dir(report_dir) / MAIN_STATE_FILE_NAME


def empty_step_state():
    return {"input": {}, "derived": {}, "output": {}}


def new_main_state(report_dir, manifest_path=""):
    state = {
        "state": {
            "current_step": "step1",
            "completed_step": None,
            "status": "idle",
            "blocking_reason": None,
            "blocking_reason_codes": [],
            "pending_interaction": None,
            "completion_summary": None,
            "last_user_response": None,
            "report_dir": str(Path(report_dir).resolve()),
            "manifest_path": str(Path(manifest_path).resolve()) if manifest_path else "",
            "saved_at": datetime.now().isoformat(),
        }
    }
    for step_id in STEP_SEQUENCE:
        state[step_id] = empty_step_state()
    return state


def ensure_main_state_structure(data, report_dir, manifest_path=""):
    base = new_main_state(report_dir, manifest_path=manifest_path)
    if not isinstance(data, dict):
        return base
    merged = dict(base)
    merged_state = dict(base["state"])
    merged_state.update(data.get("state") or {})
    merged_state["report_dir"] = str(Path(report_dir).resolve())
    if manifest_path:
        merged_state["manifest_path"] = str(Path(manifest_path).resolve())
    merged_state["saved_at"] = datetime.now().isoformat()
    merged["state"] = merged_state
    for step_id in STEP_SEQUENCE:
        step_data = data.get(step_id) if isinstance(data.get(step_id), dict) else {}
        step_state = empty_step_state()
        for key in ("input", "derived", "output"):
            if isinstance(step_data.get(key), dict):
                step_state[key] = dict(step_data.get(key) or {})
        merged[step_id] = step_state
    return merged


def load_main_state(report_dir, manifest_path=""):
    path = main_state_path(report_dir)
    if not path.exists():
        return new_main_state(report_dir, manifest_path=manifest_path)
    return ensure_main_state_structure(read_json(path), report_dir, manifest_path=manifest_path)


def save_main_state(report_dir, state):
    normalized = ensure_main_state_structure(state, report_dir, manifest_path=(state.get("state") or {}).get("manifest_path", ""))
    normalized["state"]["saved_at"] = datetime.now().isoformat()
    write_json(main_state_path(report_dir), normalized)
    write_report_landing_docs(report_dir, normalized)
    return normalized


def resolve_requested_step(step_value, main_state):
    if step_value != "auto":
        return step_value
    current_step = str(((main_state or {}).get("state") or {}).get("current_step") or "").strip()
    if not current_step or current_step == "done":
        raise StepError("main_state 中没有可继续的 current_step，请显式指定 --step")
    return current_step


def step_index(step_id):
    return STEP_SEQUENCE.index(step_id)


def next_step_id_for(step_id):
    idx = step_index(step_id)
    if idx + 1 >= len(STEP_SEQUENCE):
        return None
    return STEP_SEQUENCE[idx + 1]


def interaction_option_ids(interaction):
    return {
        str(item.get("id") or "").strip()
        for item in (interaction or {}).get("options", []) or []
        if str(item.get("id") or "").strip()
    }


def current_step_for_pending_interaction(step_id, interaction):
    interaction = dict(interaction or {})
    kind = str(interaction.get("kind") or interaction.get("type") or "").strip()
    if kind == "input_request":
        return step_id
    if "continue" not in interaction_option_ids(interaction):
        return step_id
    return next_step_id_for(step_id) or step_id


def previous_step_output(main_state, step_id):
    idx = step_index(step_id)
    if idx == 0:
        return {}
    return dict((main_state.get(STEP_SEQUENCE[idx - 1]) or {}).get("output") or {})


def build_step_input_context(main_state, step_id, fallback_existing=None):
    if step_id == "step1":
        existing = (main_state.get("step1") or {}).get("input") or {}
        if existing:
            return dict(existing)
        return dict(fallback_existing or {})
    prev_output = previous_step_output(main_state, step_id)
    current_input = (main_state.get(step_id) or {}).get("input") or {}
    if prev_output or current_input:
        merged = dict(prev_output or {})
        merged.update(current_input or {})
        return merged
    return dict(fallback_existing or {})


def clear_steps_from(main_state, step_id, preserve_current_input=None):
    preserved_input = None
    if preserve_current_input is not None:
        preserved_input = dict(preserve_current_input or {})
    for current in STEP_SEQUENCE[step_index(step_id):]:
        main_state[current] = empty_step_state()
    if preserved_input is not None:
        main_state[step_id]["input"] = preserved_input


def cleanup_step_outputs_from(step_id, report_dir):
    for current in STEP_SEQUENCE[step_index(step_id):]:
        cleanup_step_outputs(current, report_dir)


def should_reset_for_explicit_step_run(main_state, step_id, requested_step):
    if requested_step == "auto" or step_id not in STEP_SEQUENCE:
        return False
    idx = step_index(step_id)
    state = dict((main_state or {}).get("state") or {})
    completed_step = str(state.get("completed_step") or "").strip()
    current_step = str(state.get("current_step") or "").strip()
    completed_idx = step_index(completed_step) if completed_step in STEP_SEQUENCE else -1
    current_idx = step_index(current_step) if current_step in STEP_SEQUENCE else -1
    if completed_idx >= idx or current_idx > idx:
        return True
    for current in STEP_SEQUENCE[idx:]:
        step_state = dict((main_state or {}).get(current) or {})
        if any(step_state.get(section) for section in ("input", "derived", "output")):
            return True
    return False


def store_step_input(main_state, step_id, run_context):
    main_state[step_id]["input"] = dict(run_context or {})


def build_step_derived_snapshot(step_id, run_context, report_dir):
    ctx = dict(run_context or {})
    if step_id == "step1":
        return {
            key: ctx.get(key)
            for key in (
                "result_source",
                "enrichment_strategy",
                "artifact_input_mode",
                "artifact_pair_ready",
                "branch_pair_ready",
                "has_any_artifact",
                "has_any_branch",
                "base_branch_explicit",
                "current_branch_explicit",
            )
            if key in ctx
        }
    if step_id == "step2":
        return {
            key: ctx.get(key)
            for key in (
                "source_dirs_status",
                "dependency_source_mapping_conflicts",
                "unmapped_dependency_coords",
                "dependency_repo_mappings",
                "dependency_source_mappings",
            )
            if key in ctx
        }
    if step_id in ("step4", "step5"):
        return {
            key: ctx.get(key)
            for key in (
                "dependency_repo_mappings",
                "dependency_source_mappings",
                "dependency_source_mapping_conflicts",
                "step5_selected_coords",
                "step5_selected_names",
                "unmapped_dependency_coords",
            )
            if key in ctx
        }
    if step_id == "step3":
        context_json = step2_context_path(report_dir)
        if context_json.exists():
            s2_ctx = read_json(context_json)
            return {
                "jdk_upgraded": s2_ctx.get("jdk_upgraded"),
                "springboot_major_upgrade": s2_ctx.get("springboot_major_upgrade"),
            }
    return {}


def store_step_output(main_state, step_id, run_context, report_dir):
    main_state[step_id]["derived"] = build_step_derived_snapshot(step_id, run_context, report_dir)
    main_state[step_id]["output"] = dict(run_context or {})


def seed_next_step_input(main_state, step_id, run_context):
    next_step_id = next_step_id_for(step_id)
    if not next_step_id:
        return
    main_state[next_step_id]["input"] = dict(run_context or {})


def update_main_state_state(main_state, **updates):
    main_state.setdefault("state", {})
    main_state["state"].update(updates)
    main_state["state"]["saved_at"] = datetime.now().isoformat()


def record_last_user_response(main_state, pending_interaction, action, payload):
    pending_step_id = str((pending_interaction or {}).get("step_id") or "").strip()
    stored_payload = dict(payload or {})
    intent_patch = stored_payload.pop("__intent_patch", None)
    clear_fields = stored_payload.pop("__clear_fields", None)
    if intent_patch:
        stored_payload["intent_patch"] = intent_patch
    if clear_fields:
        stored_payload["clear"] = list(clear_fields)
    update_main_state_state(
        main_state,
        last_user_response={
            "step_id": pending_step_id,
            "action": action,
            "payload": stored_payload,
            "received_at": datetime.now().isoformat(),
        },
    )


def normalize_interaction_status(status):
    normalized = str(status or "").strip()
    if normalized in ("awaiting_decision", "awaiting_input", "awaiting_user", INTERACTIVE_STATUS):
        return INTERACTIVE_STATUS
    return normalized or INTERACTIVE_STATUS


def save_interaction_file(report_dir, interaction):
    if not interaction:
        return
    payload = dict(interaction)
    payload["status"] = normalize_interaction_status(payload.get("status"))
    payload.setdefault("exit_code", EXIT_AWAITING_USER)
    write_json(runtime_state_dir(report_dir) / "interaction.json", payload)


def clear_interaction_file(report_dir):
    interaction_file = runtime_state_dir(report_dir) / "interaction.json"
    if interaction_file.exists():
        interaction_file.unlink()


def load_manifest(path):
    data = read_json(path)
    steps = {item["id"]: item for item in data.get("steps", [])}
    if not steps:
        raise StepError(f"manifest 无有效 steps: {path}")
    return data, steps


def parse_bool_like(value, field_name):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "y", "on"):
            return True
        if normalized in ("0", "false", "no", "n", "off"):
            return False
    raise StepError(f"{field_name} 仅支持布尔值 true/false")


def load_user_response(args, project_dir):
    raw = None
    source = ""
    if args.response_json and args.response_file:
        raise StepError("--response-json 与 --response-file 不能同时使用")
    if args.response_json:
        raw = args.response_json
        source = "--response-json"
    elif args.response_file:
        response_path = Path(args.response_file).expanduser()
        if not response_path.is_absolute():
            response_path = project_dir / response_path
        response_path = response_path.resolve()
        if not response_path.exists():
            raise StepError(f"用户答复文件不存在：{response_path}")
        raw = response_path.read_text(encoding="utf-8")
        source = str(response_path)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StepError(f"用户答复不是合法 JSON（{source}）：{exc}") from exc
    if not isinstance(data, dict):
        raise StepError("用户答复必须是 JSON 对象，例如 {\"action\":\"continue\"}")
    return data


def normalize_intent_patch(raw_patch):
    if not isinstance(raw_patch, dict):
        raise StepError("intent_patch 必须是 JSON 对象。")
    patch = dict(raw_patch)
    set_payload = patch.get("set") or {}
    if set_payload and not isinstance(set_payload, dict):
        raise StepError("intent_patch.set 必须是 JSON 对象。")
    clear_fields = patch.get("clear") or []
    if clear_fields and not isinstance(clear_fields, list):
        raise StepError("intent_patch.clear 必须是字符串数组。")
    unresolved_slots = patch.get("unresolved_slots") or []
    if unresolved_slots and not isinstance(unresolved_slots, list):
        raise StepError("intent_patch.unresolved_slots 必须是字符串数组。")
    unknown_fields = sorted(
        key for key in (set_payload or {}).keys()
        if key not in INTENT_PATCH_ALLOWED_SET_FIELDS
    )
    if unknown_fields:
        raise StepError("intent_patch.set 包含当前不支持的字段：" + ", ".join(unknown_fields))
    normalized_clear = []
    seen_clear = set()
    for item in clear_fields:
        field = str(item or "").strip()
        if not field:
            continue
        if field not in INTENT_PATCH_ALLOWED_SET_FIELDS:
            raise StepError(f"intent_patch.clear 包含当前不支持的字段：{field}")
        if field in seen_clear:
            continue
        seen_clear.add(field)
        normalized_clear.append(field)
    normalized_unresolved = []
    for item in unresolved_slots:
        field = str(item or "").strip()
        if field:
            normalized_unresolved.append(field)
    return {
        "action": str(patch.get("action") or "").strip(),
        "set": dict(set_payload or {}),
        "clear": normalized_clear,
        "restart_step_id": str(patch.get("restart_step_id") or "").strip(),
        "notes": str(patch.get("notes") or "").strip(),
        "unresolved_slots": normalized_unresolved,
    }


def build_canonical_user_response(user_response):
    response = dict(user_response or {})
    raw_patch = response.get("intent_patch")
    if raw_patch in (None, ""):
        response_action = str(response.get("action") or "").strip()
        if response_action:
            response["action"] = response_action
            return response
        raise StepError(
            "结构化用户答复缺少 action。请提供与 interaction.options.id 之一完全一致的动作。"
        )

    extra_fields = sorted(
        key for key in response.keys()
        if key not in INTENT_PATCH_RESERVED_TOP_LEVEL_FIELDS
    )
    if extra_fields:
        raise StepError("使用 intent_patch 时，不要在顶层混用业务字段：" + ", ".join(extra_fields))

    patch = normalize_intent_patch(raw_patch)
    if patch.get("unresolved_slots"):
        raise StepError(
            "当前用户答复仍存在未消解槽位，必须先澄清后再恢复执行："
            + ", ".join(patch.get("unresolved_slots") or [])
        )
    response_action = str(response.get("action") or "").strip()
    patch_action = str(patch.get("action") or "").strip()
    if response_action and patch_action and response_action != patch_action:
        raise StepError("顶层 action 与 intent_patch.action 冲突。")
    action = patch_action or response_action
    if not action:
        raise StepError(
            "结构化用户答复缺少 action。请提供与 interaction.options.id 之一完全一致的动作。"
        )

    canonical = {"action": action, "__intent_patch": patch}
    canonical.update(dict(patch.get("set") or {}))
    restart_step_id = str(response.get("restart_step_id") or "").strip()
    patch_restart_step_id = str(patch.get("restart_step_id") or "").strip()
    if restart_step_id and patch_restart_step_id and restart_step_id != patch_restart_step_id:
        raise StepError("顶层 restart_step_id 与 intent_patch.restart_step_id 冲突。")
    if patch_restart_step_id or restart_step_id:
        canonical["restart_step_id"] = patch_restart_step_id or restart_step_id
    notes = str(response.get("notes") or "").strip()
    patch_notes = str(patch.get("notes") or "").strip()
    if patch_notes or notes:
        canonical["notes"] = patch_notes or notes
    if patch.get("clear"):
        canonical["__clear_fields"] = list(patch.get("clear") or [])
    return canonical


def apply_user_response_clears(updated, clear_fields):
    result = dict(updated or {})
    for field in clear_fields or []:
        if field == "source_dirs":
            result.pop("source_dirs", None)
            result.pop("source_dirs_status", None)
            continue
        if field == "dependency_source_dirs":
            result.pop("dependency_source_dirs", None)
            result.pop("dependency_source_git_urls", None)
            result.pop("dependency_source_git_materializations", None)
            result.pop("dependency_repo_mappings", None)
            result.pop("dependency_source_mappings", None)
            result.pop("dependency_source_mapping_conflicts", None)
            result.pop("unmapped_dependency_coords", None)
            continue
        if field == "source_repo_hints":
            result.pop("source_repo_hints", None)
            result.pop("accept_suggested_mappings", None)
            continue
        if field in ("base_branch", "current_branch"):
            result.pop(field, None)
            result.pop(f"{field}_explicit", None)
            continue
        result.pop(field, None)
    return result


def merge_user_response_into_run_context(run_context, user_response, project_dir):
    updated = dict(run_context or {})
    response = dict(user_response or {})
    if not response:
        return updated
    clear_fields = list(response.pop("__clear_fields", []) or [])
    response.pop("__intent_patch", None)

    primary_module_explicit = False
    if "analysis_mode" in response:
        updated["analysis_mode"] = normalize_analysis_mode(response.get("analysis_mode"), allow_empty=True)
        updated = apply_explicit_step1_mode_selection(updated)

    for key in ("base_branch", "current_branch", "target_module", "primary_module", "tool"):
        value = response.get(key)
        if isinstance(value, str) and value.strip():
            updated[key] = value.strip()
            if key in ("target_module", "primary_module"):
                primary_module_explicit = True
                updated["target_module"] = value.strip()
                updated["primary_module"] = value.strip()
            if key in ("base_branch", "current_branch"):
                updated[f"{key}_explicit"] = True
                side = key.split("_", 1)[0]
                updated.pop(f"{side}_allow_local_source", None)
                updated.pop(f"{side}_allow_dirty_local_source", None)
                for suffix in (
                    "requested_ref",
                    "resolved_ref",
                    "resolved_commit",
                    "ref_resolution_mode",
                    "ref_resolution_fingerprint",
                    "ref_candidate_count",
                ):
                    updated.pop(f"{side}_{suffix}", None)
                updated.pop(f"{side}_expected_commit", None)
    for key in ("jdk_base", "jdk_current", "springboot_base", "springboot_current"):
        value = response.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            updated[key] = str(value).strip()
    for side in ("base", "current"):
        expected_field = f"{side}_expected_commit"
        value = response.get(expected_field)
        if isinstance(value, str) and value.strip():
            updated[expected_field] = value.strip()
    for key in ("base_jdk_home", "current_jdk_home"):
        value = response.get(key)
        if isinstance(value, str) and value.strip():
            updated[key] = absolutize_path(value.strip(), project_dir)

    modules_value = normalize_modules_value(response.get("modules"))
    if modules_value is not None:
        updated["modules"] = modules_value
    elif primary_module_explicit:
        # If the user explicitly corrected primary_module, keep modules aligned
        # instead of inheriting a stale module selection from prior checkpoint state.
        updated["modules"] = [updated["primary_module"]]
    if updated.get("primary_module") and not (updated.get("modules") or []):
        updated["modules"] = [updated["primary_module"]]
    if (not updated.get("primary_module")) and len(updated.get("modules") or []) == 1:
        updated["primary_module"] = updated["modules"][0]
    if (modules_value is not None or primary_module_explicit) and "source_dirs" not in response:
        # Module-scope corrections must invalidate stale root-level source_dirs so
        # the next Step1 run can re-detect module-specific source directories.
        updated.pop("source_dirs", None)
        updated.pop("source_dirs_status", None)

    if response.get("active_maven_profiles") is not None:
        previous_profiles = list(updated.get("active_maven_profiles") or [])
        updated["active_maven_profiles"] = _dedupe_strings(
            response.get("active_maven_profiles") or []
        )
        if updated["active_maven_profiles"] != previous_profiles:
            updated.pop("source_dirs", None)
            updated.pop("source_dirs_status", None)

    source_dirs = normalize_source_dirs(response.get("source_dirs"), project_dir)
    if source_dirs is not None:
        updated["source_dirs"] = source_dirs

    dependency_source_dirs = normalize_dependency_source_dirs(
        response.get("dependency_source_dirs"),
        project_dir,
        "dependency_source_dirs",
    )
    if dependency_source_dirs is not None:
        updated["dependency_source_dirs"] = dependency_source_dirs
        updated["dependency_source_git_urls"] = [
            item
            for item in dependency_source_dirs
            if is_dependency_source_git_url(item, project_dir)
        ]
        updated.pop("dependency_source_git_materializations", None)
        updated.pop("dependency_repo_mappings", None)
        updated.pop("dependency_source_mappings", None)

    source_repo_hints = normalize_source_repo_hints(
        response.get("source_repo_hints"),
        project_dir,
        "source_repo_hints",
    )
    if source_repo_hints is not None:
        updated["source_repo_hints"] = source_repo_hints
        if "accept_suggested_mappings" not in response:
            updated.pop("accept_suggested_mappings", None)

    if "accept_suggested_mappings" in response:
        updated["accept_suggested_mappings"] = parse_bool_like(
            response.get("accept_suggested_mappings"),
            "accept_suggested_mappings",
        )

    dependency_git_ref_overrides = normalize_dependency_git_ref_overrides(
        response.get("dependency_git_ref_overrides"),
        "dependency_git_ref_overrides",
    )
    if dependency_git_ref_overrides is not None:
        # Checkpoint replies may arrive incrementally.  Preserve already
        # confirmed dependencies and replace only entries explicitly supplied
        # in the latest reply, keyed by the stable Maven coordinate.
        previous_overrides = normalize_dependency_git_ref_overrides(
            updated.get("dependency_git_ref_overrides"),
            "dependency_git_ref_overrides",
        ) or []
        merged_overrides = {
            str(item.get("coord") or "").strip(): dict(item)
            for item in previous_overrides
            if str(item.get("coord") or "").strip()
        }
        for item in dependency_git_ref_overrides:
            merged_overrides[str(item.get("coord") or "").strip()] = dict(item)
        updated["dependency_git_ref_overrides"] = [
            merged_overrides[coord] for coord in sorted(merged_overrides)
        ]
    for key in ("step5_selected_coords", "step5_selected_names"):
        value = normalize_step5_target_list(response.get(key), key)
        if value is not None:
            updated[key] = value

    for key in (
        "base_file",
        "current_file",
        "japicmp_jar",
        "base_artifact_path",
        "current_artifact_path",
        "base_source_project_dir",
        "current_source_project_dir",
        "base_jdk_home",
        "current_jdk_home",
    ):
        value = response.get(key)
        if isinstance(value, str) and value.strip():
            updated[key] = absolutize_path(value.strip(), project_dir)

    if "max_depth" in response:
        updated["max_depth"] = parse_positive_int_like(response.get("max_depth"), "max_depth")

    for timeout_key in (
        "step4_git_diff_timeout",
        "step4_japicmp_timeout",
        "step4_fetch_timeout",
        "step4_tool_install_timeout",
        "step4_workers",
        "step5_timeout",
    ):
        if timeout_key in response:
            updated[timeout_key] = parse_positive_int_like(response.get(timeout_key), timeout_key)

    for key in (
        "include_test_scope",
        "allow_degraded",
        "strict_risk_gate",
        "tree_sitter_installed",
        "base_allow_local_source",
        "base_allow_dirty_local_source",
        "current_allow_local_source",
        "current_allow_dirty_local_source",
    ):
        if key in response:
            updated[key] = parse_bool_like(response.get(key), key)
    if "strict_risk_gate" in response:
        updated["strict_risk_gate"] = parse_bool_like(response.get("strict_risk_gate"), "strict_risk_gate")
    manual_coord_overrides = response.get("manual_coord_overrides")
    if manual_coord_overrides is not None:
        if isinstance(manual_coord_overrides, str):
            incoming_coord_overrides = [manual_coord_overrides.strip()] if manual_coord_overrides.strip() else []
        elif isinstance(manual_coord_overrides, list):
            incoming_coord_overrides = _dedupe_strings(
                [str(item).strip() for item in manual_coord_overrides if str(item).strip()]
            )
        else:
            raise StepError("manual_coord_overrides 仅支持字符串或字符串列表")
        updated["manual_coord_overrides"] = _dedupe_strings(
            list(updated.get("manual_coord_overrides") or []) + incoming_coord_overrides
        )
    if str(response.get("action") or "").strip() == "confirm_unresolved":
        updated["allow_unresolved"] = True

    updated = apply_explicit_step1_mode_selection(updated)
    return apply_user_response_clears(updated, clear_fields)


def print_output(stdout, stderr):
    if stdout:
        sys.stdout.write(stdout)
        if not stdout.endswith("\n"):
            sys.stdout.write("\n")
    if stderr:
        sys.stderr.write(stderr)
        if not stderr.endswith("\n"):
            sys.stderr.write("\n")


def read_step_system_block_reason_codes(script_name, report_dir):
    if report_dir is None:
        return []
    report_dir = Path(report_dir).resolve()
    candidates = {
        "s4_jar_compare.py": [
            step4_api_changes_dir(report_dir) / "japicmp_preflight.json",
        ],
        "s5_call_chain_engine_integrated.py": [
            step5_call_chain_dir(report_dir) / "tree_sitter_preflight.json",
        ],
    }
    reason_codes = []
    for path in candidates.get(script_name, []):
        if not path.exists():
            continue
        try:
            payload = read_json(path)
        except Exception:
            continue
        if str(payload.get("status") or "").strip() != "blocked_by_system":
            continue
        reason_code = str(payload.get("reason_code") or "").strip()
        if reason_code:
            reason_codes.append(reason_code)
    return _dedupe_strings(reason_codes)


def run_python(script_name, script_args, cwd, report_dir=None, timeout=None):
    cmd = [sys.executable, str(SCRIPT_DIR / script_name), *script_args]
    env = {
        "JUA_ORCHESTRATED": "1",
        "JUA_SKILL_DIR": str(SKILL_DIR),
    }
    if report_dir is not None:
        env["UPGRADE_REPORT_DIR"] = str(Path(report_dir).resolve())
    stream_output = script_name == "s1_dep_diff.py"
    run_kwargs = {
        "cwd": str(cwd),
        "env": env,
        "timeout": timeout,
    }
    if stream_output:
        run_kwargs["stream_output"] = True
        # Step scripts use stdout for structured interaction messages. Maven and
        # progress logs are written to stderr, so do not expose protocol lines.
        run_kwargs["stream_stdout"] = False
    heartbeat_stop = threading.Event()
    heartbeat_thread = None
    heartbeat_started = time.perf_counter()
    try:
        heartbeat_interval = float(
            os.environ.get("JUA_HEARTBEAT_INTERVAL_SECONDS") or 30
        )
    except (TypeError, ValueError):
        heartbeat_interval = 30.0
    heartbeat_interval = max(0.01, heartbeat_interval)
    heartbeat_step_id = SCRIPT_STEP_IDS.get(script_name, "")

    def heartbeat_loop():
        while not heartbeat_stop.wait(heartbeat_interval):
            emit_progress(
                heartbeat_step_id,
                "heartbeat",
                "任务仍在执行，系统会继续自动处理，无需操作。",
                elapsed=time.perf_counter() - heartbeat_started,
                report_dir=report_dir,
            )

    if heartbeat_step_id:
        heartbeat_thread = threading.Thread(
            target=heartbeat_loop,
            name=f"jua-heartbeat-{heartbeat_step_id}",
            daemon=True,
        )
        heartbeat_thread.start()
    try:
        stdout, stderr, rc = run_cmd(cmd, **run_kwargs)
    finally:
        heartbeat_stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1)
    interaction_prefix = "JUA_STEP_INTERACTION_JSON:"
    interaction = None
    filtered_stdout_lines = []
    
    if stdout:
        for line in stdout.splitlines():
            text = str(line or "").strip()
            if text.startswith(interaction_prefix):
                payload = text[len(interaction_prefix):].strip()
                try:
                    interaction = json.loads(payload)
                except Exception as exc:
                    raise StepError(f"{script_name} 返回了无法解析的交互请求：{exc}") from exc
                continue
            filtered_stdout_lines.append(line)
        for line in reversed(stdout.splitlines()):
            text = str(line or "").strip()
            if text.startswith(interaction_prefix):
                break
    filtered_stdout = "\n".join(filtered_stdout_lines)
    if stdout.endswith("\n") and filtered_stdout:
        filtered_stdout += "\n"
    print_output(filtered_stdout, "" if stream_output else stderr)
    if interaction is not None:
        raise StepInteractionRequired(interaction)
    if rc != 0:
        reason_codes = read_step_system_block_reason_codes(script_name, report_dir)
        raise StepError(
            f"{script_name} 执行失败，退出码={rc}",
            reason_codes=reason_codes,
        )


def detect_source_dirs(project_dir):
    candidates = []
    default_java = project_dir / "src" / "main" / "java"
    if default_java.is_dir():
        candidates.append(default_java)
    default_kotlin = project_dir / "src" / "main" / "kotlin"
    if default_kotlin.is_dir():
        candidates.append(default_kotlin)
    for child in sorted(project_dir.iterdir()):
        nested_java = child / "src" / "main" / "java"
        if child.is_dir() and nested_java.is_dir():
            candidates.append(nested_java)
        nested_kotlin = child / "src" / "main" / "kotlin"
        if child.is_dir() and nested_kotlin.is_dir():
            candidates.append(nested_kotlin)
    deduped = []
    seen = set()
    for path in candidates:
        resolved = str(path.resolve())
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(resolved)
    return deduped


def normalize_modules_value(raw_value):
    if raw_value in (None, ""):
        return None
    if isinstance(raw_value, str):
        items = [raw_value]
    elif isinstance(raw_value, list):
        items = raw_value
    else:
        raise StepError("modules 仅支持字符串或字符串列表")
    normalized = []
    for item in items:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if not value:
            continue
        normalized.append(value)
    return normalized


def normalize_analysis_mode(raw_value, *, allow_empty=False):
    value = str(raw_value or "").strip()
    if not value:
        if allow_empty:
            return ""
        raise StepError("analysis_mode 不能为空")
    if value not in {"artifact_inputs", "checkout_build"}:
        raise StepError("analysis_mode 仅支持 artifact_inputs 或 checkout_build")
    return value


def apply_explicit_step1_mode_selection(run_context):
    updated = dict(run_context or {})
    explicit_mode = normalize_analysis_mode(updated.get("analysis_mode"), allow_empty=True)
    if explicit_mode == "checkout_build":
        for key in (
            "base_artifact_path",
            "current_artifact_path",
            "base_source_project_dir",
            "current_source_project_dir",
        ):
            updated[key] = ""
    return updated


def detect_source_dirs_by_modules(project_dir, modules):
    modules = normalize_modules_value(modules) or []
    if not modules:
        return []
    candidates = []
    discovery = discover_project_modules(project_dir)
    discovered_modules = list(discovery.get("modules") or [])
    for mod in modules:
        mod_value = (mod or "").strip()
        if mod_value in (".", "./", "__root__", "root"):
            module_dir = project_dir
        else:
            matches = []
            for item in discovered_modules:
                aliases = {
                    str(item.get("module") or ""),
                    str(item.get("gradle_path") or ""),
                    str(item.get("artifact_id") or ""),
                    str(item.get("coord") or ""),
                    Path(str(item.get("module_dir") or "")).name,
                }
                if mod_value in aliases:
                    matches.append(Path(item["module_dir"]).resolve())
            module_dir = (
                matches[0]
                if len(matches) == 1
                else (project_dir / mod_value).resolve()
            )
        if not module_dir.exists() or not module_dir.is_dir():
            raise StepError(f"modules 指定的模块目录不存在：{module_dir}")
        for rel in (("src", "main", "java"), ("src", "main", "kotlin")):
            candidate = module_dir.joinpath(*rel)
            if candidate.is_dir():
                candidates.append(candidate)
    deduped = []
    seen = set()
    for path in candidates:
        resolved = str(path.resolve())
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(resolved)
    return deduped


def count_data_rows(csv_path):
    if not Path(csv_path).exists():
        return 0
    with open_text(csv_path) as f:
        rows = [line for line in f if line.strip() and not line.startswith("#")]
    return max(len(rows) - 1, 0)


def resolve_value(cli_value, run_context, key, default=None):
    runtime_value = (run_context or {}).get(key, default)
    if runtime_value not in (None, "", []):
        return runtime_value
    if cli_value not in (None, "", []):
        return cli_value
    return default


def _has_explicit_string_value(cli_value, seed_payload, previous, key):
    if isinstance(cli_value, str) and cli_value.strip():
        return True
    seed_value = (seed_payload or {}).get(key)
    if isinstance(seed_value, str) and seed_value.strip():
        return True
    previous_value = (previous or {}).get(key)
    if isinstance(previous_value, str) and previous_value.strip():
        return True
    if bool((previous or {}).get(f"{key}_explicit")):
        return True
    return False


def _resolve_branch_value_for_run_context(cli_value, merged, key, default_value, explicit):
    if explicit:
        return resolve_value(cli_value, merged, key, default_value)
    if cli_value not in (None, "", []):
        return cli_value
    return default_value


def absolutize_path(path_value, project_dir):
    path_obj = Path(path_value).expanduser()
    if not path_obj.is_absolute():
        path_obj = project_dir / path_obj
    return str(path_obj.resolve())


def _guess_module_root_from_source_dir(source_dir):
    value = str(source_dir or "").strip()
    if not value:
        return ""
    try:
        normalized = str(Path(value).expanduser().resolve()).replace("\\", "/").rstrip("/")
    except Exception:
        normalized = value.replace("\\", "/").rstrip("/")
    known_suffixes = (
        "/src/main/java",
        "/src/main/kotlin",
        "/src/test/java",
        "/src/test/kotlin",
        "/src/java",
        "/java/src",
        "/src",
    )
    for suffix in known_suffixes:
        if normalized.endswith(suffix):
            module_root = normalized[: -len(suffix)].rstrip("/")
            return module_root or normalized
    path_obj = Path(normalized)
    for candidate in [path_obj, *path_obj.parents]:
        if (candidate / "pom.xml").exists():
            return str(candidate.resolve())
        if (candidate / "build.gradle").exists() or (candidate / "build.gradle.kts").exists():
            return str(candidate.resolve())
    return str(path_obj.parent.resolve()) if path_obj.parent else normalized


def _collect_relevant_dependency_coords(report_dir, ctx=None):
    report_dir = Path(report_dir)
    coords = []
    seen = set()

    dep_changes_path = step1_dep_changes_path(report_dir)
    for row in read_csv_rows(dep_changes_path):
        coord = str(row.get("coord") or "").strip()
        change_type = str(row.get("change_type") or "").strip()
        resolution_status = str(row.get("resolution_status") or "").strip()
        old_version = str(row.get("old_version") or "").strip()
        new_version = str(row.get("new_version") or "").strip()
        if not coord or change_type == "未变" or resolution_status == "unresolved":
            continue
        if old_version == "-" and new_version == "-":
            continue
        if coord not in seen:
            seen.add(coord)
            coords.append(coord)

    if coords:
        return coords

    if ctx is None:
        context_path = step2_context_path(report_dir)
        ctx = read_json(context_path) if context_path.exists() else {}
    for dep in (ctx or {}).get("changed_dependencies") or []:
        coord = str((dep or {}).get("coord") or "").strip()
        if coord and coord not in seen:
            seen.add(coord)
            coords.append(coord)

    return coords


def _collect_focus_dependency_coords(report_dir, ctx=None):
    report_dir = Path(report_dir)
    if ctx is None:
        context_path = step2_context_path(report_dir)
        ctx = read_json(context_path) if context_path.exists() else {}
    coords = []
    seen = set()
    for dep in (ctx or {}).get("changed_dependencies") or []:
        coord = str((dep or {}).get("coord") or "").strip()
        if coord and coord not in seen:
            seen.add(coord)
            coords.append(coord)
    if coords:
        return coords
    return _collect_relevant_dependency_coords(report_dir, ctx=ctx)
    


def _resolve_source_dirs_plan(project_dir, source_dirs=None, modules=None, project_scope=None):
    normalized = normalize_source_dirs(source_dirs, project_dir)
    if normalized:
        return {
            "source_dirs": _dedupe_strings(normalized),
            "status": "explicit",
        }
    scope_roots = list((project_scope or {}).get("source_roots") or [])
    if scope_roots:
        return {
            "source_dirs": _dedupe_strings(scope_roots),
            "status": "project_scope",
        }
    detected_by_modules = detect_source_dirs_by_modules(project_dir, modules) if modules else []
    if detected_by_modules:
        return {
            "source_dirs": _dedupe_strings(detected_by_modules),
            "status": "detected_by_modules",
        }
    detected = detect_source_dirs(project_dir)
    if detected:
        return {
            "source_dirs": _dedupe_strings(detected),
            "status": "auto_detected",
        }
    return {
        "source_dirs": [],
        "status": "missing",
    }


def _discover_dependency_source_candidates(
    dependency_source_dirs,
    relevant_coords=None,
):
    candidates = []
    seen = set()
    relevant_coords = {
        str(item or "").strip()
        for item in (relevant_coords or [])
        if str(item or "").strip()
    }
    for raw_path in (dependency_source_dirs or []):
        input_path = str(raw_path or "").strip()
        if not input_path:
            continue
        repo_path = resolve_repo_input_path(os.path.expanduser(input_path))
        locations = infer_maven_coord_locations(
            repo_path,
            max_poms=120,
            max_depth=4,
            target_coords=relevant_coords,
        )
        for location in locations:
            coord = str(location.get("coord") or "").strip()
            if not coord:
                continue
            module_root = str(location.get("module_dir") or repo_path)
            source_dirs = [
                str(Path(module_root) / relative)
                for relative in (
                    "src/main/java",
                    "src/main/kotlin",
                )
                if (Path(module_root) / relative).is_dir()
            ] or [""]
            for source_dir in source_dirs:
                key = (coord, repo_path, module_root, source_dir)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    {
                        "input_path": input_path,
                        "repo_path": str(location.get("repo_root") or repo_path),
                        "module_root": module_root,
                        "coord": coord,
                        "source_dir": source_dir,
                        "discovery_mode": "bounded_manifest_scan",
                    }
                )
    return candidates


def _build_dependency_source_plan(dependency_source_dirs, relevant_coords=None):
    relevant_order = []
    relevant_seen = set()
    for coord in (relevant_coords or []):
        value = str(coord or "").strip()
        if value and value not in relevant_seen:
            relevant_seen.add(value)
            relevant_order.append(value)
    relevant_set = set(relevant_order)

    raw_candidates = _discover_dependency_source_candidates(
        dependency_source_dirs,
        relevant_coords=relevant_set,
    )
    filtered_candidates = []
    for item in raw_candidates:
        coord = str(item.get("coord") or "").strip()
        if relevant_set and coord not in relevant_set:
            continue
        filtered_candidates.append(item)

    candidates_by_coord = {}
    for item in filtered_candidates:
        coord = str(item.get("coord") or "").strip()
        if not coord:
            continue
        candidates_by_coord.setdefault(coord, []).append(item)

    if relevant_order:
        coord_order = [coord for coord in relevant_order if coord in candidates_by_coord]
    else:
        coord_order = list(candidates_by_coord.keys())

    dependency_repo_mappings = []
    dependency_source_mappings = []
    ambiguous_coords = []
    unmatched_relevant_coords = [coord for coord in relevant_order if coord not in candidates_by_coord]

    for coord in coord_order:
        coord_candidates = candidates_by_coord.get(coord) or []
        repo_paths = _dedupe_strings(
            [
                str(item.get("repo_path") or "").strip()
                for item in coord_candidates
                if item.get("repo_path")
            ]
        )
        if len(repo_paths) > 1:
            ambiguous_coords.append(
                {
                    "coord": coord,
                    "repo_paths": repo_paths,
                    "candidates": coord_candidates,
                }
            )
            continue
        if repo_paths:
            dependency_repo_mappings.append(f"{coord}={repo_paths[0]}")
        source_dirs = _dedupe_strings(
            [str(item.get("source_dir") or "").strip() for item in coord_candidates if item.get("source_dir")]
        )
        for source_dir in source_dirs:
            dependency_source_mappings.append(f"{coord}={source_dir}")

    return {
        "relevant_coords": relevant_order,
        "candidates": filtered_candidates,
        "dependency_repo_mappings": _dedupe_strings(dependency_repo_mappings),
        "dependency_source_mappings": _dedupe_strings(dependency_source_mappings),
        "ambiguous_coords": ambiguous_coords,
        "unmatched_relevant_coords": unmatched_relevant_coords,
    }


def looks_like_remote_repo(path_value):
    value = (path_value or "").strip()
    if not value:
        return False
    return (
        value.startswith(("http://", "https://", "ssh://", "git://", "file://", "git@"))
        or bool(re.match(r"^[^/@\s]+@[^:\s]+:.+", value))
        or value.endswith(".git")
    )


def is_dependency_source_git_url(path_value, project_dir=None):
    """Distinguish cloneable Git addresses from existing local source paths."""
    value = str(path_value or "").strip()
    if not looks_like_remote_repo(value):
        return False
    if value.startswith(("http://", "https://", "ssh://", "git://", "file://", "git@")):
        return True
    if re.match(r"^[^/@\s]+@[^:\s]+:.+", value):
        return True
    local_path = Path(value).expanduser()
    if not local_path.is_absolute() and project_dir is not None:
        local_path = Path(project_dir) / local_path
    return not local_path.exists()


def _redact_git_url(value):
    text = str(value or "")
    return re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1***@", text)


def _dependency_source_git_origin(repo_path):
    stdout, _stderr, rc = run_cmd(
        git_cmd() + ["-C", str(repo_path), "remote", "get-url", "origin"],
        timeout=10,
        env={"GIT_TERMINAL_PROMPT": "0"},
    )
    return str(stdout or "").strip() if rc == 0 else ""


def _is_materialized_dependency_source_repo(repo_path, git_url):
    repo_path = Path(repo_path)
    if not repo_path.is_dir() or repo_path.is_symlink():
        return False
    stdout, _stderr, rc = run_cmd(
        git_cmd() + ["-C", str(repo_path), "rev-parse", "--is-inside-work-tree"],
        timeout=10,
        env={"GIT_TERMINAL_PROMPT": "0"},
    )
    return (
        rc == 0
        and str(stdout or "").strip().lower() == "true"
        and _dependency_source_git_origin(repo_path) == str(git_url or "").strip()
    )


def materialize_dependency_source_git_url(git_url, report_dir, clone_timeout=300):
    """Clone a user-provided dependency source URL into a report-owned cache."""
    git_url = str(git_url or "").strip()
    if not is_dependency_source_git_url(git_url):
        raise StepError(f"依赖源码 Git 地址格式无法识别：{git_url or '(空)'}")
    clone_timeout = parse_positive_int_like(
        clone_timeout,
        "dependency_source_clone_timeout",
    )

    cache_key = hashlib.sha256(git_url.encode("utf-8")).hexdigest()[:24]
    cache_entry = runtime_cache_dir(report_dir) / "dependency_source_git" / cache_key
    repo_path = cache_entry / "repository"
    metadata_path = cache_entry / "metadata.json"
    cache_entry.mkdir(parents=True, exist_ok=True)

    if _is_materialized_dependency_source_repo(repo_path, git_url):
        write_json(
            metadata_path,
            {
                "schema": "java-upgrade-analyzer.dependency-source-git.v1",
                "git_url": git_url,
                "repo_path": str(repo_path.resolve()),
                "status": "ready",
            },
        )
        return {
            "git_url": git_url,
            "repo_path": str(repo_path.resolve()),
            "metadata_path": str(metadata_path.resolve()),
            "reused": True,
        }

    if repo_path.exists() or repo_path.is_symlink():
        if repo_path.is_symlink():
            raise StepError(
                "依赖源码 Git 缓存路径异常（检测到符号链接），为避免覆盖未知内容已停止："
                f"{repo_path}"
            )
        shutil.rmtree(repo_path)

    temp_repo = cache_entry / f"repository.clone-{os.getpid()}-{threading.get_ident()}"
    if temp_repo.exists() or temp_repo.is_symlink():
        if temp_repo.is_symlink():
            temp_repo.unlink()
        else:
            shutil.rmtree(temp_repo)
    stdout, stderr, rc = run_cmd(
        git_cmd() + [
            "clone",
            "--no-tags",
            "--origin",
            "origin",
            git_url,
            str(temp_repo),
        ],
        cwd=str(cache_entry),
        timeout=clone_timeout,
        env={"GIT_TERMINAL_PROMPT": "0"},
    )
    if rc != 0 or not _is_materialized_dependency_source_repo(temp_repo, git_url):
        if temp_repo.exists() and not temp_repo.is_symlink():
            shutil.rmtree(temp_repo)
        reason = str(stderr or stdout or f"git clone exited with {rc}").strip()
        reason = _redact_git_url(reason.replace(git_url, _redact_git_url(git_url)))
        raise StepError(
            f"无法克隆依赖源码 Git 地址 {_redact_git_url(git_url)}：{reason[:1000]}。"
            "请确认地址和访问权限后重试；已有分析产物不会被修改。"
        )

    if repo_path.exists():
        if _is_materialized_dependency_source_repo(repo_path, git_url):
            shutil.rmtree(temp_repo)
        else:
            shutil.rmtree(temp_repo)
            raise StepError(f"依赖源码 Git 缓存被并发写入且结果无效：{repo_path}")
    else:
        temp_repo.replace(repo_path)

    write_json(
        metadata_path,
        {
            "schema": "java-upgrade-analyzer.dependency-source-git.v1",
            "git_url": git_url,
            "repo_path": str(repo_path.resolve()),
            "status": "ready",
        },
    )
    return {
        "git_url": git_url,
        "repo_path": str(repo_path.resolve()),
        "metadata_path": str(metadata_path.resolve()),
        "reused": False,
    }


def materialize_dependency_source_inputs(source_inputs, project_dir, report_dir, clone_timeout=300):
    local_dirs = []
    git_urls = []
    materializations = []
    for item in source_inputs or []:
        value = str(item or "").strip()
        if not value:
            continue
        if is_dependency_source_git_url(value, project_dir):
            materialized = materialize_dependency_source_git_url(
                value,
                report_dir,
                clone_timeout=clone_timeout,
            )
            git_urls.append(value)
            local_dirs.append(materialized["repo_path"])
            materializations.append(materialized)
        else:
            local_dirs.append(resolve_repo_input_path(absolutize_path(value, project_dir)))
    return {
        "dependency_source_dirs": _dedupe_strings(local_dirs),
        "dependency_source_git_urls": _dedupe_strings(git_urls),
        "dependency_source_git_materializations": materializations,
    }


def normalize_source_dirs(raw_value, project_dir):
    if raw_value in (None, ""):
        return None
    if isinstance(raw_value, str):
        raw_items = [raw_value]
    elif isinstance(raw_value, list):
        raw_items = raw_value
    else:
        raise StepError("当前步骤输入中的 source_dirs 仅支持字符串或字符串列表")
    normalized = []
    for item in raw_items:
        if not isinstance(item, str) or not item.strip():
            continue
        normalized.append(absolutize_path(item.strip(), project_dir))
    return normalized


def normalize_dependency_source_dirs(raw_value, project_dir, config_key="dependency_source_dirs"):
    if raw_value in (None, ""):
        return None
    if isinstance(raw_value, dict):
        iterable = [raw_value]
    elif isinstance(raw_value, list):
        iterable = raw_value
    elif isinstance(raw_value, str):
        iterable = [raw_value]
    else:
        raise StepError(f"当前步骤输入中的 {config_key} 仅支持字符串、对象或列表")

    normalized = []
    seen = set()
    for item in iterable:
        if isinstance(item, str):
            path_value = item.strip()
            if not path_value:
                continue
        elif isinstance(item, dict):
            path_value = str(
                item.get("url")
                or item.get("git_url")
                or item.get("clone_url")
                or item.get("path")
                or item.get("root")
                or item.get("repo_path")
                or item.get("git_path")
                or item.get("repo")
                or item.get("local_path")
                or ""
            ).strip()
            if not path_value:
                raise StepError(
                    f"当前步骤输入中的 {config_key} 的对象项需包含 url/git_url/path/repo_path/git_path"
                )
        else:
            raise StepError(f"当前步骤输入中的 {config_key} 存在不支持的项类型")

        if is_dependency_source_git_url(path_value, project_dir):
            normalized_path = path_value
        else:
            normalized_path = resolve_repo_input_path(absolutize_path(path_value, project_dir))
        if normalized_path in seen:
            continue
        seen.add(normalized_path)
        normalized.append(normalized_path)
    return normalized


def normalize_dependency_repo_mappings(raw_value, project_dir, config_key="dependency_repo_mappings"):
    if raw_value in (None, ""):
        return None
    if isinstance(raw_value, dict):
        iterable = [raw_value]
    elif isinstance(raw_value, list):
        iterable = raw_value
    elif isinstance(raw_value, str):
        iterable = [raw_value]
    else:
        raise StepError(f"当前步骤输入中的 {config_key} 仅支持字符串、对象或列表")

    normalized = []
    seen = set()
    for item in iterable:
        coord_hint = ""
        if isinstance(item, str):
            raw = item.strip()
            if not raw:
                continue
            if "=" in raw:
                coord_hint, path_value = raw.split("=", 1)
                coord_hint = coord_hint.strip()
                path_value = path_value.strip()
            else:
                path_value = raw
        elif isinstance(item, dict):
            coord_hint = str(item.get("coord") or item.get("coord_hint") or item.get("group") or "").strip()
            path_value = str(
                item.get("path")
                or item.get("root")
                or item.get("repo_path")
                or item.get("git_path")
                or item.get("repo")
                or item.get("local_path")
                or ""
            ).strip()
            if not path_value:
                raise StepError(f"当前步骤输入中的 {config_key} 的对象项需包含 path/repo_path/git_path")
        else:
            raise StepError(f"当前步骤输入中的 {config_key} 存在不支持的项类型")

        if looks_like_remote_repo(path_value) and not Path(path_value).expanduser().exists():
            raise StepError(
                f"当前步骤输入中的 {config_key} 当前仅支持本地已检出的源码目录，暂不支持直接传远程地址：{path_value}"
            )

        normalized_path = resolve_repo_input_path(absolutize_path(path_value, project_dir))
        normalized_value = f"{coord_hint}={normalized_path}" if coord_hint else normalized_path
        if normalized_value in seen:
            continue
        seen.add(normalized_value)
        normalized.append(normalized_value)
    return normalized


def normalize_dependency_source_mappings(raw_value, project_dir, config_key="dependency_source_mappings"):
    if raw_value in (None, ""):
        return None
    if isinstance(raw_value, dict):
        iterable = [raw_value]
    elif isinstance(raw_value, list):
        iterable = raw_value
    elif isinstance(raw_value, str):
        iterable = [raw_value]
    else:
        raise StepError(f"当前步骤输入中的 {config_key} 仅支持字符串、对象或列表")

    normalized = []
    seen = set()
    for item in iterable:
        coord_hint = ""
        if isinstance(item, str):
            raw = item.strip()
            if not raw:
                continue
            if "=" in raw:
                coord_hint, path_value = raw.split("=", 1)
                coord_hint = coord_hint.strip()
                path_value = path_value.strip()
            else:
                path_value = raw
        elif isinstance(item, dict):
            coord_hint = str(item.get("coord") or item.get("coord_hint") or item.get("group") or "").strip()
            path_value = str(
                item.get("path")
                or item.get("root")
                or item.get("source_dir")
                or item.get("src_dir")
                or item.get("repo_path")
                or item.get("git_path")
                or item.get("repo")
                or item.get("local_path")
                or ""
            ).strip()
            if not path_value:
                raise StepError(f"当前步骤输入中的 {config_key} 的对象项需包含 path/source_dir/src_dir")
        else:
            raise StepError(f"当前步骤输入中的 {config_key} 存在不支持的项类型")

        if looks_like_remote_repo(path_value) and not Path(path_value).expanduser().exists():
            raise StepError(
                f"当前步骤输入中的 {config_key} 当前仅支持本地已检出的源码目录，暂不支持直接传远程地址：{path_value}"
            )

        normalized_path = absolutize_path(path_value, project_dir)
        normalized_value = f"{coord_hint}={normalized_path}" if coord_hint else normalized_path
        if normalized_value in seen:
            continue
        seen.add(normalized_value)
        normalized.append(normalized_value)
    return normalized


def normalize_dependency_git_ref_overrides(raw_value, config_key="dependency_git_ref_overrides"):
    if raw_value in (None, ""):
        return None
    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return []
        if text.startswith("[") or text.startswith("{"):
            try:
                return normalize_dependency_git_ref_overrides(json.loads(text), config_key)
            except Exception as exc:
                raise StepError(f"当前步骤输入中的 {config_key} 不是合法 JSON：{exc}") from exc
        iterable = [text]
    elif isinstance(raw_value, dict):
        iterable = [raw_value]
    elif isinstance(raw_value, list):
        iterable = raw_value
    else:
        raise StepError(f"当前步骤输入中的 {config_key} 仅支持字符串、对象或列表")

    normalized = []
    seen = set()
    for item in iterable:
        coord = ""
        old_ref = ""
        new_ref = ""
        allow_local_source = False
        allow_dirty_local_source = False
        expected_old_commit = ""
        expected_new_commit = ""
        selection_key = ""
        if isinstance(item, str):
            raw = item.strip()
            if not raw:
                continue
            if raw.startswith("[") or raw.startswith("{"):
                nested = normalize_dependency_git_ref_overrides(raw, config_key) or []
                for nested_item in nested:
                    key = (
                        nested_item.get("coord", ""),
                        nested_item.get("old_ref", ""),
                        nested_item.get("new_ref", ""),
                        nested_item.get("expected_old_commit", ""),
                        nested_item.get("expected_new_commit", ""),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    normalized.append(nested_item)
                continue
            if "=" not in raw or ".." not in raw:
                raise StepError(
                    f"当前步骤输入中的 {config_key} 的字符串项格式必须为 "
                    "groupId:artifactId=old_ref..new_ref"
                )
            coord, refs = raw.split("=", 1)
            old_ref, new_ref = refs.split("..", 1)
        elif isinstance(item, dict):
            coord = str(item.get("coord") or item.get("coord_hint") or "").strip()
            old_ref = str(item.get("old_ref") or item.get("base_ref") or "").strip()
            new_ref = str(item.get("new_ref") or item.get("current_ref") or "").strip()
            expected_old_commit = str(item.get("expected_old_commit") or item.get("old_commit") or "").strip()
            expected_new_commit = str(item.get("expected_new_commit") or item.get("new_commit") or "").strip()
            selection_key = str(item.get("selection_key") or "").strip()
            if "allow_local_source" in item:
                allow_local_source = parse_bool_like(item.get("allow_local_source"), "allow_local_source")
            if "allow_dirty_local_source" in item:
                allow_dirty_local_source = parse_bool_like(
                    item.get("allow_dirty_local_source"), "allow_dirty_local_source"
                )
        else:
            raise StepError(f"当前步骤输入中的 {config_key} 存在不支持的项类型")

        coord = coord.strip()
        old_ref = old_ref.strip()
        new_ref = new_ref.strip()
        if not (coord and old_ref and new_ref):
            raise StepError(f"当前步骤输入中的 {config_key} 每项都必须包含 coord/old_ref/new_ref")
        if allow_dirty_local_source and not allow_local_source:
            raise StepError("allow_dirty_local_source=true 时必须同时明确 allow_local_source=true")
        key = (
            coord,
            old_ref,
            new_ref,
            expected_old_commit,
            expected_new_commit,
            allow_local_source,
            allow_dirty_local_source,
        )
        if key in seen:
            continue
        seen.add(key)
        normalized_item = {"coord": coord, "old_ref": old_ref, "new_ref": new_ref}
        if expected_old_commit:
            normalized_item["expected_old_commit"] = expected_old_commit
        if expected_new_commit:
            normalized_item["expected_new_commit"] = expected_new_commit
        if selection_key:
            normalized_item["selection_key"] = selection_key
        if allow_local_source:
            normalized_item["allow_local_source"] = True
        if allow_dirty_local_source:
            normalized_item["allow_dirty_local_source"] = True
        normalized.append(normalized_item)
    return normalized


def normalize_source_repo_hints(raw_value, project_dir, config_key):
    if raw_value in (None, ""):
        return None
    if isinstance(raw_value, dict):
        iterable = [raw_value]
    elif isinstance(raw_value, list):
        iterable = raw_value
    elif isinstance(raw_value, str):
        iterable = [raw_value]
    else:
        raise StepError(f"当前步骤输入中的 {config_key} 仅支持字符串、对象或列表")

    normalized = []
    seen = set()
    for item in iterable:
        coord_hint = ""
        notes = ""
        if isinstance(item, str):
            raw = item.strip()
            if not raw:
                continue
            if "=" in raw:
                coord_hint, path_value = raw.split("=", 1)
                coord_hint = coord_hint.strip()
                path_value = path_value.strip()
            else:
                path_value = raw
        elif isinstance(item, dict):
            coord_hint = str(item.get("coord_hint") or item.get("coord") or item.get("owner_coord") or "").strip()
            path_value = str(
                item.get("path")
                or item.get("root")
                or item.get("repo_path")
                or item.get("git_path")
                or item.get("repo")
                or item.get("local_path")
                or ""
            ).strip()
            notes = str(item.get("notes") or item.get("hint") or "").strip()
            if not path_value:
                raise StepError(f"当前步骤输入中的 {config_key} 的对象项需包含 path/repo_path/git_path")
        else:
            raise StepError(f"当前步骤输入中的 {config_key} 存在不支持的项类型")

        if looks_like_remote_repo(path_value) and not Path(path_value).expanduser().exists():
            raise StepError(
                f"当前步骤输入中的 {config_key} 当前仅支持本地已检出的源码仓库，暂不支持直接传远程地址：{path_value}"
            )
        normalized_path = resolve_repo_input_path(absolutize_path(path_value, project_dir))
        inferred_coords = [item for item in infer_maven_coords(normalized_path) if item]
        key = (coord_hint, normalized_path)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(
            {
                "coord_hint": coord_hint,
                "repo_path": normalized_path,
                "repo_inferred_coords": inferred_coords,
                "notes": notes,
            }
        )
    return normalized


def _dedupe_strings(items):
    ordered = []
    seen = set()
    for item in items or []:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def normalize_step5_target_list(raw_value, field_name):
    if raw_value is None:
        return None
    if isinstance(raw_value, str):
        values = [raw_value]
    elif isinstance(raw_value, list):
        values = raw_value
    else:
        raise StepError(f"{field_name} 仅支持字符串或字符串列表")
    normalized = []
    seen = set()
    for item in values:
        text = str(item or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(text)
    return normalized


def _artifact_name_from_coord(coord):
    parts = [part.strip() for part in str(coord or "").strip().split(":")]
    if len(parts) < 2:
        return ""
    return parts[1]


def build_interaction_selection_options(selection_options):
    normalized = []
    seen_keys = set()
    for item in selection_options or []:
        coord = str((item or {}).get("coord") or "").strip()
        name = str((item or {}).get("name") or "").strip()
        selection_key = str((item or {}).get("selection_key") or "").strip()
        if not selection_key:
            if coord:
                selection_key = f"coord:{coord}"
            elif name:
                selection_key = f"name:{name}"
        if not selection_key:
            continue
        key_lower = selection_key.lower()
        if key_lower in seen_keys:
            continue
        seen_keys.add(key_lower)
        aliases = _dedupe_strings(
            [
                selection_key,
                coord,
                name,
                str((item or {}).get("label") or "").strip(),
            ]
            + list((item or {}).get("aliases") or [])
        )
        normalized.append(
            {
                "selection_key": selection_key,
                "coord": coord,
                "name": name,
                "label": str((item or {}).get("label") or coord or name or selection_key).strip(),
                "api_count": (item or {}).get("api_count"),
                "high_risk_api_count": (item or {}).get("high_risk_api_count"),
                "recommended": _parse_bool((item or {}).get("recommended")),
                "change_types": str((item or {}).get("change_types") or "").strip(),
                "detail": str((item or {}).get("detail") or "").strip(),
                "aliases": aliases,
            }
        )
    return normalized


def build_selection_resolution(selection_options):
    normalized_options = build_interaction_selection_options(selection_options)
    if not normalized_options:
        return {}
    return {
        "enabled": True,
        "response_field": "selected_targets",
        "preferred_identifier": "coord",
        "preferred_write_fields": ["step5_selected_coords", "step5_selected_names"],
        "rules": [
            "若用户提到候选依赖，应优先输出 selected_targets，并使用 changed_dependencies.md 中的完整依赖坐标。",
            "完整依赖坐标必须严格匹配唯一目标；只有用户仅提供依赖名称时，才按 artifactId 名称筛选命中的全部候选。",
            "selected_targets 只是候选选择输入；系统会自动把它归一化为正式的 step5_selected_coords / step5_selected_names。",
        ],
        "options": normalized_options,
    }


NON_PENDING_BRIDGE_ALLOWED_ACTIONS = {
    "cancel",
    "continue",
    "rerun_current_step",
    "restart_from_step",
}


def build_report_dir_step5_selection_resolution(report_dir):
    report_dir = Path(report_dir).resolve()
    target_summary = build_step5_dependency_selection_summary(report_dir)
    selection_options = build_interaction_selection_options(
        [
            {
                "selection_key": item.get("selection_key") or f"coord:{item.get('coord')}",
                "coord": item.get("coord"),
                "name": item.get("name"),
                "api_count": item.get("api_count"),
                "high_risk_api_count": item.get("high_risk_api_count"),
                "change_types": item.get("change_types"),
                "detail": item.get("detail"),
                "label": item.get("coord") or item.get("name"),
            }
            for item in target_summary.get("available_targets", [])
        ]
    )
    return build_selection_resolution(selection_options)


def step4_changed_dependencies_path(report_dir):
    return step4_api_changes_dir(report_dir) / "changed_dependencies.csv"


def _parse_int_or_zero(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _parse_bool(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "是"}


def _is_recommended_selection_target(row):
    if str((row or {}).get("recommended") or "").strip():
        return _parse_bool((row or {}).get("recommended"))
    high_risk = _parse_int_or_zero((row or {}).get("high_risk_api_count"))
    changed = _parse_int_or_zero((row or {}).get("changed_api_count") or (row or {}).get("api_count"))
    change_types = str((row or {}).get("change_types") or "").lower()
    return bool(high_risk or "removed" in change_types or "signature" in change_types or changed >= 20)


def _is_high_risk_selection_api_row(row):
    severity = str((row or {}).get("severity") or "").strip().upper()
    change_type = str((row or {}).get("change_type") or "").strip().lower()
    if severity:
        return severity in {"P0", "P1", "HIGH", "CRITICAL"}
    return change_type in {
        "removed",
        "signature_changed",
        "method_removed",
        "field_removed",
        "class_removed",
    }


def build_step5_dependency_selection_summary(report_dir):
    report_dir = Path(report_dir).resolve()
    dependency_rows = read_csv_rows(step4_changed_dependencies_path(report_dir))
    if dependency_rows:
        available_targets = []
        for row in dependency_rows:
            coord = str(row.get("coord") or "").strip()
            if not coord:
                continue
            target = {
                    "selection_key": str(row.get("selection_key") or f"coord:{coord}").strip(),
                    "coord": coord,
                    "name": str(row.get("dependency_name") or _artifact_name_from_coord(coord)).strip(),
                    "api_count": _parse_int_or_zero(row.get("changed_api_count")),
                    "high_risk_api_count": _parse_int_or_zero(row.get("high_risk_api_count")),
                    "change_types": str(row.get("change_types") or "").strip(),
                    "detail": str(row.get("detail") or "").strip(),
                    "recommended": _is_recommended_selection_target(row),
                }
            available_targets.append(target)
        recommended_targets = [item for item in available_targets if item.get("recommended")]
        return {
            "available_targets": available_targets,
            "available_target_count": len(available_targets),
            "recommended_targets": recommended_targets,
            "recommended_target_count": len(recommended_targets),
            "source_file": str(step4_changed_dependencies_path(report_dir)),
        }
    all_rows = read_csv_rows(step4_api_changes_dir(report_dir) / "all_changed_apis.csv")
    fallback = build_step5_selection_summary(all_rows)
    fallback["recommended_targets"] = [
        item for item in fallback.get("available_targets", []) if _is_recommended_selection_target(item)
    ]
    fallback["recommended_target_count"] = len(fallback["recommended_targets"])
    fallback["source_file"] = str(step4_api_changes_dir(report_dir) / "all_changed_apis.csv")
    return fallback


def build_step5_selection_summary(all_rows, selected_coords=None, selected_names=None):
    selected_coords = normalize_step5_target_list(selected_coords, "step5_selected_coords") or []
    selected_names = normalize_step5_target_list(selected_names, "step5_selected_names") or []
    available_targets = []
    per_coord_counts = {}
    for row in all_rows or []:
        coord = str((row or {}).get("coord") or "").strip()
        if not coord:
            continue
        item = per_coord_counts.setdefault(
            coord,
            {
                "coord": coord,
                "name": _artifact_name_from_coord(coord),
                "api_count": 0,
                "high_risk_api_count": 0,
                "change_type_set": set(),
            },
        )
        item["api_count"] += 1
        if _is_high_risk_selection_api_row(row):
            item["high_risk_api_count"] += 1
        change_type = str((row or {}).get("change_type") or "").strip()
        if change_type:
            item["change_type_set"].add(change_type)
    for item in per_coord_counts.values():
        item["change_types"] = ", ".join(sorted(item.pop("change_type_set")))
        item["recommended"] = _is_recommended_selection_target(item)
    available_targets = sorted(
        per_coord_counts.values(),
        key=lambda item: (item.get("coord") or ""),
    )
    selected_coord_set = {item.lower() for item in selected_coords}
    selected_name_set = {item.lower() for item in selected_names}
    matched_coords = []
    matched_names = []
    matched_rows = []
    unmatched_coords = []
    unmatched_names = []
    seen_coords = set()
    seen_names = set()
    if not selected_coord_set and not selected_name_set:
        matched_rows = list(all_rows or [])
    else:
        for row in all_rows or []:
            coord = str((row or {}).get("coord") or "").strip()
            name = _artifact_name_from_coord(coord)
            coord_hit = coord.lower() in selected_coord_set if coord else False
            name_hit = name.lower() in selected_name_set if name else False
            if not (coord_hit or name_hit):
                continue
            matched_rows.append(dict(row))
            if coord_hit and coord not in seen_coords:
                matched_coords.append(coord)
                seen_coords.add(coord)
            if name_hit and name not in seen_names:
                matched_names.append(name)
                seen_names.add(name)
        available_coord_set = {item.get("coord", "").lower() for item in available_targets if item.get("coord")}
        available_name_set = {item.get("name", "").lower() for item in available_targets if item.get("name")}
        unmatched_coords = [item for item in selected_coords if item.lower() not in available_coord_set]
        unmatched_names = [item for item in selected_names if item.lower() not in available_name_set]
    return {
        "selected_coords": selected_coords,
        "selected_names": selected_names,
        "matched_coords": matched_coords,
        "matched_names": matched_names,
        "matched_rows": matched_rows,
        "matched_row_count": len(matched_rows),
        "available_targets": available_targets,
        "available_target_count": len(available_targets),
        "unmatched_coords": unmatched_coords,
        "unmatched_names": unmatched_names,
    }


def _response_value_present(value):
    return value not in (None, "", [])


def has_non_pending_intent_payload(user_response):
    response = dict(user_response or {})
    if list(response.get("__clear_fields") or []):
        return True
    for key, value in response.items():
        if key in {"action", "restart_step_id", "notes", "__intent_patch", "__clear_fields"}:
            continue
        if _response_value_present(value):
            return True
    return False


def infer_non_pending_target_step_from_payload(user_response):
    response = dict(user_response or {})
    if response.get("selected_targets") is not None:
        return "step5"
    step_hints = (
        (
            "step1",
            {
                "analysis_mode",
                "active_maven_profiles",
                "base_artifact_path",
                "base_branch",
                "base_jdk_home",
                "base_source_project_dir",
                "current_artifact_path",
                "current_branch",
                "current_jdk_home",
                "current_source_project_dir",
                "manual_coord_overrides",
                "modules",
                "primary_module",
                "target_module",
                "tool",
            },
        ),
        (
            "step2",
            {
                "jdk_base",
                "jdk_current",
                "springboot_base",
                "springboot_current",
                "source_dirs",
                "dependency_source_dirs",
                "source_repo_hints",
                "accept_suggested_mappings",
            },
        ),
        (
            "step3",
            {
                "include_test_scope",
            },
        ),
        (
            "step4",
            {
                "dependency_git_ref_overrides",
                "step4_fetch_timeout",
                "step4_tool_install_timeout",
                "step4_git_diff_timeout",
                "step4_japicmp_timeout",
                "step4_workers",
            },
        ),
        (
            "step5",
            {
                "allow_degraded",
                "max_depth",
                "step5_selected_coords",
                "step5_selected_names",
                "step5_timeout",
                "strict_risk_gate",
            },
        ),
    )
    for step_id, fields in step_hints:
        if any(_response_value_present(response.get(field)) for field in fields):
            return step_id
    if list(response.get("__clear_fields") or []):
        cleared = set(response.get("__clear_fields") or [])
        for step_id, fields in step_hints:
            if cleared.intersection(fields):
                return step_id
    return ""


def normalize_action_requirements(action_requirements, options, required_fields=None):
    normalized = {}
    known_actions = {
        str((item or {}).get("id") or "").strip()
        for item in (options or [])
        if str((item or {}).get("id") or "").strip()
    }
    for action_id, spec in (action_requirements or {}).items():
        action_key = str(action_id or "").strip()
        if not action_key:
            continue
        if known_actions and action_key not in known_actions:
            continue
        item = dict(spec or {})
        normalized[action_key] = {
            "required_fields": _dedupe_strings(
                [
                    str(field).strip()
                    for field in (
                        item.get("required_fields")
                        or (list(required_fields or []) if action_key == "continue" and required_fields else [])
                    )
                    if str(field).strip()
                ]
            ),
            "at_least_one_of": _dedupe_strings(
                [str(field).strip() for field in (item.get("at_least_one_of") or []) if str(field).strip()]
            ),
            "recommended_fields": _dedupe_strings(
                [str(field).strip() for field in (item.get("recommended_fields") or []) if str(field).strip()]
            ),
            "description": str(item.get("description") or "").strip(),
        }
    if "continue" in known_actions and required_fields and "continue" not in normalized:
        normalized["continue"] = {
            "required_fields": _dedupe_strings([str(field).strip() for field in required_fields if str(field).strip()]),
            "at_least_one_of": [],
            "recommended_fields": [],
            "description": "只有补齐当前检查点要求的关键字段后，才能继续执行。",
        }
    if "restart_from_step" in known_actions:
        restart_spec = normalized.setdefault("restart_from_step", {})
        restart_spec["required_fields"] = _dedupe_strings(
            list(restart_spec.get("required_fields") or []) + ["restart_step_id"]
        )
        restart_spec.setdefault("at_least_one_of", [])
        restart_spec.setdefault("recommended_fields", [])
        restart_spec.setdefault("description", "指定 restart_step_id 后，从当前步骤或更早步骤重新执行。")
    return normalized


def resolve_selected_targets(selection_resolution, raw_value):
    if raw_value is None:
        return None
    values = normalize_step5_target_list(raw_value, "selected_targets") or []
    resolution = dict(selection_resolution or {})
    options = list(resolution.get("options") or [])
    if not options:
        raise StepError("当前检查点不支持 selected_targets。")
    selection_key_map = {}
    coord_map = {}
    name_map = {}
    alias_map = {}
    for item in options:
        selection_key = str(item.get("selection_key") or "").strip()
        coord = str(item.get("coord") or "").strip()
        name = str(item.get("name") or "").strip()
        if selection_key:
            selection_key_map.setdefault(selection_key.lower(), []).append(item)
        if coord:
            coord_map.setdefault(coord.lower(), []).append(item)
        if name:
            name_map.setdefault(name.lower(), []).append(item)
        aliases = _dedupe_strings(
            [
                selection_key,
                coord,
                name,
            ]
            + list(item.get("aliases") or [])
        )
        for alias in aliases:
            alias_key = alias.lower()
            if not alias_key:
                continue
            if alias_key in {selection_key.lower(), coord.lower(), name.lower()}:
                continue
            alias_map.setdefault(alias_key, []).append(item)

    def unique_hits(raw_hits):
        resolved = []
        seen_option_keys = set()
        for hit in raw_hits:
            option_key = str(hit.get("selection_key") or "").strip().lower()
            if option_key in seen_option_keys:
                continue
            seen_option_keys.add(option_key)
            resolved.append(hit)
        return resolved

    def append_selected_hit(hit):
        coord = str(hit.get("coord") or "").strip()
        name = str(hit.get("name") or "").strip()
        if coord and coord.lower() not in seen_coords:
            selected_coords.append(coord)
            seen_coords.add(coord.lower())
            return
        if name and name.lower() not in seen_names:
            selected_names.append(name)
            seen_names.add(name.lower())

    def append_selected_name(name_value, raw_hits):
        hits = unique_hits(raw_hits)
        if not hits:
            return False
        canonical_name = str(hits[0].get("name") or name_value or "").strip() or str(name_value or "").strip()
        if canonical_name and canonical_name.lower() not in seen_names:
            selected_names.append(canonical_name)
            seen_names.add(canonical_name.lower())
        return True

    selected_coords = []
    selected_names = []
    unresolved = []
    ambiguous = {}
    seen_coords = set()
    seen_names = set()
    for raw_item in values:
        raw_key = raw_item.lower()
        if raw_key.startswith("name:"):
            name_value = raw_item.split(":", 1)[1].strip()
            if not name_value or not append_selected_name(name_value, name_map.get(name_value.lower(), [])):
                unresolved.append(raw_item)
            continue
        direct_hits = unique_hits(selection_key_map.get(raw_key, []))
        if not direct_hits:
            direct_hits = unique_hits(coord_map.get(raw_key, []))
        if direct_hits:
            if len(direct_hits) > 1:
                ambiguous[raw_item] = [str(item.get("selection_key") or "").strip() for item in direct_hits]
                continue
            append_selected_hit(direct_hits[0])
            continue
        if append_selected_name(raw_item, name_map.get(raw_key, [])):
            continue
        alias_hits = unique_hits(alias_map.get(raw_key, []))
        if not alias_hits:
            unresolved.append(raw_item)
            continue
        if len(alias_hits) > 1:
            ambiguous[raw_item] = [str(item.get("selection_key") or "").strip() for item in alias_hits]
            continue
        append_selected_hit(alias_hits[0])
    return {
        "selected_targets": values,
        "step5_selected_coords": selected_coords,
        "step5_selected_names": selected_names,
        "unresolved": unresolved,
        "ambiguous": ambiguous,
    }


def validate_selected_targets_resolution(selection_resolution, raw_value):
    selection_result = resolve_selected_targets(selection_resolution, raw_value) or {}
    if selection_result.get("ambiguous"):
        problems = []
        for raw_item, candidates in selection_result.get("ambiguous", {}).items():
            problems.append(f"{raw_item} -> {', '.join(candidates[:5])}")
        raise StepError("selected_targets 存在歧义，必须先明确唯一候选：" + "；".join(problems))
    if selection_result.get("unresolved"):
        raise StepError(
            "selected_targets 未命中当前候选："
            + ", ".join(selection_result.get("unresolved")[:10])
        )
    return selection_result


def write_step5_selected_input(output_path, selection_summary):
    import csv

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(output_path) as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in selection_summary.get("matched_rows") or []:
            writer.writerow({field: row.get(field, "") for field in ALL_CHANGED_APIS_FIELDS})
    return output_path


def write_csv_rows(output_path, rows, fieldnames):
    import csv

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(output_path) as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows or []:
            writer.writerow({field: row.get(field, "") for field in fieldnames})
    return output_path


def materialize_step5_all_changed_apis_input(all_changed_apis_path, report_dir, run_context):
    all_rows = read_csv_rows(all_changed_apis_path)
    selected_coords = run_context.get("step5_selected_coords")
    selected_names = run_context.get("step5_selected_names")
    selection_summary = build_step5_selection_summary(
        all_rows,
        selected_coords=selected_coords,
        selected_names=selected_names,
    )
    has_selection = bool(selection_summary.get("selected_coords") or selection_summary.get("selected_names"))
    base_path = Path(all_changed_apis_path)
    if has_selection:
        if selection_summary.get("unmatched_coords") or selection_summary.get("unmatched_names"):
            problems = []
            if selection_summary.get("unmatched_coords"):
                problems.append("未匹配坐标: " + ", ".join(selection_summary.get("unmatched_coords")[:10]))
            if selection_summary.get("unmatched_names"):
                problems.append("未匹配名称: " + ", ".join(selection_summary.get("unmatched_names")[:10]))
            raise StepError(
                "Step5 选择的变更 jar 未在 all_changed_apis.csv 中匹配到有效目标；"
                + "；".join(problems)
            )
        if not selection_summary.get("matched_rows"):
            raise StepError("Step5 选择的变更 jar 过滤后为空，无法执行调用链分析。")
        filtered_path = runtime_cache_dir(report_dir) / "selected_all_changed_apis.csv"
        base_selection = build_step5_selection_summary(
            all_rows,
            selected_coords=selected_coords,
            selected_names=selected_names,
        )
        base_path = write_step5_selected_input(filtered_path, base_selection)
    all_coords = sorted({str((row or {}).get("coord") or "").strip() for row in all_rows if str((row or {}).get("coord") or "").strip()})
    included_coords = sorted({
        str((row or {}).get("coord") or "").strip()
        for row in selection_summary.get("matched_rows") or []
        if str((row or {}).get("coord") or "").strip()
    })
    included_coord_set = set(included_coords)
    all_coord_set = set(all_coords)
    effective_scope_mode = (
        "partial"
        if has_selection and included_coord_set != all_coord_set
        else "full"
    )
    scope_payload = {
        "schema": "java-upgrade-analyzer.step5-selection.v1",
        "mode": effective_scope_mode,
        "selection_basis": "explicit_targets" if has_selection else "all_targets",
        "selected_coords": list(selection_summary.get("selected_coords") or []),
        "selected_names": list(selection_summary.get("selected_names") or []),
        "included_dependency_coords": included_coords,
        "excluded_dependency_coords": [coord for coord in all_coords if coord not in included_coord_set],
        "available_dependency_count": len(all_coords),
        "included_dependency_count": len(included_coords),
        "total_api_count": len(all_rows),
        "analyzed_api_count": len(selection_summary.get("matched_rows") or []),
    }
    write_json(runtime_cache_dir(report_dir) / "step5_selection.json", scope_payload)
    return base_path, selection_summary


def flatten_cli_values(raw_values):
    """兼容 argparse 的单次多值和重复传参两种形式。"""
    flattened = []
    for item in raw_values or []:
        if isinstance(item, (list, tuple)):
            candidates = item
        else:
            candidates = [item]
        for candidate in candidates:
            text = str(candidate or "").strip()
            if text:
                flattened.append(text)
    return flattened


def parse_positive_int_like(value, field_name):
    if isinstance(value, bool):
        raise StepError(f"{field_name} 必须是正整数")
    if isinstance(value, int):
        if value <= 0:
            raise StepError(f"{field_name} 必须大于 0")
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit() and int(text) > 0:
            return int(text)
    raise StepError(f"{field_name} 必须是正整数")


def _validate_coord_or_prefix_or_empty(coord, _config_key):
    coord = (coord or "").strip()
    if not coord:
        return ""
    return coord


def _filter_inferred_coords_by_prefix(inferred_coords, coord_prefix):
    coord_prefix = (coord_prefix or "").strip()
    if not coord_prefix:
        return list(inferred_coords or [])
    if ":" in coord_prefix:
        return [item for item in (inferred_coords or []) if item == coord_prefix]
    return [item for item in (inferred_coords or []) if item.startswith(coord_prefix + ":")]


def _split_coord(coord):
    value = (coord or "").strip()
    if not value:
        return "", ""
    if ":" not in value:
        return value, ""
    group_id, artifact_id = value.split(":", 1)
    return group_id.strip(), artifact_id.strip()


def _norm_token(value):
    return "".join(ch for ch in (value or "").strip().lower() if ch.isalnum())


def _filter_inferred_coords_by_hint(inferred_coords, coord_hint, normalized_path):
    inferred_coords = list(inferred_coords or [])
    direct = _filter_inferred_coords_by_prefix(inferred_coords, coord_hint)
    if direct:
        return direct
    if len(inferred_coords) == 1:
        return inferred_coords

    _, artifact_hint = _split_coord(coord_hint)
    artifact_hint_norm = _norm_token(artifact_hint)
    path_name_norm = _norm_token(Path(normalized_path).name)

    artifact_matches = []
    if artifact_hint_norm:
        artifact_matches = [
            item for item in inferred_coords
            if _norm_token(_split_coord(item)[1]) == artifact_hint_norm
        ]
        if len(artifact_matches) == 1:
            return artifact_matches

    if path_name_norm:
        path_matches = [
            item for item in inferred_coords
            if _norm_token(_split_coord(item)[1]) == path_name_norm
        ]
        if len(path_matches) == 1:
            return path_matches

    combined = []
    for item in inferred_coords:
        artifact_norm = _norm_token(_split_coord(item)[1])
        if artifact_hint_norm and artifact_hint_norm in artifact_norm:
            combined.append(item)
        elif path_name_norm and path_name_norm in artifact_norm:
            combined.append(item)
    return combined if len(combined) == 1 else []


def _current_dependency_repo_mapping_map(run_context):
    mapping = {}
    for item in (run_context or {}).get("dependency_repo_mappings", []) or []:
        value = str(item or "").strip()
        if "=" not in value:
            continue
        coord, repo_path = value.split("=", 1)
        coord = coord.strip()
        repo_path = repo_path.strip()
        if coord and repo_path:
            mapping[coord] = repo_path
    return mapping


def build_dependency_repo_mapping_suggestions(run_context, ctx):
    hints = list((run_context or {}).get("source_repo_hints") or [])
    current_mapping = _current_dependency_repo_mapping_map(run_context)
    target_coords = _collect_focus_dependency_coords(
        (run_context or {}).get("report_dir") or "",
        ctx=ctx,
    )

    result = {
        "targets": target_coords,
        "confirmed": [],
        "proposed": [],
        "ambiguous": [],
        "unmatched": [],
        "hints": hints,
    }
    if not target_coords:
        return result

    for coord in target_coords:
        if current_mapping.get(coord):
            result["confirmed"].append(
                {
                    "coord": coord,
                    "repo_path": current_mapping[coord],
                    "confidence": "confirmed",
                    "reason": "已存在于当前自动识别结果",
                }
            )
            continue

        candidates = []
        for hint in hints:
            repo_path = str(hint.get("repo_path") or "").strip()
            inferred_coords = [item for item in (hint.get("repo_inferred_coords") or []) if item]
            if coord in inferred_coords:
                candidates.append(
                    {
                        "coord": coord,
                        "repo_path": repo_path,
                        "confidence": "high",
                        "reason": "仓库模块与升级依赖坐标准确命中",
                        "hint_coord": str(hint.get("coord_hint") or "").strip(),
                    }
                )
                continue

            matched_from_hint = _filter_inferred_coords_by_hint(
                inferred_coords,
                hint.get("coord_hint") or coord,
                repo_path,
            )
            if coord in matched_from_hint:
                candidates.append(
                    {
                        "coord": coord,
                        "repo_path": repo_path,
                        "confidence": "medium",
                        "reason": "仓库模块经坐标提示收敛后命中升级依赖",
                        "hint_coord": str(hint.get("coord_hint") or "").strip(),
                    }
                )

        unique_candidates = []
        seen_pairs = set()
        for item in candidates:
            pair = (item["coord"], item["repo_path"])
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            unique_candidates.append(item)

        if len(unique_candidates) == 1:
            result["proposed"].append(unique_candidates[0])
        elif len(unique_candidates) > 1:
            result["ambiguous"].append(
                {
                    "coord": coord,
                    "candidates": unique_candidates,
                }
            )
        else:
            result["unmatched"].append(coord)
    return result


def suggested_dependency_repo_mappings(suggestions):
    values = []
    for item in (suggestions or {}).get("proposed", []) or []:
        coord = str(item.get("coord") or "").strip()
        repo_path = str(item.get("repo_path") or "").strip()
        if coord and repo_path:
            values.append(f"{coord}={repo_path}")
    return _dedupe_strings(values)


def suggested_dependency_source_dirs(suggestions):
    dirs = []
    for bucket in ("confirmed", "proposed"):
        for item in (suggestions or {}).get(bucket, []) or []:
            repo_path = str(item.get("repo_path") or "").strip()
            if repo_path:
                dirs.append(resolve_repo_input_path(os.path.expanduser(repo_path)))
    return _dedupe_strings(dirs)


def _normalized_repo_key(repo_path):
    value = str(repo_path or "").strip()
    if not value:
        return ""
    try:
        return str(Path(value).expanduser().resolve())
    except Exception:
        return value


def build_step2_source_mapping_summary(run_context, ctx):
    runtime_view = dict(run_context or {})
    source_dirs = _dedupe_strings(
        runtime_view.get("source_dirs") or (ctx or {}).get("source_dirs") or []
    )
    source_dirs_status = str(runtime_view.get("source_dirs_status") or "").strip()
    if not source_dirs_status:
        source_dirs_status = "context_detected" if source_dirs else "unknown"
    dependency_source_dirs = _dedupe_strings(runtime_view.get("dependency_source_dirs") or [])
    target_coords = _collect_focus_dependency_coords(runtime_view.get("report_dir") or "", ctx=ctx)
    relevant_coords = _collect_relevant_dependency_coords(runtime_view.get("report_dir") or "", ctx=ctx)
    plan = _build_dependency_source_plan(
        dependency_source_dirs,
        relevant_coords=relevant_coords or target_coords,
    )
    discovered_candidates = list(plan.get("candidates") or [])

    current_mapping = _current_dependency_repo_mapping_map(runtime_view)
    current_mapping_by_repo = {}
    for coord, repo_path in current_mapping.items():
        repo_key = _normalized_repo_key(repo_path)
        current_mapping_by_repo.setdefault(repo_key, []).append(coord)

    detected_dependency_repo_mappings = _dedupe_strings(
        [
            f"{item.get('coord')}={item.get('repo_path')}"
            for item in discovered_candidates
            if item.get("coord") and item.get("repo_path")
        ]
    )
    detected_dependency_source_mappings = _dedupe_strings(
        [
            f"{item.get('coord')}={item.get('source_dir')}"
            for item in discovered_candidates
            if item.get("coord") and item.get("source_dir")
        ]
    )
    ambiguous_coords = list(plan.get("ambiguous_coords") or [])
    repo_scans = []
    for repo_path in dependency_source_dirs:
        repo_key = _normalized_repo_key(repo_path)
        repo_candidates = [
            item for item in discovered_candidates
            if _normalized_repo_key(item.get("repo_path")) == repo_key
        ]
        inferred_coords = _dedupe_strings([str(item.get("coord") or "").strip() for item in repo_candidates if item.get("coord")])
        matched_target_coords = [coord for coord in target_coords if coord in inferred_coords]
        mapped_dependency_coords = [
            coord for coord in (current_mapping_by_repo.get(repo_key) or [])
            if coord in target_coords
        ]
        other_inferred_coords = [coord for coord in inferred_coords if coord not in target_coords]
        discovered_modules = []
        module_seen = set()
        for item in repo_candidates:
            module_root = str(item.get("module_root") or "").strip()
            coord = str(item.get("coord") or "").strip()
            source_dir = str(item.get("source_dir") or "").strip()
            if not module_root and not source_dir and not coord:
                continue
            key = (module_root, source_dir, coord)
            if key in module_seen:
                continue
            module_seen.add(key)
            discovered_modules.append(
                {
                    "coord": coord,
                    "module_root": module_root,
                    "source_dir": source_dir,
                    "discovery_mode": str(item.get("discovery_mode") or "").strip(),
                }
            )
        if mapped_dependency_coords:
            status = "mapped_dependency_repo"
        elif matched_target_coords:
            status = "matched_target_not_applied"
        elif inferred_coords:
            status = "inferred_non_target_only"
        else:
            status = "no_coords_inferred"
        repo_scans.append(
            {
                "repo_path": repo_path,
                "status": status,
                "inferred_coords": inferred_coords,
                "matched_target_coords": matched_target_coords,
                "mapped_dependency_coords": mapped_dependency_coords,
                "other_inferred_coords": other_inferred_coords,
                    "discovered_modules": discovered_modules,
            }
        )

    confirmed_target_mappings = []
    unmapped_target_coords = []
    for coord in target_coords:
        repo_path = current_mapping.get(coord)
        if repo_path:
            confirmed_target_mappings.append({"coord": coord, "repo_path": repo_path})
        else:
            unmapped_target_coords.append(coord)

    suggestions = build_dependency_repo_mapping_suggestions(runtime_view, ctx)
    return {
        "source_dirs": source_dirs,
        "source_dirs_status": source_dirs_status,
        "dependency_source_dirs": dependency_source_dirs,
        "target_dependency_coords": target_coords,
        "current_confirmed_repo_matches": _dedupe_strings(runtime_view.get("dependency_repo_mappings") or []),
        "confirmed_target_mappings": confirmed_target_mappings,
        "unmapped_target_coords": unmapped_target_coords,
        "detected_repo_matches": detected_dependency_repo_mappings,
        "detected_source_matches": detected_dependency_source_mappings,
        "detected_candidates": discovered_candidates,
        "ambiguous_coords": ambiguous_coords,
        "unmatched_relevant_coords": list(plan.get("unmatched_relevant_coords") or []),
        "dependency_repo_scans": repo_scans,
        "source_repo_hint_suggestions": suggestions,
        "suggested_repo_matches": suggested_dependency_repo_mappings(suggestions),
        "counts": {
            "source_dirs": len(source_dirs),
            "dependency_source_dirs": len(dependency_source_dirs),
            "target_dependency_coords": len(target_coords),
            "current_confirmed_repo_matches": len(_dedupe_strings(runtime_view.get("dependency_repo_mappings") or [])),
            "confirmed_target_mappings": len(confirmed_target_mappings),
            "unmapped_target_coords": len(unmapped_target_coords),
            "detected_repo_matches": len(detected_dependency_repo_mappings),
            "detected_source_matches": len(detected_dependency_source_mappings),
            "ambiguous_coords": len(ambiguous_coords),
        },
    }


def write_step2_source_mapping_summary(report_dir, run_context, ctx):
    summary = build_step2_source_mapping_summary(run_context, ctx)
    output_path = step2_source_mapping_summary_path(report_dir)
    write_json(output_path, summary)
    return output_path, summary


def write_step2_review(report_dir, ctx, mapping_summary, runtime_view=None):
    output_path = evidence_context_dir(report_dir) / "review.md"
    counts = dict((mapping_summary or {}).get("counts") or {})
    source_dirs = list((mapping_summary or {}).get("source_dirs") or [])
    mapped = list((mapping_summary or {}).get("confirmed_target_mappings") or [])
    unmapped = list((mapping_summary or {}).get("unmapped_target_coords") or [])
    runtime_view = runtime_view or {}
    target_module = (
        runtime_view.get("target_module")
        or runtime_view.get("primary_module")
        or ctx.get("target_module")
        or ctx.get("primary_module")
        or "未指定"
    )
    lines = [
        "# 升级上下文确认",
        "",
        "本文件回答：本次升级分析使用了什么范围和版本信息。",
        "",
        "## 分析范围",
        "",
        "| 项目 | 当前识别结果 |",
        "|---|---|",
        f"| 目标模块 | `{target_module}` |",
        f"| 比较版本 | `{ctx.get('base_branch') or '未识别'}` → `{ctx.get('current_branch') or '未识别'}` |",
        f"| JDK | {ctx.get('jdk_base') or '未识别'} → {ctx.get('jdk_current') or '未识别'} |",
        f"| Spring Boot | {ctx.get('springboot_base') or '未识别'} → {ctx.get('springboot_current') or '未识别'} |",
        f"| 发生变化的依赖包 | {len(ctx.get('changed_dependencies') or [])} 个 |",
        f"| 业务源码目录 | {len(source_dirs)} 个 |",
        f"| 已匹配依赖源码 | {counts.get('confirmed_target_mappings', len(mapped))} / {counts.get('target_dependency_coords', 0)} 个目标依赖 |",
    ]
    if source_dirs:
        lines.extend(["", "## 业务源码范围", ""])
        lines.extend(f"- `{item}`" for item in source_dirs)
    if mapped:
        lines.extend(["", "## 已匹配的依赖源码", "", "| 依赖包 | 源码目录 |", "|---|---|"])
        for item in mapped:
            lines.append(f"| `{item.get('coord') or '-'}` | `{item.get('repo_path') or '-'}` |")
    if unmapped:
        lines.extend(["", "## 尚未匹配源码的依赖包", ""])
        lines.extend(f"- `{item}`" for item in unmapped)
    lines.extend(
        [
            "",
            "完整结构化证据保存在同目录的 `context.json`、`dep_graph.json` 和 `source_mapping_summary.json`。",
        ]
    )
    _write_text_file(output_path, "\n".join(lines))
    return output_path


def build_step2_confirmation_requirements(ctx, mapping_summary, runtime_view=None):
    """Return only facts that cannot be accepted safely from generated evidence."""
    ctx = dict(ctx or {})
    mapping_summary = dict(mapping_summary or {})
    runtime_view = dict(runtime_view or {})
    reasons = []
    required_fields = []

    if not str(ctx.get("jdk_base") or "").strip() or str(ctx.get("jdk_base") or "").strip() == "unknown":
        reasons.append("未能自动识别升级前 JDK 版本")
        required_fields.append("jdk_base")
    if not str(ctx.get("jdk_current") or "").strip() or str(ctx.get("jdk_current") or "").strip() == "unknown":
        reasons.append("未能自动识别升级后 JDK 版本")
        required_fields.append("jdk_current")

    source_dirs = list(mapping_summary.get("source_dirs") or runtime_view.get("source_dirs") or [])
    source_dirs_status = str(mapping_summary.get("source_dirs_status") or "missing").strip()
    if not source_dirs or source_dirs_status == "missing":
        reasons.append("未能确定业务源码范围")
        required_fields.append("source_dirs")

    ambiguous_coords = list(mapping_summary.get("ambiguous_coords") or [])
    if ambiguous_coords:
        preview = "、".join(
            str((item or {}).get("coord") or "").strip()
            for item in ambiguous_coords[:5]
            if str((item or {}).get("coord") or "").strip()
        )
        reasons.append(
            "依赖源码存在坐标歧义" + (f"（{preview}）" if preview else "")
        )
        required_fields.append("dependency_repo_mappings")

    suggestions = dict(mapping_summary.get("source_repo_hint_suggestions") or {})
    suggestion_decision_recorded = "accept_suggested_mappings" in runtime_view
    proposed_mappings = (
        []
        if suggestion_decision_recorded
        else list(suggestions.get("proposed") or [])
    )
    if proposed_mappings:
        reasons.append(
            f"源码线索生成了 {len(proposed_mappings)} 条尚未确认的依赖源码映射建议"
        )
        # Both true and false are meaningful answers: accepting the mapping
        # improves source-behaviour coverage, while declining keeps the JAR-only
        # evidence boundary.  Do not silently choose either result for the user.
        required_fields.append("accept_suggested_mappings")

    return {
        "required": bool(reasons),
        "reason_code": (
            "step2_source_mapping_decision_required"
            if proposed_mappings and len(reasons) == 1
            else ("step2_context_facts_unresolved" if reasons else "")
        ),
        "reasons": reasons,
        "required_fields": _dedupe_strings(required_fields),
        "proposed_mappings": proposed_mappings,
    }


def _expand_coord_path_by_repo(coord, normalized_path, config_key, expand_all_inferred=False):
    inferred_coords = [item for item in infer_maven_coords(normalized_path) if item]
    coord = _validate_coord_or_prefix_or_empty(coord, config_key)
    if inferred_coords:
        if expand_all_inferred:
            return _dedupe_strings([f"{item}={normalized_path}" for item in inferred_coords])
        filtered_coords = _filter_inferred_coords_by_hint(inferred_coords, coord, normalized_path)
        if coord and filtered_coords:
            return _dedupe_strings([f"{item}={normalized_path}" for item in filtered_coords])
        if coord and not filtered_coords:
            raise StepError(
                f"当前步骤输入中的 {config_key} 里，coord={coord} 未能在源码仓库中匹配到实际模块坐标：{normalized_path}。"
                f"仓库内推断出的坐标有：{', '.join(inferred_coords[:10]) or '(无)'}"
            )
        return _dedupe_strings([f"{item}={normalized_path}" for item in inferred_coords])
    if coord and ":" in coord:
        return [f"{coord}={normalized_path}"]
    if coord:
        raise StepError(
            f"当前步骤输入中的 {config_key} 里，coord={coord} 无法映射到源码仓库：{normalized_path}。"
            f"请提供正确的源码仓库路径，或改为完整 Maven 坐标 groupId:artifactId=path。"
        )
    raise StepError(
        f"当前步骤输入中的 {config_key} 未提供 coord，且无法从源码仓库推断模块坐标：{normalized_path}"
    )


def normalize_coord_path_items(
    raw_value,
    project_dir,
    config_key,
    allow_repo_inference=False,
    expand_all_inferred=False,
):
    if raw_value in (None, ""):
        return None
    items = []
    if isinstance(raw_value, dict):
        iterable = [{"coord": k, "path": v} for k, v in raw_value.items()]
    elif isinstance(raw_value, list):
        iterable = raw_value
    else:
        raise StepError(f"当前步骤输入中的 {config_key} 仅支持列表或字典")

    for item in iterable:
        coord = ""
        if isinstance(item, str):
            if "=" not in item:
                if not allow_repo_inference:
                    raise StepError(
                        f"当前步骤输入中的 {config_key} 字符串项格式错误，需为 groupId:artifactId=path"
                    )
                coord = ""
                path_value = item
            else:
                coord, path_value = item.split("=", 1)
        elif isinstance(item, dict):
            coord = (item.get("coord") or item.get("owner_coord") or "").strip()
            path_value = (
                item.get("path")
                or item.get("root")
                or item.get("repo_path")
                or item.get("git_path")
                or item.get("repo")
                or item.get("local_path")
                or ""
            ).strip()
            if not path_value:
                raise StepError(
                    f"当前步骤输入中的 {config_key} 对象项需包含 path 字段"
                )
            if (not coord) and (not allow_repo_inference):
                raise StepError(
                    f"当前步骤输入中的 {config_key} 对象项需包含 coord 与 path 字段"
                )
        else:
            raise StepError(f"当前步骤输入中的 {config_key} 存在不支持的项类型")
        if looks_like_remote_repo(path_value) and not Path(path_value).expanduser().exists():
            raise StepError(
                f"当前步骤输入中的 {config_key} 当前只支持本地已检出的源码仓库路径，"
                f"暂不支持直接传远程 git 地址：{path_value}"
            )
        normalized_path = absolutize_path(path_value, project_dir)
        normalized_path = resolve_repo_input_path(normalized_path)
        coord = _validate_coord_or_prefix_or_empty(coord, config_key)
        if allow_repo_inference and (expand_all_inferred or not coord or ":" not in coord):
            items.extend(
                _expand_coord_path_by_repo(
                    coord,
                    normalized_path,
                    config_key,
                    expand_all_inferred=expand_all_inferred,
                )
            )
            continue
        items.append(f"{coord}={normalized_path}")
    return _dedupe_strings(items)


def _split_dependency_repo_mapping_value(value):
    raw = str(value or "").strip()
    if not raw:
        return "", ""
    if "=" not in raw:
        return "", raw
    coord_hint, repo_path = raw.split("=", 1)
    return coord_hint.strip(), repo_path.strip()


def _matching_repo_mappings_from_source_plan(coord_hint, repo_path, derived_repo_mappings):
    matches = []
    repo_path = str(repo_path or "").strip()
    coord_hint = str(coord_hint or "").strip()
    for candidate in (derived_repo_mappings or []):
        candidate_coord, candidate_repo_path = _split_dependency_repo_mapping_value(candidate)
        if not candidate_coord or not candidate_repo_path or candidate_repo_path != repo_path:
            continue
        if coord_hint:
            if ":" in coord_hint and candidate_coord != coord_hint:
                continue
            if ":" not in coord_hint and not candidate_coord.startswith(coord_hint + ":"):
                continue
        matches.append(f"{candidate_coord}={candidate_repo_path}")
    return _dedupe_strings(matches)


def load_seed_json_arg(raw_value, project_dir):
    value = str(raw_value or "").strip()
    if not value:
        return {}
    candidate_path = Path(value).expanduser()
    if not candidate_path.is_absolute():
        candidate_path = (Path(project_dir) / candidate_path).resolve()
    if candidate_path.exists():
        payload = read_json(candidate_path)
    else:
        try:
            payload = json.loads(value)
        except Exception as exc:
            raise StepError(f"--seed-json 既不是可读取的文件，也不是合法 JSON：{exc}") from exc
    if not isinstance(payload, dict):
        raise StepError("--seed-json 必须是 JSON 对象")
    return payload


def build_run_context(args, existing, seed_payload, allow_external_seed=True):
    previous = dict(existing or {})
    seed_input = dict(seed_payload or {}) if allow_external_seed else {}
    if "analysis_mode" in previous:
        previous["analysis_mode"] = normalize_analysis_mode(previous.get("analysis_mode"), allow_empty=True)
    if "analysis_mode" in seed_input:
        seed_input["analysis_mode"] = normalize_analysis_mode(seed_input.get("analysis_mode"), allow_empty=True)
    merged = {**seed_input, **previous}
    merged = apply_explicit_step1_mode_selection(merged)
    project_dir = Path(args.project_dir).resolve()
    detected_current_branch = detect_current_branch(project_dir)
    _ = detect_base_branch(project_dir, detected_current_branch)
    detected_tool = detect_build_tool(project_dir)
    cli_scalar = (lambda value: value) if allow_external_seed else (lambda _value: None)
    cli_list = (lambda value: value) if allow_external_seed else (lambda _value: [])
    artifact_input_mode = bool(
        resolve_value(cli_scalar(args.base_artifact_path), merged, "base_artifact_path", "")
        or resolve_value(cli_scalar(args.current_artifact_path), merged, "current_artifact_path", "")
    )
    manual_coord_overrides = _dedupe_strings(
        resolve_value(cli_list(getattr(args, "manual_coord_overrides", [])), merged, "manual_coord_overrides", []) or []
    )
    allow_unresolved = resolve_value(cli_scalar(getattr(args, "allow_unresolved", None)), merged, "allow_unresolved", False)
    allow_unresolved = parse_bool_like(allow_unresolved, "allow_unresolved")
    confirmed_unresolved_items = list(resolve_value(None, merged, "confirmed_unresolved_items", []) or [])
    base_branch_explicit = _has_explicit_string_value(cli_scalar(args.base_branch), seed_input, previous, "base_branch")
    current_branch_explicit = _has_explicit_string_value(cli_scalar(args.current_branch), seed_input, previous, "current_branch")
    # Branches are analysis inputs, not safe defaults.
    # Keep auto-detection out of the formal run context unless the user/runtime
    # explicitly provided them in a previous confirmed step.
    default_base_branch = ""
    default_current_branch = ""
    result = {
        "project_dir": str(project_dir),
        "report_dir": str(Path(args.report_dir).resolve()),
        "base_branch": _resolve_branch_value_for_run_context(
            cli_scalar(args.base_branch),
            merged,
            "base_branch",
            default_base_branch,
            base_branch_explicit,
        ),
        "current_branch": _resolve_branch_value_for_run_context(
            cli_scalar(args.current_branch),
            merged,
            "current_branch",
            default_current_branch,
            current_branch_explicit,
        ),
        "jdk_base": resolve_value(None, merged, "jdk_base", ""),
        "jdk_current": resolve_value(None, merged, "jdk_current", ""),
        "springboot_base": resolve_value(None, merged, "springboot_base", ""),
        "springboot_current": resolve_value(None, merged, "springboot_current", ""),
        "base_requested_ref": resolve_value(None, merged, "base_requested_ref", ""),
        "base_resolved_ref": resolve_value(None, merged, "base_resolved_ref", ""),
        "base_resolved_commit": resolve_value(None, merged, "base_resolved_commit", ""),
        "base_expected_commit": resolve_value(None, merged, "base_expected_commit", ""),
        "base_ref_resolution_mode": resolve_value(None, merged, "base_ref_resolution_mode", ""),
        "base_ref_resolution_fingerprint": resolve_value(
            None, merged, "base_ref_resolution_fingerprint", "",
        ),
        "base_ref_candidate_count": resolve_value(None, merged, "base_ref_candidate_count", 0),
        "base_ref_source_status": resolve_value(None, merged, "base_ref_source_status", ""),
        "base_allow_local_source": (
            parse_bool_like(merged.get("base_allow_local_source"), "base_allow_local_source")
            if "base_allow_local_source" in merged else False
        ),
        "base_allow_dirty_local_source": (
            parse_bool_like(merged.get("base_allow_dirty_local_source"), "base_allow_dirty_local_source")
            if "base_allow_dirty_local_source" in merged else False
        ),
        "current_requested_ref": resolve_value(None, merged, "current_requested_ref", ""),
        "current_resolved_ref": resolve_value(None, merged, "current_resolved_ref", ""),
        "current_resolved_commit": resolve_value(None, merged, "current_resolved_commit", ""),
        "current_expected_commit": resolve_value(None, merged, "current_expected_commit", ""),
        "current_ref_resolution_mode": resolve_value(None, merged, "current_ref_resolution_mode", ""),
        "current_ref_resolution_fingerprint": resolve_value(
            None, merged, "current_ref_resolution_fingerprint", "",
        ),
        "current_ref_candidate_count": resolve_value(None, merged, "current_ref_candidate_count", 0),
        "current_ref_source_status": resolve_value(None, merged, "current_ref_source_status", ""),
        "current_allow_local_source": (
            parse_bool_like(merged.get("current_allow_local_source"), "current_allow_local_source")
            if "current_allow_local_source" in merged else False
        ),
        "current_allow_dirty_local_source": (
            parse_bool_like(merged.get("current_allow_dirty_local_source"), "current_allow_dirty_local_source")
            if "current_allow_dirty_local_source" in merged else False
        ),
        "modules": resolve_value(cli_list(args.modules), merged, "modules", []),
        "active_maven_profiles": resolve_value(
            cli_list(getattr(args, "active_maven_profiles", None)),
            merged,
            "active_maven_profiles",
            [],
        ),
        "source_dirs": resolve_value(cli_list(args.source_dirs), merged, "source_dirs"),
        "dependency_source_dirs": resolve_value(cli_list(args.dependency_source_dirs), merged, "dependency_source_dirs", []),
        "dependency_source_git_urls": resolve_value(
            None,
            merged,
            "dependency_source_git_urls",
            [],
        ),
        "dependency_source_mappings": resolve_value(
            cli_list(args.dependency_source_mappings),
            merged,
            "dependency_source_mappings",
            [],
        ),
        "source_repo_hints": resolve_value(cli_list(args.source_repo_hints), merged, "source_repo_hints", []),
        "dependency_repo_mappings": resolve_value(cli_list(args.dependency_repo_mappings), merged, "dependency_repo_mappings", []),
        "dependency_git_ref_overrides": resolve_value(
            cli_scalar(getattr(args, "dependency_git_ref_overrides_json", "")),
            merged,
            "dependency_git_ref_overrides",
            [],
        ),
        "step5_selected_coords": resolve_value(None, merged, "step5_selected_coords", []),
        "step5_selected_names": resolve_value(None, merged, "step5_selected_names", []),
        "include_test_scope": (
            parse_bool_like(merged.get("include_test_scope"), "include_test_scope")
            if "include_test_scope" in merged
            else bool(args.include_test_scope if allow_external_seed else False)
        ),
        "max_depth": (
            merged.get("max_depth")
            if "max_depth" in merged
            else args.max_depth
        ),
        "tool": resolve_value(cli_scalar(args.tool), merged, "tool", detected_tool),
        "allow_degraded": (
            parse_bool_like(merged.get("allow_degraded"), "allow_degraded")
            if "allow_degraded" in merged
            else bool(args.allow_degraded if allow_external_seed else False)
        ),
        "strict_risk_gate": (
            parse_bool_like(merged.get("strict_risk_gate"), "strict_risk_gate")
            if "strict_risk_gate" in merged
            else bool(args.strict_risk_gate if allow_external_seed else False)
        ),
        "japicmp_jar": resolve_value(cli_scalar(args.japicmp_jar), merged, "japicmp_jar", ""),
        "step4_git_diff_timeout": resolve_value(
            cli_scalar(getattr(args, "step4_git_diff_timeout", None)),
            merged,
            "step4_git_diff_timeout",
            None,
        ),
        "step4_japicmp_timeout": resolve_value(
            cli_scalar(getattr(args, "step4_japicmp_timeout", None)),
            merged,
            "step4_japicmp_timeout",
            None,
        ),
        "step4_fetch_timeout": resolve_value(
            cli_scalar(getattr(args, "step4_fetch_timeout", None)),
            merged,
            "step4_fetch_timeout",
            None,
        ),
        "step4_tool_install_timeout": resolve_value(
            cli_scalar(getattr(args, "step4_tool_install_timeout", None)),
            merged,
            "step4_tool_install_timeout",
            None,
        ),
        "step4_workers": resolve_value(
            cli_scalar(getattr(args, "step4_workers", None)),
            merged,
            "step4_workers",
            None,
        ),
        "step5_timeout": resolve_value(
            cli_scalar(getattr(args, "step5_timeout", None)),
            merged,
            "step5_timeout",
            None,
        ),
        "analysis_mode": normalize_analysis_mode(merged.get("analysis_mode"), allow_empty=True),
        "base_artifact_path": resolve_value(cli_scalar(args.base_artifact_path), merged, "base_artifact_path", ""),
        "current_artifact_path": resolve_value(cli_scalar(args.current_artifact_path), merged, "current_artifact_path", ""),
        "base_source_project_dir": resolve_value(cli_scalar(args.base_source_project_dir), merged, "base_source_project_dir", ""),
        "current_source_project_dir": resolve_value(
            cli_scalar(args.current_source_project_dir),
            merged,
            "current_source_project_dir",
            "",
        ),
        "base_jdk_home": resolve_value(cli_scalar(args.base_jdk_home), merged, "base_jdk_home", ""),
        "current_jdk_home": resolve_value(cli_scalar(args.current_jdk_home), merged, "current_jdk_home", ""),
        "target_module": resolve_value(
            cli_scalar(getattr(args, "target_module", "")),
            merged,
            "target_module",
            resolve_value(cli_scalar(args.primary_module), merged, "primary_module", ""),
        ),
        "primary_module": resolve_value(cli_scalar(args.primary_module), merged, "primary_module", ""),
        "manual_coord_overrides": manual_coord_overrides,
        "allow_unresolved": allow_unresolved,
        "confirmed_unresolved_items": confirmed_unresolved_items,
        "artifact_input_mode": artifact_input_mode,
        "base_branch_explicit": base_branch_explicit,
        "current_branch_explicit": current_branch_explicit,
    }
    if "accept_suggested_mappings" in merged:
        result["accept_suggested_mappings"] = parse_bool_like(
            merged.get("accept_suggested_mappings"),
            "accept_suggested_mappings",
        )
    result.update(infer_step1_mode_fields(result))
    for path_key in (
        "base_artifact_path",
        "current_artifact_path",
        "base_source_project_dir",
        "current_source_project_dir",
        "base_jdk_home",
        "current_jdk_home",
    ):
        path_value = result.get(path_key)
        if isinstance(path_value, str) and path_value.strip():
            result[path_key] = absolutize_path(path_value.strip(), project_dir)
    dependency_source_inputs = normalize_dependency_source_dirs(
        result.get("dependency_source_dirs"),
        project_dir,
        "dependency_source_dirs",
    ) or []
    remembered_git_urls = normalize_dependency_source_dirs(
        result.get("dependency_source_git_urls"),
        project_dir,
        "dependency_source_git_urls",
    ) or []
    dependency_source_inputs = _dedupe_strings(
        dependency_source_inputs + remembered_git_urls
    )
    clone_timeout_value = result.get("step4_fetch_timeout")
    clone_timeout = (
        parse_positive_int_like(clone_timeout_value, "step4_fetch_timeout")
        if clone_timeout_value not in (None, "")
        else 300
    )
    dependency_source_materialization = materialize_dependency_source_inputs(
        dependency_source_inputs,
        project_dir,
        result["report_dir"],
        clone_timeout=clone_timeout,
    )
    dependency_source_dirs = list(
        dependency_source_materialization.get("dependency_source_dirs") or []
    )
    result.update(dependency_source_materialization)
    result["dependency_repo_mappings"] = normalize_dependency_repo_mappings(
        result.get("dependency_repo_mappings"),
        project_dir,
        "dependency_repo_mappings",
    ) or []
    result["dependency_source_mappings"] = normalize_dependency_source_mappings(
        result.get("dependency_source_mappings"),
        project_dir,
        "dependency_source_mappings",
    ) or []
    result["dependency_git_ref_overrides"] = normalize_dependency_git_ref_overrides(
        result.get("dependency_git_ref_overrides"),
        "dependency_git_ref_overrides",
    ) or []
    result["step5_selected_coords"] = normalize_step5_target_list(
        result.get("step5_selected_coords"),
        "step5_selected_coords",
    ) or []
    result["step5_selected_names"] = normalize_step5_target_list(
        result.get("step5_selected_names"),
        "step5_selected_names",
    ) or []
    for timeout_key in (
        "step4_git_diff_timeout",
        "step4_japicmp_timeout",
        "step4_fetch_timeout",
        "step4_tool_install_timeout",
        "step4_workers",
        "step5_timeout",
    ):
        value = result.get(timeout_key)
        if value not in (None, ""):
            result[timeout_key] = parse_positive_int_like(value, timeout_key)
        else:
            result[timeout_key] = None
    modules_value = normalize_modules_value(result.get("modules")) or []
    result["modules"] = modules_value
    result["active_maven_profiles"] = _dedupe_strings(
        result.get("active_maven_profiles") or []
    )
    # CLI/seed values may use the convenient string form while checkpoint
    # replies already carry structured hint objects.  Keep one invariant for
    # all downstream mapping logic so an internal representation mismatch can
    # never escape as an AttributeError to the user.
    result["source_repo_hints"] = normalize_source_repo_hints(
        result.get("source_repo_hints"),
        project_dir,
        "source_repo_hints",
    ) or []
    if result.get("target_module"):
        result["primary_module"] = result["target_module"]
        result["modules"] = [result["target_module"]]
    if not result.get("primary_module") and len(modules_value) == 1:
        result["primary_module"] = modules_value[0]
        result["target_module"] = modules_value[0]
    if result.get("primary_module") and not result.get("target_module"):
        result["target_module"] = result["primary_module"]
    if result.get("target_module"):
        result["project_scope"] = build_project_scope(
            project_dir,
            result["target_module"],
            active_profiles=set(result["active_maven_profiles"]),
            build_tool=result.get("tool", ""),
        )
    else:
        discovery = discover_project_modules(
            project_dir, build_tool=result.get("tool", "")
        )
        result["project_scope"] = {
            "schema": "java-upgrade-analyzer.project-scope.v1",
            "status": "insufficient",
            "reason_codes": ["target_module_unconfirmed"],
            "target_module": "",
            "candidate_modules": [item.get("module") for item in discovery.get("modules") or []],
            "candidate_module_details": list(discovery.get("modules") or []),
            "included_modules": [],
            "source_roots": [],
            "resource_roots": [],
        }
    source_dir_plan = _resolve_source_dirs_plan(
        project_dir,
        source_dirs=result.get("source_dirs"),
        modules=result.get("modules"),
        project_scope=result.get("project_scope"),
    )
    result["source_dirs"] = list(source_dir_plan.get("source_dirs") or [])
    result["source_dirs_status"] = source_dir_plan.get("status") or "missing"
    source_plan_input_dirs = list(dependency_source_dirs)
    for item in list(result.get("dependency_repo_mappings") or []):
        coord_hint, repo_path = _split_dependency_repo_mapping_value(item)
        if not repo_path:
            continue
        if coord_hint and ":" in coord_hint:
            continue
        source_plan_input_dirs.append(repo_path)
    source_plan_input_dirs = _dedupe_strings(source_plan_input_dirs)
    if source_plan_input_dirs:
        relevant_coords = _collect_relevant_dependency_coords(result["report_dir"])
        source_plan = _build_dependency_source_plan(
            source_plan_input_dirs,
            relevant_coords=relevant_coords,
        )
        result["dependency_source_mapping_conflicts"] = list(source_plan.get("ambiguous_coords") or [])
        derived_repo_mappings = list(source_plan.get("dependency_repo_mappings") or [])
        resolved_existing_repo_mappings = []
        for item in list(result.get("dependency_repo_mappings") or []):
            coord_hint, repo_path = _split_dependency_repo_mapping_value(item)
            if not repo_path:
                continue
            if coord_hint and ":" in coord_hint:
                resolved_existing_repo_mappings.append(f"{coord_hint}={repo_path}")
                continue
            replacements = _matching_repo_mappings_from_source_plan(
                coord_hint,
                repo_path,
                derived_repo_mappings,
            )
            if replacements:
                resolved_existing_repo_mappings.extend(replacements)
        result["dependency_repo_mappings"] = _dedupe_strings(
            resolved_existing_repo_mappings + derived_repo_mappings
        )
        derived_source_mappings = list(source_plan.get("dependency_source_mappings") or [])
        if derived_source_mappings:
            result["dependency_source_mappings"] = _dedupe_strings(
                list(result.get("dependency_source_mappings") or []) + derived_source_mappings
            )
        focus_dependency_coords = _collect_focus_dependency_coords(result["report_dir"])
        current_mapping_map = {}
        for item in list(result.get("dependency_repo_mappings") or []):
            coord, repo_path = _split_dependency_repo_mapping_value(item)
            if coord and repo_path and coord not in current_mapping_map:
                current_mapping_map[coord] = repo_path
        result["unmapped_dependency_coords"] = [
            coord for coord in focus_dependency_coords if coord not in current_mapping_map
        ]
    return result


def validate_run_context_for_step(step_id, run_context):
    source_dirs = list(run_context.get("source_dirs") or [])
    source_dirs_status = str(run_context.get("source_dirs_status") or "").strip() or "missing"
    dependency_source_mapping_conflicts = list(run_context.get("dependency_source_mapping_conflicts") or [])
    unmapped_dependency_coords = list(run_context.get("unmapped_dependency_coords") or [])

    if step_id in ("step3", "step4", "step5") and not source_dirs:
        raise StepError(
            "未确认业务源码目录 source_dirs。请回到 Step2 补充或确认 source_dirs 后再继续；"
            "不要依赖后续步骤临时自动探测。"
        )
    if step_id in ("step3", "step4", "step5") and source_dirs_status == "missing":
        raise StepError("业务源码目录仍处于 missing 状态，请先在 Step2 确认 source_dirs。")
    if step_id in ("step4", "step5") and dependency_source_mapping_conflicts:
        conflict_coords = [str(item.get("coord") or "").strip() for item in dependency_source_mapping_conflicts if item.get("coord")]
        raise StepError(
            "dependency_source_dirs 存在坐标冲突，无法保证源码映射正确。"
            f"请先在 Step2 确认后再继续。冲突坐标：{', '.join(conflict_coords[:10]) or '(未识别)'}"
        )
    if step_id == "step5" and unmapped_dependency_coords and not run_context.get("allow_degraded"):
        # Step5 会基于实际需要跨依赖分析的 API 决定是否阻塞，这里仅保留冲突校验，不做全量缺失阻塞。
        pass


def ensure_exists(path, message):
    if not Path(path).exists():
        raise StepError(message)


def resolve_source_dirs(args, run_context, project_dir):
    source_dirs = resolve_value(args.source_dirs, run_context, "source_dirs")
    if not source_dirs:
        modules = run_context.get("modules") or []
        detected = detect_source_dirs_by_modules(project_dir, modules) if modules else []
        source_dirs = detected or detect_source_dirs(project_dir)
    if not source_dirs:
        raise StepError("未找到业务源码目录，请通过 --source-dirs 显式传入")
    return [str(Path(item).resolve()) for item in source_dirs]


def run_gate(gate_name, report_dir, cwd, strict_risk_gate=False):
    if not gate_name:
        return
    gate_args = ["--step", gate_name, "--report-dir", str(report_dir)]
    if strict_risk_gate:
        gate_args.append("--strict-risk-gate")
    try:
        run_python("gate.py", gate_args, cwd, report_dir=report_dir)
    except StepError as exc:
        reason_codes = list(exc.reason_codes)
        if gate_name == "jar_compare":
            coverage_file = runtime_coverage_dir(report_dir) / "s4_coverage.json"
            if coverage_file.is_file():
                coverage = read_json(coverage_file)
                for section in coverage.values():
                    if not isinstance(section, dict):
                        continue
                    reason_codes.extend(section.get("reason_codes") or [])
                    for run in section.get("runs") or []:
                        if isinstance(run, dict) and run.get("reason_code"):
                            reason_codes.append(run["reason_code"])
        raise StepError(str(exc), reason_codes=reason_codes) from exc


def detect_build_tool(project_dir):
    if (project_dir / "pom.xml").is_file():
        return "maven"
    if (project_dir / "build.gradle").is_file() or (project_dir / "build.gradle.kts").is_file():
        return "gradle"
    if (project_dir / "settings.gradle").is_file() or (project_dir / "settings.gradle.kts").is_file():
        return "gradle"
    if (project_dir / "gradlew").is_file() or (project_dir / "gradlew.bat").is_file():
        return "gradle"
    return "maven"


def _git_try(project_dir, args):
    stdout, _stderr, rc = run_cmd(git_cmd() + list(args), cwd=str(project_dir))
    if rc != 0:
        return None
    out = (stdout or "").strip()
    return out or None


def is_git_repo(project_dir):
    if not (project_dir / ".git").exists():
        return False
    inside = _git_try(project_dir, ["rev-parse", "--is-inside-work-tree"])
    return (inside or "").lower() == "true"


def detect_current_branch(project_dir):
    if not (project_dir / ".git").exists():
        return None
    name = _git_try(project_dir, ["rev-parse", "--abbrev-ref", "HEAD"])
    if not name or name == "HEAD":
        return None
    return name


def detect_base_branch(project_dir, current_branch):
    if not (project_dir / ".git").exists():
        return None
    upstream = _git_try(project_dir, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    if upstream:
        return upstream
    for candidate in ("main", "master", "develop"):
        local = _git_try(project_dir, ["show-ref", "--verify", f"refs/heads/{candidate}"])
        remote = _git_try(project_dir, ["show-ref", "--verify", f"refs/remotes/origin/{candidate}"])
        if local or remote:
            return candidate if local else f"origin/{candidate}"
    return current_branch


def _response_example_value(field, meta=None):
    """Return a schema-valid, user-recognizable sample for one response field."""
    meta = dict(meta or {})
    samples = {
        "target_module": "app-module",
        "primary_module": "app-module",
        "modules": ["app-module"],
        "base_branch": "origin/main",
        "current_branch": "feature/upgrade",
        "base_artifact_path": "/abs/path/to/base.jar",
        "current_artifact_path": "/abs/path/to/current.jar",
        "jdk_base": "8",
        "jdk_current": "17",
        "springboot_base": "2.7.18",
        "springboot_current": "3.3.2",
        "source_dirs": ["src/main/java"],
        "dependency_source_dirs": ["/abs/path/to/dependency-repo"],
        "source_repo_hints": ["/abs/path/to/dependency-repo"],
        "dependency_repo_mappings": [
            "com.example:demo-lib=/abs/path/to/dependency-repo"
        ],
        "selected_targets": ["com.example:demo-lib"],
        "step5_selected_coords": ["com.example:demo-lib"],
        "step5_selected_names": ["demo-lib"],
        "strict_risk_gate": True,
        "accept_suggested_mappings": True,
        "notes": "用户补充说明",
    }
    if field in samples:
        return samples[field]
    enum_values = [value for value in (meta.get("enum") or []) if value not in (None, "")]
    if enum_values:
        return enum_values[0]
    value_type = str(meta.get("type") or "string").strip()
    if value_type == "boolean":
        return True
    if value_type == "integer":
        return 1
    if value_type == "number":
        return 1.0
    if value_type == "array":
        return [f"<{_user_field_label(field) or field}>"]
    return f"<{_user_field_label(field) or field}>"


def _populate_required_response_example(payload, required_fields, properties):
    for field in required_fields or []:
        field = str(field or "").strip()
        if not field or field == "action" or field in payload:
            continue
        payload[field] = _response_example_value(field, (properties or {}).get(field))
    return payload


def _response_payload_example(action_id, required_fields, properties, overrides=None):
    payload = {"action": action_id}
    if action_id == "rerun_current_step":
        if "primary_module" in properties:
            payload["primary_module"] = "<用户指定模块>"
        if "modules" in properties:
            payload["modules"] = ["<用户指定模块>"]
        if "dependency_source_dirs" in properties:
            payload["dependency_source_dirs"] = ["/abs/path/to/dependency-repo"]
        if "allow_degraded" in properties:
            payload["allow_degraded"] = True
    elif action_id == "restart_from_step":
        payload["restart_step_id"] = "<step1|step2|step3|step4|step5>"
        if "dependency_source_dirs" in properties:
            payload["dependency_source_dirs"] = ["/abs/path/to/dependency-repo"]
    elif action_id == "continue":
        fields = ["base_branch", "current_branch", "source_dirs", "dependency_source_dirs"]
        for field in fields:
            if field in required_fields:
                if field in ("source_dirs", "dependency_source_dirs"):
                    payload[field] = [f"<{field} 值>"]
                elif field not in payload:
                    payload[field] = f"<{field} 值>"
        if "selected_targets" in required_fields:
            payload["selected_targets"] = ["<依赖包完整坐标>"]
        elif "step5_selected_coords" in required_fields:
            payload["step5_selected_coords"] = ["<coord 值>"]
        elif "step5_selected_names" in required_fields:
            payload["step5_selected_names"] = ["<name 值>"]
        if "strict_risk_gate" in required_fields:
            payload["strict_risk_gate"] = True
    _populate_required_response_example(payload, required_fields, properties)
    payload.update(dict(overrides or {}))
    return _wrap_response_payload_as_intent_patch(payload)


def _wrap_response_payload_as_intent_patch(payload):
    payload = dict(payload or {})
    action = str(payload.pop("action", "") or "").strip()
    restart_step_id = str(payload.pop("restart_step_id", "") or "").strip()
    notes = str(payload.pop("notes", "") or "").strip()
    intent_patch = {
        "action": action,
        "set": payload,
    }
    if restart_step_id:
        intent_patch["restart_step_id"] = restart_step_id
    if notes:
        intent_patch["notes"] = notes
    return {"intent_patch": intent_patch}


def _format_resume_shell_command(arguments, *, platform_name=None):
    """Render argv for POSIX shells or PowerShell without losing arguments."""
    values = [str(item) for item in arguments]
    system = str(platform_name or sys.platform).lower()
    if system.startswith("win"):
        quoted = [
            "'" + value.replace("'", "''") + "'"
            for value in values
        ]
        return "& " + " ".join(quoted)
    return shlex.join(values)


def build_resume_command_examples(options, required_fields, properties, project_dir, report_dir):
    examples = []
    for option in options or []:
        action_id = str(option.get("id") or "").strip()
        if not action_id:
            continue
        variants = [(option.get("label") or action_id, {})]
        if action_id == "continue" and "accept_suggested_mappings" in set(required_fields or []):
            variants = [
                ("采用建议映射后继续", {"accept_suggested_mappings": True}),
                ("不采用建议映射，按最终制品证据继续", {"accept_suggested_mappings": False}),
            ]
        for label, overrides in variants:
            payload = _response_payload_example(
                action_id,
                required_fields,
                properties,
                overrides=overrides,
            )
            examples.append(
                {
                    "action": action_id,
                    "label": label,
                    "command": _format_resume_shell_command([
                        sys.executable,
                        SCRIPT_DIR / "run_step.py",
                        "--step",
                        "auto",
                        "--project-dir",
                        project_dir,
                        "--report-dir",
                        report_dir,
                        "--response-json",
                        json.dumps(payload, ensure_ascii=False),
                    ]),
                }
            )
    examples.append(
        {
            "action": "response_file",
            "label": "从文件恢复",
            "command": _format_resume_shell_command([
                sys.executable,
                SCRIPT_DIR / "run_step.py",
                "--step",
                "auto",
                "--project-dir",
                project_dir,
                "--report-dir",
                report_dir,
                "--response-file",
                report_dir / "user_response.json",
            ]),
        }
    )
    return examples


def _response_payload_action_example(action_id, properties, required_fields=None):
    required_field_list = list(required_fields or [])
    required_fields = set(required_field_list)
    payload = {"action": action_id}
    if action_id == "rerun_current_step":
        if "primary_module" in properties:
            payload["primary_module"] = "module-a"
        if "modules" in properties:
            payload["modules"] = ["module-a"]
        if "dependency_source_dirs" in properties:
            payload["dependency_source_dirs"] = ["/abs/path/to/dependency-repo"]
        if "notes" in properties:
            payload["notes"] = "修正源码映射后重跑当前步骤"
    elif action_id == "restart_from_step":
        payload["restart_step_id"] = "step2"
        if "dependency_source_dirs" in properties:
            payload["dependency_source_dirs"] = ["/abs/path/to/dependency-repo"]
        if "notes" in properties:
            payload["notes"] = "从指定步骤重新执行"
    elif action_id == "continue":
        for field, sample in (
            ("base_branch", "origin/main"),
            ("current_branch", "feature/upgrade"),
        ):
            if field in required_fields:
                payload[field] = sample
                break
        if "source_dirs" in required_fields:
            payload["source_dirs"] = ["src/main/java"]
        if "dependency_source_dirs" in required_fields:
            payload["dependency_source_dirs"] = ["/abs/path/to/dependency-repo"]
        if "selected_targets" in required_fields:
            payload["selected_targets"] = ["com.example:demo-lib"]
        elif "step5_selected_coords" in required_fields:
            payload["step5_selected_coords"] = ["com.example:demo-lib"]
        if "strict_risk_gate" in required_fields:
            payload["strict_risk_gate"] = True
        if "notes" in required_fields:
            payload["notes"] = "当前结果可信，继续"
    elif action_id == "cancel":
        if "notes" in properties:
            payload["notes"] = "先补充信息，稍后继续"
    _populate_required_response_example(payload, required_field_list, properties)
    return _wrap_response_payload_as_intent_patch(payload)


def _build_user_reply_examples(action_id, properties):
    if action_id == "continue":
        examples = ["可以，继续下一步。", "当前结果没问题，继续。"]
        if "base_branch" in properties:
            examples.append("继续，不过基准分支改成 origin/main。")
        elif "source_dirs" in properties:
            examples.append("继续，源码目录补上 module-a/src/main/java。")
        if "selected_targets" in properties or "step5_selected_coords" in properties:
            examples.append("继续，但 Step5 只分析 commons-lang:commons-lang 这个依赖。")
        return examples
    if action_id == "rerun_current_step":
        examples = [
            "先不要继续，只分析 module-a 后重跑当前步骤。",
            "范围太大了，改成只看 module-a。",
        ]
        if "dependency_source_dirs" in properties:
            examples.append("这个依赖源码目录配错了，我换一个仓库目录后重跑当前步骤。")
        return examples
    if action_id == "restart_from_step":
        return [
            "从 step2 重新开始跑，当前这一步先不要继续。",
            "回到 step4 重跑，我要先修正前面的输入。",
            "先从 step2 重跑，再看这次源码映射和 git refs 是否正确。",
        ]
    if action_id == "cancel":
        return [
            "先停一下，我补完信息后再继续。",
            "先取消，这一轮我还要再确认一下。",
        ]
    return [f"执行 {action_id}。"]


def build_step1_response_properties():
    return {
        "analysis_mode": {
            "type": "string",
            "enum": ["artifact_inputs", "checkout_build"],
            "description": "可选。显式声明 Step1 输入模式；当需要从旧上下文切换模式时必须提供。",
        },
        "base_artifact_path": {
            "type": "string",
            "description": "可选。基准侧已编译产物绝对路径；与 current_artifact_path 一起使用时，将跳过隔离分支构建。",
        },
        "current_artifact_path": {
            "type": "string",
            "description": "可选。当前侧已编译产物绝对路径；与 base_artifact_path 一起使用时，将跳过隔离分支构建。",
        },
        "base_branch": {
            "type": "string",
            "description": "可选。基准侧分支名；artifact 模式下若嵌套依赖缺少 pom.properties，会优先用该分支生成 Maven/Gradle runtime 依赖报告补全坐标。",
        },
        "current_branch": {
            "type": "string",
            "description": "可选。当前侧分支名；artifact 模式下若嵌套依赖缺少 pom.properties，会优先用该分支生成 Maven/Gradle runtime 依赖报告补全坐标。",
        },
        "base_source_project_dir": {
            "type": "string",
            "description": "可选。基准侧源码工程目录；仅在不是同仓库双分支场景时，作为 artifact 模式的兜底补全来源。",
        },
        "current_source_project_dir": {
            "type": "string",
            "description": "可选。当前侧源码工程目录；仅在不是同仓库双分支场景时，作为 artifact 模式的兜底补全来源。",
        },
        "base_jdk_home": {
            "type": "string",
            "description": "可选。基准侧专用 JDK Home；未提供时默认回落主机 JAVA_HOME。",
        },
        "current_jdk_home": {
            "type": "string",
            "description": "可选。当前侧专用 JDK Home；未提供时默认回落主机 JAVA_HOME。",
        },
        "target_module": {
            "type": "string",
            "description": "必填。本次分析唯一的目标部署模块；用户已明确时视为已确认，否则必须在 Step1 前选择。",
        },
        "primary_module": {
            "type": "string",
            "description": "兼容字段。等价于 target_module，新交互应优先使用 target_module。",
        },
        "modules": {
            "type": "array",
            "description": "可选。仅支持单模块；可传单元素数组，与 primary_module 表达同一含义。",
        },
        "active_maven_profiles": {
            "type": "array",
            "description": (
                "可选。本次构建显式激活的 Maven profile ID；必须与最终制品的实际构建命令一致。"
            ),
        },
        "manual_coord_overrides": {
            "type": "array",
            "description": (
                "可选。补充本轮新增的 Step1 unresolved 坐标，格式为 "
                "artifact:version -> group:artifact；系统会与前几轮已提交的坐标合并。"
            ),
        },
        "tool": {
            "type": "string",
            "enum": ["maven", "gradle"],
            "description": "构建工具；通常从项目根目录自动识别 Maven 或 Gradle。",
        },
    }


def build_step1_input_modes():
    return [
        {
            "id": "artifact_inputs",
            "label": "直接产物模式",
            "required_fields": ["base_artifact_path", "current_artifact_path"],
            "recommended_fields": ["base_branch", "current_branch"],
            "required_confirmation_fields": ["target_module"],
            "fallback_fields": ["base_source_project_dir", "current_source_project_dir"],
            "notes": [
                "适合同一系统、同一仓库、不同分支，且用户已经拿到 base/current 编译产物的场景。",
                "若嵌套依赖缺少 pom.properties，优先补对应侧 branch；只有特殊场景才补 source_project_dir。",
            ],
        },
        {
            "id": "checkout_build",
            "label": "隔离分支构建模式",
            "required_fields": ["base_branch", "current_branch"],
            "recommended_fields": [],
            "required_confirmation_fields": ["target_module"],
            "fallback_fields": [],
            "notes": [
                "适合未提供编译产物，由系统按 base/current 分支执行真实 package 的场景。",
                "两侧构建均使用固定 commit 的隔离临时 worktree，不切换或修改用户当前工作区。",
            ],
        },
    ]


def build_step1_static_contract():
    properties = build_step1_response_properties()
    input_modes = build_step1_input_modes()
    return {
        "schema": "java-upgrade-analyzer.step1-contract.v1",
        "step_id": "step1",
        "title": "Step1 前置输入协议",
        "goal": "让 agent 在首次调用 Step1 前，就能按默认场景优先抽取可完成分析的关键字段。",
        "default_user_scenario": {
            "name": "same_system_same_repo_two_branches",
            "description": "同一个系统、同一个仓库、不同分支；优先使用两侧编译产物做正式分析，并用 branch 作为坐标补全来源。",
        },
        "analysis_mode_selection": [
            {
                "analysis_mode": "artifact_inputs",
                "select_when": "用户已提供 base/current 编译产物路径，或提示词明确表示已有两侧 jar/war。",
                "result_source": "provided_artifacts",
                "enrichment_strategy_candidates": ["branch_checkout", "source_project_dir"],
            },
            {
                "analysis_mode": "checkout_build",
                "select_when": "用户未提供两侧编译产物，但已明确要比较 base/current 分支，并由 Step1 自行构建。",
                "result_source": "built_artifacts",
                "enrichment_strategy_candidates": ["none"],
            },
        ],
        "input_modes": input_modes,
        "fields": properties,
        "first_turn_collection": {
            "strategy": "completion_oriented",
            "default_priority_fields": [
                "base_artifact_path",
                "current_artifact_path",
                "base_branch",
                "current_branch",
                "target_module",
            ],
            "rules": [
                "首轮目标不是只让 Step1 能启动，而是尽量一次收齐能完成分析的关键字段。",
                "若提示词已经明确模块范围，第一次执行 Step1 前必须写入 target_module；否则先展示候选并要求用户确认。",
                "artifact_inputs 模式下，若用户已给两侧产物，仍应优先继续抽取 base_branch/current_branch，避免运行时反复补参。",
                "只有在不是同仓库双分支场景时，才把 base_source_project_dir/current_source_project_dir 作为兜底字段。",
                "checkout_build 模式一旦成立，就天然表示由系统在隔离 worktree 中 package，不需要任何额外布尔许可字段。",
                "若已知某一侧 Maven/Gradle 需要特定 JDK，可分别显式提供 base_jdk_home/current_jdk_home；未提供时各侧默认回落主机 JAVA_HOME。",
            ],
        },
        "agent_workflow": [
            "先读取静态前置协议，再从用户提示词中抽取已知字段。",
            "首轮尽量按 default_priority_fields 组装当前步骤输入或命令行参数。",
            "若首轮仍不完整，再调用 Step1；此时 run_step.py 只负责返回本次调用的动态缺口。",
            "收到 interaction.json 后，优先消费 missing_inputs/fallback_inputs/response_schema/input_normalization，再向用户追问。",
        ],
        "dynamic_interaction_boundary": {
            "static_contract_purpose": "说明 agent 在首次调用前就应知道的模式、字段、优先级与规则。",
            "runtime_interaction_purpose": "说明本次调用还缺哪些字段、缺的是哪一侧、为什么缺、优先补什么、兜底补什么。",
            "runtime_fields": [
                "missing_inputs",
                "fallback_inputs",
                "input_modes",
                "response_schema",
                "input_normalization",
                "analysis_mode",
                "result_source",
                "enrichment_strategy",
            ],
        },
        "examples": {
            "artifact_inputs_default": {
                "analysis_mode": "artifact_inputs",
                "base_artifact_path": "/abs/path/base-app.jar",
                "current_artifact_path": "/abs/path/current-app.jar",
                "base_branch": "main",
                "current_branch": "feature/upgrade",
                "target_module": "app-module",
            },
            "checkout_build_default": {
                "analysis_mode": "checkout_build",
                "base_branch": "main",
                "current_branch": "feature/upgrade",
                "target_module": "app-module",
            },
        },
        "forbidden": [
            "不要先执行 Step1 再靠失败结果倒逼用户补参。",
            "不要在 artifact_inputs 失败后自动切到 checkout_build。",
            "不要暴露或依赖 allow_checkout 这类布尔许可字段。",
            "不要把工作区自动探测到的分支冒充用户显式提供的 base_branch/current_branch。",
        ],
    }


def infer_step1_mode_fields(run_context):
    ctx = dict(run_context or {})
    explicit_analysis_mode = normalize_analysis_mode(ctx.get("analysis_mode"), allow_empty=True)
    base_artifact_path = str(ctx.get("base_artifact_path") or "").strip()
    current_artifact_path = str(ctx.get("current_artifact_path") or "").strip()
    base_branch = str(ctx.get("base_branch") or "").strip()
    current_branch = str(ctx.get("current_branch") or "").strip()
    base_source_project_dir = str(ctx.get("base_source_project_dir") or "").strip()
    current_source_project_dir = str(ctx.get("current_source_project_dir") or "").strip()
    artifact_pair = bool(base_artifact_path and current_artifact_path)
    any_artifact = bool(base_artifact_path or current_artifact_path)
    branch_pair = bool(base_branch and current_branch)
    any_branch = bool(base_branch or current_branch)
    if explicit_analysis_mode == "artifact_inputs":
        analysis_mode = "artifact_inputs"
        result_source = "provided_artifacts"
    elif explicit_analysis_mode == "checkout_build":
        analysis_mode = "checkout_build"
        result_source = "built_artifacts"
    elif artifact_pair or any_artifact:
        analysis_mode = "artifact_inputs"
        result_source = "provided_artifacts"
    elif branch_pair or any_branch:
        analysis_mode = "checkout_build"
        result_source = "built_artifacts"
    else:
        analysis_mode = ""
        result_source = ""
    enrichment_strategy = "none"
    if analysis_mode == "artifact_inputs":
        if branch_pair:
            enrichment_strategy = "branch_checkout"
        elif base_source_project_dir or current_source_project_dir:
            enrichment_strategy = "source_project_dir"
    return {
        "analysis_mode": analysis_mode,
        "analysis_mode_explicit": explicit_analysis_mode,
        "result_source": result_source,
        "enrichment_strategy": enrichment_strategy,
        "artifact_pair_ready": artifact_pair,
        "branch_pair_ready": branch_pair,
        "has_any_artifact": any_artifact,
        "has_any_branch": any_branch,
    }


def write_step1_module_candidates(report_dir, module_candidates):
    output_path = evidence_dependencies_dir(report_dir) / "module_candidates.md"
    lines = [
        "# 目标模块候选",
        "",
        "请选择本次实际部署和升级的一个业务模块。部署线索只用于排序，系统不会据此替你决定分析范围。",
        "",
        "| 模块路径 | 依赖坐标 | packaging | 部署线索 |",
        "|---|---|---|---|",
    ]
    for item in module_candidates or []:
        if isinstance(item, dict):
            module = str(item.get("module") or item.get("path") or item.get("name") or "").strip()
            coord = str(item.get("coord") or "-").strip()
            packaging = str(item.get("packaging") or "-").strip()
            hints = "、".join(str(value) for value in (item.get("deploy_hints") or []) if str(value).strip()) or "-"
        else:
            module = str(item or "").strip()
            coord = packaging = hints = "-"
        if module:
            lines.append(f"| `{module}` | `{coord}` | {packaging} | {hints} |")
    _write_text_file(output_path, "\n".join(lines))
    return output_path


def build_step1_preflight_interaction(run_context):
    base_artifact_path = str(run_context.get("base_artifact_path") or "").strip()
    current_artifact_path = str(run_context.get("current_artifact_path") or "").strip()
    base_branch = str(run_context.get("base_branch") or "").strip()
    current_branch = str(run_context.get("current_branch") or "").strip()
    mode_info = infer_step1_mode_fields(run_context)
    target_module = str(run_context.get("target_module") or run_context.get("primary_module") or "").strip()

    properties = {
        "action": {
            "type": "string",
            "enum": ["continue", "cancel"],
        },
        "notes": {
            "type": "string",
            "description": "记录用户确认的输入方式、模块范围或补充说明。",
        },
    }
    properties.update(build_step1_response_properties())

    missing_inputs = []
    fallback_inputs = []
    analysis_mode = mode_info.get("analysis_mode") or ""
    if analysis_mode == "artifact_inputs":
        if not mode_info.get("artifact_pair_ready"):
            if not base_artifact_path:
                missing_inputs.append(
                    {
                        "field": "base_artifact_path",
                        "label": "基准侧编译产物路径",
                        "side": "base",
                        "required": True,
                        "recommended": True,
                        "reason": "当前看起来选择的是直接产物模式，但尚未提供 base_artifact_path。",
                        "value_type": "path",
                    }
                )
            if not current_artifact_path:
                missing_inputs.append(
                    {
                        "field": "current_artifact_path",
                        "label": "当前侧编译产物路径",
                        "side": "current",
                        "required": True,
                        "recommended": True,
                        "reason": "当前看起来选择的是直接产物模式，但尚未提供 current_artifact_path。",
                        "value_type": "path",
                    }
                )
    elif analysis_mode == "checkout_build":
        if not base_branch:
            missing_inputs.append(
                {
                    "field": "base_branch",
                    "label": "基准侧分支",
                    "side": "base",
                    "required": True,
                    "recommended": True,
                    "reason": "当前选择的是隔离分支构建模式，但尚未提供基准侧分支。",
                    "value_type": "branch",
                }
            )
        if not current_branch:
            missing_inputs.append(
                {
                    "field": "current_branch",
                    "label": "当前侧分支",
                    "side": "current",
                    "required": True,
                    "recommended": True,
                    "reason": "当前选择的是隔离分支构建模式，但尚未提供当前侧分支。",
                    "value_type": "branch",
                }
            )

    if not target_module:
        missing_inputs.append(
            {
                "field": "target_module",
                "label": "本次分析的目标模块",
                "required": True,
                "recommended": True,
                "reason": "一次分析只对应一个部署模块，必须在 Step1 构建和依赖提取前由用户确认。",
                "value_type": "module",
            }
        )

    checklist_lines = [
        "支持 Maven 与 Gradle，且一次分析只对应一个部署模块。",
        "执行前请先明确一种输入方式；模式一旦进入执行，不允许因为失败自动切到另一种模式。",
        "主推荐场景：同一系统、同一仓库、不同分支；若已拿到编译产物，优先走直接产物模式。",
        "直接产物模式先使用两侧最终制品；分支和源码目录只用于后续上下文或坐标补全，不替代制品事实。",
    ]
    for mode in build_step1_input_modes():
        checklist_lines.append(
            f"输入方式 {mode.get('id')}（{mode.get('label')}）: 必填={', '.join(mode.get('required_fields') or [])}"
        )
        if mode.get("recommended_fields"):
            checklist_lines.append(
                f"  - 推荐补充: {', '.join(mode.get('recommended_fields') or [])}"
            )
        if mode.get("fallback_fields"):
            checklist_lines.append(
                f"  - 兜底字段: {', '.join(mode.get('fallback_fields') or [])}"
            )

    if analysis_mode == "artifact_inputs" and mode_info.get("artifact_pair_ready"):
        question = "两侧编译产物已经齐全。请补充本次分析真正缺少的信息。"
    elif analysis_mode == "checkout_build":
        question = "当前已选择隔离分支构建模式，请补齐缺失的基准侧或当前侧分支。"
    else:
        question = (
            "执行 step1 前，请先明确输入方式："
            "要么提供 `base_artifact_path/current_artifact_path`；"
            "要么提供 `base_branch/current_branch` 进入隔离分支构建模式。"
        )
    if missing_inputs:
        missing_text = "、".join(item.get("field") for item in missing_inputs if item.get("field"))
        question = f"{question} 当前还缺：{missing_text}。"
    elif analysis_mode:
        return None

    missing_fields = {item.get("field") for item in missing_inputs}
    reason_code = (
        "missing_step1_target_module"
        if analysis_mode and missing_fields == {"target_module"}
        else "missing_step1_entry_inputs"
    )
    project_scope = dict(run_context.get("project_scope") or {})
    module_candidates = list(
        project_scope.get("candidate_module_details")
        or project_scope.get("candidate_modules")
        or []
    )
    if module_candidates and all(isinstance(item, dict) for item in module_candidates):
        module_candidates.sort(
            key=lambda item: (
                not bool(item.get("deploy_hints")),
                str(item.get("packaging") or "").strip() == "pom",
                str(item.get("module") or ""),
            )
        )
    files_to_review = []
    if len(module_candidates) > 20 and run_context.get("report_dir"):
        files_to_review.append(
            str(
                write_step1_module_candidates(
                    run_context.get("report_dir"), module_candidates
                ).resolve()
            )
        )
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "input_request",
        "step_id": "step1",
        "reason_code": reason_code,
        "summary": "Step1 需要先明确执行入口和关键字段，agent 应先向用户索取这些输入，再启动实际分析。",
        "title": "step1 需要先确认输入方式",
        "analysis_mode": analysis_mode,
        "result_source": mode_info.get("result_source", ""),
        "enrichment_strategy": mode_info.get("enrichment_strategy", "none"),
        "question": question,
        "files_to_review": files_to_review,
        "required_fields": [item.get("field") for item in missing_inputs if item.get("field")],
        "missing_inputs": missing_inputs,
        "fallback_inputs": fallback_inputs,
        "input_modes": build_step1_input_modes(),
        "module_candidates": module_candidates,
        "checklist_lines": checklist_lines,
        "action_requirements": {
            "continue": {
                "required_fields": [item.get("field") for item in missing_inputs if item.get("field")],
                "description": "只有补齐当前缺失输入后，才能继续执行 Step1。",
            }
        },
        "options": [
            {
                "id": "continue",
                "label": "补充输入后继续",
                "description": "补齐 Step1 所需输入后继续执行。",
            },
            {
                "id": "cancel",
                "label": "取消",
                "description": "先停止本次执行，稍后再继续。",
            },
        ],
        "response_schema": {
            "type": "object",
            "required": ["action"],
            "properties": properties,
        },
        "input_normalization": {
            "enabled": True,
            "mode": "llm_assisted_structuring",
            "source": "user_free_text",
            "target": "response_json",
            "target_schema_ref": "response_schema",
            "allowed_actions": ["continue", "cancel"],
            "required_fields": [item.get("field") for item in missing_inputs if item.get("field")],
            "rules": [
                "可以将用户自然语言答复整理为符合 response_schema 的 JSON 对象。",
                "必须忠实保留用户意图，不得脑补未提供的路径、分支名或模块名。",
                "若用户选择直接产物模式，应优先抽取 base_artifact_path 和 current_artifact_path。",
                "若用户选择隔离分支构建模式，应抽取 base_branch、current_branch。",
                "若用户选择直接产物模式，为避免运行时反复补参，应尽量同时抽取 base_branch、current_branch 或对应侧 source_project_dir。",
                "若用户补充了 primary_module 或 modules，应一并写回，避免 Step1 模块范围漂移。",
            ],
        },
        "resume_hint": "先补齐 Step1 输入方式和关键字段，再继续执行 Step1。",
        "runtime_rules": [
            "看到 awaiting_user_input 后，必须先向用户索要 Step1 所需输入，再决定是否继续。",
            "禁止假设分支名、jar 路径、源码目录或模块名。",
        ],
        "next_action_rule": "只能向用户确认 Step1 的输入方式和缺失字段并等待回复，不得继续执行后续步骤。",
        "must_wait_for_user_reply": True,
    }


def _step1_ref_repository(run_context, side, project_dir):
    source_dir = str(run_context.get(f"{side}_source_project_dir") or "").strip()
    return Path(source_dir).resolve() if source_dir else Path(project_dir).resolve()


def _step1_ref_request(side, field, source_dir, resolution, *, source_only=False):
    candidates = [dict(item) for item in (resolution.get("candidates") or [])]
    for candidate in candidates:
        payload = {
            "side": side,
            "ref": str(candidate.get("ref") or ""),
            "commit": str(candidate.get("commit") or ""),
        }
        candidate["selection_key"] = "s1ref:" + hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
    request = {
        "side": side,
        "field": field,
        "requested_ref": str(resolution.get("requested_ref") or ""),
        "status": str(resolution.get("status") or "not_found"),
        "fingerprint": str(resolution.get("fingerprint") or ""),
        "source_project_dir": str(source_dir or ""),
        "candidates": candidates,
        "source_status": str(resolution.get("source_status") or ""),
        "remote_failures": [dict(item) for item in (resolution.get("failures") or resolution.get("remote_failures") or [])],
        "local_candidate_commit": str(resolution.get("local_candidate_commit") or ""),
        "dirty": bool(resolution.get("dirty")),
        "expected_commit": str(resolution.get("expected_commit") or ""),
        "observed_commit": str(resolution.get("observed_commit") or ""),
    }
    detected_commit = str(
        resolution.get("resolved_commit") or resolution.get("local_candidate_commit") or ""
    ).strip()
    if source_only and detected_commit:
        request.update({
            "detected_ref": str(resolution.get("resolved_ref") or "HEAD"),
            "detected_commit": detected_commit,
            "status": "confirmation_required",
            "candidates": [{
                "ref": detected_commit,
                "display_ref": str(resolution.get("resolved_ref") or "HEAD"),
                "commit": detected_commit,
                "kind": "detected_source_head",
                "score": 0,
            }],
        })
    for candidate in request.get("candidates") or []:
        if candidate.get("selection_key"):
            continue
        payload = {
            "side": side,
            "ref": str(candidate.get("ref") or candidate.get("display_ref") or ""),
            "commit": str(candidate.get("commit") or ""),
        }
        candidate["selection_key"] = "s1ref:" + hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
    return request


def build_step1_ref_confirmation_interaction(run_context, requests):
    requests = [dict(item) for item in (requests or [])]
    required_fields = [
        str(item.get("field") or "").strip()
        for item in requests
        if item.get("status") != "fetch_failed"
        if str(item.get("field") or "").strip()
    ]
    reason_codes = {
        "source_only" if item.get("status") == "confirmation_required" else item.get("status")
        for item in requests
    }
    if "fetch_failed" in reason_codes:
        reason_code = "step1_remote_fetch_failed"
        title = "Step1 远端源码 fetch 失败"
        summary = "远端查询或 fetch 按错误类型完成受控重试后仍失败；无需重新选择分支。"
    elif "ref_moved" in reason_codes:
        reason_code = "step1_remote_ref_moved"
        title = "Step1 远端分支已移动"
        summary = "确认或解析期间远端 ref 指向了新的 commit，需要基于刷新后的候选重新确认。"
    elif "source_only" in reason_codes:
        reason_code = "step1_source_revision_confirmation_required"
        title = "Step1 需要确认源码 revision"
        summary = "仅有源码目录不能证明其对应 base 或 current 制品，必须先确认并固定 commit。"
    elif "ambiguous" in reason_codes:
        reason_code = "ambiguous_step1_source_ref"
        title = "Step1 分支存在多个候选"
        summary = "提供的分支名称在远程仓库匹配到多个不同 commit，不能自动选择。"
    elif any(item.get("source_status") == "awaiting_dirty_local_source_confirmation" for item in requests):
        reason_code = "step1_dirty_local_source_confirmation_required"
        title = "Step1 本地源码包含未提交修改"
        summary = "远程源码不可用；本地仓库存在未提交修改，使用前必须单独确认。"
    elif any(item.get("source_status") == "awaiting_local_source_confirmation" for item in requests):
        reason_code = "step1_remote_source_unavailable"
        title = "Step1 远程源码不可用"
        summary = "远程分支无法获取；不会自动使用本地分支，可更正远程 ref 或明确确认本地兜底。"
    else:
        reason_code = "step1_source_ref_not_found"
        title = "Step1 无法定位源码分支"
        summary = "提供的分支无法从远程仓库解析并固定为 commit。"
    properties = {
        "action": {"type": "string", "enum": ["continue", "confirm_local_source", "cancel"]},
        "source_ref_selections": {
            "type": "array",
            "description": "按 base/current 侧选择候选 selection_key；系统会同时写回 ref 与 expected commit。",
        },
        "retry_remote_fetch": {
            "type": "boolean",
            "description": (
                "用户已确认远端配置、权限或 ref 状态正常后，显式重新查询远端并重试定向 fetch。"
            ),
        },
        "notes": {"type": "string", "description": "可选。记录分支或 revision 的确认依据。"},
    }
    missing_inputs = []
    checklist_lines = []
    for request in requests:
        field = request["field"]
        side = str(request.get("side") or "").strip()
        side_cn = "基准侧" if side == "base" else "当前侧"
        source_field = f"{side}_source_project_dir"
        properties[field] = {
            "type": "string",
            "description": f"{side_cn}明确的远程分支或 tag；指定 remote 时使用 origin/release 形式。",
        }
        properties[source_field] = {
            "type": "string",
            "description": (
                f"可选。修正{side_cn}实际执行 Git ref 解析的源码仓库目录；"
                "当 ref 已确认存在但卡片中的解析目录不正确时，与原 ref 一起提交。"
            ),
        }
        properties[f"{side}_expected_commit"] = {
            "type": "string",
            "description": f"内部固定值：{side_cn}确认卡中所选 ref 对应的 commit。",
        }
        allow_local_field = f"{side}_allow_local_source"
        allow_dirty_field = f"{side}_allow_dirty_local_source"
        properties[allow_local_field] = {
            "type": "boolean",
            "description": f"仅当远程不可用时，明确允许{side_cn}使用本地 commit 作为辅助源码。",
        }
        if request.get("dirty"):
            properties[allow_dirty_field] = {
                "type": "boolean",
                "description": f"明确知晓{side_cn}本地仓库含未提交修改并仍允许使用固定 commit。",
            }
        missing_inputs.append({
            "field": field,
            "label": f"{side_cn}源码 ref",
            "side": request.get("side"),
            "required": request.get("status") != "fetch_failed",
            "recommended": True,
            "reason": summary,
            "value_type": "branch",
        })
        if request.get("requested_ref"):
            checklist_lines.append(f"{side_cn}原始输入: {request.get('requested_ref')}")
        if request.get("source_project_dir"):
            checklist_lines.append(
                f"{side_cn}实际解析目录: {request.get('source_project_dir')}"
            )
        if request.get("detected_commit"):
            checklist_lines.append(
                f"{side_cn}源码目录当前 revision: {request.get('detected_ref')} "
                f"({request.get('detected_commit')})"
            )
        for candidate in request.get("candidates") or []:
            checklist_lines.append(
                f"{side_cn}候选: {candidate.get('ref')} ({candidate.get('commit')})"
            )
        for failure in request.get("remote_failures") or []:
            checklist_lines.append(
                f"{side_cn}远程失败: {failure.get('remote') or '远程仓库'} / "
                f"{failure.get('stage') or '解析'} / {failure.get('reason') or '未知原因'}"
            )
        if request.get("local_candidate_commit"):
            checklist_lines.append(
                f"{side_cn}可确认的本地 commit: {request.get('local_candidate_commit')}"
            )
    fingerprint_payload = json.dumps(
        [item.get("fingerprint") for item in requests],
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    source_ref_decision_items = [
        {
            "side": item.get("side"),
            "field": item.get("field"),
            "status": item.get("status"),
            "source_status": item.get("source_status"),
            "requested_ref": item.get("requested_ref"),
            "candidates": list(item.get("candidates") or []),
        }
        for item in requests
    ]
    fetch_only = reason_codes == {"fetch_failed"}
    question = (
        "远端查询或 fetch 失败；请在网络或权限恢复后确认重试。"
        if fetch_only
        else "请为列出的每一侧选择或填写一个明确 ref；确认后 Step1 会固定 commit 再执行。"
    )
    continue_option = (
        {"id": "continue", "label": "重试远端 fetch", "description": "保持已唯一定位的 ref，并重新执行受控 fetch。"}
        if fetch_only
        else {"id": "continue", "label": "确认 ref 后继续", "description": "重新查询远程，并验证所选 ref 仍指向确认卡中的 commit。"}
    )
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "input_request",
        "step_id": "step1",
        "reason_code": reason_code,
        "summary": summary,
        "title": title,
        "question": question,
        "files_to_review": [
            item.get("source_project_dir") for item in requests if item.get("source_project_dir")
        ],
        "required_fields": required_fields,
        "missing_inputs": missing_inputs,
        "fallback_inputs": [],
        "checklist_lines": checklist_lines,
        "ref_resolution_requests": requests,
        "source_ref_decision_items": source_ref_decision_items,
        "ref_resolution_fingerprint": hashlib.sha256(fingerprint_payload).hexdigest(),
        "options": [
            continue_option,
            {"id": "confirm_local_source", "label": "确认使用本地源码兜底", "description": "仅在远程不可用时使用用户明确确认的本地 commit。"},
            {"id": "cancel", "label": "取消", "description": "停止本次分析。"},
        ],
        "response_schema": {
            "type": "object",
            "required": ["action"],
            "properties": properties,
        },
        "action_requirements": {
            "continue": {"required_fields": []},
            "confirm_local_source": {
                "required_fields": [
                    field
                    for item in requests
                    for field in (
                        [f"{item.get('side')}_allow_local_source"]
                        + ([f"{item.get('side')}_allow_dirty_local_source"] if item.get("dirty") else [])
                    )
                ],
            },
        },
        "input_normalization": {
            "enabled": True,
            "mode": "llm_assisted_structuring",
            "source": "user_free_text",
            "target": "response_json",
            "target_schema_ref": "response_schema",
            "allowed_actions": ["continue", "confirm_local_source", "cancel"],
            "required_fields": required_fields,
            "rules": [
                "更正远程 ref 时必须使用完整 remote/ref，或用户明确提供的其他远程 ref。",
                "若 ref 已确认存在但实际解析目录不正确，可保留原 ref，并同时修正对应侧 source_project_dir。",
                "只有用户明确同意本地兜底时才能设置 allow_local_source=true。",
                "ref 与实际解析目录都未变化时，只有用户明确要求 retry_remote_fetch=true 才能重新查询。",
            ],
        },
        "runtime_rules": [
            "确认前不得执行 Maven/Gradle、创建分析 worktree 或继续后续步骤。",
            "用户确认后必须固定到 resolved commit，不能依赖工作区当前 checkout。",
        ],
        "next_action_rule": "只能等待用户补充远程 ref、修正实际解析目录、明确确认本地兜底或取消。",
        "must_wait_for_user_reply": True,
    }


def resolve_step1_refs_for_execution(run_context, project_dir):
    """Resolve explicit Step1 refs before Maven/Gradle execution."""
    updated = dict(run_context or {})
    if updated.get("base_artifact_path") and updated.get("current_artifact_path"):
        # Direct artifacts are parsed first. Ref resolution is deferred until a
        # concrete unresolved nested JAR actually needs build-tool coordinate fallback.
        return updated, None
    requests = []
    for side in ("base", "current"):
        branch_field = f"{side}_branch"
        source_field = f"{side}_source_project_dir"
        requested_ref = str(updated.get(branch_field) or "").strip()
        source_dir = str(updated.get(source_field) or "").strip()
        repo_dir = _step1_ref_repository(updated, side, project_dir)
        if requested_ref:
            expected_commit = str(
                updated.get(f"{side}_expected_commit")
                or updated.get(f"{side}_resolved_commit")
                or ""
            ).strip()
            resolution = resolve_step1_ref(
                repo_dir,
                requested_ref,
                expected_commit=expected_commit,
                allow_local_source=bool(updated.get(f"{side}_allow_local_source")),
                allow_dirty_local_source=bool(updated.get(f"{side}_allow_dirty_local_source")),
            )
            if resolution.get("status") != "resolved":
                if resolution.get("expected_commit"):
                    updated[f"{side}_expected_commit"] = str(resolution.get("expected_commit") or "")
                requests.append(
                    _step1_ref_request(side, branch_field, source_dir or str(repo_dir), resolution)
                )
                continue
            updated[f"{side}_requested_ref"] = requested_ref
            updated[f"{side}_resolved_ref"] = str(resolution.get("resolved_ref") or requested_ref)
            updated[f"{side}_resolved_commit"] = str(resolution.get("resolved_commit") or "")
            updated[f"{side}_expected_commit"] = str(
                resolution.get("resolved_commit") or expected_commit
            )
            updated[f"{side}_ref_resolution_mode"] = str(resolution.get("resolution_mode") or "exact")
            updated[f"{side}_ref_resolution_fingerprint"] = str(resolution.get("fingerprint") or "")
            updated[f"{side}_ref_candidate_count"] = len(resolution.get("candidates") or [])
            updated[f"{side}_ref_source_status"] = str(
                resolution.get("source_status") or "remote_source_resolved"
            )
            updated[f"{side}_ref_remote"] = str(resolution.get("remote") or "")
            updated[f"{side}_ref_remote_ref"] = str(resolution.get("remote_ref") or "")
            updated[f"{side}_ref_queried_at"] = str(resolution.get("queried_at") or "")
            continue
        if source_dir:
            resolution = resolve_step1_ref(repo_dir, "HEAD")
            requests.append(
                _step1_ref_request(
                    side,
                    branch_field,
                    str(repo_dir),
                    resolution,
                    source_only=True,
                )
            )
    if requests:
        return updated, build_step1_ref_confirmation_interaction(updated, requests)
    return updated, None


def build_input_normalization_contract(options, required_fields, properties):
    option_ids = []
    field_hints = {}
    action_examples = []
    for name, meta in (properties or {}).items():
        if not isinstance(meta, dict):
            meta = {}
        field_hints[name] = {
            "type": meta.get("type", "string"),
            "description": meta.get("description", ""),
        }
        if meta.get("enum"):
            field_hints[name]["enum"] = meta.get("enum")

    for option in options or []:
        action_id = str(option.get("id") or "").strip()
        if not action_id:
            continue
        option_ids.append(action_id)
        action_examples.append(
            {
                "action": action_id,
                "label": option.get("label") or action_id,
                "description": option.get("description", ""),
                "user_reply_examples": _build_user_reply_examples(action_id, properties),
                "normalized_response_example": _response_payload_action_example(
                    action_id,
                    properties,
                    required_fields=required_fields,
                ),
            }
        )

    return {
        "enabled": True,
        "mode": "llm_assisted_structuring",
        "source": "user_free_text",
        "target": "response_json",
        "target_schema_ref": "response_schema",
        "allowed_actions": option_ids,
        "required_fields": list(required_fields or []),
        "rules": [
            "可以将用户自然语言答复整理为符合 response_schema 的 JSON 对象。",
            "必须忠实保留用户意图，不得替用户做决定，不得脑补未提供的事实。",
            "action 必须严格等于 options.id 之一；若用户未表达明确动作，必须继续追问。",
            "仅提取用户明确确认、修正或补充的字段；不要把历史上下文里的候选值当成用户本次输入。",
            "若答复存在歧义、冲突或缺少该动作所需关键信息，必须先澄清，不能直接恢复执行。",
            "需要保留原始语义时，可把用户原话摘要写入 notes。",
        ],
        "do_not": [
            "不要猜测模块名、分支名、源码路径或跨依赖坐标。",
            "不要输出不在 response_schema 中定义的业务字段。",
        ],
        "field_hints": field_hints,
        "action_examples": action_examples,
    }


def enrich_input_normalization_contract(contract, action_requirements=None, selection_resolution=None):
    payload = dict(contract or {})
    rules = list(payload.get("rules") or [])
    do_not = list(payload.get("do_not") or [])
    if action_requirements:
        payload["action_requirements"] = action_requirements
        requirement_rule = "恢复前必须满足 action_requirements；若 required_fields 或 at_least_one_of 未满足，必须先追问。"
        if requirement_rule not in rules:
            rules.append(requirement_rule)
    if selection_resolution and selection_resolution.get("enabled"):
        payload["selection_resolution"] = selection_resolution
        selection_rule = "若用户提到候选对象，优先归一化为 selected_targets；若匹配到多个候选，必须先澄清。"
        if selection_rule not in rules:
            rules.append(selection_rule)
        selection_do_not = "不要把候选展示文案直接当成正式业务字段；先解析为 selected_targets 或正式主键。"
        if selection_do_not not in do_not:
            do_not.append(selection_do_not)
    payload["rules"] = rules
    if do_not:
        payload["do_not"] = do_not
    return payload


def apply_interaction_protocol_enhancements(interaction, step_id, project_dir=None, report_dir=None):
    payload = dict(interaction or {})
    if not payload:
        return payload
    step_id = str(step_id or "").strip()
    options = [dict(item) for item in (payload.get("options") or [])]
    response_schema = dict(payload.get("response_schema") or {})
    properties = dict(response_schema.get("properties") or {})
    if step_id == "step1" and payload.get("ref_resolution_requests"):
        requests = [
            dict(item) for item in (payload.get("ref_resolution_requests") or [])
            if isinstance(item, dict)
        ]
        for request in payload.get("ref_resolution_requests") or []:
            side = str(request.get("side") or "").strip()
            if side not in {"base", "current"}:
                continue
            side_cn = "基准侧" if side == "base" else "当前侧"
            properties.setdefault(
                f"{side}_source_project_dir",
                {
                    "type": "string",
                    "description": (
                        f"可选。修正{side_cn}实际执行 Git ref 解析的源码仓库目录；"
                        "可与原 ref 一起提交。"
                    ),
                },
            )
        artifact_triggered_sides = [
            str(item.get("side") or "").strip()
            for item in requests
            if str(item.get("side") or "").strip() in {"base", "current"}
            and (
                str(item.get("artifact_path") or "").strip()
                or str(item.get("resolution_trigger") or "").strip()
                == "artifact_coordinate_enrichment"
            )
        ]
        if artifact_triggered_sides:
            queried_sides = list(dict.fromkeys(artifact_triggered_sides))
            queried_labels = "、".join(
                "基准侧" if side == "base" else "当前侧"
                for side in queried_sides
            )
            absent_sides = [
                side for side in ("base", "current") if side not in queried_sides
            ]
            absent_labels = "、".join(
                "基准侧" if side == "base" else "当前侧"
                for side in absent_sides
            )
            scope_note = (
                f"本卡片只记录{queried_labels}因产物坐标补全而触发的 Git ref 查询。"
            )
            if absent_sides:
                scope_note += (
                    f"它不表示{absent_labels}执行过远端查询；"
                    f"只有{absent_labels}状态明确为 remote_source_resolved，"
                    "才能认定其远端解析成功。"
                )
            payload["ref_resolution_scope"] = {
                "trigger": "artifact_coordinate_enrichment",
                "queried_sides": queried_sides,
                "not_evaluated_sides": absent_sides,
                "note": scope_note,
            }
            checklist_lines = list(payload.get("checklist_lines") or [])
            if scope_note not in checklist_lines:
                checklist_lines.insert(0, scope_note)
            payload["checklist_lines"] = checklist_lines
            question = str(payload.get("question") or "").strip()
            if scope_note not in question:
                payload["question"] = f"{question}{scope_note}"
            decision_items = []
            request_by_side = {
                str(item.get("side") or "").strip(): item
                for item in requests
                if str(item.get("side") or "").strip()
            }
            for raw_item in payload.get("source_ref_decision_items") or []:
                item = dict(raw_item or {})
                request = request_by_side.get(str(item.get("side") or "").strip(), {})
                item.setdefault("source_project_dir", request.get("source_project_dir"))
                item.setdefault(
                    "resolution_trigger",
                    request.get("resolution_trigger") or "artifact_coordinate_enrichment",
                )
                item.setdefault("remote_query_scope", request.get("side"))
                decision_items.append(item)
            if decision_items:
                payload["source_ref_decision_items"] = decision_items
    selection_options = build_interaction_selection_options(payload.get("selection_options") or [])
    selection_resolution = dict(payload.get("selection_resolution") or {})
    if not selection_resolution.get("enabled"):
        selection_resolution = build_selection_resolution(selection_options)
    if step_id == "step5" and not selection_resolution.get("enabled") and report_dir:
        selection_resolution = build_report_dir_step5_selection_resolution(report_dir)
    if selection_options:
        payload["selection_options"] = selection_options
    elif step_id == "step5" and selection_resolution.get("enabled"):
        payload["selection_options"] = build_interaction_selection_options(
            selection_resolution.get("options") or []
        )
    if selection_resolution.get("enabled"):
        for internal_field in ("step5_selected_coords", "step5_selected_names"):
            properties.pop(internal_field, None)
        sanitized_required_fields = []
        for field in payload.get("required_fields") or []:
            normalized_field = (
                "selected_targets"
                if field in ("step5_selected_coords", "step5_selected_names")
                else field
            )
            if normalized_field not in sanitized_required_fields:
                sanitized_required_fields.append(normalized_field)
        payload["required_fields"] = sanitized_required_fields
        properties.setdefault(
            "selected_targets",
            {
                "type": "array",
                "description": (
                    "内部恢复字段，不向用户展示或要求用户填写。"
                    "系统根据用户回复的依赖名称或完整坐标自动生成。"
                ),
            },
        )
        payload["selection_resolution"] = selection_resolution
    action_requirements = normalize_action_requirements(
        payload.get("action_requirements") or {},
        options,
        required_fields=payload.get("required_fields") or [],
    )
    if selection_resolution.get("enabled"):
        for requirement in action_requirements.values():
            for field_list_name in ("required_fields", "recommended_fields", "at_least_one_of"):
                fields = []
                for field in requirement.get(field_list_name) or []:
                    normalized_field = (
                        "selected_targets"
                        if field in ("step5_selected_coords", "step5_selected_names")
                        else field
                    )
                    if normalized_field not in fields:
                        fields.append(normalized_field)
                if fields:
                    requirement[field_list_name] = fields
                else:
                    requirement.pop(field_list_name, None)
    if action_requirements:
        payload["action_requirements"] = action_requirements
    response_schema["properties"] = properties
    response_schema["required"] = [
        field
        for field in (response_schema.get("required") or ["action"])
        if field not in ("step5_selected_coords", "step5_selected_names")
    ]
    response_schema.setdefault("required", ["action"])
    payload["response_schema"] = response_schema
    existing_normalization = dict(payload.get("input_normalization") or {})
    rebuilt_normalization = build_input_normalization_contract(
        options,
        payload.get("required_fields") or [],
        properties,
    )
    for list_key in ("rules", "do_not"):
        merged_items = []
        for item in list(existing_normalization.get(list_key) or []) + list(
            rebuilt_normalization.get(list_key) or []
        ):
            if item not in merged_items:
                merged_items.append(item)
        if merged_items:
            rebuilt_normalization[list_key] = merged_items
    for key, value in existing_normalization.items():
        if key not in rebuilt_normalization:
            rebuilt_normalization[key] = value
    payload["input_normalization"] = enrich_input_normalization_contract(
        rebuilt_normalization,
        action_requirements=action_requirements,
        selection_resolution=selection_resolution,
    )
    if project_dir is not None and report_dir is not None:
        payload["resume_command_examples"] = build_resume_command_examples(
            options,
            payload.get("required_fields") or [],
            properties,
            project_dir,
            report_dir,
        )
    return payload


def _user_field_label(field):
    labels = {
        "action": "动作",
        "target_module": "目标模块",
        "primary_module": "目标模块",
        "modules": "模块列表",
        "base_branch": "基准分支",
        "current_branch": "当前分支",
        "base_source_project_dir": "基准侧源码仓库目录",
        "current_source_project_dir": "当前侧源码仓库目录",
        "base_artifact_path": "升级前构建产物",
        "current_artifact_path": "升级后构建产物",
        "jdk_base": "升级前 JDK 版本",
        "jdk_current": "升级后 JDK 版本",
        "springboot_base": "升级前 Spring Boot 版本",
        "springboot_current": "升级后 Spring Boot 版本",
        "source_dirs": "业务源码目录",
        "dependency_source_dirs": "依赖源码目录或 Git 地址",
        "source_repo_hints": "源码仓库线索",
        "dependency_repo_mappings": "依赖源码映射",
        "accept_suggested_mappings": "是否采用建议的依赖源码映射",
        "dependency_git_ref_overrides": "依赖 git ref 确认",
        "dependency_git_ref_selections": "依赖 git ref 方案",
        "source_ref_selections": "主项目源码 ref 方案",
        "retry_remote_fetch": "重试远端 Git 操作",
        "step5_selected_coords": "系统触达证据要分析的依赖坐标",
        "step5_selected_names": "系统触达证据要分析的依赖名称",
        "selected_targets": "选择的依赖包",
        "strict_risk_gate": "严格门控",
        "step4_git_diff_timeout": "源码差异对比超时秒数",
        "step4_japicmp_timeout": "JApiCmp 对比超时秒数",
        "step4_fetch_timeout": "远端 Git fetch 超时秒数",
        "step4_tool_install_timeout": "JApiCmp 工具自动安装超时秒数",
        "restart_step_id": "重跑起点",
        "notes": "备注",
    }
    return labels.get(str(field or "").strip(), str(field or "").strip())


def _user_field_description(field, meta=None):
    meta = meta or {}
    description = str(meta.get("description") or "").strip()
    descriptions = {
        "target_module": "要分析的业务模块。",
        "primary_module": "要分析的业务模块。",
        "modules": "一个或多个要分析的业务模块。",
        "base_branch": "升级前代码所在分支。",
        "current_branch": "升级后代码所在分支。",
        "base_artifact_path": "升级前构建出的 jar/war 路径。",
        "current_artifact_path": "升级后构建出的 jar/war 路径。",
        "jdk_base": "升级前实际使用的 JDK 主版本。",
        "jdk_current": "升级后实际使用的 JDK 主版本。",
        "springboot_base": "升级前实际使用的 Spring Boot 版本。",
        "springboot_current": "升级后实际使用的 Spring Boot 版本。",
        "dependency_source_dirs": "相关依赖源码仓库目录、多模块仓库根目录或 HTTPS/SSH Git 地址。",
        "dependency_repo_mappings": "存在多个源码候选时，明确依赖坐标对应的源码仓库。",
        "accept_suggested_mappings": "采用会增加源码行为覆盖；不采用则保留最终制品证据边界。",
        "dependency_git_ref_overrides": "当依赖版本无法自动匹配 git ref 时，显式给出 old_ref/new_ref。",
        "dependency_git_ref_selections": "从当前决策卡中按依赖选择方案编号。",
        "source_ref_selections": "从当前决策卡中按 base/current 侧选择源码 ref 方案。",
        "retry_remote_fetch": "确认远端状态已正常后，显式重新查询 ref 并重试定向 fetch。",
        "selected_targets": "从 changed_dependencies.md 的“依赖包”列复制完整坐标。",
        "step5_selected_coords": "只分析这些依赖坐标的系统触达证据。",
        "step5_selected_names": "只分析这些依赖名称的系统触达证据。",
        "strict_risk_gate": "要求存在未确认项时不要继续产出无盲区结论。",
    }
    return descriptions.get(str(field or "").strip(), description)


def _format_user_field(field, meta=None):
    label = _user_field_label(field)
    description = _user_field_description(field, meta)
    if description:
        return f"{label}：{description}"
    return label


def _humanize_interaction_text(text):
    value = str(text or "")
    replacements = {
        "Step5 是全量分析": "系统触达证据是覆盖全部依赖",
        "dependency_source_dirs": "依赖源码目录或 Git 地址",
        "dependency_repo_mappings": "依赖源码映射",
        "accept_suggested_mappings": "是否采用建议的依赖源码映射",
        "dependency_git_ref_overrides": "依赖 old_ref/new_ref",
        "source_dirs": "业务源码目录",
        "target_module": "目标模块",
        "project_scope": "项目范围",
        "step5_selected_coords": "系统触达证据要分析的依赖坐标",
        "step5_selected_names": "系统触达证据要分析的依赖名称",
        "selected_targets": "选择的依赖包",
        "selection_key": "依赖坐标",
        "action=continue": "全量分析",
        "restart_step_id": "重跑起始步骤",
        "not_analyzed": "本次未完成分析",
        "allow_degraded=true": "允许降级执行",
    }
    for old, new in replacements.items():
        value = value.replace(old, new)
    for step_id, task_name in USER_TASK_NAMES.items():
        value = re.sub(rf"\b{re.escape(step_id)}\b", task_name, value, flags=re.IGNORECASE)
    value = re.sub(r"(?<=[\u4e00-\u9fff])\s+(?=[\u4e00-\u9fff])", "", value)
    return value


def _response_schema_properties(interaction):
    response_schema = dict((interaction or {}).get("response_schema") or {})
    properties = response_schema.get("properties") or {}
    return properties if isinstance(properties, dict) else {}


def _decision_card_reply_examples(interaction, selection_options, options):
    properties = _response_schema_properties(interaction)
    fields = set(properties)
    for item in (interaction.get("missing_inputs") or []):
        field = str((item or {}).get("field") or "").strip()
        if field:
            fields.add(field)
    required_fields = {
        str(field or "").strip()
        for field in (interaction.get("required_fields") or [])
        if str(field or "").strip() and str(field or "").strip() != "action"
    }
    continue_requirements = dict(
        ((interaction.get("action_requirements") or {}).get("continue") or {})
    )
    required_fields.update(
        str(field or "").strip()
        for field in (continue_requirements.get("required_fields") or [])
        if str(field or "").strip() and str(field or "").strip() != "action"
    )
    examples = []
    option_ids = {str((item or {}).get("id") or "").strip() for item in options}
    git_ref_items = list(interaction.get("git_ref_decision_items") or [])
    source_ref_items = list(interaction.get("source_ref_decision_items") or [])
    if source_ref_items:
        choices = [
            f"{'基准侧' if item.get('side') == 'base' else '当前侧'}选方案 1"
            for item in source_ref_items
            if item.get("status") != "fetch_failed" and item.get("candidates")
        ]
        if choices:
            examples.append("；".join(choices) + "，确认后继续")
        if any(item.get("status") == "fetch_failed" for item in source_ref_items):
            examples.append("网络已恢复，重试 fetch")
    elif git_ref_items:
        selections = []
        for item in git_ref_items:
            coord = str(item.get("coord") or "").strip()
            pair_options = list(item.get("pair_options") or [])
            if coord and pair_options:
                selections.append(f"{coord} 选方案 1")
        if selections:
            examples.append("；".join(selections) + "，确认后重跑")
        if any(item.get("pending_kind") in {"fetch_failed", "remote_query_failed"} for item in git_ref_items):
            examples.append("网络已恢复，重试全部 fetch 失败项")
        if any(item.get("pending_kind") not in {"fetch_failed", "remote_query_failed"} for item in git_ref_items):
            examples.append("我直接提供每个依赖的 old_ref/new_ref，并一次性确认后重跑")
    elif selection_options:
        visible_targets = [
            str(item.get("coord") or item.get("name") or "").strip()
            for item in selection_options[:2]
            if str(item.get("coord") or item.get("name") or "").strip()
        ]
        examples.append("全量继续")
        if visible_targets:
            examples.append("只分析 " + " 和 ".join(visible_targets))
    elif "continue" in option_ids and not required_fields:
        examples.append("继续")

    if "accept_suggested_mappings" in required_fields:
        examples.extend(
            [
                "采用建议的依赖源码映射后继续",
                "不采用建议映射，按最终制品 JAR 证据继续",
            ]
        )
    jdk_fields = {"jdk_base", "jdk_current"} & required_fields
    if jdk_fields:
        values = []
        if "jdk_base" in jdk_fields:
            values.append("升级前 JDK 是 8")
        if "jdk_current" in jdk_fields:
            values.append("升级后 JDK 是 17")
        examples.append("，".join(values) + "，继续")
    springboot_fields = {"springboot_base", "springboot_current"} & required_fields
    if springboot_fields:
        values = []
        if "springboot_base" in springboot_fields:
            values.append("升级前 Spring Boot 是 2.7.18")
        if "springboot_current" in springboot_fields:
            values.append("升级后 Spring Boot 是 3.3.2")
        examples.append("，".join(values) + "，继续")
    if "dependency_repo_mappings" in required_fields:
        examples.append("将 com.example:demo-lib 映射到 /path/to/demo-lib 后继续")

    if {"base_artifact_path", "current_artifact_path"} & fields:
        examples.append("目标模块是 app，升级前产物是 /path/base.jar，升级后产物是 /path/current.jar")
    if {"base_branch", "current_branch"} <= fields:
        examples.append("目标模块是 app，基准分支 main，当前分支 feature/upgrade")
    elif {"base_branch", "current_branch"} & fields:
        examples.append("基准分支 main，当前分支 feature/upgrade")
    if "dependency_source_dirs" in fields:
        examples.append("依赖源码目录是 /path/to/dependency-repo，补充后重跑")
        examples.append("依赖源码 Git 地址是 https://git.example.com/team/dependency-repo.git，补充后重跑")
    if "dependency_git_ref_overrides" in fields:
        examples.append('依赖 com.acme:lib 的 old_ref 是 v1.0.0，new_ref 是 v2.0.0，补充后重跑')
    if {
        "step4_git_diff_timeout",
        "step4_japicmp_timeout",
        "step4_fetch_timeout",
        "step4_tool_install_timeout",
    } & fields:
        examples.append("把 JApiCmp 对比超时放宽到 1800 秒后重新分析")
    if "restart_from_step" in option_ids:
        examples.append("从升级上下文重新分析")

    unique = []
    for item in examples:
        if item and item not in unique:
            unique.append(item)
    return unique[:5]


def build_user_decision_card(interaction):
    lines = []
    interaction = interaction or {}
    question = _humanize_interaction_text(interaction.get("question") or "请确认当前结果，然后继续。").strip()
    lines.append(f"当前需要确认：{question}")

    reason = _humanize_interaction_text(interaction.get("user_reason") or interaction.get("reason") or "").strip()
    if not reason:
        reason = "分析已暂停，等待你确认当前结果或补充信息。"
    lines.append(f"为什么暂停：{reason}")

    recommended = _humanize_interaction_text(interaction.get("recommended_action") or "").strip()
    if recommended:
        lines.append(f"推荐动作：{recommended}")

    missing_inputs = list(interaction.get("missing_inputs") or [])
    if missing_inputs:
        lines.append("需要补充的信息：")
        for item in missing_inputs[:10]:
            field = str(item.get("field") or "").strip()
            label = item.get("label") or _user_field_label(field)
            reason_text = str(item.get("reason") or "").strip()
            suffix = f" - {reason_text}" if reason_text else ""
            lines.append(f"- {label}{suffix}")

    fallback_inputs = list(interaction.get("fallback_inputs") or [])
    if fallback_inputs:
        lines.append("可选补充信息：")
        for item in fallback_inputs[:8]:
            field = str(item.get("field") or "").strip()
            label = item.get("label") or _user_field_label(field)
            reason_text = str(item.get("reason") or "").strip()
            suffix = f" - {reason_text}" if reason_text else ""
            lines.append(f"- {label}{suffix}")

    input_modes = list(interaction.get("input_modes") or [])
    if input_modes:
        lines.append("可选输入方式：")
        for item in input_modes[:5]:
            label = item.get("label") or item.get("id") or "输入方式"
            required_fields = [
                _user_field_label(field)
                for field in (item.get("required_fields") or [])
                if str(field or "").strip()
            ]
            if required_fields:
                lines.append(f"- {label}：需要 " + "、".join(required_fields))
            else:
                lines.append(f"- {label}")

    module_candidates = list(interaction.get("module_candidates") or [])
    if module_candidates:
        module_candidate_file = next(
            (
                str(path)
                for path in (interaction.get("files_to_review") or [])
                if str(path).endswith("module_candidates.md")
            ),
            "",
        )
        lines.append("检测到的目标模块候选：")
        for item in module_candidates[:20]:
            if isinstance(item, dict):
                module = str(
                    item.get("module") or item.get("path") or item.get("name") or ""
                ).strip()
                coord = str(item.get("coord") or "").strip()
                packaging = str(item.get("packaging") or "").strip()
                details = "，".join(value for value in (coord, packaging) if value)
                lines.append(f"- `{module}`" + (f"（{details}）" if details else ""))
            else:
                module = str(item or "").strip()
                if module:
                    lines.append(f"- `{module}`")
        if len(module_candidates) > 20:
            lines.append(f"- 其余 {len(module_candidates) - 20} 个候选未展开。")
            if module_candidate_file:
                lines.append(f"- 完整候选及部署线索见 `{module_candidate_file}`。")
        lines.append("直接回复其中一个完整模块路径即可；系统不会替你猜测部署模块。")

    git_ref_decision_items = list(interaction.get("git_ref_decision_items") or [])
    source_ref_decision_items = list(interaction.get("source_ref_decision_items") or [])
    if source_ref_decision_items:
        lines.append("需要确认的主项目源码 ref：")
        for item in source_ref_decision_items:
            side = str(item.get("side") or "")
            side_label = "基准侧" if side == "base" else "当前侧"
            status = str(item.get("status") or "")
            candidates = list(item.get("candidates") or [])
            if status == "fetch_failed":
                lines.append(f"- {side_label}：远端查询或 fetch 在受控重试后仍失败；无需猜测分支。")
                continue
            lines.append(f"- {side_label}（原输入 `{item.get('requested_ref') or '-'}`）：")
            for index, candidate in enumerate(candidates[:6], start=1):
                ref = candidate.get("ref") or candidate.get("display_ref") or "-"
                commit = str(candidate.get("commit") or "")[:8]
                lines.append(f"  - 方案 {index}：`{ref}`（commit {commit or '?'}）")
            if len(candidates) > 6:
                lines.append(f"  - 当前展示 6 / {len(candidates)} 个候选。")
    if git_ref_decision_items:
        lines.append(f"需要确认的依赖源码版本（共 {len(git_ref_decision_items)} 个，请一次答全）：")
        for item in git_ref_decision_items:
            coord = str(item.get("coord") or "未知依赖").strip()
            old_version = str(item.get("old_version") or "-").strip()
            new_version = str(item.get("new_version") or "-").strip()
            reason_text = _humanize_interaction_text(item.get("reason") or "").strip()
            lines.append(f"- `{coord}`：{old_version} → {new_version}")
            if reason_text:
                lines.append(f"  - 暂停原因：{reason_text}")
            pair_options = list(item.get("pair_options") or [])
            if not pair_options:
                if item.get("pending_kind") in {"fetch_failed", "remote_query_failed"}:
                    lines.append("  - 无需猜测分支；请检查网络/权限后回复“重试远端操作”。")
                else:
                    lines.append("  - 当前没有可供选择的完整远端 ref 组合；请修正源码仓库或直接提供 old/new ref。")
                continue
            for option in pair_options:
                rank = int(option.get("rank") or 0)
                old_ref = str(option.get("old_ref") or "-")
                new_ref = str(option.get("new_ref") or "-")
                old_commit = str(option.get("old_commit") or "")[:8]
                new_commit = str(option.get("new_commit") or "")[:8]
                commit_text = ""
                if old_commit or new_commit:
                    commit_text = f"（commit {old_commit or '?'} → {new_commit or '?'}）"
                traits = []
                if option.get("same_remote"):
                    traits.append("同一 remote")
                if option.get("same_prefix"):
                    traits.append("同一分支族")
                if option.get("version_delta_match") == "exact":
                    traits.append("版本后缀变化一致")
                trait_text = f"；{'、'.join(traits)}" if traits else ""
                lines.append(
                    f"  - 方案 {rank}：升级前 `{old_ref}` → 升级后 `{new_ref}`"
                    f"{commit_text}{trait_text}"
                )
            if item.get("pair_options_truncated"):
                lines.append(
                    f"  - 当前展示 {item.get('displayed_pair_option_count')} / "
                    f"{item.get('pair_option_count')} 个方案；可在 git_ref_pending.json 查看完整候选。"
                )

    options = list(interaction.get("options") or [])
    selection_options = list(interaction.get("selection_options") or [])
    if selection_options:
        selection_resolution = interaction.get("selection_resolution") or {}
        scope_preview = dict(interaction.get("scope_preview") or {})
        all_selection_options = list(selection_resolution.get("options") or [])
        total_candidates = len(all_selection_options) or len(selection_options)
        total_api_count = int(
            scope_preview.get("total_api_count")
            if scope_preview.get("total_api_count") is not None
            else sum(_parse_int_or_zero(item.get("api_count")) for item in all_selection_options)
        )
        total_high_risk_count = int(
            scope_preview.get("high_risk_api_count")
            if scope_preview.get("high_risk_api_count") is not None
            else sum(
                _parse_int_or_zero(item.get("high_risk_api_count"))
                for item in all_selection_options
            )
        )
        recommended_options = list(interaction.get("recommended_selection_options") or [])
        if not recommended_options:
            recommended_options = [
                item for item in selection_options if _is_recommended_selection_target(item)
            ]
        recommended_total = int(
            interaction.get("recommended_candidate_count")
            if interaction.get("recommended_candidate_count") is not None
            else len(recommended_options)
        )
        displayed_recommended = min(10, len(recommended_options))
        full_candidate_file = next(
            (
                str(path)
                for path in (interaction.get("files_to_review") or [])
                if str(path).endswith("changed_dependencies.md")
            ),
            "",
        )
        if not full_candidate_file:
            full_candidate_file = str(selection_resolution.get("source_file") or "").strip()
        lines.append("请选择分析范围：")
        lines.append("1. 全量分析（默认，完整性优先）")
        lines.append(
            f"- 覆盖全部 {total_candidates} 个变化依赖、{total_api_count} 个变化 API，"
            f"其中高风险 API {total_high_risk_count} 个。"
        )
        lines.append("- 没有明确耗时约束时选择这一项。")
        lines.append("- 直接回复：全量继续")
        lines.append("2. 部分分析（仅在明确控制耗时时）")
        lines.append("- 未选择的依赖及其变化 API 不会进入系统触达分析，最终报告只适用于所选范围。")
        lines.append("- 高优先级项依据：含高风险 API、删除或签名变化，或变化 API 数不少于 20 个。")
        lines.append("- 该排序只帮助部分分析时取舍，不表示系统建议缩小范围，也不代表已经确认影响。")
        if recommended_total:
            lines.append(
                f"- 推荐 {recommended_total} 个，展示 {displayed_recommended} / {recommended_total} 个。"
            )
            lines.append("| 部分分析高优先级依赖 | 变化 API 数 | 高风险 API 数 |")
            lines.append("|---|---:|---:|")
            for item in recommended_options[:10]:
                lines.append(
                    f"| `{item.get('coord') or item.get('name') or ''}` | "
                    f"{item.get('api_count') or 0} | {item.get('high_risk_api_count') or 0} |"
                )
            first_recommended_coord = str(
                recommended_options[0].get("coord")
                or recommended_options[0].get("name")
                or ""
            ).strip()
            if first_recommended_coord:
                lines.append(f"- 直接回复，例如：只分析 {first_recommended_coord}")
            if recommended_total > displayed_recommended:
                remaining_recommended = recommended_total - displayed_recommended
                if full_candidate_file:
                    lines.append(
                        f"- 其余 {remaining_recommended} 个高优先级项见 `{full_candidate_file}` 的“部分分析优先项”列。"
                    )
        else:
            lines.append("- 当前没有符合高优先级规则的候选依赖包。")
        displayed_candidates = selection_options[:20]
        lines.append(
            f"- 可直接选择的依赖（展示 {len(displayed_candidates)} / {total_candidates} 个；"
            "直接回复依赖名称或完整坐标）："
        )
        lines.append("| 依赖包 | 变化 API 数 | 高风险 API 数 |")
        lines.append("|---|---:|---:|")
        for item in displayed_candidates:
            lines.append(
                f"| `{item.get('coord') or item.get('name') or ''}` | "
                f"{item.get('api_count') or 0} | {item.get('high_risk_api_count') or 0} |"
            )
        visible_targets = [
            str(item.get("coord") or item.get("name") or "").strip()
            for item in displayed_candidates[:2]
            if str(item.get("coord") or item.get("name") or "").strip()
        ]
        if visible_targets:
            lines.append("- 直接回复，例如：只分析 " + " 和 ".join(visible_targets))
        if total_candidates > len(displayed_candidates):
            remaining = total_candidates - len(displayed_candidates)
            lines.append(f"- 还有 {remaining} 个候选未在卡片中展示。")
        if full_candidate_file:
            lines.append(
                f"- 完整依赖选择清单：`{full_candidate_file}`。"
            )
            lines.append(
                "- 该文件不是普通复核材料；需要选择未展示的依赖时，"
                "从“依赖包”列复制名称或完整坐标，然后直接回复“只分析 …”。"
            )

    if options:
        primary_options = [
            option for option in options
            if (
                str(option.get("id") or "").strip() != "restart_from_step"
                and not (
                    selection_options
                    and str(option.get("id") or "").strip() == "continue"
                )
            )
        ]
        advanced_options = [
            option for option in options
            if str(option.get("id") or "").strip() == "restart_from_step"
        ]
        if primary_options:
            lines.append("你可以选择：")
        for option in primary_options:
            option_id = str(option.get("id") or "").strip()
            label = option.get("label") or USER_ACTION_LABELS.get(option_id, "选择此处理方式")
            desc = _humanize_interaction_text(option.get("description") or "").strip()
            suffix = f" - {desc}" if desc else ""
            lines.append(f"- {label}{suffix}")
        if advanced_options:
            lines.append("需要修正更早输入时：")
            for option in advanced_options:
                label = option.get("label") or USER_ACTION_LABELS["restart_from_step"]
                desc = _humanize_interaction_text(option.get("description") or "").strip()
                lines.append(f"- {label}" + (f" - {desc}" if desc else ""))

    files_to_review = list(interaction.get("files_to_review") or [])
    if files_to_review:
        lines.append("完整候选或证据文件：")
        for path in files_to_review:
            if selection_options and str(path).endswith("changed_dependencies.md"):
                lines.append(
                    f"- 完整依赖选择清单：`{path}`"
                    "（包含未展示候选；部分分析时从“依赖包”列选择）"
                )
            else:
                lines.append(f"- `{path}`")

    checklist_lines = [
        _humanize_interaction_text(item).strip()
        for item in (interaction.get("checklist_lines") or [])
        if str(item or "").strip()
    ]
    if checklist_lines:
        lines.append("复核提示：")
        for item in checklist_lines[:8]:
            lines.append(f"- {item.lstrip('- ').strip()}")

    reply_examples = _decision_card_reply_examples(interaction, selection_options, options)
    if reply_examples:
        lines.append("你可以直接回复：")
        for item in reply_examples:
            lines.append(f"- “{item}”")
    return lines


def allowed_restart_step_ids(current_step_id):
    current_step_id = str(current_step_id or "").strip()
    if current_step_id not in STEP_SEQUENCE:
        return list(STEP_SEQUENCE)
    return STEP_SEQUENCE[: STEP_SEQUENCE.index(current_step_id) + 1]


def augment_interaction_meta_with_restart_option(step_id, interaction_meta):
    base = dict(interaction_meta or {})
    options = [dict(item) for item in (base.get("options", []) or [])]
    if not any(str(item.get("id") or "").strip() == "restart_from_step" for item in options):
        options.append(
            {
                "id": "restart_from_step",
                "label": "从指定步骤重跑",
                "description": "通过对话指定 restart_step_id，从该步骤重新执行。",
            }
        )
    base["options"] = options

    response_schema = dict(base.get("response_schema") or {})
    properties = dict(response_schema.get("properties") or {})
    action_prop = dict(properties.get("action") or {})
    enums = [str(v) for v in (action_prop.get("enum") or []) if str(v).strip()]
    if "restart_from_step" not in enums:
        enums.append("restart_from_step")
    action_prop["enum"] = enums
    properties["action"] = action_prop
    properties.setdefault(
        "restart_step_id",
        {
            "type": "string",
            "enum": allowed_restart_step_ids(step_id),
            "description": "当 action=restart_from_step 时必填，只能选择当前步骤或更早步骤。",
        },
    )
    response_schema["properties"] = properties
    response_schema.setdefault("required", ["action"])
    base["response_schema"] = response_schema
    return base


def print_interaction_to_streams(interaction, report_dir, event="interaction_required"):
    if not interaction:
        return
    output_mode = str(os.environ.get("JUA_INTERACTION_OUTPUT") or "auto").strip().lower()
    if output_mode not in {"auto", "human", "json", "both"}:
        output_mode = "auto"
    human_enabled = output_mode != "json"
    machine_enabled = output_mode in {"json", "both"} or (
        output_mode == "auto" and not bool(getattr(sys.stdout, "isatty", lambda: False)())
    )
    runtime_rules = interaction.get("runtime_rules", []) or []
    next_action_rule = interaction.get("next_action_rule")
    resume_examples = interaction.get("resume_command_examples", []) or []
    task_name = USER_TASK_NAMES.get(str(interaction.get("step_id") or "").lower(), interaction.get("title") or "当前分析")
    user_decision_card = list(
        interaction.get("user_decision_card") or build_user_decision_card(interaction)
    )
    if human_enabled:
        sys.stderr.write("\n")
        sys.stderr.write("【分析已暂停，等待你的确认】\n")
        sys.stderr.write(f"当前任务：{task_name}\n")
        for line in user_decision_card:
            sys.stderr.write(f"{line}\n")
    missing_inputs = interaction.get("missing_inputs", []) or []
    fallback_inputs = interaction.get("fallback_inputs", []) or []
    input_modes = interaction.get("input_modes", []) or []
    files_to_review = interaction.get("files_to_review", []) or []
    options = interaction.get("options", []) or []
    action_requirements = interaction.get("action_requirements") or {}
    selection_options = interaction.get("selection_options", []) or []
    if human_enabled:
        sys.stderr.write("\n")
        sys.stderr.flush()
    if not machine_enabled:
        return
    sys.stdout.write(
        "JUA_CONFIRMATION_JSON:" + json.dumps(
            {
                "schema": "java-upgrade-analyzer.confirmation.v1",
                "event": event,
                "status": normalize_interaction_status(interaction.get("status")),
                "exit_code": EXIT_AWAITING_USER,
                "step_id": interaction.get("step_id"),
                "title": interaction.get("title"),
                "question": interaction.get("question"),
                "user_decision_card": user_decision_card,
                "reason_code": interaction.get("reason_code"),
                "summary": interaction.get("summary"),
                "options": interaction.get("options", []),
                "files_to_review": files_to_review,
                "required_fields": interaction.get("required_fields", []),
                "missing_inputs": missing_inputs,
                "fallback_inputs": fallback_inputs,
                "input_modes": input_modes,
                "response_schema": interaction.get("response_schema", {}),
                "input_normalization": interaction.get("input_normalization", {}),
                "action_requirements": action_requirements,
                "selection_options": selection_options,
                "recommended_selection_options": interaction.get(
                    "recommended_selection_options", []
                ),
                "recommended_candidate_count": interaction.get(
                    "recommended_candidate_count", 0
                ),
                "selection_resolution": interaction.get("selection_resolution", {}),
                "scope_preview": interaction.get("scope_preview", {}),
                "git_ref_decision_items": interaction.get("git_ref_decision_items", []),
                "runtime_rules": runtime_rules,
                "next_action_rule": interaction.get("next_action_rule"),
                "must_wait_for_user_reply": interaction.get("must_wait_for_user_reply", True),
                "rules_file": interaction.get("rules_file"),
                "resume_command_examples": resume_examples,
                "checkpoint": interaction.get("checkpoint", True),
                "hard_stop": interaction.get("hard_stop", True),
                "awaiting_user_input": True,
                "interaction_file": str((runtime_state_dir(report_dir) / "interaction.json").resolve()),
            },
            ensure_ascii=False,
        )
        + "\n"
    )
    sys.stdout.flush()


def build_dependency_source_dirs_state(run_context, report_dir):
    runtime_view = dict(run_context or {})
    dependency_source_dirs = _dedupe_strings(runtime_view.get("dependency_source_dirs") or [])
    current_mapping = _current_dependency_repo_mapping_map(runtime_view)
    relevant_coords = _collect_relevant_dependency_coords(report_dir) if report_dir else []
    recognized = bool(_discover_dependency_source_candidates(dependency_source_dirs)) if dependency_source_dirs else False
    uncovered_target_coords = [coord for coord in relevant_coords if coord not in current_mapping]
    covers_targets = bool(current_mapping)
    if relevant_coords:
        covers_targets = not uncovered_target_coords
    required_uncovered_coords = []
    if report_dir:
        summary_path = step5_call_chain_dir(report_dir) / "summary.json"
        call_summary = read_json(summary_path) if summary_path.exists() else {}
        for item in list(call_summary.get("uncertain_apis") or []) + list(call_summary.get("not_analyzed_apis") or []):
            if str(item.get("reason_code") or "").strip() != "DEPENDENCY_SOURCE_MAPPING_MISSING":
                continue
            coords = list(item.get("dependency_chain_coords") or [])
            if not coords and item.get("coord"):
                coords = [item.get("coord")]
            for coord in coords:
                coord = str(coord or "").strip()
                if coord and coord not in current_mapping and coord not in required_uncovered_coords:
                    required_uncovered_coords.append(coord)
    return {
        "provided": bool(dependency_source_dirs),
        "recognized": recognized,
        "covers_targets": covers_targets,
        "dependency_source_dirs": dependency_source_dirs,
        "current_mapped_coords": sorted(current_mapping.keys()),
        "uncovered_target_coords": uncovered_target_coords,
        "required_uncovered_coords": required_uncovered_coords,
        "analysis_requires_more_source": bool(required_uncovered_coords),
    }


def annotate_dependency_source_dirs_interaction(interaction, run_context, report_dir):
    payload = dict(interaction or {})
    if not payload:
        return payload
    response_schema = dict(payload.get("response_schema") or {})
    properties = dict(response_schema.get("properties") or {})
    has_dependency_source_dirs_field = "dependency_source_dirs" in properties
    reason_code = str(payload.get("reason_code") or "").strip()
    if not has_dependency_source_dirs_field and reason_code != "step5_dependency_source_mapping_missing":
        return payload

    source_state = build_dependency_source_dirs_state(run_context, report_dir)
    payload["dependency_source_dirs_state"] = source_state

    if reason_code != "step5_dependency_source_mapping_missing":
        if has_dependency_source_dirs_field:
            dep_dirs_prop = dict(properties.get("dependency_source_dirs") or {})
            dep_dirs_prop["description"] = (
                "可选增强。已检测到目录时，仅当现有目录不正确或覆盖范围不足时填写修正值；"
                "缺失不会触发例行确认。"
            )
            properties["dependency_source_dirs"] = dep_dirs_prop
            response_schema["properties"] = properties
            payload["response_schema"] = response_schema
        return payload

    question_prefix = ""
    if not source_state.get("provided"):
        question_prefix = "当前还没有可用于该调用链分析的依赖源码目录。"
    elif not source_state.get("recognized"):
        question_prefix = "已收到依赖源码目录，但当前目录未识别出有效依赖源码仓库。"
    elif (
        str(payload.get("step_id") or "").strip() == "step5"
        and reason_code != "step5_dependency_source_mapping_missing"
        and not source_state.get("analysis_requires_more_source")
    ):
        question_prefix = (
            "已识别依赖源码目录；本轮没有因依赖源码缺失而中断的 API。"
            "被删除依赖本身已有旧 JAR 符号证据，不要求额外提供其源码。"
        )
    elif source_state.get("required_uncovered_coords"):
        missing = ", ".join((source_state.get("required_uncovered_coords") or [])[:10])
        question_prefix = f"已收到依赖源码目录，但这些实际调用链仍因缺少依赖源码而中断：{missing}。"
    elif source_state.get("uncovered_target_coords"):
        missing = ", ".join((source_state.get("uncovered_target_coords") or [])[:10])
        question_prefix = f"已收到依赖源码目录，但当前仍未覆盖这些目标依赖坐标：{missing}。"
    elif source_state.get("covers_targets"):
        question_prefix = "已收到依赖源码目录；仅当现有目录不正确或覆盖范围不足时才需要修正。"
    elif source_state.get("provided"):
        question_prefix = "已收到依赖源码目录；请确认当前目录是否仍然适用于本次重跑。"

    checklist_lines = list(payload.get("checklist_lines") or [])
    if question_prefix and question_prefix not in checklist_lines:
        checklist_lines.insert(0, question_prefix)
    recorded_dirs = list((source_state.get("dependency_source_dirs") or [])[:5])
    dir_preview = "当前已记录目录： " + ", ".join(recorded_dirs)
    if recorded_dirs and dir_preview not in checklist_lines:
        checklist_lines.insert(1, dir_preview)
    payload["checklist_lines"] = checklist_lines

    question = str(payload.get("question") or "").strip()
    if reason_code == "step5_dependency_source_mapping_missing":
        if source_state.get("provided"):
            payload["question"] = (
                question_prefix
                + "请补充仍缺失的依赖源码目录，或确认现有目录需要替换后再重跑。"
            )
        else:
            payload["question"] = (
                question_prefix
                + "请补充依赖源码目录后重跑 Step5；如果暂时没有源码，可以明确选择降级执行。"
            )
    if has_dependency_source_dirs_field:
        dep_dirs_prop = dict(properties.get("dependency_source_dirs") or {})
        dep_dirs_prop["description"] = (
            "可选。填写依赖源码目录、仓库根目录或 Git 地址；仅当现有输入不正确、无法识别，"
            "或仍未覆盖目标依赖时再修正。字段名为 dependency_source_dirs。"
        )
        properties["dependency_source_dirs"] = dep_dirs_prop
        response_schema["properties"] = properties
        payload["response_schema"] = response_schema
    return payload


def build_interaction_payload(step_id, report_dir, manifest_steps, project_dir, run_context=None, main_state=None):
    step_meta = manifest_steps.get(step_id) or {}
    scope_confirmation_only = bool(step_meta.get("requires_scope_confirmation"))
    if "interaction" in step_meta and step_meta.get("interaction") is None:
        return None
    interaction_meta = step_meta.get("interaction")
    if not interaction_meta and step_meta.get("confirm") is False:
        return None
    interaction_meta = interaction_meta or {
        "type": "decision",
        "question": "请确认当前结果是否可接受，然后继续执行下一步。",
        "options": [
            {"id": "continue", "label": "继续", "description": "确认当前结果可接受，继续执行下一步。"},
            {"id": "cancel", "label": "取消", "description": "停止本次执行，稍后再继续。"},
        ],
    }
    interaction_meta = augment_interaction_meta_with_restart_option(step_id, interaction_meta)
    title = f"{step_id} {step_meta.get('title') or ''}（进入下一步前请确认）".strip()
    outputs = step_meta.get("outputs", []) or []
    if step_id == "step5":
        files_to_review = [
            str((step5_call_chain_dir(report_dir) / "alerts.csv").resolve()),
        ]
    else:
        files_to_review = [str(artifact_path(report_dir, rel).resolve()) for rel in outputs]
    checklist_lines = []
    if files_to_review:
        checklist_lines.append("需要打开并复核的产物：")
        for item in files_to_review:
            checklist_lines.append(f"  - {item}")
    notes = step_meta.get("notes", []) or []
    if notes:
        checklist_lines.append("建议复核要点：")
        for note in notes:
            checklist_lines.append(f"  - {note}")
    if step_id == "step1":
        runtime_view = dict(previous_step_output(main_state or {}, step_id) or {})
        runtime_view.update((main_state or {}).get(step_id, {}).get("input") or {})
        runtime_view.update(run_context or {})
        mode_info = infer_step1_mode_fields(runtime_view)
        missing_context_fields = []
        if mode_info.get("analysis_mode") == "artifact_inputs":
            if not str(runtime_view.get("base_branch") or "").strip():
                missing_context_fields.append("base_branch")
            if not str(runtime_view.get("current_branch") or "").strip():
                missing_context_fields.append("current_branch")
        if missing_context_fields:
            interaction_meta["question"] = (
                "两侧制品和依赖变化范围已经生成。继续推断升级上下文前，"
                "请补充缺失的基准侧/当前侧分支，并同时确认目标模块和依赖范围是否正确。"
            )
            interaction_meta["reason_code"] = "step1_context_refs_required"
            interaction_meta["required_fields"] = _dedupe_strings(
                [
                    field
                    for field in (interaction_meta.get("required_fields") or [])
                    if field != "action"
                ]
                + missing_context_fields
            )
            interaction_meta["missing_inputs"] = [
                {
                    "field": field,
                    "label": "基准侧分支" if field == "base_branch" else "当前侧分支",
                    "reason": "该分支用于只读推断 JDK、构建上下文和版本差异，不替代最终制品证据。",
                }
                for field in missing_context_fields
            ]
            action_requirements = dict(interaction_meta.get("action_requirements") or {})
            continue_requirements = dict(action_requirements.get("continue") or {})
            continue_requirements["required_fields"] = missing_context_fields
            continue_requirements["description"] = (
                "补齐两侧分支后，系统会直接继续生成升级上下文，不再重复确认已确定的模块和依赖范围。"
            )
            action_requirements["continue"] = continue_requirements
            interaction_meta["action_requirements"] = action_requirements
            checklist_lines.extend([
                "继续前仍需补齐：" + "、".join(
                    "基准侧分支" if field == "base_branch" else "当前侧分支"
                    for field in missing_context_fields
                ),
                "这些分支只用于上下文推断；API 事实仍以两侧最终制品为准。",
            ])
    if step_id == "step2":
        context_json = step2_context_path(report_dir)
        dep_graph_json = step2_dep_graph_path(report_dir)
        ctx = read_json(context_json) if context_json.exists() else {}
        runtime_view = dict(previous_step_output(main_state or {}, step_id) or {})
        runtime_view.update((main_state or {}).get(step_id, {}).get("input") or {})
        runtime_view.update(run_context or {})
        suggestions = build_dependency_repo_mapping_suggestions(runtime_view, ctx)
        proposed_paths = suggested_dependency_repo_mappings(suggestions)
        mapping_summary_path, mapping_summary = write_step2_source_mapping_summary(report_dir, runtime_view, ctx)
        mapping_counts = mapping_summary.get("counts") or {}
        extra_files = [str(context_json.resolve()), str(dep_graph_json.resolve())]
        extra_files.append(str(mapping_summary_path.resolve()))
        for item in extra_files:
            if item not in files_to_review:
                files_to_review.append(item)
        checklist_lines.extend(
            [
                "关键口径确认（影响后续 Step3/Step4/Step5）：",
                f"  - base_branch={ctx.get('base_branch')}",
                f"  - current_branch={ctx.get('current_branch')}",
                f"  - jdk={ctx.get('jdk_base') or '❓'} -> {ctx.get('jdk_current') or '❓'}",
                f"  - springboot={ctx.get('springboot_base') or '❓'} -> {ctx.get('springboot_current') or '❓'} (source={ctx.get('springboot_version_source')})",
                f"  - changed_dependencies={len(ctx.get('changed_dependencies') or [])}",
                f"  - source_dirs={mapping_counts.get('source_dirs', 0)} status={mapping_summary.get('source_dirs_status')}",
                f"  - context={context_json}",
                f"  - dep_graph={dep_graph_json}",
                f"  - source_mapping_summary={mapping_summary_path}",
            ]
        )
        if mapping_summary.get("source_dirs"):
            for item in mapping_summary.get("source_dirs", [])[:10]:
                checklist_lines.append(f"  - 业务源码: {item}")
        else:
            checklist_lines.append("  - 业务源码缺失: 继续到 Step3/Step4/Step5 前必须先补 source_dirs")
        checklist_lines.append("依赖包源码映射确认（影响 Step4 git diff 与 Step5 调用链分析）：")
        checklist_lines.append(
            f"  - dependency_source_dirs={mapping_counts.get('dependency_source_dirs', 0)} "
            f"confirmed_target_mappings={mapping_counts.get('confirmed_target_mappings', 0)}"
        )
        checklist_lines.append(
            f"  - 自动识别结果: matched_target={mapping_counts.get('confirmed_target_mappings', 0)} "
            f"detected_source_matches={mapping_counts.get('detected_source_matches', 0)}"
        )
        if mapping_counts.get("ambiguous_coords", 0):
            checklist_lines.append(
                f"  - 存在坐标冲突: {mapping_counts.get('ambiguous_coords', 0)} 个，需要人工确认后再继续"
            )
        checklist_lines.append(
            f"  - 目标依赖映射命中={mapping_counts.get('confirmed_target_mappings', 0)}/"
            f"{mapping_counts.get('target_dependency_coords', 0)}"
        )
        if mapping_summary.get("confirmed_target_mappings"):
            for item in mapping_summary.get("confirmed_target_mappings", [])[:10]:
                checklist_lines.append(
                    f"  - 已映射: {item.get('coord')} -> {item.get('repo_path')}"
                )
        if mapping_summary.get("detected_source_matches"):
            for item in mapping_summary.get("detected_source_matches", [])[:10]:
                checklist_lines.append(f"  - 自动依赖源码映射: {item}")
        if mapping_summary.get("ambiguous_coords"):
            for item in mapping_summary.get("ambiguous_coords", [])[:10]:
                checklist_lines.append(
                    f"  - 坐标冲突: {item.get('coord')} 候选仓库={', '.join((item.get('repo_paths') or [])[:3])}"
                )
        if mapping_summary.get("unmapped_target_coords"):
            checklist_lines.append(
                f"  - 尚未映射目标依赖: {', '.join(mapping_summary.get('unmapped_target_coords')[:10])}"
            )
        problematic_repo_scans = [
            item for item in (mapping_summary.get("dependency_repo_scans") or [])
            if item.get("status") != "mapped_dependency_repo"
        ]
        for item in problematic_repo_scans[:10]:
            status = item.get("status")
            if status == "no_coords_inferred":
                checklist_lines.append(
                    f"  - 目录未识别出模块坐标: {item.get('repo_path')}"
                )
            elif status == "inferred_non_target_only":
                checklist_lines.append(
                    f"  - 目录仅识别到非目标模块: {item.get('repo_path')} -> "
                    f"{', '.join((item.get('other_inferred_coords') or [])[:5])}"
                )
            elif status == "matched_target_not_applied":
                checklist_lines.append(
                    f"  - 命中目标依赖但尚未写入映射: {item.get('repo_path')} -> "
                    f"{', '.join((item.get('matched_target_coords') or [])[:5])}"
                )
        if runtime_view.get("source_repo_hints"):
            checklist_lines.append("源码线索解析结果（仅保留当前系统引用的升级依赖映射建议）：")
            for item in suggestions.get("confirmed", [])[:20]:
                checklist_lines.append(
                    f"  - 已确认: {item.get('coord')} -> {item.get('repo_path')} ({item.get('reason')})"
                )
            for item in suggestions.get("proposed", [])[:20]:
                checklist_lines.append(
                    f"  - 建议映射: {item.get('coord')} -> {item.get('repo_path')} [{item.get('confidence')}]"
                )
            for item in suggestions.get("ambiguous", [])[:20]:
                candidate_paths = ", ".join(
                    f"{cand.get('repo_path')}" for cand in (item.get("candidates") or [])[:3]
                )
                checklist_lines.append(
                    f"  - 待确认: {item.get('coord')} 候选仓库={candidate_paths or '(无)'}"
                )
            if suggestions.get("unmatched"):
                checklist_lines.append(
                    f"  - 未匹配目标依赖: {', '.join(suggestions.get('unmatched')[:10])}"
                )
            if proposed_paths:
                checklist_lines.append("继续流程不会自动接受建议映射，避免把流程确认和证据选择混为一体。")
                checklist_lines.append("请直接说明“采用建议映射”或“不采用建议映射，按最终制品证据继续”。")
        review_path = write_step2_review(report_dir, ctx, mapping_summary, runtime_view)
        target_module = (
            runtime_view.get("target_module")
            or runtime_view.get("primary_module")
            or ctx.get("target_module")
            or ctx.get("primary_module")
            or "未指定"
        )
        files_to_review = [str(review_path.resolve())]
        checklist_lines = [
            "请确认以下信息是否符合本次升级范围：",
            f"  - 目标模块：{target_module}",
            f"  - 比较版本：{ctx.get('base_branch') or '未识别'} → {ctx.get('current_branch') or '未识别'}",
            f"  - JDK：{ctx.get('jdk_base') or '未识别'} → {ctx.get('jdk_current') or '未识别'}",
            f"  - Spring Boot：{ctx.get('springboot_base') or '未识别'} → {ctx.get('springboot_current') or '未识别'}",
            f"  - 发生变化的依赖包：{len(ctx.get('changed_dependencies') or [])} 个",
            f"  - 已匹配依赖源码：{mapping_counts.get('confirmed_target_mappings', 0)} / {mapping_counts.get('target_dependency_coords', 0)} 个目标依赖",
            f"完整确认页：{review_path.resolve()}",
        ]
        confirmation = build_step2_confirmation_requirements(
            ctx, mapping_summary, runtime_view
        )
        if step_meta.get("conditional_confirmation") and not confirmation.get("required"):
            return None
        if confirmation.get("required"):
            reason_text = "；".join(confirmation.get("reasons") or [])
            interaction_meta["type"] = "input_request"
            interaction_meta["reason_code"] = confirmation.get("reason_code")
            if confirmation.get("reason_code") == "step2_source_mapping_decision_required":
                interaction_meta["question"] = (
                    "现有源码线索生成了会改变源码行为覆盖率的映射建议："
                    f"{reason_text}。请明确是否采用这些建议后继续。"
                )
                interaction_meta["options"] = [
                    {
                        "id": "continue",
                        "label": "说明采用或不采用后继续",
                        "description": "采用会增加源码行为覆盖；不采用则保留最终制品证据边界。",
                    },
                    {
                        "id": "cancel",
                        "label": "稍后处理",
                        "description": "保留当前分析现场，稍后再决定。",
                    },
                    {
                        "id": "restart_from_step",
                        "label": "从指定任务重新分析",
                        "description": "仅在需要修正更早输入时使用。",
                    },
                ]
            else:
                interaction_meta["question"] = (
                    "自动生成的升级上下文仍有会影响后续分析口径的事项："
                    f"{reason_text}。请一次处理后继续。"
                )
            interaction_meta["required_fields"] = list(
                confirmation.get("required_fields") or []
            )
            action_requirements = dict(interaction_meta.get("action_requirements") or {})
            continue_requirements = dict(action_requirements.get("continue") or {})
            continue_requirements["required_fields"] = list(
                confirmation.get("required_fields") or []
            )
            continue_requirements["description"] = (
                "请补齐无法确定的事实；若存在源码映射建议，必须明确说明采用或不采用。"
            )
            action_requirements["continue"] = continue_requirements
            interaction_meta["action_requirements"] = action_requirements
            checklist_lines = [
                "以下事项无法由系统替你决定：",
                *[f"  - {item}" for item in confirmation.get("reasons") or []],
                f"完整上下文页：{review_path.resolve()}",
            ]
            for item in confirmation.get("proposed_mappings") or []:
                checklist_lines.append(
                    f"  - 建议映射：{item.get('coord')} -> {item.get('repo_path')}"
                )
            if confirmation.get("proposed_mappings"):
                checklist_lines.append(
                    "采用会增加对应依赖的源码行为覆盖；不采用则按最终制品 JAR 证据继续，"
                    "并在报告中保留源码行为覆盖边界。"
                )
    if step_id == "step4":
        all_changed_apis = step4_api_changes_dir(report_dir) / "all_changed_apis.csv"
        available_rows = read_csv_rows(all_changed_apis)
        target_summary = build_step5_dependency_selection_summary(report_dir)
        available_target_count = int(target_summary.get("available_target_count") or 0)
        # A scope checkpoint is meaningful only when the user can choose between
        # at least two different dependency sets. With zero targets Step5 has no
        # work; with one target, selecting that target is identical to full scope.
        minimum_scope_candidates = max(
            2, int(step_meta.get("scope_confirmation_min_candidates") or 2)
        )
        if scope_confirmation_only and available_target_count < minimum_scope_candidates:
            return None
        full_selection_options = build_interaction_selection_options(
            [
                {
                    "selection_key": item.get("selection_key") or f"coord:{item.get('coord')}",
                    "coord": item.get("coord"),
                    "name": item.get("name"),
                    "api_count": item.get("api_count"),
                    "high_risk_api_count": item.get("high_risk_api_count"),
                    "recommended": item.get("recommended"),
                    "change_types": item.get("change_types"),
                    "detail": item.get("detail"),
                    "label": item.get("coord") or item.get("name"),
                }
                for item in target_summary.get("available_targets", [])
            ]
        )
        selection_options = full_selection_options[:20]
        recommended_selection_options = build_interaction_selection_options(
            [item for item in full_selection_options if item.get("recommended")]
        )
        interaction_meta["selection_options"] = selection_options
        interaction_meta["recommended_selection_options"] = recommended_selection_options[:20]
        interaction_meta["recommended_candidate_count"] = len(recommended_selection_options)
        interaction_meta["selection_resolution"] = build_selection_resolution(full_selection_options)
        total_api_count = len(available_rows) or sum(
            _parse_int_or_zero(item.get("api_count"))
            for item in full_selection_options
        )
        interaction_meta["scope_preview"] = {
            "available_dependency_count": available_target_count,
            "total_api_count": total_api_count,
            "high_risk_api_count": sum(
                _parse_int_or_zero(item.get("high_risk_api_count"))
                for item in full_selection_options
            ),
            "partial_scope_effect": (
                "未选择的变化依赖不会进入系统触达分析；最终报告只适用于所选范围。"
            ),
        }
        checklist_lines.append("当前需要确认：系统触达分析是覆盖全部变化依赖，还是只分析部分依赖？")
        checklist_lines.append("默认动作：全量分析；依赖数量多本身不构成缩小范围的理由。")
        checklist_lines.append("只有用户明确需要控制耗时时，才从完整候选清单中选择一个或多个依赖坐标。")
        checklist_lines.append("完整候选清单见 evidence/api_changes/changed_dependencies.md；需要自动化筛选时再用 changed_dependencies.csv。")
        checklist_lines.append(
            f"  - 可选依赖数={target_summary.get('available_target_count', 0)} "
            f"变化 API 行数={len(available_rows)}"
        )
        for item in selection_options[:10]:
            checklist_lines.append(
                f"  - 可选择 `{item.get('coord') or item.get('name')}`："
                f"变化 API {item.get('api_count') or 0}，"
                f"高风险 API {item.get('high_risk_api_count') or 0}"
            )
        if target_summary.get("available_target_count", 0) > 10:
            checklist_lines.append(
                "  - 未展示候选位于完整依赖选择清单 "
                "evidence/api_changes/changed_dependencies.md；"
                "从“依赖包”列取得名称或完整坐标后，直接回复“只分析 …”"
            )
        existing_selection = build_step5_selection_summary(
            available_rows,
            selected_coords=(run_context or {}).get("step5_selected_coords"),
            selected_names=(run_context or {}).get("step5_selected_names"),
        )
        if existing_selection.get("selected_coords") or existing_selection.get("selected_names"):
            checklist_lines.append("当前已记录的 Step5 定向分析范围：")
            if existing_selection.get("selected_coords"):
                checklist_lines.append(
                    "  - 已选坐标: " + ", ".join(existing_selection.get("selected_coords")[:10])
                )
            if existing_selection.get("selected_names"):
                checklist_lines.append(
                    "  - 已选名称: " + ", ".join(existing_selection.get("selected_names")[:10])
                )
            checklist_lines.append(
                f"  - 当前命中依赖={len(existing_selection.get('matched_coords') or [])} "
                f"命中 API 行={existing_selection.get('matched_row_count', 0)}"
            )
            if existing_selection.get("unmatched_coords"):
                checklist_lines.append(
                    "  - 未匹配坐标: " + ", ".join(existing_selection.get("unmatched_coords")[:10])
                )
            if existing_selection.get("unmatched_names"):
                checklist_lines.append(
                    "  - 未匹配名称: " + ", ".join(existing_selection.get("unmatched_names")[:10])
                )
        files_to_review = [
            str((step4_api_changes_dir(report_dir) / "changed_dependencies.md").resolve()),
        ]
        checklist_lines = [
            "请选择系统触达证据的分析范围：",
            f"  - 全部分析：覆盖 {available_target_count} 个发生 API 变化的依赖包。",
            f"  - 全部变化 API：{total_api_count} 个；其中高风险 API："
            f"{interaction_meta['scope_preview']['high_risk_api_count']} 个。",
            "  - 定向分析：从下面的候选依赖包中选择一个或多个。",
            "  - 未选依赖不会进入系统触达分析，最终报告只适用于所选范围。",
            "  - 完整依赖包清单见 changed_dependencies.md；API 级明细不作为普通选择入口。",
            "  - 本卡只确认分析范围；源码/ref/超时等内部证据故障已由系统记录和处理，不需要在这里修复。",
        ]
        if existing_selection.get("matched_coords"):
            checklist_lines.append(
                "  - 当前已选：" + "、".join(existing_selection.get("matched_coords")[:10])
            )
    if step_id == "step5":
        summary_json = step5_call_chain_dir(report_dir) / "summary.json"
        # Checkpoint is user-facing: point readers to the complete ledger,
        # not to summary JSON, caches, or indexes that only the program consumes.
        files_to_review = [
            str((step5_call_chain_dir(report_dir) / "alerts.csv").resolve()),
        ]
        call_summary = read_json(summary_json) if summary_json.exists() else {}
        runtime_view = dict(previous_step_output(main_state or {}, step_id) or {})
        runtime_view.update((main_state or {}).get(step_id, {}).get("input") or {})
        runtime_view.update(run_context or {})
        dependency_source_dirs = list(runtime_view.get("dependency_source_dirs") or [])
        step5_selected_coords = list(runtime_view.get("step5_selected_coords") or [])
        step5_selected_names = list(runtime_view.get("step5_selected_names") or [])
        user_conclusion_summary = call_summary.get("user_conclusion_summary") or {}
        quality_gate = call_summary.get("quality_gate") or {}
        uncertain_apis = list(call_summary.get("uncertain_apis") or [])
        not_analyzed_apis = list(call_summary.get("not_analyzed_apis") or [])
        reachable_apis = list(call_summary.get("reachable_apis") or [])
        not_found_apis = list(call_summary.get("not_found_apis") or [])
        checklist_lines.extend(
            [
                "调用链结论摘要：",
                f"  - 已确认影响={user_conclusion_summary.get('已确认影响', call_summary.get('reachable', 0))}",
                f"  - 可能影响={user_conclusion_summary.get('可能影响', 0)}",
                f"  - 已确认不受影响={user_conclusion_summary.get('已确认不受影响', call_summary.get('not_impacted', 0))}",
                f"  - 需人工复核={user_conclusion_summary.get('当前无法确认', 0)}",
                f"  - 缺少依赖源码/构建产物={user_conclusion_summary.get('需要补充输入', 0)}",
                f"  - 已提供依赖源码目录={len(dependency_source_dirs)} 个",
                "覆盖缺口（可能与上面的结论重叠，不要相加）：",
                f"  - 本次未完成分析={len(not_analyzed_apis)}",
                f"  - 未发现调用路径={len(not_found_apis)}",
            ]
        )
        if step5_selected_coords:
            checklist_lines.append("  - 本轮按坐标定向分析: " + ", ".join(step5_selected_coords[:10]))
        if step5_selected_names:
            checklist_lines.append("  - 本轮按名称定向分析: " + ", ".join(step5_selected_names[:10]))
        if quality_gate.get("needs_input", 0):
            checklist_lines.append("推荐动作：先补充上面点名的源码、构建产物或映射信息，再重新分析系统触达证据。")
        elif quality_gate.get("inconclusive", 0):
            checklist_lines.append("推荐动作：优先抽查“需人工复核”的高风险项，再决定是否继续。")
        elif quality_gate.get("probable_impact", 0):
            checklist_lines.append("推荐动作：优先执行相关业务测试，确认这些“可能影响”项。")
        missing_mapping_items = [
            item
            for item in (uncertain_apis + not_analyzed_apis)
            if (item.get("reason_code") or "").strip() == "DEPENDENCY_SOURCE_MAPPING_MISSING"
        ]
        if missing_mapping_items:
            coords = []
            for item in missing_mapping_items:
                for coord in item.get("dependency_chain_coords") or []:
                    if coord and coord not in coords:
                        coords.append(coord)
            checklist_lines.append(
                "存在缺失依赖源码映射的调用链项；补齐依赖源码目录后重跑 Step5，通常能减少需人工复核或本次未完成分析的项。"
            )
            if coords:
                checklist_lines.append(f"  - 建议优先补这些依赖：{', '.join(coords[:10])}")
        if reachable_apis:
            checklist_lines.append("已确认影响示例（完整结果见 alerts.csv）：")
            for item in reachable_apis[:3]:
                checklist_lines.append(
                    f"  - {item.get('severity')} {item.get('coord')} | "
                    f"{item.get('api') or item.get('api_name') or '未知 API'} | "
                    f"{item.get('user_reason') or item.get('reason') or '未说明原因'}"
                )
        possible_items = [
            item for item in (uncertain_apis + not_analyzed_apis)
            if (item.get("user_conclusion") or "").strip() == "可能影响"
        ]
        if possible_items:
            checklist_lines.append("可能影响示例（完整结果见 alerts.csv）：")
            for item in possible_items[:3]:
                checklist_lines.append(
                    f"  - {item.get('severity')} {item.get('coord')} | "
                    f"{item.get('api') or item.get('api_name') or '未知 API'} | "
                    f"{item.get('user_reason') or item.get('reason') or '需要运行时验证'}"
                )
        inconclusive_items = [
            item for item in (uncertain_apis + not_analyzed_apis + not_found_apis)
            if (item.get("user_conclusion") or "").strip() == "当前无法确认"
        ]
        if inconclusive_items:
            checklist_lines.append("需人工复核示例（完整结果见 alerts.csv）：")
            for item in inconclusive_items[:3]:
                checklist_lines.append(
                    f"  - {item.get('severity')} {item.get('coord')} | "
                    f"{item.get('api') or item.get('api_name') or '未知 API'} | "
                    f"{item.get('user_reason') or item.get('reason') or '未说明原因'}"
                )
        needs_input_items = [
            item for item in (uncertain_apis + not_analyzed_apis + not_found_apis)
            if (item.get("user_conclusion") or "").strip() == "需要补充输入"
        ]
        if needs_input_items:
            checklist_lines.append("缺少依赖源码/构建产物示例（完整结果见 alerts.csv）：")
            for item in needs_input_items[:3]:
                checklist_lines.append(
                    f"  - {item.get('severity')} {item.get('coord')} | "
                    f"{item.get('api') or item.get('api_name') or '未知 API'} | "
                    f"{item.get('user_reason') or item.get('reason') or '缺少完成分析所需的输入'}"
                )
    option_values = [item.get("id") for item in (interaction_meta.get("options", []) or []) if item.get("id")]
    response_schema = interaction_meta.get("response_schema") or {
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {
                "type": "string",
                "enum": option_values,
                "description": "必须与 options.id 之一完全一致。",
            },
            "notes": {
                "type": "string",
                "description": "可选。用于补充用户确认意见、风险说明或后续处理建议。",
            },
        },
    }
    properties = response_schema.setdefault("properties", {})
    if step_id in ("step2", "step4", "step5") and not (
        step_id == "step4" and scope_confirmation_only
    ):
        properties.setdefault(
            "dependency_source_dirs",
            {
                "type": "array",
                "description": "可选。提供依赖源码目录或 Git 地址，支持单模块或多模块仓库；Git 地址会克隆到报告内部缓存，系统会自动推断模块坐标、Step4 仓库映射与 Step5 源码映射。",
            },
        )
    if step_id == "step4":
        if not scope_confirmation_only:
            properties.setdefault(
                "dependency_git_ref_overrides",
                {
                    "type": "array",
                    "description": "可选。按依赖显式确认 old_ref/new_ref；用于版本号无法唯一匹配源码仓库 git ref 的场景。",
                },
            )
        properties.setdefault(
            "selected_targets",
            {
                "type": "array",
                "description": (
                    "内部恢复字段，不向用户展示或要求用户填写。"
                    "系统根据用户回复的依赖名称或完整坐标自动生成。"
                ),
            },
        )
    if step_id == "step2":
        properties.setdefault(
            "source_dirs",
            {
                "type": "array",
                "description": "可选但强烈建议确认。业务源码目录，Step3/Step5 将直接消费；若留空，系统仅尝试自动探测并在后续步骤前做强校验。",
            },
        )
        properties.setdefault(
            "source_repo_hints",
            {
                "type": "array",
                "description": "可选。提供源码线索而非最终映射，支持 path、repo_path、git_path、或 {coord_hint,path,notes}。",
            },
        )
        for field_name, label in (
            ("jdk_base", "升级前 JDK 版本"),
            ("jdk_current", "升级后 JDK 版本"),
            ("springboot_base", "升级前 Spring Boot 版本"),
            ("springboot_current", "升级后 Spring Boot 版本"),
        ):
            properties.setdefault(
                field_name,
                {
                    "type": "string",
                    "description": f"可选。仅当自动识别缺失或不正确时，明确提供{label}。",
                },
            )
        properties.setdefault(
            "dependency_repo_mappings",
            {
                "type": "array",
                "description": "可选。依赖源码候选存在歧义时，用 groupId:artifactId=/abs/repo/path 明确对应关系。",
            },
        )
    if step_id == "step1":
        for field_name, field_meta in build_step1_response_properties().items():
            properties.setdefault(field_name, field_meta)
    if step_id == "step5":
        properties.setdefault(
            "dependency_source_dirs",
            {
                "type": "array",
                "description": "可选。补充依赖源码目录或 Git 地址；Git 地址会克隆到报告内部缓存，系统会自动推断依赖源码映射并重跑分析。",
            },
        )
        properties.setdefault(
            "selected_targets",
            {
                "type": "array",
                "description": (
                    "内部恢复字段，不向用户展示或要求用户填写。"
                    "系统根据用户回复的依赖名称或完整坐标自动生成。"
                ),
            },
        )
    for field in interaction_meta.get("required_fields", []) or []:
        properties.setdefault(
            field,
            {
                "type": "string",
                "description": f"当用户答复涉及 {field} 时，Agent 应显式记录并在恢复命令中传回。",
            },
        )
    required_fields = interaction_meta.get("required_fields", []) or []
    resume_examples = build_resume_command_examples(
        interaction_meta.get("options", []) or [],
        required_fields,
        properties,
        project_dir,
        report_dir,
    )
    input_normalization = build_input_normalization_contract(
        interaction_meta.get("options", []) or [],
        required_fields,
        properties,
    )
    payload = {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": normalize_interaction_status(interaction_meta.get("status")),
        "kind": interaction_meta.get("type", "decision"),
        "step_id": step_id,
        "title": title,
        "reason_code": interaction_meta.get("reason_code") or "",
        "question": interaction_meta.get("question") or "请确认当前结果，然后继续。",
        "options": interaction_meta.get("options", []),
        "files_to_review": files_to_review,
        "required_fields": required_fields,
        "missing_inputs": list(interaction_meta.get("missing_inputs") or []),
        "fallback_inputs": list(interaction_meta.get("fallback_inputs") or []),
        "response_schema": response_schema,
        "input_normalization": input_normalization,
        "resume_hint": interaction_meta.get("resume_hint", "在 Agent 收到用户答复后继续执行下一步。"),
        "rules_file": str(CHECKPOINT_RULES_FILE.resolve()),
        "runtime_rules": CHECKPOINT_RULES,
        "next_action_rule": "只能向用户提问并等待回复，不得直接继续执行后续步骤。",
        "must_wait_for_user_reply": True,
        "resume_command_examples": resume_examples,
        "checklist_lines": checklist_lines,
        "created_at": datetime.now().isoformat(),
        "action_requirements": interaction_meta.get("action_requirements") or {},
    }
    if interaction_meta.get("scope_preview"):
        payload["scope_preview"] = dict(interaction_meta.get("scope_preview") or {})
    if interaction_meta.get("selection_options"):
        payload["selection_options"] = list(interaction_meta.get("selection_options") or [])
    if interaction_meta.get("recommended_selection_options") is not None:
        payload["recommended_selection_options"] = list(
            interaction_meta.get("recommended_selection_options") or []
        )
        payload["recommended_candidate_count"] = int(
            interaction_meta.get("recommended_candidate_count") or 0
        )
    if interaction_meta.get("selection_resolution"):
        payload["selection_resolution"] = dict(interaction_meta.get("selection_resolution") or {})
    if step_id == "step5" and not payload.get("selection_resolution"):
        selection_resolution = build_report_dir_step5_selection_resolution(report_dir)
        if selection_resolution.get("enabled"):
            payload["selection_resolution"] = selection_resolution
            payload["selection_options"] = build_interaction_selection_options(
                selection_resolution.get("options") or []
            )
    runtime_view = dict(previous_step_output(main_state or {}, step_id) or {})
    runtime_view.update((main_state or {}).get(step_id, {}).get("input") or {})
    runtime_view.update(run_context or {})
    payload = apply_interaction_protocol_enhancements(payload, step_id, project_dir=project_dir, report_dir=report_dir)
    payload = annotate_dependency_source_dirs_interaction(payload, runtime_view, report_dir)
    payload["user_decision_card"] = build_user_decision_card(payload)
    return payload


def option_ids(interaction):
    return interaction_option_ids(interaction)


def default_interaction_action(interaction):
    options = option_ids(interaction)
    if "continue" in options:
        return "continue"
    if options:
        return options[0]
    return "continue"


def resolve_user_response(args, project_dir):
    if not (args.response_json or args.response_file):
        raise StepError("收到待用户交互状态后，必须通过 --response-json 或 --response-file 提供结构化用户答复。")
    response = load_user_response(args, project_dir) or {}
    return build_canonical_user_response(response)


def resolve_resume_step_id(current_step_id, pending_interaction, action, user_response=None):
    pending_step_id = str((pending_interaction or {}).get("step_id") or "").strip()
    pending_kind = str((pending_interaction or {}).get("kind") or "").strip()
    if action == "continue" and pending_step_id:
        if pending_kind == "input_request":
            return pending_step_id
        if (
            pending_step_id == "step2"
            and infer_non_pending_target_step_from_payload(user_response or {}) == "step2"
        ):
            # Backward compatibility for Step2 review checkpoints created by
            # older versions: corrections must rebuild Step2, not leak into a
            # stale Step3 continuation.
            return "step2"
    if action == "rerun_current_step":
        if pending_step_id:
            return pending_step_id
    if action == "restart_from_step":
        response = dict(user_response or {})
        target_step_id = str(response.get("restart_step_id") or "").strip()
        if not target_step_id:
            raise StepError("action=restart_from_step 时必须提供 restart_step_id")
        allowed_steps = allowed_restart_step_ids(pending_step_id)
        if target_step_id not in allowed_steps:
            raise StepError(
                f"restart_step_id={target_step_id} 不合法；当前检查点仅允许重跑到这些步骤：{allowed_steps}"
            )
        return target_step_id
    return current_step_id


def expand_step1_ref_selections(pending_interaction, user_response):
    """Bind a Step1 ref choice to the commit shown on the current decision card."""
    response = dict(user_response or {})
    if str((pending_interaction or {}).get("step_id") or "") != "step1":
        return response
    decision_items = {
        str(item.get("side") or "").strip(): dict(item)
        for item in ((pending_interaction or {}).get("source_ref_decision_items") or [])
        if str(item.get("side") or "").strip()
    }
    raw_selections = response.get("source_ref_selections")
    if raw_selections not in (None, "", []):
        if isinstance(raw_selections, dict):
            selections = [raw_selections]
        elif isinstance(raw_selections, list):
            selections = raw_selections
        else:
            raise StepError("source_ref_selections 必须是对象或对象数组。")
        seen_sides = set()
        for selection in selections:
            if not isinstance(selection, dict):
                raise StepError("source_ref_selections 的每项都必须是对象。")
            side = str(selection.get("side") or "").strip()
            if side not in decision_items:
                raise StepError(f"Step1 ref 方案中的 side 不存在于当前确认项：{side or '(空)'}")
            if side in seen_sides:
                raise StepError(f"Step1 的 {side} 侧只能选择一个 ref 方案。")
            seen_sides.add(side)
            candidates = list(decision_items[side].get("candidates") or [])
            selection_key = str(selection.get("selection_key") or "").strip()
            raw_option = selection.get("option", selection.get("rank"))
            chosen = None
            if selection_key:
                chosen = next(
                    (item for item in candidates if str(item.get("selection_key") or "") == selection_key),
                    None,
                )
            elif raw_option not in (None, ""):
                try:
                    option_number = int(raw_option)
                except (TypeError, ValueError) as exc:
                    raise StepError(f"Step1 {side} 侧的 ref 方案编号必须是正整数。") from exc
                if 1 <= option_number <= len(candidates):
                    chosen = candidates[option_number - 1]
            if not chosen:
                raise StepError(f"Step1 {side} 侧选择的 ref 方案不存在或已过期。")
            field = str(decision_items[side].get("field") or f"{side}_branch")
            response[field] = str(chosen.get("ref") or chosen.get("display_ref") or "")
            response[f"{side}_expected_commit"] = str(chosen.get("commit") or "")

    if response.get("retry_remote_fetch") is True:
        for side, item in decision_items.items():
            if str(item.get("source_status") or "") != "remote_fetch_failed":
                continue
            candidates = list(item.get("candidates") or [])
            commits = {str(candidate.get("commit") or "") for candidate in candidates if candidate.get("commit")}
            refs = {str(candidate.get("ref") or "") for candidate in candidates if candidate.get("ref")}
            if len(commits) != 1 or len(refs) != 1:
                continue
            field = str(item.get("field") or f"{side}_branch")
            response[field] = next(iter(refs))
            response[f"{side}_expected_commit"] = next(iter(commits))

    # A manually entered remote-qualified ref can still be bound automatically
    # when it identifies exactly one commit in the current card.
    for side, item in decision_items.items():
        field = str(item.get("field") or f"{side}_branch")
        selected_ref = str(response.get(field) or "").strip()
        if not selected_ref or response.get(f"{side}_expected_commit"):
            continue
        matches = [
            candidate for candidate in (item.get("candidates") or [])
            if selected_ref in {
                str(candidate.get("ref") or ""),
                str(candidate.get("canonical_ref") or ""),
                str(candidate.get("display_ref") or ""),
            }
        ]
        commits = {str(candidate.get("commit") or "") for candidate in matches if candidate.get("commit")}
        if len(commits) == 1:
            response[f"{side}_expected_commit"] = next(iter(commits))
    return response


def expand_dependency_git_ref_selections(pending_interaction, user_response):
    """Translate compact Step4 option selections into canonical ref overrides."""
    response = dict(user_response or {})
    raw_selections = response.get("dependency_git_ref_selections")
    if raw_selections in (None, "", []):
        selections = []
    elif isinstance(raw_selections, dict):
        selections = [raw_selections]
    elif isinstance(raw_selections, list):
        selections = raw_selections
    else:
        raise StepError("dependency_git_ref_selections 必须是对象或对象数组。")

    decision_items = {
        str(item.get("coord") or "").strip(): dict(item)
        for item in ((pending_interaction or {}).get("git_ref_decision_items") or [])
        if str(item.get("coord") or "").strip()
    }
    selected_overrides = []
    seen_coords = set()
    for selection in selections:
        if not isinstance(selection, dict):
            raise StepError("dependency_git_ref_selections 的每项都必须是对象。")
        coord = str(selection.get("coord") or "").strip()
        if not coord or coord not in decision_items:
            raise StepError(f"git ref 方案中的依赖坐标不存在于当前确认项：{coord or '(空)'}")
        if coord in seen_coords:
            raise StepError(f"同一依赖只能选择一个 git ref 方案：{coord}")
        seen_coords.add(coord)
        pair_options = list(decision_items[coord].get("pair_options") or [])
        selection_key = str(selection.get("selection_key") or "").strip()
        raw_option = selection.get("option", selection.get("rank"))
        chosen = None
        if selection_key:
            chosen = next(
                (item for item in pair_options if str(item.get("selection_key") or "") == selection_key),
                None,
            )
        elif raw_option not in (None, ""):
            try:
                option_number = int(raw_option)
            except (TypeError, ValueError) as exc:
                raise StepError(f"{coord} 的 git ref 方案编号必须是正整数。") from exc
            chosen = next(
                (item for item in pair_options if int(item.get("rank") or 0) == option_number),
                None,
            )
        if not chosen:
            raise StepError(f"{coord} 选择的 git ref 方案不存在或已过期，请按当前决策卡重新选择。")
        selected_overrides.append({
            "coord": coord,
            "old_ref": str(chosen.get("old_ref") or ""),
            "new_ref": str(chosen.get("new_ref") or ""),
            "expected_old_commit": str(chosen.get("old_commit") or ""),
            "expected_new_commit": str(chosen.get("new_commit") or ""),
            "selection_key": str(chosen.get("selection_key") or ""),
        })

    if response.get("retry_remote_fetch") is True or response.get("step4_fetch_timeout") not in (None, ""):
        for item in (pending_interaction or {}).get("pending_git_ref_items") or []:
            if str(item.get("pending_kind") or "") not in {"fetch_failed", "remote_query_failed"}:
                continue
            coord = str(item.get("coord") or "").strip()
            old_ref = str(item.get("selected_old_ref") or item.get("old_ref_override") or "").strip()
            new_ref = str(item.get("selected_new_ref") or item.get("new_ref_override") or "").strip()
            if not (coord and old_ref and new_ref):
                continue

            def commit_for_ref(candidates, selected_ref):
                commits = {
                    str(candidate.get("commit") or "")
                    for candidate in (candidates or [])
                    if str(candidate.get("ref") or "") == selected_ref
                    and str(candidate.get("commit") or "")
                }
                return next(iter(commits)) if len(commits) == 1 else ""

            selected_overrides.append({
                "coord": coord,
                "old_ref": old_ref,
                "new_ref": new_ref,
                "expected_old_commit": str(
                    item.get("expected_old_commit")
                    or commit_for_ref(item.get("old_candidates"), old_ref)
                    or ""
                ),
                "expected_new_commit": str(
                    item.get("expected_new_commit")
                    or commit_for_ref(item.get("new_candidates"), new_ref)
                    or ""
                ),
                "selection_key": "automatic_fetch_retry",
            })

    existing = normalize_dependency_git_ref_overrides(
        response.get("dependency_git_ref_overrides"),
        "dependency_git_ref_overrides",
    ) or []
    merged = {
        str(item.get("coord") or "").strip(): dict(item)
        for item in existing
        if str(item.get("coord") or "").strip()
    }
    for item in selected_overrides:
        merged[item["coord"]] = item
    if merged:
        response["dependency_git_ref_overrides"] = [merged[coord] for coord in sorted(merged)]
    return response


def validate_pending_interaction_response(pending_interaction, user_response):
    pending_interaction = dict(pending_interaction or {})
    user_response = expand_step1_ref_selections(pending_interaction, user_response)
    user_response = expand_dependency_git_ref_selections(pending_interaction, user_response)
    step_id = str(pending_interaction.get("step_id") or "").strip()
    reason_code = str(pending_interaction.get("reason_code") or "").strip()
    action = str(user_response.get("action") or "").strip()
    response_schema = dict(pending_interaction.get("response_schema") or {})
    properties = dict(response_schema.get("properties") or {})
    if properties:
        unknown_fields = sorted(
            key for key in user_response.keys()
            if not key.startswith("__") and key not in properties
        )
        if unknown_fields:
            raise StepError("用户答复包含当前检查点未定义的字段：" + ", ".join(unknown_fields))
    for field in response_schema.get("required", []) or []:
        if user_response.get(field) in (None, "", []):
            raise StepError(f"当前检查点要求字段 {field} 必填，不能为空。")
    action_requirements = dict(pending_interaction.get("action_requirements") or {})
    requirement = dict(action_requirements.get(action) or {})
    retry_remote_fetch = user_response.get("retry_remote_fetch") is True
    step1_remote_retry_fields = {
        str(item.get("field") or "").strip()
        for item in (pending_interaction.get("ref_resolution_requests") or [])
        if item.get("status") in {"fetch_failed", "not_found", "ref_moved"}
        if str(item.get("field") or "").strip()
    }
    for field in requirement.get("required_fields") or []:
        if (
            step_id == "step1"
            and retry_remote_fetch
            and field in step1_remote_retry_fields
        ):
            continue
        if not _response_value_present(user_response.get(field)):
            raise StepError(f"当前动作 {action} 要求字段 {field} 必填，不能为空。")
    if step_id == "step1" and action == "confirm_local_source":
        confirmation_fields = [
            str(field or "").strip()
            for field in (requirement.get("required_fields") or [])
            if str(field or "").strip().endswith(
                ("_allow_local_source", "_allow_dirty_local_source")
            )
        ]
        for field in confirmation_fields:
            if user_response.get(field) is not True:
                raise StepError(f"当前动作 confirm_local_source 要求 {field}=true，不能隐式确认本地源码。")
    if step_id == "step1" and action == "continue" and pending_interaction.get("ref_resolution_requests"):
        remote_retry_sides = {
            str(item.get("side") or "")
            for item in (pending_interaction.get("ref_resolution_requests") or [])
            if item.get("status") in {"fetch_failed", "not_found", "ref_moved"}
        }
        for request in pending_interaction.get("ref_resolution_requests") or []:
            side = str(request.get("side") or "")
            field = str(request.get("field") or "").strip()
            if retry_remote_fetch and side in remote_retry_sides:
                continue
            if field and not str(user_response.get(field) or "").strip():
                raise StepError(f"Step1 请一次性处理全部待确认侧；本次仍缺少：{field}")
        if retry_remote_fetch and not remote_retry_sides:
            raise StepError("当前 Step1 确认项中没有可显式重查的远端 ref 失败侧。")
    step5_missing_source_rerun = (
        step_id == "step5"
        and reason_code == "step5_dependency_source_mapping_missing"
        and action == "rerun_current_step"
    )
    step5_has_selection_override = False
    if step5_missing_source_rerun:
        step5_has_selection_override = any(
            _response_value_present(user_response.get(field))
            for field in ("selected_targets", "step5_selected_coords", "step5_selected_names")
        )
    at_least_one_of = [str(field).strip() for field in (requirement.get("at_least_one_of") or []) if str(field).strip()]
    if (
        at_least_one_of
        and not step5_has_selection_override
        and not any(_response_value_present(user_response.get(field)) for field in at_least_one_of)
    ):
        raise StepError(
            f"当前动作 {action} 至少需要提供以下字段之一：{', '.join(at_least_one_of)}"
        )
    if "selected_targets" in user_response:
        validate_selected_targets_resolution(
            pending_interaction.get("selection_resolution") or {},
            user_response.get("selected_targets"),
        )

    if step_id == "step1" and reason_code in {
        "ambiguous_step1_source_ref",
        "step1_source_ref_not_found",
        "step1_remote_source_unavailable",
        "step1_dirty_local_source_confirmation_required",
    } and action == "continue":
        for request in pending_interaction.get("ref_resolution_requests") or []:
            side = str(request.get("side") or "").strip()
            field = str(request.get("field") or "").strip()
            previous = str(request.get("requested_ref") or "").strip()
            current = str(user_response.get(field) or "").strip()
            source_field = f"{side}_source_project_dir"
            previous_source = str(request.get("source_project_dir") or "").strip()
            current_source = str(user_response.get(source_field) or "").strip()
            source_changed = bool(
                current_source and current_source != previous_source
            )
            if (
                field
                and previous
                and current == previous
                and not source_changed
                and user_response.get("retry_remote_fetch") is not True
            ):
                raise StepError(
                    f"{field}={current} 已经解析失败或存在歧义；"
                    f"必须补充不同的明确 ref/commit，或修正 {source_field}，"
                    "不能用完全相同的输入重复执行 Step1。"
                )

    if step5_missing_source_rerun:
        dependency_source_dirs = [
            str(item).strip()
            for item in (user_response.get("dependency_source_dirs") or [])
            if str(item).strip()
        ]
        allow_degraded = bool(user_response.get("allow_degraded"))
        if not dependency_source_dirs and not allow_degraded and not step5_has_selection_override:
            raise StepError(
                "Step5 当前检查点要求先补充依赖源码目录，或明确允许降级执行，"
                "或选择需要分析的目标 jar 后，再重跑当前步骤。"
            )

    if (
        step_id == "step4"
        and reason_code == "step4_git_refs_need_confirmation"
        and action == "rerun_current_step"
    ):
        dependency_source_dirs = [
            str(item).strip()
            for item in (user_response.get("dependency_source_dirs") or [])
            if str(item).strip()
        ]
        overrides = normalize_dependency_git_ref_overrides(
            user_response.get("dependency_git_ref_overrides"),
            "dependency_git_ref_overrides",
        ) or []
        retry_remote_fetch = (
            user_response.get("retry_remote_fetch") is True
            or user_response.get("step4_fetch_timeout") not in (None, "")
        )
        if not overrides and not dependency_source_dirs and not retry_remote_fetch:
            raise StepError(
                "Step4 当前检查点要求先确认依赖 old_ref/new_ref，"
                "确认重试 fetch，或修正依赖源码目录后，再重跑当前步骤。"
            )
        if not dependency_source_dirs:
            pending_items = list(pending_interaction.get("pending_git_ref_items") or [])
            pending_coords = {
                str(item.get("coord") or "").strip()
                for item in pending_items
                if str(item.get("coord") or "").strip()
            }
            retryable_coords = {
                str(item.get("coord") or "").strip()
                for item in pending_items
                if str(item.get("pending_kind") or "") in {"fetch_failed", "remote_query_failed"}
                and str(item.get("coord") or "").strip()
            }
            supplied_coords = {
                str(item.get("coord") or "").strip()
                for item in overrides
                if str(item.get("coord") or "").strip()
            }
            covered_by_retry = retryable_coords if retry_remote_fetch else set()
            missing_coords = sorted(pending_coords - supplied_coords - covered_by_retry)
            if missing_coords:
                raise StepError(
                    "Step4 请一次性处理当前全部待处理依赖；"
                    f"本次仍缺少：{', '.join(missing_coords)}"
                )
            if retry_remote_fetch and not retryable_coords:
                raise StepError("当前 Step4 确认项中没有可直接重试的 fetch 失败条目。")
    if (
        step_id == "step4"
        and reason_code == "step4_timeouts_need_resolution"
        and action == "rerun_current_step"
    ):
        dependency_source_dirs = [
            str(item).strip()
            for item in (user_response.get("dependency_source_dirs") or [])
            if str(item).strip()
        ]
        timeout_fields = [
            "step4_git_diff_timeout",
            "step4_japicmp_timeout",
            "step4_fetch_timeout",
            "step4_tool_install_timeout",
        ]
        has_timeout_override = any(user_response.get(field) not in (None, "") for field in timeout_fields)
        if not has_timeout_override and not dependency_source_dirs:
            raise StepError(
                "Step4 当前检查点要求先调整至少一个 Step4 超时参数，或修正 "
                "依赖源码目录后，再重跑当前步骤。"
            )
    if (
        step_id == "step4"
        and reason_code == "step4_japicmp_missing_need_resolution"
        and action == "rerun_current_step"
    ):
        japicmp_jar = str(user_response.get("japicmp_jar") or "").strip()
        if not japicmp_jar:
            raise StepError(
                "Step4 当前检查点要求先安装或提供 japicmp_jar，再使用 "
                "action=rerun_current_step 重跑；不允许缺少 JApiCmp 时降级执行。"
            )
    if (
        step_id == "step5"
        and reason_code == "step5_tree_sitter_missing_need_resolution"
        and action == "rerun_current_step"
    ):
        tree_sitter_installed = bool(user_response.get("tree_sitter_installed"))
        if not tree_sitter_installed:
            raise StepError(
                "Step5 当前检查点要求先安装 tree-sitter/tree-sitter-java，"
                "并设置 tree_sitter_installed=true 后，再使用 action=rerun_current_step 重跑；"
                "不允许源码 AST 降级执行。"
            )


def apply_user_response_to_main_state(main_state, pending_interaction, user_response, project_dir, target_step_id=""):
    user_response = build_canonical_user_response(user_response)
    user_response = expand_step1_ref_selections(pending_interaction, user_response)
    user_response = expand_dependency_git_ref_selections(pending_interaction, user_response)
    if user_response.get("selected_targets") is not None:
        selection_result = resolve_selected_targets(
            (pending_interaction or {}).get("selection_resolution") or {},
            user_response.get("selected_targets"),
        ) or {}
        user_response["step5_selected_coords"] = list(
            selection_result.get("step5_selected_coords") or []
        )
        user_response["step5_selected_names"] = list(
            selection_result.get("step5_selected_names") or []
        )
    pending_step_id = str((pending_interaction or {}).get("step_id") or "").strip()
    pending_kind = str((pending_interaction or {}).get("kind") or "").strip()
    step_id = str(target_step_id or pending_step_id or "").strip()
    if not step_id:
        return main_state, {}
    base_context = build_restore_context(main_state, step_id)
    action = str((user_response or {}).get("action") or "").strip()
    if (
        step_id == "step4"
        and action == "continue"
        and not user_response.get("step5_selected_coords")
        and not user_response.get("step5_selected_names")
    ):
        base_context.pop("step5_selected_coords", None)
        base_context.pop("step5_selected_names", None)
    if action == "restart_from_step" and pending_step_id and pending_step_id != step_id:
        # When restarting to an earlier step, preserve already known runtime context
        # from the current checkpoint (for example base/current branches from Step4).
        restart_fallback_context = build_restore_context(main_state, pending_step_id)
        if restart_fallback_context:
            merged_base_context = dict(base_context)
            merged_base_context.update(restart_fallback_context)
            base_context = merged_base_context
    updated = merge_user_response_into_run_context(base_context, user_response, project_dir)
    for selection_field in ("step5_selected_coords", "step5_selected_names"):
        if selection_field in updated and not updated.get(selection_field):
            updated.pop(selection_field, None)
    if step_id == "step1":
        main_state["step1"]["input"] = dict(updated)
    else:
        main_state[step_id]["input"] = dict(updated)
    if action == "continue" and pending_step_id == step_id and pending_kind != "input_request":
        # Review checkpoint replies may补充后续步骤必需的业务字段（例如 Step1 direct
        # artifact 模式在确认范围后补入 base/current branch）。这些字段必须立即
        # 种入下一步输入，不能继续沿用当前步骤执行时保存的旧 output。
        seed_next_step_input(main_state, step_id, updated)
    if action == "confirm_unresolved":
        pending_unresolved_items = list((pending_interaction or {}).get("unresolved_items") or [])
        if pending_unresolved_items:
            main_state[step_id]["input"]["confirmed_unresolved_items"] = pending_unresolved_items
    record_last_user_response(main_state, pending_interaction, action, user_response)
    update_main_state_state(
        main_state,
        status="ready",
        blocking_reason=None,
        pending_interaction=None,
    )
    return main_state, updated


def reset_step_state_for_restart(main_state, step_id, report_dir, preserve_current_input=None):
    preserved_input = dict(preserve_current_input or {})
    if not preserved_input:
        preserved_input = build_step_input_context(main_state, step_id, fallback_existing={})
    clear_steps_from(main_state, step_id, preserve_current_input=preserved_input)
    cleanup_step_outputs_from(step_id, report_dir)
    update_main_state_state(
        main_state,
        current_step=step_id,
        completed_step=STEP_SEQUENCE[step_index(step_id) - 1] if step_index(step_id) > 0 else "",
        status="ready",
        blocking_reason=None,
        pending_interaction=None,
    )
    return preserved_input


def build_restore_context(main_state, step_id):
    """恢复 checkpoint 时优先使用当前 step 最新 input，再回补该 step 的旧 output。"""
    step_state = dict((main_state.get(step_id) or {}))
    current_output = dict(step_state.get("output") or {})
    current_input = dict(step_state.get("input") or {})
    if current_output or current_input:
        merged = dict(current_output)
        merged.update(current_input)
        return merged
    return build_step_input_context(main_state, step_id, fallback_existing={})


def resolve_non_pending_structured_response_step(args, main_state, user_response):
    action = str((user_response or {}).get("action") or "").strip()
    if action not in NON_PENDING_BRIDGE_ALLOWED_ACTIONS:
        raise StepError(
            "当前没有 pending interaction 时，结构化用户意图仅支持以下 action："
            + ", ".join(sorted(NON_PENDING_BRIDGE_ALLOWED_ACTIONS))
        )
    restart_step_id = str((user_response or {}).get("restart_step_id") or "").strip()
    if action == "restart_from_step":
        if restart_step_id not in STEP_SEQUENCE:
            raise StepError("action=restart_from_step 时，必须提供合法的 restart_step_id。")
        return restart_step_id
    requested_step = str(getattr(args, "step", "") or "").strip()
    if requested_step and requested_step != "auto":
        return requested_step
    current_step = str(((main_state or {}).get("state") or {}).get("current_step") or "").strip()
    if current_step in STEP_SEQUENCE:
        return current_step
    inferred_step_id = infer_non_pending_target_step_from_payload(user_response)
    if inferred_step_id:
        return inferred_step_id
    raise StepError(
        "当前没有待恢复的 pending interaction，且无法根据结构化用户意图推断目标步骤。"
        "请显式指定 --step，或在 intent_patch 中提供 restart_step_id。"
    )


def build_non_pending_structured_response_interaction(target_step_id, report_dir, user_response):
    interaction = {
        "step_id": target_step_id,
        "kind": "non_pending_intent_bridge",
        "status": "ready",
    }
    if user_response.get("selected_targets") is not None:
        selection_resolution = build_report_dir_step5_selection_resolution(report_dir)
        if not (selection_resolution.get("options") or []):
            raise StepError(
                "当前无法解析 selected_targets：缺少可用的 Step5 候选目标。"
                "请先完成依赖 API 变化分析，生成 changed_dependencies.md 后再选择依赖包。"
            )
        interaction["selection_resolution"] = selection_resolution
    return interaction


def apply_non_pending_structured_response(args, project_dir, report_dir, main_state, user_response):
    response_action = str((user_response or {}).get("action") or "").strip()
    if response_action == "cancel":
        print("已取消这次新指令；当前分析状态和已有产物保持不变。", file=sys.stderr)
        return {
            "main_state": main_state,
            "step_id": "",
            "pending_interaction": None,
            "resumed_interaction_step_id": "",
            "response_action": response_action,
            "user_response": user_response,
            "early_exit_code": 0,
        }
    if response_action != "restart_from_step" and not has_non_pending_intent_payload(user_response):
        raise StepError(
            "当前没有待恢复的 pending interaction。若要提交新的正式业务意图，"
            "请在 intent_patch.set / clear 中提供至少一个业务字段，或使用 action=restart_from_step。"
        )
    target_step_id = resolve_non_pending_structured_response_step(args, main_state, user_response)
    synthetic_interaction = build_non_pending_structured_response_interaction(
        target_step_id,
        report_dir,
        user_response,
    )
    if response_action == "restart_from_step":
        state_meta = (main_state or {}).get("state") or {}
        source_step_id = str(state_meta.get("current_step") or "").strip()
        if source_step_id not in STEP_SEQUENCE:
            source_step_id = str(state_meta.get("completed_step") or "").strip()
        if source_step_id in STEP_SEQUENCE and source_step_id != target_step_id:
            # Reuse the latest known execution context when restarting from a
            # non-pending state. Otherwise branches and source mappings known
            # by Step4/Step5 can be lost when the target's older input is sparse.
            synthetic_interaction["step_id"] = source_step_id
    if user_response.get("selected_targets") is not None:
        validate_selected_targets_resolution(
            synthetic_interaction.get("selection_resolution") or {},
            user_response.get("selected_targets"),
        )
    main_state, updated_context = apply_user_response_to_main_state(
        main_state,
        synthetic_interaction,
        user_response,
        project_dir,
        target_step_id=target_step_id,
    )
    reset_step_state_for_restart(
        main_state,
        target_step_id,
        report_dir,
        preserve_current_input=dict(updated_context),
    )
    save_main_state(report_dir, main_state)
    target_name = USER_TASK_NAMES.get(target_step_id, "指定任务")
    target_index = step_index(target_step_id)
    if target_index > 0:
        retained_step_id = STEP_SEQUENCE[target_index - 1]
        retained_text = (
            f"{USER_TASK_NAMES.get(retained_step_id, retained_step_id)}及之前的正式产物继续保留；"
        )
    else:
        retained_text = "不复用旧的正式分析产物；"
    print(
        f"将从{target_name}重新分析。{retained_text}{target_name}及之后的产物会按新输入重建。",
        file=sys.stderr,
    )
    return {
        "main_state": main_state,
        "step_id": target_step_id,
        "pending_interaction": None,
        "resumed_interaction_step_id": "",
        "response_action": response_action,
        "user_response": user_response,
        "early_exit_code": None,
    }


def apply_structured_user_response_if_present(args, project_dir, report_dir, main_state, step_id, user_response=None):
    pending_interaction = (main_state.get("state") or {}).get("pending_interaction")
    has_structured_response = bool(args.response_json or args.response_file)
    resumed_interaction_step_id = ""
    response_action = ""
    user_response = dict(user_response or {})
    early_exit_code = None

    if pending_interaction and has_structured_response:
        if not user_response:
            user_response = resolve_user_response(args, project_dir)
        response_action = str(user_response.get("action") or "").strip()
        resumed_interaction_step_id = str((pending_interaction or {}).get("step_id") or "").strip()
        available_actions = option_ids(pending_interaction)
        if available_actions and response_action not in available_actions:
            allowed_labels = []
            for option in (pending_interaction or {}).get("options") or []:
                option_id = str((option or {}).get("id") or "").strip()
                if option_id not in available_actions:
                    continue
                allowed_labels.append(
                    str((option or {}).get("label") or USER_ACTION_LABELS.get(option_id) or option_id)
                )
            print(
                "当前回复无法与本次确认项的可选操作对应。"
                f"请从以下方式中选择：{'、'.join(allowed_labels)}。",
                file=sys.stderr,
            )
            early_exit_code = 1
        else:
            validate_pending_interaction_response(pending_interaction, user_response)
            if response_action == "cancel":
                paused_step_id = current_step_for_pending_interaction(
                    resumed_interaction_step_id,
                    pending_interaction,
                )
                update_main_state_state(
                    main_state,
                    current_step=paused_step_id
                    or (main_state.get("state") or {}).get("current_step"),
                    completed_step=(main_state.get("state") or {}).get("completed_step"),
                    status="paused_by_user",
                    blocking_reason="用户选择稍后处理",
                    pending_interaction=dict(pending_interaction),
                )
                save_main_state(report_dir, main_state)
                print("分析已暂停；再次运行时会回到当前确认任务。", file=sys.stderr)
                early_exit_code = 0
            else:
                step_id = resolve_resume_step_id(step_id, pending_interaction, response_action, user_response=user_response)
                response_storage_step_id = resumed_interaction_step_id or step_id
                if response_action == "restart_from_step":
                    response_storage_step_id = step_id
                main_state, _updated_context = apply_user_response_to_main_state(
                    main_state,
                    pending_interaction,
                    user_response,
                    project_dir,
                    target_step_id=response_storage_step_id,
                )
                clear_interaction_file(report_dir)
                if response_action == "restart_from_step":
                    preserved_input = dict((main_state.get(step_id) or {}).get("input") or {})
                    reset_step_state_for_restart(
                        main_state,
                        step_id,
                        report_dir,
                        preserve_current_input=preserved_input,
                    )
                save_main_state(report_dir, main_state)
                pending_interaction = (main_state.get("state") or {}).get("pending_interaction")
    elif has_structured_response:
        if not user_response:
            user_response = resolve_user_response(args, project_dir)
        return apply_non_pending_structured_response(
            args,
            project_dir,
            report_dir,
            main_state,
            user_response,
        )

    return {
        "main_state": main_state,
        "step_id": step_id,
        "pending_interaction": pending_interaction,
        "resumed_interaction_step_id": resumed_interaction_step_id,
        "response_action": response_action,
        "user_response": user_response,
        "early_exit_code": early_exit_code,
    }


def maybe_return_pending_interaction(report_dir, pending_interaction):
    if not pending_interaction:
        return None
    print_interaction_to_streams(pending_interaction, report_dir)
    print("分析仍在等待你的确认，请直接回复上面的任一选择。", file=sys.stderr)
    return EXIT_AWAITING_USER


def handle_step2_resume_followups(
    main_state,
    report_dir,
    resumed_interaction_step_id,
    resume_target_step_id,
    response_action,
    user_response,
):
    if (
        resumed_interaction_step_id != "step2"
        or resume_target_step_id != "step2"
        or response_action != "continue"
    ):
        return
    # 不要在 "continue" 时自动接受建议映射。
    # 建议映射需要用户显式确认，避免“继续流程”和“接受推断值”绑定。
    # 当前用户主入口是 dependency_source_dirs；accept_suggested_mappings 用于确认是否固化自动推断结果。
    if user_response.get("accept_suggested_mappings"):
        ctx = read_json(step2_context_path(report_dir)) if step2_context_path(report_dir).exists() else {}
        step2_input = dict((main_state.get("step2") or {}).get("input") or {})
        suggestions = build_dependency_repo_mapping_suggestions(step2_input, ctx)
        relevant_coords = _collect_relevant_dependency_coords(report_dir)
        accepted_dirs = _dedupe_strings(
            list(step2_input.get("dependency_source_dirs") or [])
            + suggested_dependency_source_dirs(suggestions)
        )
        source_plan = _build_dependency_source_plan(
            accepted_dirs,
            relevant_coords=relevant_coords,
        )
        step2_input["dependency_source_dirs"] = accepted_dirs
        step2_input.pop("dependency_repo_mappings", None)
        step2_input.pop("dependency_source_mappings", None)
        main_state["step2"]["input"] = step2_input
        if suggested_dependency_source_dirs(suggestions):
            print("  ✅ 已接受建议的依赖源码目录，并将按自动识别结果继续后续步骤", file=sys.stderr)
        elif source_plan.get("dependency_source_mappings"):
            print("  ✅ 已采用你提供的依赖源码目录，并将按自动识别结果继续后续任务", file=sys.stderr)
        if source_plan.get("ambiguous_coords"):
            print("  ⚠️ 部分源码目录匹配到多个依赖，系统已跳过这些冲突项并保留覆盖边界", file=sys.stderr)
    # An input-request reply reruns Step2. Invalidate stale Step2+ outputs now,
    # preserve the corrected input, and let the normal execution path rebuild
    # the context exactly once.
    step2_input = dict((main_state.get("step2") or {}).get("input") or {})
    reset_step_state_for_restart(
        main_state,
        "step2",
        report_dir,
        preserve_current_input=step2_input,
    )
    save_main_state(report_dir, main_state)
    print(
        "已保留分析对象与依赖范围；升级上下文及之后的产物会按本次答复重建。",
        file=sys.stderr,
    )


def handle_step4_resume_followups(
    main_state,
    report_dir,
    resumed_interaction_step_id,
    response_action,
):
    if resumed_interaction_step_id != "step4" or response_action != "continue":
        return
    step4_input = dict((main_state.get("step4") or {}).get("input") or {})
    step5_input = dict((main_state.get("step5") or {}).get("input") or {})
    for key in ("step5_selected_coords", "step5_selected_names"):
        values = normalize_step5_target_list(step4_input.get(key), key) or []
        if values:
            step5_input[key] = values
        else:
            step5_input.pop(key, None)
    main_state["step5"]["input"] = step5_input
    save_main_state(report_dir, main_state)
    all_rows = read_csv_rows(step4_api_changes_dir(report_dir) / "all_changed_apis.csv")
    selection = build_step5_selection_summary(
        all_rows,
        selected_coords=step5_input.get("step5_selected_coords"),
        selected_names=step5_input.get("step5_selected_names"),
    )
    has_partial_request = bool(
        selection.get("selected_coords") or selection.get("selected_names")
    )
    total_high_risk = sum(1 for row in all_rows if _is_high_risk_selection_api_row(row))
    selected_high_risk = sum(
        1
        for row in (selection.get("matched_rows") or [])
        if _is_high_risk_selection_api_row(row)
    )
    if has_partial_request:
        matched_coord_count = len(
            {
                str((row or {}).get("coord") or "").strip()
                for row in (selection.get("matched_rows") or [])
                if str((row or {}).get("coord") or "").strip()
            }
        )
        print(
            "已按你的选择确定部分分析范围："
            f"纳入 {matched_coord_count}/{selection.get('available_target_count', 0)} 个变化依赖，"
            f"覆盖 {selection.get('matched_row_count', 0)}/{len(all_rows)} 个变化 API，"
            f"其中高风险 API {selected_high_risk}/{total_high_risk} 个。",
            file=sys.stderr,
        )
        print("未选择的依赖不会进入系统触达分析，最终报告会明确记录该范围边界。", file=sys.stderr)
    else:
        print(
            f"已确认全量分析：覆盖 {selection.get('available_target_count', 0)} 个变化依赖、"
            f"{len(all_rows)} 个变化 API，其中高风险 API {total_high_risk} 个。",
            file=sys.stderr,
        )


def prepare_main_state_for_step_execution(args, main_state, step_id, report_dir):
    if args.step == "auto":
        repair_step_id = detect_integrity_repair_step(step_id, report_dir)
        if repair_step_id and repair_step_id != step_id:
            reset_step_state_for_restart(main_state, repair_step_id, report_dir)
            save_main_state(report_dir, main_state)
            return repair_step_id
        return step_id
    if should_reset_for_explicit_step_run(main_state, step_id, args.step):
        preserved_input = dict((main_state.get(step_id) or {}).get("input") or {})
        reset_step_state_for_restart(
            main_state,
            step_id,
            report_dir,
            preserve_current_input=preserved_input,
        )
        save_main_state(report_dir, main_state)
    return step_id


def maybe_emit_step1_preflight_interaction(step_id, main_state, report_dir, preflight_interaction):
    if step_id != "step1" or not preflight_interaction:
        return None
    preflight_interaction = apply_interaction_protocol_enhancements(
        preflight_interaction,
        step_id,
        project_dir=Path(report_dir).resolve().parent,
        report_dir=report_dir,
    )
    update_main_state_state(
        main_state,
        current_step=step_id,
        completed_step=(main_state.get("state") or {}).get("completed_step"),
        status=normalize_interaction_status(preflight_interaction.get("status")),
        blocking_reason=preflight_interaction.get("question") or preflight_interaction.get("title") or step_id,
        pending_interaction=dict(preflight_interaction),
    )
    save_main_state(report_dir, main_state)
    save_interaction_file(report_dir, preflight_interaction)
    print_interaction_to_streams(preflight_interaction, report_dir)
    print(f"{USER_TASK_NAMES.get(step_id, '当前分析')}需要先补齐上面的信息。", file=sys.stderr)
    return EXIT_AWAITING_USER


def persist_step_interaction(main_state, step_id, report_dir, run_context, interaction):
    store_step_output(main_state, step_id, run_context, report_dir)
    seed_next_step_input(main_state, step_id, run_context)
    interaction = apply_interaction_protocol_enhancements(
        interaction,
        step_id,
        project_dir=Path(report_dir).resolve().parent,
        report_dir=report_dir,
    )
    update_main_state_state(
        main_state,
        current_step=current_step_for_pending_interaction(step_id, interaction),
        completed_step=step_id,
        status=normalize_interaction_status(interaction.get("status")),
        blocking_reason=interaction.get("question") or interaction.get("title") or step_id,
        pending_interaction=dict(interaction),
    )
    save_main_state(report_dir, main_state)
    write_coverage_report(runtime_coverage_dir(report_dir), project_scope=run_context.get("project_scope"))
    save_interaction_file(report_dir, interaction)
    return interaction


def build_final_completion_summary(report_dir):
    """Summarize result certainty without converting a completed run into a false success claim."""
    findings_path = s6_findings_path(report_dir)
    try:
        findings = read_json(findings_path) if findings_path.is_file() else {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        findings = {}

    coverage = dict(findings.get("coverage") or {})
    scope = dict(findings.get("analysis_scope") or {})
    coverage_status = str(coverage.get("overall_status") or "unknown").strip()
    scope_mode = str(scope.get("mode") or "unknown").strip()
    confirmed_count = sum(len(findings.get(key) or []) for key in ("p0", "p1", "p2"))
    high_risk_count = sum(len(findings.get(key) or []) for key in ("p0", "p1"))
    probable_count = len(findings.get("probable_impact") or [])
    uncertain_count = len(findings.get("uncertain") or [])
    needs_input_count = len(findings.get("needs_input") or [])
    not_analyzed_count = len(findings.get("not_analyzed") or [])
    diagnostic_count = len(findings.get("diagnostics") or [])

    limitations = []
    if not findings:
        limitations.append("最终结构化结果缺失或无法读取")
    if scope_mode == "partial":
        limitations.append("用户选择了部分变化依赖")
    elif scope_mode != "full":
        limitations.append("分析范围快照缺失")
    if coverage_status not in {"complete", "not_applicable"}:
        limitations.append("关键证据覆盖不完整")
    if probable_count:
        limitations.append(f"{probable_count} 项只能判定为可能影响")
    if uncertain_count:
        limitations.append(f"{uncertain_count} 项需要人工复核")
    if needs_input_count:
        limitations.append(f"{needs_input_count} 项缺少依赖源码或构建产物")
    if not_analyzed_count:
        limitations.append(f"{not_analyzed_count} 项未完成分析")
    if diagnostic_count:
        limitations.append(f"{diagnostic_count} 个证据文件读取异常")

    return {
        "status": "completed_with_limits" if limitations else "completed",
        "scope_mode": scope_mode,
        "included_dependency_count": int(scope.get("included_dependency_count") or 0),
        "available_dependency_count": int(scope.get("available_dependency_count") or 0),
        "analyzed_api_count": int(scope.get("analyzed_api_count") or 0),
        "total_api_count": int(scope.get("total_api_count") or 0),
        "coverage_status": coverage_status,
        "confirmed_count": confirmed_count,
        "high_risk_count": high_risk_count,
        "probable_count": probable_count,
        "uncertain_count": uncertain_count,
        "needs_input_count": needs_input_count,
        "not_analyzed_count": not_analyzed_count,
        "diagnostic_count": diagnostic_count,
        "limitations": limitations,
    }


def persist_completed_step(main_state, step_id, report_dir, run_context):
    store_step_output(main_state, step_id, run_context, report_dir)
    seed_next_step_input(main_state, step_id, run_context)
    next_step = next_step_id_for(step_id)
    completion_summary = (
        build_final_completion_summary(report_dir)
        if step_id == "step6"
        else None
    )
    update_main_state_state(
        main_state,
        current_step=next_step or "done",
        completed_step=step_id,
        status=(completion_summary or {}).get("status") or "completed",
        blocking_reason=None,
        blocking_reason_codes=[],
        pending_interaction=None,
        completion_summary=completion_summary,
    )
    save_main_state(report_dir, main_state)
    write_coverage_report(runtime_coverage_dir(report_dir), project_scope=run_context.get("project_scope"))
    clear_interaction_file(report_dir)
    return completion_summary


def should_auto_continue_success_review(step_id, interaction, manifest_steps):
    """Skip routine success reviews when a safe default preserves full scope."""
    step_meta = (manifest_steps or {}).get(step_id) or {}
    # Step4 的范围选择会改变覆盖率、耗时和最终结论边界，不属于例行成功复核。
    # 即使未来误配 auto_continue_on_success，也必须保留该确认点。
    if step_meta.get("requires_scope_confirmation"):
        return False
    if not step_meta.get("auto_continue_on_success") or not interaction:
        return False
    # A producer-supplied reason code represents a real decision or evidence
    # blocker. Only generic post-success review cards are auto-continued.
    if str((interaction or {}).get("reason_code") or "").strip():
        return False
    option_ids = {
        str(item.get("id") or "").strip()
        for item in (interaction or {}).get("options") or []
    }
    return "continue" in option_ids


def print_auto_continue_success_review(step_id, run_context):
    if step_id == "step2":
        print(
            "升级上下文已由现有证据完整确定，直接继续兼容性扫描。",
            file=sys.stderr,
        )
    elif step_id == "step5":
        print(
            "后续直接生成带覆盖边界的最终报告，无需再次确认。",
            file=sys.stderr,
        )


def persist_interaction_required_error(main_state, step_id, report_dir, interaction):
    runtime_view = dict(previous_step_output(main_state or {}, step_id) or {})
    runtime_view.update((main_state or {}).get(step_id, {}).get("input") or {})
    interaction = apply_interaction_protocol_enhancements(
        interaction,
        step_id,
        project_dir=Path(report_dir).resolve().parent,
        report_dir=report_dir,
    )
    interaction = annotate_dependency_source_dirs_interaction(interaction, runtime_view, report_dir)
    update_main_state_state(
        main_state,
        current_step=step_id,
        completed_step=(main_state.get("state") or {}).get("completed_step"),
        status=normalize_interaction_status(interaction.get("status")),
        blocking_reason=interaction.get("question") or interaction.get("title") or step_id,
        pending_interaction=dict(interaction),
    )
    save_main_state(report_dir, main_state)
    save_interaction_file(report_dir, interaction)
    return interaction


def persist_step_error(main_state, step_id, report_dir, exc):
    update_main_state_state(
        main_state,
        current_step=step_id,
        completed_step=(main_state.get("state") or {}).get("completed_step"),
        status="blocked_by_system",
        blocking_reason=str(exc),
        blocking_reason_codes=list(getattr(exc, "reason_codes", []) or []),
        pending_interaction=None,
    )
    save_main_state(report_dir, main_state)
    clear_interaction_file(report_dir)


def persist_user_interrupt(main_state, step_id, report_dir):
    preserved_input = dict((main_state.get(step_id) or {}).get("input") or {})
    reset_step_state_for_restart(
        main_state,
        step_id,
        report_dir,
        preserve_current_input=preserved_input,
    )
    update_main_state_state(
        main_state,
        current_step=step_id,
        status="paused_by_user",
        blocking_reason="你已停止当前任务；未完成的临时产物已清理。",
        pending_interaction=None,
    )
    save_main_state(report_dir, main_state)
    clear_interaction_file(report_dir)


def refresh_step2_outputs(report_dir, project_dir, run_context):
    report_dir = Path(report_dir).resolve()
    project_dir = Path(project_dir).resolve()
    dep_changes = step1_dep_changes_path(report_dir)
    context_json = step2_context_path(report_dir)
    dep_graph_json = step2_dep_graph_path(report_dir)

    ensure_exists(dep_changes, "重建 Step2 产物时缺少 evidence/dependencies/dep_changes.csv，请先执行 Step1")
    if not (run_context.get("base_branch") and run_context.get("current_branch")):
        raise StepError("重建 Step2 产物需要 base_branch 和 current_branch")
    cmd = [
        "--dep-changes", str(dep_changes),
        "--work-dir", str(project_dir),
        "--output", str(context_json),
        "--output-dep-graph", str(dep_graph_json),
    ]
    run_python(
        "s2_context_from_deps.py",
        cmd,
        project_dir,
        report_dir=report_dir,
    )


def detect_integrity_repair_step(step_id, report_dir):
    report_dir = Path(report_dir).resolve()
    required_outputs = {
        "step2": [("step1", "evidence/dependencies/dep_changes.csv")],
        "step3": [
            ("step1", "evidence/dependencies/dep_changes.csv"),
            ("step2", "evidence/context/context.json"),
        ],
        "step4": [
            ("step1", "evidence/dependencies/dep_changes.csv"),
            ("step2", "evidence/context/context.json"),
        ],
        "step5": [
            ("step1", "evidence/dependencies/dep_changes.csv"),
            ("step2", "evidence/context/context.json"),
            ("step4", "evidence/api_changes/all_changed_apis.csv"),
        ],
        "step6": [
            ("step1", "evidence/dependencies/dep_changes.csv"),
            ("step2", "evidence/context/context.json"),
            ("step4", "evidence/api_changes/all_changed_apis.csv"),
            ("step5", "evidence/call_chain/summary.json"),
        ],
    }
    missing_restart_steps = []
    for restart_step_id, rel_path in required_outputs.get(str(step_id or "").strip(), []):
        if not artifact_path(report_dir, rel_path).exists():
            missing_restart_steps.append(restart_step_id)
    if not missing_restart_steps:
        return ""
    return min(missing_restart_steps, key=step_index)


def cleanup_step3_candidate_outputs(report_dir):
    report_dir = Path(report_dir).resolve()
    # Step3 candidate artifacts are independent diagnostic evidence; reruns must
    # not inherit stale matches from an earlier dependency selection.
    aggregate_path = evidence_static_scan_dir(report_dir) / STEP3_RISK_CANDIDATES_FILE
    if aggregate_path.exists():
        aggregate_path.unlink()

    per_dependency_dir = step4_api_changes_dir(report_dir) / PER_DEPENDENCY_DIRNAME
    if not per_dependency_dir.exists():
        return

    for dep_dir in per_dependency_dir.iterdir():
        if not dep_dir.is_dir():
            continue
        candidate_hits_path = dep_dir / PER_DEPENDENCY_CANDIDATE_HITS_FILE
        if candidate_hits_path.exists():
            candidate_hits_path.unlink()
        summary_path = dep_dir / PER_DEPENDENCY_SUMMARY_FILE
        if not summary_path.exists():
            continue
        try:
            summary = read_json(summary_path)
        except Exception:
            continue
        # Preserve the rest of the per-dependency summary and only clear the
        # Step3-owned candidate section.
        summary.pop("step3", None)
        artifacts = dict(summary.get("artifacts") or {})
        artifacts.pop("candidate_hits_csv", None)
        if artifacts:
            summary["artifacts"] = artifacts
        else:
            summary.pop("artifacts", None)
        if summary:
            summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        else:
            summary_path.unlink()


def step_output_paths_for_cleanup(step_id, report_dir):
    report_dir = Path(report_dir).resolve()
    outputs = {
        "step1": [
            step1_dep_alerts_path(report_dir),
            step1_dep_changes_path(report_dir),
            step1_dep_summary_path(report_dir),
            step1_current_resolved_path(report_dir),
            runtime_observability_dir(report_dir) / "step1_progress.jsonl",
            runtime_observability_dir(report_dir) / "step1_timing.csv",
            build_provenance_path(report_dir),
            step1_artifacts_dir(report_dir),
            step1_dependency_jars_manifest_path(report_dir),
            step1_dependency_jars_dir(report_dir),
        ],
        "step2": [
            step2_context_path(report_dir),
            step2_dep_graph_path(report_dir),
            step2_source_mapping_summary_path(report_dir),
        ],
        "step3": [
            evidence_static_scan_dir(report_dir) / "s3_jdk_removed_api.csv",
            evidence_static_scan_dir(report_dir) / "s3_jdk_javax_refs.csv",
            evidence_static_scan_dir(report_dir) / "s3_jdk_internal_api.csv",
            evidence_static_scan_dir(report_dir) / "s3_jdk_reflection.csv",
            evidence_static_scan_dir(report_dir) / "s3_jdk_serialization.txt",
            evidence_static_scan_dir(report_dir) / "s3_jdk_runtime_flags.csv",
            evidence_static_scan_dir(report_dir) / "s3_springboot_config.csv",
            evidence_static_scan_dir(report_dir) / "s3_springboot_autoconfig.txt",
            evidence_static_scan_dir(report_dir) / "s3_dependency_compat.csv",
            evidence_static_scan_dir(report_dir) / "s3_dependency_classfile.csv",
            evidence_static_scan_dir(report_dir) / STEP3_RISK_CANDIDATES_FILE,
        ],
        "step4": [
            step4_api_changes_dir(report_dir),
            runtime_observability_dir(report_dir) / "step4_timing.csv",
        ],
        "step5": [
            step5_call_chain_dir(report_dir),
            runtime_observability_dir(report_dir) / "step5_timing.csv",
            runtime_cache_dir(report_dir) / STEP5_ARTIFACT_BYTECODE_CATALOG_FILE,
            runtime_cache_dir(report_dir) / STEP5_ARTIFACT_BYTECODE_INDEX_FILE,
            runtime_cache_dir(report_dir) / STEP5_ARTIFACT_BYTECODE_DIRNAME,
            step5_query_index_path(report_dir),
            evidence_call_chain_dir(report_dir) / "framework_adapters.json",
            evidence_call_chain_dir(report_dir) / "source_artifact_alignment.json",
        ],
        "step6": [
            s6_findings_path(report_dir),
            s6_report_path(report_dir),
            deliverables_dir(report_dir),
        ],
    }
    return list(outputs.get(str(step_id or "").strip(), []))


def cleanup_step_outputs(step_id, report_dir):
    for path in step_output_paths_for_cleanup(step_id, report_dir):
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    if str(step_id or "").strip() == "step3":
        cleanup_step3_candidate_outputs(report_dir)


def execute_step(step_id, args, manifest_steps, run_context, main_state=None):
    project_dir = Path(args.project_dir).resolve()
    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    cleanup_step_outputs(step_id, report_dir)

    dep_changes = step1_dep_changes_path(report_dir)
    dep_current = step1_current_resolved_path(report_dir)
    context_json = step2_context_path(report_dir)
    s4_dir = step4_api_changes_dir(report_dir)

    if step_id == "step1":
        output = step1_dep_changes_path(report_dir)
        base_artifact_path = run_context.get("base_artifact_path", "")
        current_artifact_path = run_context.get("current_artifact_path", "")
        base_branch = run_context.get("base_branch")
        current_branch = run_context.get("current_branch")
        if base_artifact_path or current_artifact_path:
            if not (base_artifact_path and current_artifact_path):
                raise StepError("Step1 的直接产物模式必须同时提供 base_artifact_path 和 current_artifact_path。")
            cmd = [
                "--work-dir", str(project_dir),
                "--output", str(output),
            ]
            run_python("s1_dep_diff.py", cmd, project_dir, report_dir=report_dir)
        elif base_branch and current_branch:
            cmd = [
                "--work-dir", str(project_dir),
                "--output", str(output),
            ]
            run_python("s1_dep_diff.py", cmd, project_dir, report_dir=report_dir)
        else:
            raise StepError(
                "Step1 需要二选一的输入方式："
                "要么提供 base_artifact_path/current_artifact_path 直接读取编译产物，"
                "要么提供 base_branch/current_branch，在固定 commit 的隔离 worktree 中执行真实 package。"
            )

    elif step_id == "step2":
        ensure_exists(dep_changes, "Step2 缺少 evidence/dependencies/dep_changes.csv，请先执行 Step1")
        base_branch = run_context.get("base_branch")
        current_branch = run_context.get("current_branch")
        base_revision = str(run_context.get("base_resolved_commit") or base_branch or "").strip()
        current_revision = str(run_context.get("current_resolved_commit") or current_branch or "").strip()
        if not (base_branch and current_branch):
            if run_context.get("artifact_input_mode"):
                raise StepError(
                    "Step2 检测到当前流程来自用户提供的编译产物路径，但尚未明确提供 base_branch/current_branch。"
                "请回到最近的 checkpoint，通过结构化用户答复把这两个分支写回 .runtime/state/main_state.json 后再继续，"
                    "避免把产物差异和自动探测到的工作区分支混用。"
                )
            raise StepError(
                "Step2 需要基准分支和当前分支。请检查 .runtime/state/main_state.json 中的 step2.input / step1.output，"
                "或回到最近的 checkpoint 通过 --response-json / --response-file 把分支写回主状态后再继续。"
            )
        if is_git_repo(project_dir) and base_revision == current_revision:
            raise StepError(
                f"Step2 检测到 base/current 执行 revision 相同（{base_revision}），无法进行 git diff/推断。"
                "请回到最近的 checkpoint 或修正 .runtime/state/main_state.json，明确写入两个不同分支后再继续。"
            )
        cmd = [
            "--dep-changes", str(dep_changes),
            "--work-dir", str(project_dir),
            "--output", str(context_json),
            "--output-dep-graph", str(step2_dep_graph_path(report_dir)),
        ]
        run_python(
            "s2_context_from_deps.py",
            cmd,
            project_dir,
            report_dir=report_dir,
        )
    elif step_id == "step3":
        validate_run_context_for_step(step_id, run_context)
        ensure_exists(context_json, "Step3 缺少 evidence/context/context.json，请先执行 Step2")
        cmd = [
            "--all",
            "--output-dir", str(evidence_static_scan_dir(report_dir)),
            "--report-dir", str(report_dir),
            "--coverage-output", str(runtime_coverage_dir(report_dir) / "s3_coverage.json"),
        ]
        if dep_current.exists():
            cmd.extend(["--dep-current", str(dep_current)])
        elif dep_changes.exists():
            cmd.extend(["--dep-changes", str(dep_changes)])
        run_python("s3_scan.py", cmd, project_dir, report_dir=report_dir)

    elif step_id == "step4":
        validate_run_context_for_step(step_id, run_context)
        ensure_exists(dep_changes, "Step4 缺少 evidence/dependencies/dep_changes.csv，请先执行 Step1")
        ensure_exists(context_json, "Step4 缺少 evidence/context/context.json，请先执行 Step2")
        cmd = [
            "--dep-changes", str(dep_changes),
            "--context", str(context_json),
            "--output-dir", str(s4_dir),
            "--coverage-output", str(runtime_coverage_dir(report_dir) / "s4_coverage.json"),
        ]
        run_python("s4_jar_compare.py", cmd, project_dir, report_dir=report_dir)

    elif step_id == "step5":
        validate_run_context_for_step(step_id, run_context)
        all_changed_apis = s4_dir / "all_changed_apis.csv"
        ensure_exists(all_changed_apis, "Step5 缺少 all_changed_apis.csv，请先执行 Step4")
        step5_all_changed_apis, _selection_summary = materialize_step5_all_changed_apis_input(
            all_changed_apis,
            report_dir,
            run_context,
        )
        cmd = [
            "--all-changed-apis", str(step5_all_changed_apis),
            "--jdk-scan-dir", str(evidence_static_scan_dir(report_dir)),
            "--report-dir", str(report_dir),
            "--output-dir", str(step5_call_chain_dir(report_dir)),
            "--query-index", str(step5_query_index_path(report_dir)),
        ]
        step5_timeout = run_context.get("step5_timeout")
        if step5_timeout not in (None, ""):
            step5_timeout = parse_positive_int_like(step5_timeout, "step5_timeout")
        else:
            step5_timeout = None
        run_python(
            "s5_call_chain_engine_integrated.py",
            cmd,
            project_dir,
            report_dir=report_dir,
            timeout=step5_timeout,
        )

    elif step_id == "step6":
        ensure_exists(step5_call_chain_dir(report_dir) / "summary.json", "Step6 缺少 Step5 的 summary.json，请先执行 Step5")
        run_python(
            "s6_report.py",
            [
                "--report-dir", str(report_dir),
                "--output-findings", str(s6_findings_path(report_dir)),
                "--output-report", str(s6_report_path(report_dir)),
            ],
            project_dir,
            report_dir=report_dir,
        )
    else:
        raise StepError(f"未知 step: {step_id}")

    refreshed_run_context = build_run_context(args, run_context, {}, allow_external_seed=False)
    gate_name = manifest_steps[step_id].get("gate")
    run_gate(gate_name, report_dir, project_dir, strict_risk_gate=bool(refreshed_run_context.get("strict_risk_gate")))
    # Step5 的成功结果可直接进入最终报告。Step4 的全量/部分范围选择会
    # 实质改变覆盖率与结论边界，即使误配自动继续也必须构造确认载荷。
    step_meta = manifest_steps.get(step_id) or {}
    if (
        step_meta.get("auto_continue_on_success")
        and not step_meta.get("requires_scope_confirmation")
        and not step_meta.get("conditional_confirmation")
    ):
        return None
    return build_interaction_payload(
        step_id,
        report_dir,
        manifest_steps,
        project_dir,
        run_context=refreshed_run_context,
        main_state=main_state,
    )


def main(argv=None, _skip_environment_contract=False):
    ap = argparse.ArgumentParser(description="统一执行 Java 升级分析的单个 Step")
    ap.add_argument("--step", choices=STEP_SEQUENCE + ["auto"])
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--report-dir", default=".upgrade-report")
    ap.add_argument("--seed-json", dest="seed_json", default="", help="初始化输入 JSON；仅用于首次建立主状态")
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--base-branch")
    ap.add_argument("--current-branch")
    ap.add_argument("--modules", action="append", nargs="+", default=None)
    ap.add_argument(
        "--active-maven-profile",
        dest="active_maven_profiles",
        action="append",
        default=None,
    )
    ap.add_argument("--source-dirs", action="append", nargs="+")
    ap.add_argument("--dependency-source-dirs", action="append", nargs="+", default=[])
    ap.add_argument("--dependency-source-mappings", action="append", nargs="+", default=[])
    ap.add_argument("--source-repo-hints", action="append", nargs="+", default=[])
    ap.add_argument("--dependency-repo-mappings", action="append", nargs="+", default=[])
    ap.add_argument("--dependency-git-ref-overrides-json", default="")
    ap.add_argument("--japicmp-jar", default="")
    ap.add_argument("--step4-git-diff-timeout", type=int, default=None)
    ap.add_argument("--step4-japicmp-timeout", type=int, default=None)
    ap.add_argument("--step4-fetch-timeout", type=int, default=None)
    ap.add_argument("--step4-tool-install-timeout", type=int, default=None)
    ap.add_argument("--step4-workers", type=int, default=None)
    ap.add_argument("--step5-timeout", type=int, default=None)
    ap.add_argument("--base-artifact-path", default="")
    ap.add_argument("--current-artifact-path", default="")
    ap.add_argument("--base-source-project-dir", default="")
    ap.add_argument("--current-source-project-dir", default="")
    ap.add_argument("--base-jdk-home", default="")
    ap.add_argument("--current-jdk-home", default="")
    ap.add_argument("--include-test-scope", action="store_true")
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--allow-degraded", action="store_true")
    ap.add_argument("--strict-risk-gate", action="store_true")
    ap.add_argument("--primary-module", default="")
    ap.add_argument("--target-module", default="", help="本次分析唯一的目标部署模块；新流程优先使用")
    ap.add_argument("--tool", choices=["maven", "gradle"], default="")
    ap.add_argument("--response-json", default="", help="结构化用户答复 JSON，例如 '{\"action\":\"continue\"}'")
    ap.add_argument("--response-file", default="", help="结构化用户答复 JSON 文件路径")
    ap.add_argument(
        "--describe-step1-contract",
        action="store_true",
        help="输出 Step1 的静态前置输入协议（JSON），供 Agent 在首次调用前读取。",
    )
    args = ap.parse_args(argv)
    args.modules = _dedupe_strings(flatten_cli_values(args.modules)) if args.modules else None
    args.active_maven_profiles = _dedupe_strings(
        args.active_maven_profiles or []
    ) if args.active_maven_profiles is not None else None
    args.source_dirs = flatten_cli_values(args.source_dirs)
    args.dependency_source_dirs = _dedupe_strings(flatten_cli_values(args.dependency_source_dirs))
    args.dependency_source_mappings = _dedupe_strings(flatten_cli_values(args.dependency_source_mappings))
    args.source_repo_hints = _dedupe_strings(flatten_cli_values(args.source_repo_hints))
    args.dependency_repo_mappings = _dedupe_strings(flatten_cli_values(args.dependency_repo_mappings))

    if args.describe_step1_contract:
        sys.stdout.write(json.dumps(build_step1_static_contract(), ensure_ascii=False, indent=2) + "\n")
        return 0
    if not args.step:
        ap.error("--step 是必填参数；若只想读取前置协议，请改用 --describe-step1-contract")

    project_dir = Path(args.project_dir).resolve()
    environment = (
        {"status": "passed", "checks": []}
        if _skip_environment_contract
        else contract_payload()
    )
    if environment["status"] != "passed":
        for line in build_environment_block_message(environment):
            print(line, file=sys.stderr)
        return 1

    if not project_dir.is_dir():
        print(f"❌ 项目目录不存在：{project_dir}", file=sys.stderr)
        return 1

    seed_payload = load_seed_json_arg(args.seed_json, project_dir)
    report_dir = Path(args.report_dir).resolve()
    main_state = load_main_state(report_dir, manifest_path=args.manifest)
    manifest_data, manifest_steps = load_manifest(args.manifest)
    pending_interaction = (main_state.get("state") or {}).get("pending_interaction")
    if pending_interaction:
        enhanced_pending_interaction = apply_interaction_protocol_enhancements(
            pending_interaction,
            str(pending_interaction.get("step_id") or ""),
            project_dir=project_dir,
            report_dir=report_dir,
        )
        if enhanced_pending_interaction != pending_interaction:
            pending_interaction = enhanced_pending_interaction
            main_state["state"]["pending_interaction"] = dict(pending_interaction)
            save_main_state(report_dir, main_state)
            save_interaction_file(report_dir, pending_interaction)
    structured_user_response = None
    has_structured_response = bool(args.response_json or args.response_file)
    if has_structured_response:
        structured_user_response = resolve_user_response(args, project_dir)
    if args.step == "auto" and has_structured_response and not pending_interaction:
        step_id = ""
    elif (
        args.step == "auto"
        and not has_structured_response
        and not pending_interaction
        and str(((main_state or {}).get("state") or {}).get("current_step") or "").strip() == "done"
    ):
        repair_step_id = detect_integrity_repair_step("step6", report_dir)
        if not repair_step_id:
            write_report_landing_docs(report_dir, main_state)
            print(
                "分析已经完成，正式证据链完整；可直接查看 deliverables/report.md。",
                file=sys.stderr,
            )
            return 0
        reset_step_state_for_restart(main_state, repair_step_id, report_dir)
        save_main_state(report_dir, main_state)
        print(
            f"检测到早期证据缺失，将从{USER_TASK_NAMES.get(repair_step_id, repair_step_id)}自动重建受影响的后续结果。",
            file=sys.stderr,
        )
        step_id = repair_step_id
    else:
        step_id = resolve_requested_step(args.step, main_state)
    response_result = apply_structured_user_response_if_present(
        args,
        project_dir,
        report_dir,
        main_state,
        step_id,
        user_response=structured_user_response,
    )
    main_state = response_result["main_state"]
    step_id = response_result["step_id"]
    pending_interaction = response_result["pending_interaction"]
    resumed_interaction_step_id = response_result["resumed_interaction_step_id"]
    response_action = response_result["response_action"]
    user_response = response_result["user_response"]
    if response_result["early_exit_code"] is not None:
        return response_result["early_exit_code"]

    early_exit = maybe_return_pending_interaction(report_dir, pending_interaction)
    if early_exit is not None:
        return early_exit

    handle_step2_resume_followups(
        main_state,
        report_dir,
        resumed_interaction_step_id,
        step_id,
        response_action,
        user_response,
    )
    handle_step4_resume_followups(
        main_state,
        report_dir,
        resumed_interaction_step_id,
        response_action,
    )
    step_id = prepare_main_state_for_step_execution(args, main_state, step_id, report_dir)

    base_context = build_step_input_context(main_state, step_id, fallback_existing={})
    run_context = build_run_context(
        args,
        base_context,
        seed_payload,
        allow_external_seed=not bool(base_context),
    )
    store_step_input(main_state, step_id, run_context)
    save_main_state(report_dir, main_state)
    preflight_exit = maybe_emit_step1_preflight_interaction(
        step_id,
        main_state,
        report_dir,
        build_step1_preflight_interaction(run_context),
    )
    if preflight_exit is not None:
        return preflight_exit
    if step_id == "step1":
        run_context, ref_interaction = resolve_step1_refs_for_execution(run_context, project_dir)
        store_step_input(main_state, step_id, run_context)
        save_main_state(report_dir, main_state)
        ref_preflight_exit = maybe_emit_step1_preflight_interaction(
            step_id,
            main_state,
            report_dir,
            ref_interaction,
        )
        if ref_preflight_exit is not None:
            return ref_preflight_exit

    task_name = USER_TASK_NAMES.get(step_id, "当前分析")
    print("", file=sys.stderr)
    for line in build_user_runtime_message("start", step_id):
        print(line, file=sys.stderr)

    try:
        interaction = execute_step(step_id, args, manifest_steps, run_context, main_state=main_state)
        run_context = build_run_context(args, run_context, {}, allow_external_seed=False)
        auto_continued_success_review = False
        if should_auto_continue_success_review(step_id, interaction, manifest_steps):
            interaction = None
            auto_continued_success_review = True
        elif (
            not interaction
            and (manifest_steps.get(step_id) or {}).get("auto_continue_on_success")
            and not (manifest_steps.get(step_id) or {}).get("requires_scope_confirmation")
        ):
            auto_continued_success_review = True
        if auto_continued_success_review:
            print_auto_continue_success_review(step_id, run_context)
        # Always save main_state after interaction to maintain protocol integrity.
        # Per CHECKPOINT_RULES.md: must_wait_for_user_reply.
        if interaction:
            interaction = persist_step_interaction(main_state, step_id, report_dir, run_context, interaction)
            print_interaction_to_streams(interaction, report_dir)
            print(f"{task_name}已完成，分析正在等待你的确认。", file=sys.stderr)
            return EXIT_AWAITING_USER
        completion_summary = persist_completed_step(
            main_state, step_id, report_dir, run_context
        )
        for line in build_user_runtime_message(
            "complete", step_id, completion_summary=completion_summary
        ):
            print(line, file=sys.stderr)
        next_step = next_step_id_for(step_id)
        if (
            args.step == "auto"
            and next_step
            and bool(manifest_data.get("auto_run_until_checkpoint"))
        ):
            print(
                f"流程自动继续：{USER_TASK_NAMES.get(next_step, next_step)}",
                file=sys.stderr,
            )
            return main(
                [
                    "--step", "auto",
                    "--project-dir", str(project_dir),
                    "--report-dir", str(report_dir),
                    "--manifest", str(args.manifest),
                ],
                _skip_environment_contract=True,
            )
        return 0
    except StepInteractionRequired as exc:
        interaction = exc.interaction or {}
        interaction = persist_interaction_required_error(main_state, step_id, report_dir, interaction)
        print_interaction_to_streams(interaction, report_dir)
        print(f"{task_name}需要补充上面的信息后才能继续。", file=sys.stderr)
        return EXIT_AWAITING_USER
    except StepError as exc:
        persist_step_error(main_state, step_id, report_dir, exc)
        for line in build_user_runtime_message("failed", step_id, reason=exc):
            print(line, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        persist_user_interrupt(main_state, step_id, report_dir)
        print("\n已安全停止当前任务。已完成任务和正式证据保持不变。", file=sys.stderr)
        print(
            f"再次运行分析时，将从{USER_TASK_NAMES.get(step_id, '当前任务')}重新开始。",
            file=sys.stderr,
        )
        return EXIT_INTERRUPTED


def _cli_report_dir(argv):
    values = list(sys.argv[1:] if argv is None else argv)
    try:
        index = values.index("--report-dir")
    except ValueError:
        return None
    if index + 1 >= len(values):
        return None
    value = str(values[index + 1] or "").strip()
    return Path(value).expanduser().resolve() if value else None


def _record_unexpected_cli_error(exc, argv=None):
    report_dir = _cli_report_dir(argv)
    if report_dir is None:
        return ""
    diagnostic_path = report_dir / ".runtime" / "observability" / "internal_error.json"
    try:
        diagnostic_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(
            diagnostic_path,
            {
                "schema": "java-upgrade-analyzer.internal-error.v1",
                "recorded_at": datetime.now().isoformat(),
                "error_type": exc.__class__.__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            },
        )
    except (OSError, TypeError, ValueError):
        return ""
    return str(diagnostic_path)


def cli_main(argv=None):
    """Keep implementation failures out of the user-facing terminal channel."""
    try:
        return main(argv)
    except StepError as exc:
        reason = _humanize_interaction_text(str(exc)).strip()
        print(f"分析未能继续：{reason or '当前输入或状态不完整。'}", file=sys.stderr)
        print("已有正式产物保持不变；条件修正后重新运行即可。", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n运行已停止。再次运行时会先检查已有证据完整性。", file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as exc:
        diagnostic_path = _record_unexpected_cli_error(exc, argv=argv)
        print("系统未能完成当前操作，已停止以避免生成不完整结论。", file=sys.stderr)
        if diagnostic_path:
            print(f"诊断已记录：{diagnostic_path}", file=sys.stderr)
        else:
            print("当前无法写入诊断文件；已有正式产物保持不变。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(cli_main())
