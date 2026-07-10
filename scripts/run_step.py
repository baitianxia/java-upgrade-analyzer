#!/usr/bin/env python3
"""统一调度入口：执行单个 Step，并负责门控与主状态持久化。"""

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from compat import infer_maven_coords, open_text, resolve_repo_input_path, run_cmd
from compat import git_cmd
from auto_discover_bridge_sources import discover_bridge_source_mappings
from analysis_contract import build_project_scope, discover_maven_modules, write_coverage_report
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
    RUNTIME_STATE_DIRNAME,
    STEP1_ARTIFACTS_DIRNAME,
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


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
DEFAULT_MANIFEST = SCRIPT_DIR / "step_manifest.json"
CHECKPOINT_RULES_FILE = SKILL_DIR / "CHECKPOINT_RULES.md"
EXIT_AWAITING_USER = 4
MAIN_STATE_FILE_NAME = "main_state.json"
STEP1_MAVEN_MODULE_SEP = re.compile(r"\[INFO\]\s*---.*@\s*(\S+)\s*---")
INTENT_PATCH_ALLOWED_SET_FIELDS = {
    "allow_degraded",
    "accept_suggested_mappings",
    "analysis_mode",
    "base_artifact_path",
    "base_branch",
    "base_jdk_home",
    "base_source_project_dir",
    "current_artifact_path",
    "current_branch",
    "current_jdk_home",
    "current_source_project_dir",
    "dependency_git_ref_overrides",
    "dependency_source_dirs",
    "manual_coord_overrides",
    "max_depth",
    "modules",
    "primary_module",
    "source_dirs",
    "source_repo_hints",
    "selected_targets",
    "step4_fetch_timeout",
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
    pass


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


def write_report_landing_docs(report_dir):
    report_dir = Path(report_dir)
    deliverables = deliverables_dir(report_dir)
    evidence = evidence_dir(report_dir)
    runtime = runtime_dir(report_dir)
    for path in (report_dir, deliverables, evidence, runtime):
        path.mkdir(parents=True, exist_ok=True)

    _write_text_file(
        report_dir / "README.md",
        """# 升级分析产物阅读入口

这个目录分成三层，避免把给人看的报告、深入复核证据和程序状态混在一起。

| 目录 | 谁看 | 用途 |
|---|---|---|
| `deliverables/` | 普通使用者、评审人 | 给用户看的交付物。先看 `deliverables/report.md`。 |
| `evidence/` | 需要深入复核的人 | Step1-Step5 的事实证据和完整台账。 |
| `.runtime/` | 程序和 Agent | 状态、缓存、索引、恢复信息；普通用户不需要阅读。 |

## 推荐阅读顺序

1. 先看 `deliverables/report.md`。
2. 如需核对依赖包变化，看 `evidence/api_changes/changed_dependencies.md`。
3. 如需核对完整 API 明细，看 `evidence/api_changes/all_changed_apis.csv`。
4. 如需核对调用链，看 `evidence/call_chain/alerts.csv`。
""",
    )
    _write_text_file(
        deliverables / "README.md",
        """# deliverables/

给用户看的交付物目录。

| 文件 | 用途 |
|---|---|
| `report.md` | 最终报告；呈现客观分析结果、证据和结论限制。 |
| `s6_*_apis.md/csv` | Step6 按结论分类拆出的明细；当主报告省略大量结果时再打开。 |

这里的文件面向阅读和评审，不作为程序恢复状态的来源。
""",
    )
    _write_text_file(
        evidence / "README.md",
        """# evidence/

深入复核证据目录。这里保存 Step1-Step5 的事实材料和完整台账。

| 目录 | 主要文件 | 用途 |
|---|---|---|
| `dependencies/` | `dep_changes.csv`、`build_provenance.json` | 依赖变更和构建产物来源。 |
| `context/` | `context.json`、`source_mapping_summary.json` | 分析上下文和源码/依赖映射。 |
| `static_scan/` | `s3_*.csv/.txt` | JDK、Spring、Jakarta 等背景线索。 |
| `api_changes/` | `changed_dependencies.md`、`changed_dependencies.csv`、`all_changed_apis.csv` | 依赖包维度选择入口和完整 API 变化事实。 |
| `call_chain/` | `alerts.csv`、`alerts_<status>.csv`、`summary.json` | 调用链完整台账和拆分阅读视图。 |

普通选择 Step5 分析范围时优先使用 `api_changes/changed_dependencies.md` 中的 `selection_key`；`all_changed_apis.csv` 是完整 API 明细，不作为普通选择入口。
""",
    )
    _write_text_file(
        runtime / "README.md",
        """# .runtime/

程序使用的状态和缓存目录。普通用户不需要阅读这里。

| 目录 | 用途 |
|---|---|
| `state/` | `main_state.json`、`interaction.json`，用于恢复流程和 checkpoint。 |
| `coverage/` | 各步骤覆盖情况，用于 Step6 结论限制。 |
| `indexes/` | Step5 查询索引。 |
| `findings/` | Step6 结构化结果，供程序读取。 |
| `cache/` | 中间缓存和筛选后的输入。 |

不要把这里的 JSON 当作用户报告；需要给人看的结论在 `../deliverables/`，需要复核的证据在 `../evidence/`。
""",
    )


def read_csv_rows(path):
    import csv

    path = Path(path)
    if not path.exists():
        return []
    with open_text(path) as f:
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
            "pending_interaction": None,
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
    write_report_landing_docs(report_dir)
    normalized = ensure_main_state_structure(state, report_dir, manifest_path=(state.get("state") or {}).get("manifest_path", ""))
    normalized["state"]["saved_at"] = datetime.now().isoformat()
    write_json(main_state_path(report_dir), normalized)
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
            result.pop("dependency_repo_mappings", None)
            result.pop("dependency_source_mappings", None)
            result.pop("dependency_source_mapping_conflicts", None)
            result.pop("unmapped_dependency_coords", None)
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
        updated.pop("dependency_repo_mappings", None)
        updated.pop("dependency_source_mappings", None)

    source_repo_hints = normalize_source_repo_hints(
        response.get("source_repo_hints"),
        project_dir,
        "source_repo_hints",
    )
    if source_repo_hints is not None:
        updated["source_repo_hints"] = source_repo_hints

    dependency_git_ref_overrides = normalize_dependency_git_ref_overrides(
        response.get("dependency_git_ref_overrides"),
        "dependency_git_ref_overrides",
    )
    if dependency_git_ref_overrides is not None:
        updated["dependency_git_ref_overrides"] = dependency_git_ref_overrides
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
        "step4_workers",
        "step5_timeout",
    ):
        if timeout_key in response:
            updated[timeout_key] = parse_positive_int_like(response.get(timeout_key), timeout_key)

    for key in ("include_test_scope", "allow_degraded", "strict_risk_gate", "tree_sitter_installed"):
        if key in response:
            updated[key] = parse_bool_like(response.get(key), key)
    if "strict_risk_gate" in response:
        updated["strict_risk_gate"] = parse_bool_like(response.get("strict_risk_gate"), "strict_risk_gate")
    manual_coord_overrides = response.get("manual_coord_overrides")
    if manual_coord_overrides is not None:
        if isinstance(manual_coord_overrides, str):
            updated["manual_coord_overrides"] = [manual_coord_overrides.strip()] if manual_coord_overrides.strip() else []
        elif isinstance(manual_coord_overrides, list):
            updated["manual_coord_overrides"] = _dedupe_strings(
                [str(item).strip() for item in manual_coord_overrides if str(item).strip()]
            )
        else:
            raise StepError("manual_coord_overrides 仅支持字符串或字符串列表")
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


def run_python(script_name, script_args, cwd, report_dir=None, timeout=None):
    cmd = [sys.executable, str(SCRIPT_DIR / script_name), *script_args]
    env = {
        "JUA_ORCHESTRATED": "1",
        "JUA_SKILL_DIR": str(SKILL_DIR),
    }
    if report_dir is not None:
        env["UPGRADE_REPORT_DIR"] = str(Path(report_dir).resolve())
    stdout, stderr, rc = run_cmd(cmd, cwd=str(cwd), env=env, timeout=timeout)
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
    print_output(filtered_stdout, stderr)
    if interaction is not None:
        raise StepInteractionRequired(interaction)
    if rc != 0:
        raise StepError(f"{script_name} 执行失败，退出码={rc}")


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
    for mod in modules:
        mod_value = (mod or "").strip()
        if mod_value in (".", "./", "__root__", "root"):
            module_dir = project_dir
        else:
            module_dir = (project_dir / mod_value).resolve()
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


def _discover_dependency_source_candidates(dependency_source_dirs):
    candidates = []
    seen = set()
    for raw_path in (dependency_source_dirs or []):
        input_path = str(raw_path or "").strip()
        if not input_path:
            continue
        repo_path = resolve_repo_input_path(os.path.expanduser(input_path))
        discovered_pairs = discover_bridge_source_mappings("", repo_path)
        if discovered_pairs:
            for coord, source_dir in discovered_pairs:
                coord = str(coord or "").strip()
                source_dir = str(source_dir or "").strip()
                if not coord:
                    continue
                module_root = _guess_module_root_from_source_dir(source_dir) if source_dir else repo_path
                key = (coord, repo_path, module_root, source_dir)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    {
                        "input_path": input_path,
                        "repo_path": repo_path,
                        "module_root": module_root,
                        "coord": coord,
                        "source_dir": source_dir,
                        "discovery_mode": "bridge_source_scan",
                    }
                )
        inferred_coords = [item for item in infer_maven_coords(repo_path) if item]
        for coord in inferred_coords:
            coord = str(coord or "").strip()
            if not coord:
                continue
            key = (coord, repo_path, repo_path, "")
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "input_path": input_path,
                    "repo_path": repo_path,
                    "module_root": repo_path,
                    "coord": coord,
                    "source_dir": "",
                    "discovery_mode": "coord_inference_only",
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

    raw_candidates = _discover_dependency_source_candidates(dependency_source_dirs)
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
            [str(item.get("repo_path") or "").strip() for item in coord_candidates if item.get("repo_path")]
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
    return value.startswith(("http://", "https://", "ssh://", "git@")) or value.endswith(".git")


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
        else:
            raise StepError(f"当前步骤输入中的 {config_key} 存在不支持的项类型")

        coord = coord.strip()
        old_ref = old_ref.strip()
        new_ref = new_ref.strip()
        if not (coord and old_ref and new_ref):
            raise StepError(f"当前步骤输入中的 {config_key} 每项都必须包含 coord/old_ref/new_ref")
        key = (coord, old_ref, new_ref)
        if key in seen:
            continue
        seen.add(key)
        normalized.append({"coord": coord, "old_ref": old_ref, "new_ref": new_ref})
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
        "preferred_identifier": "selection_key",
        "preferred_write_fields": ["step5_selected_coords", "step5_selected_names"],
        "rules": [
            "若用户提到候选依赖，应优先输出 selected_targets，并优先使用 selection_key。",
            "selected_targets 若填写 selection_key 或 coord，必须严格按该唯一目标执行；若只填写 name，则按 artifactId 名称筛选命中的全部候选。",
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


def build_step5_dependency_selection_summary(report_dir):
    report_dir = Path(report_dir).resolve()
    dependency_rows = read_csv_rows(step4_changed_dependencies_path(report_dir))
    if dependency_rows:
        available_targets = []
        for row in dependency_rows:
            coord = str(row.get("coord") or "").strip()
            if not coord:
                continue
            available_targets.append(
                {
                    "selection_key": str(row.get("selection_key") or f"coord:{coord}").strip(),
                    "coord": coord,
                    "name": str(row.get("dependency_name") or _artifact_name_from_coord(coord)).strip(),
                    "api_count": _parse_int_or_zero(row.get("changed_api_count")),
                    "high_risk_api_count": _parse_int_or_zero(row.get("high_risk_api_count")),
                    "change_types": str(row.get("change_types") or "").strip(),
                    "detail": str(row.get("detail") or "").strip(),
                }
            )
        return {
            "available_targets": available_targets,
            "available_target_count": len(available_targets),
            "source_file": str(step4_changed_dependencies_path(report_dir)),
        }
    all_rows = read_csv_rows(step4_api_changes_dir(report_dir) / "all_changed_apis.csv")
    fallback = build_step5_selection_summary(all_rows)
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
            },
        )
        item["api_count"] += 1
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
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in selection_summary.get("matched_rows") or []:
            writer.writerow({field: row.get(field, "") for field in ALL_CHANGED_APIS_FIELDS})
    return output_path


def write_csv_rows(output_path, rows, fieldnames):
    import csv

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
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
    source_dirs = _dedupe_strings(runtime_view.get("source_dirs") or [])
    source_dirs_status = str(runtime_view.get("source_dirs_status") or "").strip() or "unknown"
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
        "modules": resolve_value(cli_list(args.modules), merged, "modules", []),
        "source_dirs": resolve_value(cli_list(args.source_dirs), merged, "source_dirs"),
        "dependency_source_dirs": resolve_value(cli_list(args.dependency_source_dirs), merged, "dependency_source_dirs", []),
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
    dependency_source_dirs = normalize_dependency_source_dirs(
        result.get("dependency_source_dirs"),
        project_dir,
        "dependency_source_dirs",
    ) or []
    result["dependency_source_dirs"] = dependency_source_dirs
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
    if result.get("target_module"):
        result["primary_module"] = result["target_module"]
        result["modules"] = [result["target_module"]]
    if not result.get("primary_module") and len(modules_value) == 1:
        result["primary_module"] = modules_value[0]
        result["target_module"] = modules_value[0]
    if result.get("primary_module") and not result.get("target_module"):
        result["target_module"] = result["primary_module"]
    if result.get("target_module"):
        result["project_scope"] = build_project_scope(project_dir, result["target_module"])
    else:
        discovery = discover_maven_modules(project_dir)
        result["project_scope"] = {
            "schema": "java-upgrade-analyzer.project-scope.v1",
            "status": "insufficient",
            "reason_codes": ["target_module_unconfirmed"],
            "target_module": "",
            "candidate_modules": [item.get("module") for item in discovery.get("modules") or []],
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
    run_python("gate.py", gate_args, cwd, report_dir=report_dir)


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


def _print_confirmation_json(event, payload):
    try:
        body = {
            "schema": "java-upgrade-analyzer.confirmation.v1",
            "event": event,
            **(payload or {}),
        }
        sys.stderr.write("JUA_CONFIRMATION_JSON:" + json.dumps(body, ensure_ascii=False) + "\n")
        sys.stderr.flush()
    except Exception:
        return


def _response_payload_example(action_id, required_fields, properties):
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
            if field in required_fields or field in properties:
                if field in ("source_dirs", "dependency_source_dirs"):
                    payload[field] = [f"<{field} 值>"]
                elif field not in payload:
                    payload[field] = f"<{field} 值>"
        if "selected_targets" in properties:
            payload["selected_targets"] = ["<selection_key 或 coord>"]
        elif "step5_selected_coords" in properties:
            payload["step5_selected_coords"] = ["<coord 值>"]
        elif "step5_selected_names" in properties:
            payload["step5_selected_names"] = ["<name 值>"]
        if "strict_risk_gate" in properties:
            payload["strict_risk_gate"] = True
    if "notes" in properties:
        payload["notes"] = "<可选：用户补充说明>"
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


def build_resume_command_examples(options, required_fields, properties, project_dir, report_dir):
    examples = []
    for option in options or []:
        action_id = str(option.get("id") or "").strip()
        if not action_id:
            continue
        payload = _response_payload_example(action_id, required_fields, properties)
        examples.append(
            {
                "action": action_id,
                "label": option.get("label") or action_id,
                "command": (
                    f'python3 "{SCRIPT_DIR / "run_step.py"}" --step auto '
                    f'--project-dir "{project_dir}" --report-dir "{report_dir}" '
                    f"--response-json '{json.dumps(payload, ensure_ascii=False)}'"
                ),
            }
        )
    examples.append(
        {
            "action": "response_file",
            "label": "从文件恢复",
            "command": (
                f'python3 "{SCRIPT_DIR / "run_step.py"}" --step auto '
                f'--project-dir "{project_dir}" --report-dir "{report_dir}" '
                f'--response-file "{report_dir / "user_response.json"}"'
            ),
        }
    )
    return examples


def _response_payload_action_example(action_id, properties):
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
            if field in properties:
                payload[field] = sample
                break
        if "source_dirs" in properties:
            payload["source_dirs"] = ["src/main/java"]
        if "dependency_source_dirs" in properties:
            payload["dependency_source_dirs"] = ["/abs/path/to/dependency-repo"]
        if "selected_targets" in properties:
            payload["selected_targets"] = ["coord:com.example:demo-lib"]
        elif "step5_selected_coords" in properties:
            payload["step5_selected_coords"] = ["com.example:demo-lib"]
        if "strict_risk_gate" in properties:
            payload["strict_risk_gate"] = True
        if "notes" in properties:
            payload["notes"] = "当前结果可信，继续"
    elif action_id == "cancel":
        if "notes" in properties:
            payload["notes"] = "先补充信息，稍后继续"
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
            "description": "可选。基准侧已编译产物绝对路径；与 current_artifact_path 一起使用时，Step1 将跳过自动切分支和 package。",
        },
        "current_artifact_path": {
            "type": "string",
            "description": "可选。当前侧已编译产物绝对路径；与 base_artifact_path 一起使用时，Step1 将跳过自动切分支和 package。",
        },
        "base_branch": {
            "type": "string",
            "description": "可选。基准侧分支名；artifact 模式下若嵌套依赖缺少 pom.properties，会优先用该分支执行 mvn dependency:list 补全坐标。",
        },
        "current_branch": {
            "type": "string",
            "description": "可选。当前侧分支名；artifact 模式下若嵌套依赖缺少 pom.properties，会优先用该分支执行 mvn dependency:list 补全坐标。",
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
        "manual_coord_overrides": {
            "type": "array",
            "description": "可选。人工补充 Step1 unresolved 坐标，格式为 artifact:version -> group:artifact。",
        },
        "tool": {
            "type": "string",
            "enum": ["maven"],
            "description": "当前 Step1 只支持 maven。",
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
            "label": "自动切分支构建模式",
            "required_fields": ["base_branch", "current_branch"],
            "recommended_fields": [],
            "required_confirmation_fields": ["target_module"],
            "fallback_fields": [],
            "notes": [
                "适合未提供编译产物，由 Step1 自己切换分支并执行真实 package 的场景。",
                "一旦选择该模式，Step1 就会自动切换 base/current 分支并执行真实构建。",
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
                "checkout_build 模式一旦成立，就天然表示由 Step1 自动 checkout + package，不需要任何额外布尔许可字段。",
                "若已知某一侧 Maven 需要特定 JDK，可分别显式提供 base_jdk_home/current_jdk_home；未提供时各侧默认回落主机 JAVA_HOME。",
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
                    "reason": "当前看起来选择的是自动切分支构建模式，但尚未提供 base_branch。",
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
                    "reason": "当前看起来选择的是自动切分支构建模式，但尚未提供 current_branch。",
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
        "Step1 当前只支持 Maven，且只支持单模块。",
        "执行前请先明确一种输入方式；模式一旦进入执行，不允许因为失败自动切到另一种模式。",
        "主推荐场景：同一系统、同一仓库、不同分支；若已拿到编译产物，优先走直接产物模式。",
        "artifact 模式进入执行前，优先补齐 base/current 分支；只有特殊场景才用 source_project_dir 兜底。",
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
        question = (
            "当前已选择直接产物模式。为避免 Step1 运行中反复中断，"
            "请先补齐缺失侧的 branch；若不是同仓库双分支场景，再改补对应侧 source_project_dir。"
        )
    elif analysis_mode == "checkout_build":
        question = "当前已选择自动切分支构建模式，请先补齐缺失的 base/current 分支。"
    else:
        question = (
            "执行 step1 前，请先明确输入方式："
            "要么提供 `base_artifact_path/current_artifact_path`；"
            "要么提供 `base_branch/current_branch` 直接进入自动切分支构建模式。"
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
        "files_to_review": [],
        "required_fields": [item.get("field") for item in missing_inputs if item.get("field")],
        "missing_inputs": missing_inputs,
        "fallback_inputs": fallback_inputs,
        "input_modes": build_step1_input_modes(),
        "module_candidates": list((run_context.get("project_scope") or {}).get("candidate_modules") or []),
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
                "若用户选择自动切分支构建模式，应抽取 base_branch、current_branch。",
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
                "normalized_response_example": _response_payload_action_example(action_id, properties),
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
    if step_id == "step5":
        properties.setdefault(
            "step5_selected_coords",
            {
                "type": "array",
                "description": "可选。重跑 Step5 时，只分析这些依赖包对应的变更 API；优先使用 changed_dependencies.csv 中的 selection_key。",
            },
        )
        properties.setdefault(
            "step5_selected_names",
            {
                "type": "array",
                "description": "可选。重跑 Step5 时，只分析这些依赖名称对应的变更 API；名称按 coord 的 artifactId 匹配。",
            },
        )
    if selection_resolution.get("enabled"):
        properties.setdefault(
            "selected_targets",
            {
                "type": "array",
                "description": "可选。优先填写 selection_key；也支持精确填写候选的 coord 或 name。系统会自动解析为正式的 Step5 目标字段。",
            },
        )
        payload["selection_resolution"] = selection_resolution
    action_requirements = normalize_action_requirements(
        payload.get("action_requirements") or {},
        options,
        required_fields=payload.get("required_fields") or [],
    )
    if action_requirements:
        payload["action_requirements"] = action_requirements
    response_schema["properties"] = properties
    response_schema.setdefault("required", ["action"])
    payload["response_schema"] = response_schema
    payload["input_normalization"] = enrich_input_normalization_contract(
        payload.get("input_normalization") or {},
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


def build_user_decision_card(interaction):
    lines = []
    interaction = interaction or {}
    question = str(interaction.get("question") or "请确认当前结果，然后继续。").strip()
    lines.append(f"当前需要确认：{question}")

    reason = str(interaction.get("user_reason") or interaction.get("reason") or "").strip()
    if reason:
        lines.append(f"为什么停下：{reason}")

    recommended = str(interaction.get("recommended_action") or "").strip()
    if recommended:
        lines.append(f"推荐动作：{recommended}")

    options = list(interaction.get("options") or [])
    if options:
        lines.append("可选动作：")
        for option in options:
            label = option.get("label") or option.get("id")
            desc = option.get("description") or ""
            suffix = f" - {desc}" if desc else ""
            lines.append(f"- `{option.get('id')}`：{label}{suffix}")

    selection_options = list(interaction.get("selection_options") or [])
    if selection_options:
        lines.append("候选依赖包：")
        lines.append("| 选择值 | 依赖包 | 变化 API 数 | 高风险 API 数 |")
        lines.append("|---|---|---:|---:|")
        for item in selection_options[:10]:
            lines.append(
                f"| `{item.get('selection_key')}` | `{item.get('coord') or ''}` | "
                f"{item.get('api_count') or 0} | {item.get('high_risk_api_count') or 0} |"
            )

    files_to_review = list(interaction.get("files_to_review") or [])
    if files_to_review:
        lines.append("完整候选或证据文件：")
        for path in files_to_review[:5]:
            lines.append(f"- `{path}`")

    if selection_options:
        first_key = selection_options[0].get("selection_key") or "<selection_key>"
        lines.append("你可以直接回复：")
        lines.append("- “全量继续”")
        lines.append(f"- “只分析 {first_key}”")
        lines.append("- “我补充依赖源码目录 /path/to/repo 后重跑”")
    elif options:
        lines.append("你可以直接回复选项名称，例如：“继续”或“补材料后重跑”。")
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
    sys.stderr.write("\n")
    sys.stderr.write("╔════════════════════════════════════════════════════════════╗\n")
    sys.stderr.write("║                    AWAITING USER INPUT                    ║\n")
    sys.stderr.write("╚════════════════════════════════════════════════════════════╝\n")
    if interaction.get("hard_stop", True):
        sys.stderr.write("HARD STOP: 在用户明确回复前，禁止继续执行后续步骤。\n")
    runtime_rules = interaction.get("runtime_rules", []) or []
    if runtime_rules:
        sys.stderr.write("RULE: awaiting_* -> ask user -> wait -> resume with --response-json/--response-file\n")
        for idx, rule in enumerate(runtime_rules[:5], 1):
            sys.stderr.write(f"  {idx}. {rule}\n")
    next_action_rule = interaction.get("next_action_rule")
    if next_action_rule:
        sys.stderr.write(f"NEXT ACTION ONLY: {next_action_rule}\n")
    resume_examples = interaction.get("resume_command_examples", []) or []
    if resume_examples:
        sys.stderr.write("恢复命令模板：\n")
        for item in resume_examples[:2]:
            if isinstance(item, dict):
                label = item.get("label") or item.get("action") or "resume"
                command = item.get("command") or ""
                sys.stderr.write(f"  - {label}: {command}\n")
            else:
                sys.stderr.write(f"  {item}\n")
    sys.stderr.write("\n" + "=" * 60 + "\n")
    sys.stderr.write(f"【待用户交互】{interaction.get('title') or ''}\n")
    sys.stderr.write("=" * 60 + "\n")
    for line in build_user_decision_card(interaction):
        sys.stderr.write(f"{line}\n")
    sys.stderr.write("-" * 60 + "\n")
    question = interaction.get("question")
    if question:
        sys.stderr.write(f"问题：{question}\n")
    missing_inputs = interaction.get("missing_inputs", []) or []
    if missing_inputs:
        sys.stderr.write("缺失输入：\n")
        for item in missing_inputs:
            field = item.get("field") or ""
            label = item.get("label") or field
            side = item.get("side") or ""
            reason = item.get("reason") or ""
            artifact_path = item.get("artifact_path") or ""
            sys.stderr.write(f"  - {field}（{label}）")
            if side:
                sys.stderr.write(f" [side={side}]")
            sys.stderr.write("\n")
            if reason:
                sys.stderr.write(f"    原因: {reason}\n")
            if artifact_path:
                sys.stderr.write(f"    产物: {artifact_path}\n")
    fallback_inputs = interaction.get("fallback_inputs", []) or []
    if fallback_inputs:
        sys.stderr.write("可选兜底输入：\n")
        for item in fallback_inputs:
            field = item.get("field") or ""
            label = item.get("label") or field
            side = item.get("side") or ""
            reason = item.get("reason") or ""
            sys.stderr.write(f"  - {field}（{label}）")
            if side:
                sys.stderr.write(f" [side={side}]")
            sys.stderr.write("\n")
            if reason:
                sys.stderr.write(f"    说明: {reason}\n")
    input_modes = interaction.get("input_modes", []) or []
    if input_modes:
        sys.stderr.write("支持输入方式：\n")
        for item in input_modes:
            mode_id = item.get("id") or ""
            label = item.get("label") or mode_id
            required_fields = ", ".join(item.get("required_fields") or []) or "(无)"
            recommended_fields = ", ".join(item.get("recommended_fields") or []) or ""
            sys.stderr.write(f"  - {mode_id}（{label}） required={required_fields}\n")
            if recommended_fields:
                sys.stderr.write(f"    推荐: {recommended_fields}\n")
    files_to_review = interaction.get("files_to_review", []) or []
    if files_to_review:
        sys.stderr.write("需优先复核文件：\n")
        for item in files_to_review:
            sys.stderr.write(f"  - {item}\n")
    for line in interaction.get("checklist_lines", []) or []:
        if line is None:
            continue
        sys.stderr.write(f"- {str(line).rstrip()}\n")
    options = interaction.get("options", []) or []
    if options:
        sys.stderr.write("可选动作：\n")
        for option in options:
            line = f"  - {option.get('id')}: {option.get('label') or option.get('id')}"
            desc = option.get("description")
            if desc:
                line += f" - {desc}"
            sys.stderr.write(line.rstrip() + "\n")
    action_requirements = interaction.get("action_requirements") or {}
    if action_requirements:
        sys.stderr.write("动作约束：\n")
        for action_id, spec in action_requirements.items():
            required_fields = ", ".join(spec.get("required_fields") or []) or "(无)"
            at_least_one = ", ".join(spec.get("at_least_one_of") or []) or ""
            recommended = ", ".join(spec.get("recommended_fields") or []) or ""
            sys.stderr.write(f"  - {action_id}: required={required_fields}\n")
            if at_least_one:
                sys.stderr.write(f"    至少其一: {at_least_one}\n")
            if recommended:
                sys.stderr.write(f"    推荐: {recommended}\n")
    selection_options = interaction.get("selection_options", []) or []
    if selection_options:
        sys.stderr.write("候选目标：\n")
        for item in selection_options[:10]:
            selection_key = item.get("selection_key") or ""
            coord = item.get("coord") or ""
            name = item.get("name") or ""
            sys.stderr.write(
                f"  - {selection_key} | coord={coord or '(无)'} | name={name or '(无)'}\n"
            )
    sys.stderr.write("=" * 60 + "\n")
    sys.stderr.flush()
    body = {
        "stop": interaction.get("hard_stop", True),
        "must_wait_for_user_reply": interaction.get("must_wait_for_user_reply", True),
        "exit_code": EXIT_AWAITING_USER,
        "next_action_rule": interaction.get("next_action_rule"),
        "runtime_rules": runtime_rules,
        "rules_file": interaction.get("rules_file"),
        "resume_command_examples": resume_examples,
        "interaction": interaction,
        "report_dir": str(Path(report_dir).resolve()),
        "interaction_file": str((runtime_state_dir(report_dir) / "interaction.json").resolve()),
    }
    _print_confirmation_json(event, body)
    sys.stdout.write(
        json.dumps(
            {
                "status": normalize_interaction_status(interaction.get("status")),
                "exit_code": EXIT_AWAITING_USER,
                "step_id": interaction.get("step_id"),
                "title": interaction.get("title"),
                "question": interaction.get("question"),
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
                "selection_resolution": interaction.get("selection_resolution", {}),
                "runtime_rules": runtime_rules,
                "next_action_rule": interaction.get("next_action_rule"),
                "must_wait_for_user_reply": interaction.get("must_wait_for_user_reply", True),
                "rules_file": interaction.get("rules_file"),
                "resume_command_examples": resume_examples,
                "checkpoint": interaction.get("checkpoint", True),
                "hard_stop": interaction.get("hard_stop", True),
                "awaiting_user_input": True,
                "interaction_file": body["interaction_file"],
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
    if not source_state.get("provided"):
        return payload

    question_prefix = "已收到 dependency_source_dirs。"
    if not source_state.get("recognized"):
        question_prefix = "已收到 dependency_source_dirs，但当前目录未识别出有效依赖源码仓库。"
    elif (
        str(payload.get("step_id") or "").strip() == "step5"
        and reason_code != "step5_dependency_source_mapping_missing"
        and not source_state.get("analysis_requires_more_source")
    ):
        question_prefix = (
            "已识别 dependency_source_dirs；本轮没有因依赖源码缺失而中断的 API。"
            "被删除依赖本身已有旧 JAR 符号证据，不要求额外提供其源码。"
        )
    elif source_state.get("required_uncovered_coords"):
        missing = ", ".join((source_state.get("required_uncovered_coords") or [])[:10])
        question_prefix = f"已收到 dependency_source_dirs，但这些实际调用链仍因缺少依赖源码而中断：{missing}。"
    elif source_state.get("uncovered_target_coords"):
        missing = ", ".join((source_state.get("uncovered_target_coords") or [])[:10])
        question_prefix = f"已收到 dependency_source_dirs，但当前仍未覆盖这些目标依赖坐标：{missing}。"
    elif source_state.get("covers_targets"):
        question_prefix = "已收到 dependency_source_dirs；仅当现有目录不正确或覆盖范围不足时才需要修正。"

    checklist_lines = list(payload.get("checklist_lines") or [])
    if question_prefix not in checklist_lines:
        checklist_lines.insert(0, question_prefix)
    dir_preview = "当前已记录目录： " + ", ".join((source_state.get("dependency_source_dirs") or [])[:5])
    if dir_preview not in checklist_lines:
        checklist_lines.insert(1, dir_preview)
    payload["checklist_lines"] = checklist_lines

    question = str(payload.get("question") or "").strip()
    if reason_code == "step5_dependency_source_mapping_missing":
        payload["question"] = (
            question_prefix
            + " 请仅补充仍缺失的依赖源码目录，或确认现有目录需要替换后再重跑。"
        )
    elif has_dependency_source_dirs_field and question and question_prefix not in question:
        payload["question"] = question_prefix + " " + question

    if has_dependency_source_dirs_field:
        dep_dirs_prop = dict(properties.get("dependency_source_dirs") or {})
        dep_dirs_prop["description"] = (
            "可选。系统已收到 dependency_source_dirs；仅当现有目录不正确、无法识别，"
            "或仍未覆盖目标依赖时再修正。"
        )
        properties["dependency_source_dirs"] = dep_dirs_prop
        response_schema["properties"] = properties
        payload["response_schema"] = response_schema
    return payload


def build_interaction_payload(step_id, report_dir, manifest_steps, project_dir, run_context=None, main_state=None):
    step_meta = manifest_steps.get(step_id) or {}
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
            str((step5_call_chain_dir(report_dir) / "summary.txt").resolve()),
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
                checklist_lines.append("注意：选择 continue 不会自动接受建议映射。")
                checklist_lines.append("若要接受建议，请提供 accept_suggested_mappings=true 参数。")
    if step_id == "step4":
        all_changed_apis = step4_api_changes_dir(report_dir) / "all_changed_apis.csv"
        available_rows = read_csv_rows(all_changed_apis)
        target_summary = build_step5_dependency_selection_summary(report_dir)
        full_selection_options = build_interaction_selection_options(
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
        selection_options = full_selection_options[:20]
        interaction_meta["selection_options"] = selection_options
        interaction_meta["selection_resolution"] = build_selection_resolution(full_selection_options)
        checklist_lines.append("当前需要确认：Step5 是全量分析，还是只分析部分依赖包？")
        checklist_lines.append("推荐默认动作：如果依赖包数量不多，选择 continue 全量进入 Step5。")
        checklist_lines.append("如果依赖包很多，请从候选依赖包中选择一个或多个 selection_key。")
        checklist_lines.append("候选依赖包来自 evidence/api_changes/changed_dependencies.csv。")
        checklist_lines.append(
            f"  - 可选依赖数={target_summary.get('available_target_count', 0)} "
            f"Step4 API 行数={len(available_rows)}"
        )
        for item in selection_options[:10]:
            checklist_lines.append(
                f"  - {item.get('selection_key')} | {item.get('coord')} | "
                f"changed_api_count={item.get('api_count')} | high_risk_api_count={item.get('high_risk_api_count') or 0}"
            )
        if target_summary.get("available_target_count", 0) > 10:
            checklist_lines.append("  - 其余候选请查看 evidence/api_changes/changed_dependencies.md；展示列表之外的目标仍可通过精确 selection_key/coord/name 正式选择")
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
    if step_id == "step5":
        summary_json = step5_call_chain_dir(report_dir) / "summary.json"
        # Checkpoint is user-facing: point readers to the concise summary and
        # complete ledger, not to caches/indexes that only the program consumes.
        files_to_review = [
            str((step5_call_chain_dir(report_dir) / "summary.txt").resolve()),
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
                f"  - 当前无法确认={user_conclusion_summary.get('当前无法确认', 0)}",
                f"  - 需要补充输入={user_conclusion_summary.get('需要补充输入', 0)}",
                f"  - 已提供依赖源码目录={len(dependency_source_dirs)} 个",
            ]
        )
        if step5_selected_coords:
            checklist_lines.append("  - 本轮按坐标定向分析: " + ", ".join(step5_selected_coords[:10]))
        if step5_selected_names:
            checklist_lines.append("  - 本轮按名称定向分析: " + ", ".join(step5_selected_names[:10]))
        if quality_gate.get("needs_input", 0):
            checklist_lines.append("推荐动作：先补充关键输入再重跑 Step5，否则最终结论不完整。")
        elif quality_gate.get("inconclusive", 0):
            checklist_lines.append("推荐动作：优先抽查“当前无法确认”的高风险项，再决定是否继续。")
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
                "存在缺失依赖源码映射的调用链项；优先补齐 dependency_source_dirs 后重跑 Step5，通常能显著减少 uncertain / not_analyzed。"
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
            checklist_lines.append("当前无法确认示例（完整结果见 alerts.csv）：")
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
            checklist_lines.append("需要补充输入示例（完整结果见 alerts.csv）：")
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
    if step_id in ("step2", "step4", "step5"):
        properties.setdefault(
            "dependency_source_dirs",
            {
                "type": "array",
                "description": "可选。直接提供依赖源码目录，支持单模块或多模块仓库；系统会自动推断模块坐标、Step4 仓库映射与 Step5 源码映射。",
            },
        )
    if step_id == "step4":
        properties.setdefault(
            "dependency_git_ref_overrides",
            {
                "type": "array",
                "description": "可选。按依赖显式确认 old_ref/new_ref；用于版本号无法唯一匹配源码仓库 git ref 的场景。",
            },
        )
        properties.setdefault(
            "step5_selected_coords",
            {
                "type": "array",
                "description": "可选。继续进入 Step5 时，只分析这些依赖包对应的变更 API；优先使用 changed_dependencies.csv 中的 selection_key。",
            },
        )
        properties.setdefault(
            "step5_selected_names",
            {
                "type": "array",
                "description": "可选。继续进入 Step5 时，只分析这些依赖名称对应的变更 API；名称按 coord 的 artifactId 匹配。",
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
    if step_id == "step1":
        for field_name, field_meta in build_step1_response_properties().items():
            properties.setdefault(field_name, field_meta)
    if step_id == "step5":
        properties.setdefault(
            "dependency_source_dirs",
            {
                "type": "array",
                "description": "可选。直接补充依赖源码目录；系统会自动推断依赖源码映射并重跑分析。",
            },
        )
        properties.setdefault(
            "step5_selected_coords",
            {
                "type": "array",
                "description": "可选。重跑 Step5 时，只分析这些依赖包对应的变更 API；优先使用 changed_dependencies.csv 中的 selection_key。",
            },
        )
        properties.setdefault(
            "step5_selected_names",
            {
                "type": "array",
                "description": "可选。重跑 Step5 时，只分析这些依赖名称对应的变更 API；名称按 coord 的 artifactId 匹配。",
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
        "question": interaction_meta.get("question") or "请确认当前结果，然后继续。",
        "options": interaction_meta.get("options", []),
        "files_to_review": files_to_review,
        "required_fields": required_fields,
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
    if interaction_meta.get("selection_options"):
        payload["selection_options"] = list(interaction_meta.get("selection_options") or [])
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
    return annotate_dependency_source_dirs_interaction(payload, runtime_view, report_dir)


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
    if action == "continue" and pending_kind == "input_request" and pending_step_id:
        return pending_step_id
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


def step2_continue_requires_refresh(user_response):
    if not isinstance(user_response, dict):
        return False
    refresh_keys = {
        "base_branch",
        "current_branch",
        "source_dirs",
        "dependency_source_dirs",
        "source_repo_hints",
    }
    if any(user_response.get(key) not in (None, "", []) for key in refresh_keys):
        return True
    cleared_refresh_keys = {
        "source_dirs",
        "dependency_source_dirs",
        "source_repo_hints",
    }
    cleared_fields = {
        str(item or "").strip()
        for item in (user_response.get("__clear_fields") or [])
        if str(item or "").strip()
    }
    if cleared_fields & cleared_refresh_keys:
        return True
    return bool(user_response.get("accept_suggested_mappings"))


def validate_pending_interaction_response(pending_interaction, user_response):
    pending_interaction = dict(pending_interaction or {})
    user_response = dict(user_response or {})
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
    for field in requirement.get("required_fields") or []:
        if not _response_value_present(user_response.get(field)):
            raise StepError(f"当前动作 {action} 要求字段 {field} 必填，不能为空。")
    at_least_one_of = [str(field).strip() for field in (requirement.get("at_least_one_of") or []) if str(field).strip()]
    if at_least_one_of and not any(_response_value_present(user_response.get(field)) for field in at_least_one_of):
        raise StepError(
            f"当前动作 {action} 至少需要提供以下字段之一：{', '.join(at_least_one_of)}"
        )
    if "selected_targets" in user_response:
        validate_selected_targets_resolution(
            pending_interaction.get("selection_resolution") or {},
            user_response.get("selected_targets"),
        )

    if (
        step_id == "step5"
        and reason_code == "step5_dependency_source_mapping_missing"
        and action == "rerun_current_step"
    ):
        dependency_source_dirs = [
            str(item).strip()
            for item in (user_response.get("dependency_source_dirs") or [])
            if str(item).strip()
        ]
        allow_degraded = bool(user_response.get("allow_degraded"))
        has_selection_override = any(
            _response_value_present(user_response.get(field))
            for field in ("selected_targets", "step5_selected_coords", "step5_selected_names")
        )
        if not dependency_source_dirs and not allow_degraded and not has_selection_override:
            raise StepError(
                "Step5 当前检查点要求先补充 dependency_source_dirs，或显式设置 "
                "allow_degraded=true，或选择需要分析的目标 jar 后，再使用 "
                "action=rerun_current_step 重跑。"
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
        if not overrides and not dependency_source_dirs:
            raise StepError(
                "Step4 当前检查点要求先确认 dependency_git_ref_overrides，或修正 "
                "dependency_source_dirs 后，再使用 action=rerun_current_step 重跑。"
            )
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
        ]
        has_timeout_override = any(user_response.get(field) not in (None, "") for field in timeout_fields)
        if not has_timeout_override and not dependency_source_dirs:
            raise StepError(
                "Step4 当前检查点要求先调整至少一个 Step4 超时参数，或修正 "
                "dependency_source_dirs 后，再使用 action=rerun_current_step 重跑。"
            )
    if (
        step_id == "step4"
        and reason_code == "step4_japicmp_missing_need_resolution"
        and action == "rerun_current_step"
    ):
        japicmp_jar = str(user_response.get("japicmp_jar") or "").strip()
        allow_degraded = bool(user_response.get("allow_degraded"))
        if not japicmp_jar and not allow_degraded:
            raise StepError(
                "Step4 当前检查点要求先安装/提供 japicmp_jar，或显式设置 "
                "allow_degraded=true 确认降级后，再使用 action=rerun_current_step 重跑。"
            )
    if (
        step_id == "step5"
        and reason_code == "step5_tree_sitter_missing_need_resolution"
        and action == "rerun_current_step"
    ):
        allow_degraded = bool(user_response.get("allow_degraded"))
        tree_sitter_installed = bool(user_response.get("tree_sitter_installed"))
        if not tree_sitter_installed and not allow_degraded:
            raise StepError(
                "Step5 当前检查点要求先安装 tree-sitter/tree-sitter-java，"
                "并设置 tree_sitter_installed=true；或显式设置 allow_degraded=true 确认源码 AST 降级后，再使用 "
                "action=rerun_current_step 重跑。"
            )


def apply_user_response_to_main_state(main_state, pending_interaction, user_response, project_dir, target_step_id=""):
    user_response = build_canonical_user_response(user_response)
    if user_response.get("selected_targets") is not None:
        selection_result = resolve_selected_targets(
            (pending_interaction or {}).get("selection_resolution") or {},
            user_response.get("selected_targets"),
        ) or {}
        if selection_result.get("step5_selected_coords"):
            user_response["step5_selected_coords"] = selection_result.get("step5_selected_coords")
        if selection_result.get("step5_selected_names"):
            user_response["step5_selected_names"] = selection_result.get("step5_selected_names")
    pending_step_id = str((pending_interaction or {}).get("step_id") or "").strip()
    pending_kind = str((pending_interaction or {}).get("kind") or "").strip()
    step_id = str(target_step_id or pending_step_id or "").strip()
    if not step_id:
        return main_state, {}
    base_context = build_restore_context(main_state, step_id)
    action = str((user_response or {}).get("action") or "").strip()
    if action == "restart_from_step" and pending_step_id and pending_step_id != step_id:
        # When restarting to an earlier step, preserve already known runtime context
        # from the current checkpoint (for example base/current branches from Step4).
        restart_fallback_context = build_restore_context(main_state, pending_step_id)
        if restart_fallback_context:
            merged_base_context = dict(base_context)
            merged_base_context.update(restart_fallback_context)
            base_context = merged_base_context
    updated = merge_user_response_into_run_context(base_context, user_response, project_dir)
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
                "请先执行 Step4 生成候选，或直接提供 step5_selected_coords / step5_selected_names。"
            )
        interaction["selection_resolution"] = selection_resolution
    return interaction


def apply_non_pending_structured_response(args, project_dir, report_dir, main_state, user_response):
    response_action = str((user_response or {}).get("action") or "").strip()
    if response_action == "cancel":
        print("⏹ 用户取消非 checkpoint 结构化意图，保持当前主状态不继续执行。", file=sys.stderr)
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
    print(
        f"🔁 当前没有 pending interaction；已将结构化用户意图桥接为从 {target_step_id} 重跑。",
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
            print(
                f"❌ 用户答复 action 不在允许列表中：{response_action}，可选值={sorted(available_actions)}",
                file=sys.stderr,
            )
            early_exit_code = 1
        else:
            validate_pending_interaction_response(pending_interaction, user_response)
            if response_action == "cancel":
                print("⏹ 用户选择取消，保持当前主状态，不继续执行。", file=sys.stderr)
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
    print(
        "⏸ 检测到待用户交互状态。请由 Agent 读取 interaction.json 并向用户发问；"
        f"当前退出码={EXIT_AWAITING_USER}；收到答复后，使用 --response-json / --response-file 继续。",
        file=sys.stderr,
    )
    return EXIT_AWAITING_USER


def handle_step2_resume_followups(
    args,
    main_state,
    report_dir,
    project_dir,
    resumed_interaction_step_id,
    response_action,
    user_response,
):
    if resumed_interaction_step_id != "step2" or response_action != "continue":
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
            print("  ✅ 已接受当前 dependency_source_dirs，并将按自动识别结果继续后续步骤", file=sys.stderr)
        if source_plan.get("ambiguous_coords"):
            print("  ⚠️ 存在坐标冲突的源码目录，已跳过自动固化这些冲突项", file=sys.stderr)
        if accepted_dirs:
            save_main_state(report_dir, main_state)
    if step2_continue_requires_refresh(user_response):
        step2_input = dict((main_state.get("step2") or {}).get("input") or {})
        refreshed_step2_context = build_run_context(args, step2_input, {})
        main_state["step2"]["input"] = dict(refreshed_step2_context)
        refresh_step2_outputs(report_dir, project_dir, refreshed_step2_context)
        store_step_output(main_state, "step2", refreshed_step2_context, report_dir)
        seed_next_step_input(main_state, "step2", refreshed_step2_context)
        save_main_state(report_dir, main_state)


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
    print(
        f"⏸ {step_id} 执行前需要先补齐输入方式和关键字段；当前退出码={EXIT_AWAITING_USER}",
        file=sys.stderr,
    )
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


def persist_completed_step(main_state, step_id, report_dir, run_context):
    store_step_output(main_state, step_id, run_context, report_dir)
    seed_next_step_input(main_state, step_id, run_context)
    next_step = next_step_id_for(step_id)
    update_main_state_state(
        main_state,
        current_step=next_step or "done",
        completed_step=step_id,
        status="completed",
        blocking_reason=None,
        pending_interaction=None,
    )
    save_main_state(report_dir, main_state)
    write_coverage_report(runtime_coverage_dir(report_dir), project_scope=run_context.get("project_scope"))
    clear_interaction_file(report_dir)


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
        "step3": [("step2", "evidence/context/context.json")],
        "step4": [
            ("step1", "evidence/dependencies/dep_changes.csv"),
            ("step2", "evidence/context/context.json"),
        ],
        "step5": [("step4", "evidence/api_changes/all_changed_apis.csv")],
        "step6": [("step5", "evidence/call_chain/summary.json")],
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
            build_provenance_path(report_dir),
            step1_artifacts_dir(report_dir),
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
        ],
        "step5": [
            step5_call_chain_dir(report_dir),
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
        if run_context.get("tool", "maven") != "maven":
            raise StepError("Step1 当前只支持 Maven，并且只比较单模块的最终打包依赖。")
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
                "要么提供 base_branch/current_branch 自动切分支执行真实 package。"
            )

    elif step_id == "step2":
        ensure_exists(dep_changes, "Step2 缺少 evidence/dependencies/dep_changes.csv，请先执行 Step1")
        base_branch = run_context.get("base_branch")
        current_branch = run_context.get("current_branch")
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
        if is_git_repo(project_dir) and base_branch == current_branch:
            raise StepError(
                f"Step2 检测到 base_branch 与 current_branch 相同（{base_branch}），无法进行 git diff/推断。"
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
    return build_interaction_payload(
        step_id,
        report_dir,
        manifest_steps,
        project_dir,
        run_context=refreshed_run_context,
        main_state=main_state,
    )


def main():
    ap = argparse.ArgumentParser(description="统一执行 Java 升级分析的单个 Step")
    ap.add_argument("--step", choices=STEP_SEQUENCE + ["auto"])
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--report-dir", default=".upgrade-report")
    ap.add_argument("--seed-json", dest="seed_json", default="", help="初始化输入 JSON；仅用于首次建立主状态")
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--base-branch")
    ap.add_argument("--current-branch")
    ap.add_argument("--modules", action="append", nargs="+", default=None)
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
    ap.add_argument("--tool", choices=["maven", "gradle"], default="maven")
    ap.add_argument("--response-json", default="", help="结构化用户答复 JSON，例如 '{\"action\":\"continue\"}'")
    ap.add_argument("--response-file", default="", help="结构化用户答复 JSON 文件路径")
    ap.add_argument(
        "--describe-step1-contract",
        action="store_true",
        help="输出 Step1 的静态前置输入协议（JSON），供 Agent 在首次调用前读取。",
    )
    args = ap.parse_args()
    args.modules = _dedupe_strings(flatten_cli_values(args.modules)) if args.modules else None
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
    if not project_dir.is_dir():
        print(f"❌ 项目目录不存在：{project_dir}", file=sys.stderr)
        return 1

    seed_payload = load_seed_json_arg(args.seed_json, project_dir)
    report_dir = Path(args.report_dir).resolve()
    main_state = load_main_state(report_dir, manifest_path=args.manifest)
    manifest_data, manifest_steps = load_manifest(args.manifest)
    _ = manifest_data
    pending_interaction = (main_state.get("state") or {}).get("pending_interaction")
    structured_user_response = None
    has_structured_response = bool(args.response_json or args.response_file)
    if has_structured_response:
        structured_user_response = resolve_user_response(args, project_dir)
    if args.step == "auto" and has_structured_response and not pending_interaction:
        step_id = ""
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
        args,
        main_state,
        report_dir,
        project_dir,
        resumed_interaction_step_id,
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
    if resumed_interaction_step_id == "step2" and step_id == "step2":
        refresh_step2_outputs(report_dir, project_dir, run_context)
    preflight_exit = maybe_emit_step1_preflight_interaction(
        step_id,
        main_state,
        report_dir,
        build_step1_preflight_interaction(run_context),
    )
    if preflight_exit is not None:
        return preflight_exit

    print(f"\n=== 执行 {step_id} ===", file=sys.stderr)
    print(f"项目目录：{project_dir}", file=sys.stderr)
    print(f"报告目录：{report_dir}", file=sys.stderr)

    try:
        interaction = execute_step(step_id, args, manifest_steps, run_context, main_state=main_state)
        run_context = build_run_context(args, run_context, {}, allow_external_seed=False)
        # Always save main_state after interaction to maintain protocol integrity.
        # Per CHECKPOINT_RULES.md: must_wait_for_user_reply.
        if interaction:
            interaction = persist_step_interaction(main_state, step_id, report_dir, run_context, interaction)
            print_interaction_to_streams(interaction, report_dir)
            print(
                f"⏸ {step_id} 已执行完成，进入待用户交互状态。用户答复后执行："
                f" python3 {SCRIPT_DIR / 'run_step.py'} --step auto --project-dir {project_dir} "
                f"--report-dir {report_dir} --response-json "
                f"'{{\"action\":\"{default_interaction_action(interaction)}\"}}'"
                f"；当前退出码={EXIT_AWAITING_USER}",
                file=sys.stderr,
            )
            return EXIT_AWAITING_USER
        persist_completed_step(main_state, step_id, report_dir, run_context)
        print(f"✅ {step_id} 执行完成，main_state 已更新：{main_state_path(report_dir)}", file=sys.stderr)
        return 0
    except StepInteractionRequired as exc:
        interaction = exc.interaction or {}
        interaction = persist_interaction_required_error(main_state, step_id, report_dir, interaction)
        print_interaction_to_streams(interaction, report_dir)
        print(
            f"⏸ {step_id} 需要补充业务信息后才能继续；当前退出码={EXIT_AWAITING_USER}",
            file=sys.stderr,
        )
        return EXIT_AWAITING_USER
    except StepError as exc:
        persist_step_error(main_state, step_id, report_dir, exc)
        print(f"❌ {step_id} 执行失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
