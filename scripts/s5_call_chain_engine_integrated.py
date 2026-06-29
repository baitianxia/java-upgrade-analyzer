#!/usr/bin/env python3
"""
s5_call_chain_engine_integrated.py

集成所有改进模块的Step 5引擎。

核心改进：
  ✓ 自动发现依赖源码映射（解决重复配置问题）
  ✓ Java AST 主链路 + Kotlin/异常场景正则降级
  ✓ 置信度加权深度（不再固定3跳）
  ✓ 系统代码触达识别（Service/Facade/Manager/Handler 等业务层）
  ✓ 增强型输出格式（可读调用链 + 明确action）

使用方式：
  python s5_call_chain_engine_integrated.py \
    --all-changed-apis .upgrade-report/s4_jar_compare/all_changed_apis.csv \
    --source-dirs src/main/java \
    --report-dir .upgrade-report \
    --output-dir .upgrade-report/s5_call_chain

注：无需手动配置 `--dependency-source-mappings`，系统自动从 Step 4 配置推断
"""

import argparse
import csv
import gc
import json
import os
import re
import sys
import time
import traceback
import zipfile
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

# 引入新模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auto_discover_bridge_sources import auto_discover_bridge_sources
from enhanced_source_analyzer import (
    analyze_file,
    extract_call_edges_enhanced,
)
from confidence_weighted_tracer import (
    build_api_identity_key,
    critical_parser_fallback_reasons,
    build_api_target_keys,
    trace_all_apis_with_confidence_weighting,
)
from enhanced_output_formatter import generate_enhanced_summary
from compat import maven_repo_dir
from progress_logging import PhaseTimer, emit_progress

EXIT_AWAITING_USER = 4
STEP_INTERACTION_PREFIX = "JUA_STEP_INTERACTION_JSON:"
MAIN_STATE_FILE_NAME = "main_state.json"


def _env_flag_enabled(name):
    return str(os.environ.get(name, '') or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def _step5_debug_enabled():
    return _env_flag_enabled('JUA_STEP5_DEBUG')


def _step5_debug(topic, message, **fields):
    if not _step5_debug_enabled():
        return
    payload = {
        'topic': str(topic or '').strip(),
        'message': str(message or '').strip(),
    }
    for key, value in (fields or {}).items():
        if value is None:
            continue
        payload[key] = value
    print(f"[step5-debug] {json.dumps(payload, ensure_ascii=False, sort_keys=True)}", file=sys.stderr)


# ══════════════════════════════════════════════════════════════════
# Step 5集成版：完整流程
# ══════════════════════════════════════════════════════════════════

def emit_step_interaction(interaction):
    sys.stdout.write(STEP_INTERACTION_PREFIX + json.dumps(interaction, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def load_orchestrated_step5_input(report_dir):
    """正式流程下仅从 main_state 读取 Step5 已确认输入，调试 CLI 不参与正式求值。"""
    if os.environ.get("JUA_ORCHESTRATED") != "1":
        return {}
    state_path = os.path.join(report_dir, MAIN_STATE_FILE_NAME)
    if not os.path.exists(state_path):
        return {}
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            main_state = json.load(f)
    except Exception:
        return {}
    return dict((((main_state or {}).get("step5") or {}).get("input")) or {})


def write_missing_dependency_mapping_details(
    output_dir,
    missing_mapping_items,
    missing_mapping_coords,
    has_provided_dependency_inputs,
    bridge_discovery=None,
):
    details_path = os.path.join(output_dir, "missing_dependency_source_mappings.json")
    details = {
        "status": "awaiting_user_input",
        "reason_code": "step5_dependency_source_mapping_missing",
        "generated_at": datetime.now().isoformat(),
        "missing_mapping_count": len(missing_mapping_items or []),
        "missing_mapping_coords": list(missing_mapping_coords or []),
        "has_provided_dependency_inputs": bool(has_provided_dependency_inputs),
        "missing_items": list(missing_mapping_items or []),
        "provided_dependency_source_dirs": list((bridge_discovery or {}).get("provided_dependency_source_dirs") or []),
        "source_dirs_detected_without_coord": list((bridge_discovery or {}).get("source_dirs_detected_without_coord") or []),
        "unresolved_dependency_source_dirs": list((bridge_discovery or {}).get("unresolved_dependency_source_dirs") or []),
        "discovery_log": list((bridge_discovery or {}).get("discovery_log") or []),
    }
    with open(details_path, "w", encoding="utf-8") as f:
        json.dump(details, f, ensure_ascii=False, indent=2)
    return details_path


def build_missing_dependency_mapping_interaction(
    output_dir,
    details_path,
    missing_mapping_count,
    missing_mapping_coords,
    has_provided_dependency_inputs,
):
    files_to_review = [os.path.abspath(details_path)]
    report_dir = os.path.abspath(os.path.dirname(output_dir))
    for extra_name in (
        os.path.join(report_dir, "s2_source_mapping_summary.json"),
        os.path.join(report_dir, "s4_jar_compare", "all_changed_apis.csv"),
    ):
        if os.path.exists(extra_name):
            files_to_review.append(os.path.abspath(extra_name))
    if has_provided_dependency_inputs:
        question = (
            "Step5 检测到需要跨依赖边界分析的变更 API，但当前提供的依赖源码目录/仓库"
            "仍不足以解析出完整 dependency_source_mappings。请先补齐或修正 dependency_source_dirs，"
            "或者明确允许降级执行后再重跑 Step5；在此之前不要继续 Step6。"
        )
        summary = (
            f"共有 {missing_mapping_count} 个变更 API 需要跨依赖分析，"
            f"其中 {len(missing_mapping_coords)} 个依赖坐标缺少可用源码映射。"
        )
    else:
        question = (
            "Step5 检测到需要跨依赖边界分析的变更 API，但当前没有可用的依赖源码映射。"
            "请先补充 dependency_source_dirs，或者明确允许降级执行后再重跑 Step5；"
            "在此之前不要继续 Step6。"
        )
        summary = (
            f"共有 {missing_mapping_count} 个变更 API 需要跨依赖分析，"
            f"涉及 {len(missing_mapping_coords)} 个依赖坐标缺少源码映射。"
        )
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "review",
        "step_id": "step5",
        "title": "step5 缺少依赖源码映射",
        "question": question,
        "summary": summary,
        "reason_code": "step5_dependency_source_mapping_missing",
        "files_to_review": files_to_review,
        "required_fields": ["action"],
        "options": [
            {
                "id": "rerun_current_step",
                "label": "补输入后重跑",
                "description": "补充 dependency_source_dirs 或允许降级后，重跑 Step5。",
            },
            {
                "id": "restart_from_step",
                "label": "从指定步骤重跑",
                "description": "若需要回到更早步骤修正输入，可指定 restart_step_id 后重跑。",
            },
            {
                "id": "cancel",
                "label": "取消",
                "description": "先人工复核缺失映射明细，再决定下一步。",
            },
        ],
        "response_schema": {
            "type": "object",
            "required": ["action"],
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["rerun_current_step", "restart_from_step", "cancel"],
                },
                "dependency_source_dirs": {
                    "type": "array",
                    "description": "可选。补充依赖源码目录或仓库根目录，系统会自动重新推断 dependency_source_mappings。",
                },
                "allow_degraded": {
                    "type": "boolean",
                    "description": "可选。设为 true 时允许在缺失依赖源码映射的前提下降级执行，相关 API 将标记为 not_analyzed。",
                },
                "restart_step_id": {
                    "type": "string",
                    "enum": ["step1", "step2", "step3", "step4", "step5"],
                },
                "notes": {
                    "type": "string",
                },
            },
        },
        "input_normalization": {
            "enabled": True,
            "allowed_actions": ["rerun_current_step", "restart_from_step", "cancel"],
            "required_fields": ["action"],
        },
        "missing_mapping_coords": list(missing_mapping_coords or []),
        "resume_hint": (
            "若用户补充 dependency_source_dirs，请使用 --response-json 传回 "
            "action=rerun_current_step 与 dependency_source_dirs 重跑 Step5；"
            "若用户接受降级执行，可同时传回 allow_degraded=true。"
        ),
        "next_action_rule": "只能先补充 dependency_source_dirs 或明确允许降级后重跑 Step5，不得直接继续 Step6。",
        "must_wait_for_user_reply": True,
        "exit_code": EXIT_AWAITING_USER,
    }

def step5_integrated_main(args):
    previous_debug = os.environ.get('JUA_STEP5_DEBUG')
    previous_break = os.environ.get('JUA_STEP5_DEBUG_BREAK')
    if getattr(args, 'debug_analysis', False):
        os.environ['JUA_STEP5_DEBUG'] = '1'
    if getattr(args, 'debug_break', False):
        os.environ['JUA_STEP5_DEBUG_BREAK'] = '1'
    try:
        return _step5_integrated_main_impl(args)
    finally:
        if previous_debug is None:
            os.environ.pop('JUA_STEP5_DEBUG', None)
        else:
            os.environ['JUA_STEP5_DEBUG'] = previous_debug
        if previous_break is None:
            os.environ.pop('JUA_STEP5_DEBUG_BREAK', None)
        else:
            os.environ['JUA_STEP5_DEBUG_BREAK'] = previous_break


def infer_step5_report_dir(args):
    explicit = str(getattr(args, 'report_dir', '') or '').strip()
    if explicit:
        return explicit

    all_changed_apis = str(getattr(args, 'all_changed_apis', '') or '').strip()
    if all_changed_apis:
        api_path = Path(all_changed_apis).expanduser()
        if api_path.name == 'all_changed_apis.csv' and api_path.parent.name == 's4_jar_compare':
            return str(api_path.parent.parent)

    output_dir = str(getattr(args, 'output_dir', '') or '').strip()
    if output_dir:
        output_path = Path(output_dir).expanduser()
        if output_path.name.startswith('s5_call_chain'):
            return str(output_path.parent)

    return '.upgrade-report'


def _report_step5_debug_event(hypothesis_id, location, msg, data=None, run_id='pre-fix'):
    if not _step5_debug_enabled():
        return
    # #region debug-point A:bridge-check
    _step5_debug(
        f"debug_event:{hypothesis_id}",
        msg,
        location=location,
        run_id=run_id,
        **(data or {}),
    )
    # #endregion


def _step5_integrated_main_impl(args):
    """
    Step 5集成版主流程

    改进点：
      1. 自动发现依赖源码映射（无需手动配置）
      2. 使用当前主分析器构建图（Java AST 优先）
      3. 置信度加权追踪
      4. 增强型输出格式
      5. 【修复】真正使用Step2解析出的业务源码目录（优先args.source_dirs，再用context恢复）
    """
    print("\nStep 5 开始（集成版）", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    step_timer = PhaseTimer("step5", "total")
    emit_progress("step5", "plan", "开始调用链影响分析")

    # Phase 0: 参数准备
    report_dir = infer_step5_report_dir(args)
    output_dir = args.output_dir or os.path.join(report_dir, 's5_call_chain')
    os.makedirs(output_dir, exist_ok=True)
    orchestrated_input = load_orchestrated_step5_input(report_dir)

    # Phase 1: 先确定 all_changed_apis_path（避免未定义变量错误）
    all_changed_apis_path = args.all_changed_apis
    if not all_changed_apis_path:
        all_changed_apis_path = os.path.join(report_dir, 's4_jar_compare', 'all_changed_apis.csv')

    # Phase 2: 正式流程优先使用 main_state 中已确认的 Step5 输入；调试模式才使用 CLI
    context_path = os.path.join(report_dir, 's2_context.json')
    context_source_dirs = []

    if os.path.exists(context_path):
        try:
            with open(context_path, 'r', encoding='utf-8') as f:
                context = json.load(f)
                context_source_dirs = context.get('source_dirs') or []
        except:
            pass

    # 业务源码目录来源优先级：
    # 1. 正式流程：main_state.step5.input.source_dirs
    # 2. 调试模式：命令行 args.source_dirs
    # 3. s2_context.json（恢复/兼容兜底）
    business_source_dirs = (
        orchestrated_input.get("source_dirs")
        if orchestrated_input.get("source_dirs")
        else (args.source_dirs if args.source_dirs else context_source_dirs)
    )

    if not business_source_dirs:
        print("❌ 至少需要提供一个业务源码目录", file=sys.stderr)
        print("  请通过以下方式指定：", file=sys.stderr)
        print("  1. 命令行 --source-dirs", file=sys.stderr)
        print("  2. 主状态中已确认并由调度层展开到 args.source_dirs 的业务源码目录", file=sys.stderr)
        print("  3. s2_context.json 中的 source_dirs（恢复场景）", file=sys.stderr)
        return 1

    if orchestrated_input.get("source_dirs"):
        print(f"  【正式流程】从 main_state 读取源码目录：{business_source_dirs}", file=sys.stderr)
    elif args.source_dirs:
        print(f"  使用命令行指定源码目录：{args.source_dirs}", file=sys.stderr)
    elif context_source_dirs:
        print(f"  【恢复场景】从 context 恢复源码目录：{context_source_dirs}", file=sys.stderr)
    _step5_debug(
        'step5_inputs',
        'resolved step5 input sources',
        report_dir=os.path.abspath(report_dir),
        output_dir=os.path.abspath(output_dir),
        all_changed_apis_path=os.path.abspath(all_changed_apis_path),
        business_source_dirs=list(business_source_dirs or []),
        input_source='main_state' if orchestrated_input.get("source_dirs") else ('cli' if args.source_dirs else 'context'),
        orchestrated=bool(orchestrated_input),
    )

    # Phase 2.5: 自动发现依赖源码映射
    dependency_source_mappings = (
        orchestrated_input.get("dependency_source_mappings")
        if "dependency_source_mappings" in orchestrated_input
        else (args.dependency_source_mappings or [])
    )
    allow_degraded = (
        bool(orchestrated_input.get("allow_degraded"))
        if "allow_degraded" in orchestrated_input
        else bool(args.allow_degraded)
    )
    bridge_discovery = None

    if not dependency_source_mappings:
        print("\n自动发现依赖源码映射...", file=sys.stderr)
        discovery_timer = time.perf_counter()
        emit_progress("step5", "discovery", "开始自动发现依赖源码映射")
        bridge_discovery = auto_discover_bridge_sources(report_dir)

        if bridge_discovery['dependency_source_mappings']:
            dependency_source_mappings = bridge_discovery['dependency_source_mappings']
            print(f"  发现：{len(bridge_discovery['matched_coords'])} 个可用依赖源码映射", file=sys.stderr)
        else:
            provided_dependency_dirs = bridge_discovery.get('provided_dependency_source_dirs') or []
            detected_unmapped_dirs = bridge_discovery.get('source_dirs_detected_without_coord') or []
            if provided_dependency_dirs or detected_unmapped_dirs:
                print("  ⚠️ 已提供依赖源码目录/仓库，但当前未能自动解析到可用依赖源码映射", file=sys.stderr)
                for line in (bridge_discovery.get('discovery_log') or [])[:3]:
                    print(f"    - {line}", file=sys.stderr)
            else:
                print("  ⚠️ 未找到可用的依赖源码映射", file=sys.stderr)
        emit_progress(
            "step5",
            "discovery",
            f"依赖源码映射发现完成，可用映射 {len(dependency_source_mappings)} 个",
            elapsed=time.perf_counter() - discovery_timer,
        )
    _step5_debug(
        'dependency_mapping_resolution',
        'resolved dependency source mappings for step5',
        mapping_count=len(dependency_source_mappings or []),
        mappings=list(dependency_source_mappings or []),
        allow_degraded=allow_degraded,
        discovery_summary={
            'matched_coords': list((bridge_discovery or {}).get('matched_coords') or []),
            'provided_dependency_source_dirs': list((bridge_discovery or {}).get('provided_dependency_source_dirs') or []),
            'source_dirs_detected_without_coord': list((bridge_discovery or {}).get('source_dirs_detected_without_coord') or []),
            'unresolved_dependency_source_dirs': list((bridge_discovery or {}).get('unresolved_dependency_source_dirs') or []),
        },
    )

    # Phase 3: 先只用业务源码构建基础图，判断哪些API真的必须跨依赖边界
    business_roots = build_source_roots(business_source_dirs, [])
    if not business_roots:
        print("❌ 至少需要提供一个业务源码目录", file=sys.stderr)
        return 1

    # Phase 4: 检查API文件是否存在
    if not os.path.exists(all_changed_apis_path):
        print(f"❌ 变更API文件不存在：{all_changed_apis_path}", file=sys.stderr)
        return 1

    all_apis = load_changed_apis(all_changed_apis_path, args.jdk_scan_dir)

    if not all_apis:
        print("⚠️ Step 5跳过：all_changed_apis.csv为空", file=sys.stderr)
        write_skip_summary(output_dir, all_changed_apis_path)
        return 0

    print(f"\n加载变更API：{len(all_apis)} 个", file=sys.stderr)
    emit_progress("step5", "input", f"已加载 {len(all_apis)} 个变更 API")
    _step5_debug(
        'step5_api_scope',
        'loaded api scope for tracing',
        total_apis=len(all_apis),
        sample_apis=[
            {
                'api_name': item.get('api_name', ''),
                'api_signature': item.get('api_signature', ''),
                'coord': item.get('coord', ''),
            }
            for item in all_apis[:5]
        ],
    )

    print("\n构建业务源码基础图（跨依赖判定预分析）...", file=sys.stderr)
    business_graph_timer = time.perf_counter()
    emit_progress("step5", "graph", "开始构建业务源码基础图")
    business_graph_result = build_enhanced_source_graph(
        business_roots,
        max_methods=getattr(args, 'max_methods', None),
        retain_analysis_cache=bool(dependency_source_mappings),
    )
    emit_progress(
        "step5",
        "graph",
        "业务源码基础图构建完成",
        elapsed=time.perf_counter() - business_graph_timer,
    )

    bridge_check_timer = time.perf_counter()
    emit_progress("step5", "bridge-check", "开始判断哪些 API 需要跨依赖继续分析")
    _report_step5_debug_event(
        'CATALOG',
        's5_call_chain_engine_integrated.py:runtime-catalog',
        'starting runtime dependency catalog build',
        data={
            'report_dir': report_dir,
            'all_api_count': len(all_apis),
        },
    )
    runtime_dependency_catalog = build_runtime_dependency_catalog(report_dir)
    _report_step5_debug_event(
        'CATALOG',
        's5_call_chain_engine_integrated.py:runtime-catalog',
        'finished runtime dependency catalog build',
        data={
            'report_dir': report_dir,
            'runtime_coord_count': len((runtime_dependency_catalog or {}).get('by_coord') or {}),
            'sample_runtime_coords': sorted(list(((runtime_dependency_catalog or {}).get('by_coord') or {}).keys()))[:8],
        },
    )
    api_bridge_requirements = check_apis_that_need_bridge(
        all_apis,
        report_dir,
        business_source_dirs,
        business_graph_result['graph'],
        dependency_source_mappings,
        business_graph_result['stats'],
        runtime_dependency_catalog=runtime_dependency_catalog,
    )
    emit_progress(
        "step5",
        "bridge-check",
        "跨依赖分析判定完成",
        elapsed=time.perf_counter() - bridge_check_timer,
    )
    needs_count = sum(1 for v in api_bridge_requirements.values() if v.get('needs_bridge'))
    missing_mapping_items = [
        item for item in api_bridge_requirements.values()
        if (
            item.get('needs_bridge')
            and not item.get('has_dependency_source_mapping')
            and not item.get('has_packaged_bytecode_fallback')
        )
    ]
    missing_mapping_count = len(missing_mapping_items)
    missing_mapping_coords = sorted(
        {
            str(item.get('coord') or '').strip()
            for item in missing_mapping_items
            if str(item.get('coord') or '').strip()
        }
    )
    if needs_count:
        print(f"  需要跨依赖继续分析的 API：{needs_count} 个", file=sys.stderr)
    else:
        print("  当前变更 API 均可直接在业务源码图中分析，无需额外依赖源码映射", file=sys.stderr)
    if missing_mapping_count:
        print(
            f"  缺少依赖源码映射的 API：{missing_mapping_count} 个"
            f"（涉及依赖 {len(missing_mapping_coords)} 个）",
            file=sys.stderr,
        )
    _step5_debug(
        'bridge_check_summary',
        'evaluated which apis need cross-dependency tracing',
        total_apis=len(all_apis),
        needs_bridge_count=needs_count,
        missing_mapping_count=missing_mapping_count,
        missing_mapping_coords=missing_mapping_coords,
        sample_bridge_requirements=[
            {
                'api': key,
                'needs_bridge': bool(info.get('needs_bridge')),
                'has_dependency_source_mapping': bool(info.get('has_dependency_source_mapping', True)),
                'has_packaged_bytecode_fallback': bool(info.get('has_packaged_bytecode_fallback')),
                'reason': info.get('reason', ''),
            }
            for key, info in list((api_bridge_requirements or {}).items())[:5]
        ],
    )

    has_provided_dependency_inputs = bool(
        dependency_source_mappings
        or (bridge_discovery or {}).get('provided_dependency_source_dirs')
        or (bridge_discovery or {}).get('source_dirs_detected_without_coord')
    )

    if missing_mapping_count and not allow_degraded:
        _step5_debug(
            'bridge_check_blocked',
            'step5 blocked because dependency source mappings are missing',
            missing_mapping_count=missing_mapping_count,
            missing_mapping_coords=missing_mapping_coords,
            has_provided_dependency_inputs=has_provided_dependency_inputs,
        )
        if has_provided_dependency_inputs:
            print("\n❌ 错误：检测到需要跨依赖边界分析的变更API。", file=sys.stderr)
            print("当前状态：用户已提供依赖源码目录，但系统尚未为全部目标依赖解析出可用的依赖源码映射。", file=sys.stderr)
            print("影响：无法确认这些API是否真正影响系统。", file=sys.stderr)
            unresolved_dirs = (bridge_discovery or {}).get('unresolved_dependency_source_dirs') or []
            if unresolved_dirs:
                print("\n未解析成功的依赖源码输入：", file=sys.stderr)
                for item in unresolved_dirs[:5]:
                    reason = item.get('reason') or 'unknown'
                    root_path = item.get('root_path') or ''
                    source_dirs = item.get('source_dirs') or []
                    if source_dirs:
                        print(
                            f"  - {root_path} | reason={reason} | detected_source_dirs={len(source_dirs)}",
                            file=sys.stderr,
                        )
                    else:
                        print(f"  - {root_path} | reason={reason}", file=sys.stderr)
            print("\n解决方案：", file=sys.stderr)
            print("  1. 优先修正 dependency_source_dirs，使其指向依赖工程根目录或多模块仓库根目录", file=sys.stderr)
            print("  2. 确认目录下包含可识别的模块清单与源码目录（如 pom.xml/build.gradle、src/main/java）", file=sys.stderr)
            print("  3. 或者使用 --allow-degraded 继续分析（相关API将标记为not_analyzed）", file=sys.stderr)
        else:
            print("\n❌ 错误：检测到需要跨依赖边界分析的变更API，但未提供可用的依赖源码映射", file=sys.stderr)
            print("影响：无法确认这些API是否真正影响系统", file=sys.stderr)
            print("\n解决方案：", file=sys.stderr)
            print("  1. 提供 dependency_source_dirs 指向依赖源码目录/仓库", file=sys.stderr)
            print("  2. 确认目录下包含可识别的模块清单与源码目录", file=sys.stderr)
            print("  3. 或者使用 --allow-degraded 继续分析（相关API将标记为not_analyzed）", file=sys.stderr)
        if missing_mapping_coords:
            print(
                f"  缺失映射的依赖坐标：{', '.join(missing_mapping_coords[:10])}",
                file=sys.stderr,
            )
        details_path = write_missing_dependency_mapping_details(
            output_dir,
            missing_mapping_items,
            missing_mapping_coords,
            has_provided_dependency_inputs,
            bridge_discovery=bridge_discovery,
        )
        emit_step_interaction(
            build_missing_dependency_mapping_interaction(
                output_dir,
                details_path,
                missing_mapping_count,
                missing_mapping_coords,
                has_provided_dependency_inputs,
            )
        )
        return EXIT_AWAITING_USER

    if missing_mapping_count and allow_degraded:
        _step5_debug(
            'bridge_check_degraded',
            'step5 continues in degraded mode for missing dependency mappings',
            missing_mapping_count=missing_mapping_count,
            missing_mapping_coords=missing_mapping_coords,
        )
        if has_provided_dependency_inputs:
            print("  ⚠️ 允许降级执行：已提供依赖源码目录/仓库，但目标依赖的源码映射仍不完整；相关API将标记为not_analyzed", file=sys.stderr)
        else:
            print("  ⚠️ 允许降级执行：需要依赖源码映射的 API 将标记为 not_analyzed", file=sys.stderr)

    # Phase 5: 构建增强型源码图
    source_roots = build_source_roots(business_source_dirs, dependency_source_mappings)
    jar_metadata = build_jar_metadata_for_source_roots(source_roots, report_dir)
    _step5_debug(
        'graph_roots',
        'prepared source roots and jar metadata',
        source_root_count=len(source_roots or []),
        source_roots=source_roots,
        jar_metadata_class_count=len((jar_metadata or {}).get('by_class') or {}),
        jar_metadata_jar_count=len((jar_metadata or {}).get('jar_paths') or {}),
    )
    if dependency_source_mappings:
        print("\n构建完整源码调用图（业务 + 依赖源码映射）...", file=sys.stderr)
        full_graph_timer = time.perf_counter()
        emit_progress(
            "step5",
            "graph",
            f"开始构建依赖源码图，映射数 {len(dependency_source_mappings)}",
        )
        dependency_only_roots = [
            root for root in source_roots
            if str(root.get('owner_type') or '').strip() == 'dependency'
        ]
        reused_analysis = business_graph_result.get('analysis_cache') or []
        # 依赖源码增量构图前释放业务预分析阶段的大对象，避免双图长时间并存。
        business_graph_result['graph'] = None
        business_graph_result['type_metadata'] = None
        business_graph_result['stats'] = None
        gc.collect()
        graph_result = build_enhanced_source_graph(
            dependency_only_roots,
            max_methods=getattr(args, 'max_methods', None),
            jar_metadata=jar_metadata,
            reused_analysis=reused_analysis,
            retain_analysis_cache=False,
        )
        business_graph_result = None
        reused_analysis = None
        emit_progress(
            "step5",
            "graph",
            f"依赖源码图构建完成，依赖源码根 {len(dependency_only_roots)} 个",
            elapsed=time.perf_counter() - full_graph_timer,
        )
    else:
        print("\n复用业务源码图进行调用链分析...", file=sys.stderr)
        emit_progress("step5", "graph", "未提供依赖源码映射，复用业务源码图")
        graph_result = business_graph_result

    graph = graph_result['graph']
    type_metadata = graph_result['type_metadata']
    graph_stats = graph_result['stats']
    graph.runtime_dependency_catalog = runtime_dependency_catalog

    print(f"  方法数：{len(graph.methods_by_id)}", file=sys.stderr)
    print(f"  反向边数：{len(graph.reverse_edges)}", file=sys.stderr)
    parser_usage = graph_stats.get('parser_usage', {})
    print(
        f"  解析器使用：tree_sitter={parser_usage.get('tree_sitter', 0)}, "
        f"regex={parser_usage.get('regex', 0)}",
        file=sys.stderr,
    )
    if graph_stats.get('parser_fallback_reasons'):
        print(
            f"  解析器降级：{graph_stats.get('parser_fallback_reasons')}",
            file=sys.stderr,
        )

    if graph_stats.get('truncated'):
        print(f"  ⚠️ 图构建截断：{','.join(graph_stats.get('truncation_reasons', []))}", file=sys.stderr)
    _step5_debug(
        'graph_summary',
        'graph build completed',
        methods_indexed=len(graph.methods_by_id),
        reverse_edge_keys=len(graph.reverse_edges),
        graph_stats=graph_stats,
        type_metadata_count=len(type_metadata or {}),
    )

    # Phase 5: 置信度加权反向追踪（核心改进）
    print("\n反向追踪调用链（置信度加权）...", file=sys.stderr)
    emit_progress("step5", "trace", f"开始反向追踪，共 {len(all_apis)} 个 API")

    # Key clarification: max_depth semantics
    # SKILL.md defines:
    #   - High confidence edge: depth_cost=1 (max_depth=5 allows 5 hops)
    #   - Medium confidence edge: depth_cost=2 (max_depth=5 allows 2-3 hops)
    #   - Low confidence edge: depth_cost=5 (stops immediately)
    # max_depth controls "max cumulative cost", not "max hop count"
    # User passing 5 means "paths with cost<=5", actual hops depend on each hop's confidence
    max_depth = orchestrated_input.get("max_depth") if "max_depth" in orchestrated_input else (
        args.max_depth if hasattr(args, 'max_depth') else 5
    )
    if max_depth in (None, ""):
        max_depth = 5
    # 关键修复：直接使用max_depth，让语义清晰
    # 用户传3就是最多3条边，不再转换
    all_results = trace_all_apis_with_confidence_weighting(
        all_apis,
        graph,
        type_metadata,
        max_total_cost=max_depth,
        api_bridge_requirements=api_bridge_requirements,
        allow_degraded=allow_degraded,
        graph_stats=graph_stats,
    )
    _step5_debug(
        'trace_batch_summary',
        'completed tracing all apis',
        total_results=len(all_results),
        status_counts={
            'reachable': sum(1 for r in all_results if r.analysis_status == 'reachable'),
            'uncertain': sum(1 for r in all_results if r.analysis_status == 'uncertain'),
            'not_analyzed': sum(1 for r in all_results if r.analysis_status == 'not_analyzed'),
            'not_found_in_static_analysis': sum(
                1 for r in all_results if r.analysis_status in ('not_found_in_static_analysis', 'not_reachable')
            ),
        },
        sample_results=[
            {
                'api_name': r.api_name,
                'analysis_status': r.analysis_status,
                'reason_code': r.reason_code,
                'match_provenance': r.match_provenance,
            }
            for r in all_results[:5]
        ],
    )

    # Phase 6: 增强型输出（核心改进）
    print("\n生成分析报告...", file=sys.stderr)
    summary_timer = time.perf_counter()
    emit_progress("step5", "report", "开始生成汇总报告与证据视图")
    generate_enhanced_summary(all_results, output_dir, graph_stats=graph_stats)
    emit_progress(
        "step5",
        "report",
        "汇总报告生成完成",
        elapsed=time.perf_counter() - summary_timer,
    )

    # 统计
    reachable_count = sum(1 for r in all_results if r.analysis_status == 'reachable')
    uncertain_count = sum(1 for r in all_results if r.analysis_status == 'uncertain')
    not_analyzed_count = sum(1 for r in all_results if r.analysis_status == 'not_analyzed')
    not_found_count = sum(
        1 for r in all_results
        if r.analysis_status in ('not_found_in_static_analysis', 'not_reachable')
    )

    print("\n分析结果：", file=sys.stderr)
    print(f"  ✓ reachable: {reachable_count}", file=sys.stderr)
    print(f"  ❓ uncertain: {uncertain_count}", file=sys.stderr)
    print(f"  ⊘ not_analyzed: {not_analyzed_count}", file=sys.stderr)
    print(f"  ✗ not_found_in_static_analysis: {not_found_count}", file=sys.stderr)

    print("\nStep 5 完成", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    emit_progress(
        "step5",
        "done",
        (
            "Step5 完成，"
            f"reachable={reachable_count}，uncertain={uncertain_count}，"
            f"not_analyzed={not_analyzed_count}，not_found={not_found_count}"
        ),
        elapsed=step_timer.elapsed(),
    )
    _step5_debug(
        'step5_done',
        'step5 completed',
        reachable=reachable_count,
        uncertain=uncertain_count,
        not_analyzed=not_analyzed_count,
        not_found=not_found_count,
        elapsed_seconds=step_timer.elapsed(),
    )

    return 0


# ══════════════════════════════════════════════════════════════════
# 辅助函数
# ══════════════════════════════════════════════════════════════════

def build_source_roots(source_dirs, dependency_source_mappings):
    """
    构建源码根配置（兼容原有格式）
    """
    roots = []

    # 业务源码
    for path in source_dirs:
        if os.path.isdir(path):
            roots.append({
                'root': os.path.abspath(path),
                'owner_type': 'business',
                'owner_coord': 'BUSINESS',
                'module': infer_module_name(path)
            })

    # 依赖源码映射
    for mapping in dependency_source_mappings or []:
        if '=' not in mapping:
            continue

        coord, path = mapping.split('=', 1)
        coord = coord.strip()
        path = path.strip()

        if os.path.isdir(path):
            roots.append({
                'root': os.path.abspath(path),
                'owner_type': 'dependency',
                'owner_coord': coord,
                'module': infer_module_name(path)
            })

    return roots


def infer_module_name(path):
    """推断模块名"""
    normalized = path.replace('\\', '/').rstrip('/')
    for marker in ('/src/main/', '/src/test/'):
        if marker in normalized:
            module_root = normalized.split(marker, 1)[0]
            return os.path.basename(module_root) or 'root'
    return os.path.basename(normalized) or 'root'


def _split_coord(coord):
    parts = str(coord or '').strip().split(':')
    if len(parts) < 2:
        return '', ''
    return parts[0].strip(), parts[1].strip()


def _find_maven_jar(coord, version):
    group_id, artifact_id = _split_coord(coord)
    version = str(version or '').strip()
    if not group_id or not artifact_id or not version or version == '-':
        return ''
    base = maven_repo_dir()
    for part in group_id.split('.'):
        base = base / part
    base = base / artifact_id / version
    if not base.exists():
        return ''
    candidates = []
    for pattern in (f'{artifact_id}-{version}.jar', f'{artifact_id}-{version}-*.jar'):
        candidates.extend(base.glob(pattern))
    for jar_path in candidates:
        name = jar_path.name
        if 'sources' in name or 'javadoc' in name:
            continue
        return str(jar_path)
    return ''


def _load_coord_versions(report_dir):
    dep_changes_path = os.path.join(report_dir, 's1_dep_changes.csv')
    result = {}
    if not os.path.exists(dep_changes_path):
        return result
    with open(dep_changes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if str((row or {}).get('resolution_status') or '').strip() == 'unresolved':
                continue
            coord = str(row.get('coord') or '').strip()
            if coord:
                result[coord] = dict(row)
    return result


def build_runtime_dependency_catalog(report_dir):
    current_resolved_path = os.path.join(report_dir, 's1_deps_current_resolved.csv')
    catalog = {
        'by_coord': {},
        'jar_paths': {},
    }
    if not os.path.exists(current_resolved_path):
        return catalog

    with open(current_resolved_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            coord = str((row or {}).get('coord') or '').strip()
            version = str((row or {}).get('version') or '').strip()
            scope = str((row or {}).get('scope') or '').strip()
            if not coord or not version:
                continue
            if scope in {'test', 'provided', 'optional'}:
                continue
            jar_path = _find_maven_jar(coord, version)
            if not jar_path:
                continue
            item = {
                'coord': coord,
                'version': version,
                'scope': scope,
                'jar_path': jar_path,
            }
            catalog['by_coord'][coord] = item
            catalog['jar_paths'][coord] = jar_path
    return catalog


def _normalize_descriptor_type(descriptor, preserve_array=False):
    if not descriptor:
        return ''
    array_dims = 0
    while descriptor.startswith('['):
        array_dims += 1
        descriptor = descriptor[1:]
    primitive_map = {
        'V': 'void',
        'Z': 'boolean',
        'B': 'byte',
        'C': 'char',
        'S': 'short',
        'I': 'int',
        'J': 'long',
        'F': 'float',
        'D': 'double',
    }
    if descriptor in primitive_map:
        base = primitive_map[descriptor]
    elif descriptor.startswith('L') and descriptor.endswith(';'):
        base = descriptor[1:-1].replace('/', '.')
    else:
        base = descriptor.replace('/', '.')
    if array_dims:
        suffix = '[]' * array_dims
        if preserve_array:
            return f'{base}{suffix}'
    return base


def _parse_method_descriptor(descriptor):
    descriptor = str(descriptor or '').strip()
    if not descriptor.startswith('('):
        return [], ''
    idx = 1
    params = []
    while idx < len(descriptor) and descriptor[idx] != ')':
        start = idx
        while idx < len(descriptor) and descriptor[idx] == '[':
            idx += 1
        if idx >= len(descriptor):
            break
        if descriptor[idx] == 'L':
            end = descriptor.find(';', idx)
            if end < 0:
                break
            idx = end + 1
        else:
            idx += 1
        params.append(_normalize_descriptor_type(descriptor[start:idx], preserve_array=True))
    return_type = ''
    if idx < len(descriptor) and descriptor[idx] == ')':
        return_type = _normalize_descriptor_type(descriptor[idx + 1:], preserve_array=True)
    return params, return_type


def _build_signature_from_params(param_types):
    params = [str(item or '').strip() for item in (param_types or [])]
    if not params:
        return '()'
    normalized = []
    for item in params:
        text = item.replace('...', '[]')
        if '<' in text:
            text = text.split('<', 1)[0].strip()
        if '.' in text:
            text = text.rsplit('.', 1)[-1]
        normalized.append(text)
    return '(' + ', '.join(normalized) + ')'


def _run_javap_for_class(jar_path, class_fqcn):
    from compat import run_cmd
    stdout, _stderr, rc = run_cmd(
        ['javap', '-classpath', jar_path, '-s', '-p', class_fqcn],
        timeout=30,
    )
    return stdout if rc == 0 else ''


def _parse_javap_signature_block(text, class_fqcn):
    metadata = {
        'class_fqcn': class_fqcn,
        'kind': 'class',
        'extends': [],
        'implements': [],
        'methods': defaultdict(dict),
    }
    current_method_name = ''
    current_param_types = []
    header_match = re.search(
        r'(?:public|protected|private)?\s*(?:abstract\s+|final\s+)?(class|interface)\s+'
        r'[\w.$]+\s*(?:extends\s+([^{\n]+?))?\s*(?:implements\s+([^{\n]+))?\s*\{',
        text,
    )
    if header_match:
        metadata['kind'] = 'interface' if header_match.group(1) == 'interface' else 'class'
        extends_part = (header_match.group(2) or '').strip()
        implements_part = (header_match.group(3) or '').strip()
        if extends_part:
            metadata['extends'] = [
                item.strip().replace('$', '.')
                for item in extends_part.split(',')
                if item.strip() and item.strip() != 'java.lang.Object'
            ]
        if implements_part:
            metadata['implements'] = [
                item.strip().replace('$', '.')
                for item in implements_part.split(',')
                if item.strip()
            ]
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        descriptor_match = re.match(r'descriptor:\s*(\S+)', line)
        if descriptor_match and current_method_name:
            descriptor = descriptor_match.group(1).strip()
            current_param_types, return_type = _parse_method_descriptor(descriptor)
            signature = _build_signature_from_params(current_param_types)
            metadata['methods'][current_method_name][signature] = return_type
            continue
        if line.startswith('descriptor:'):
            continue
        if not line.endswith(';'):
            current_method_name = ''
            current_param_types = []
            continue
        if '(' not in line or ')' not in line:
            current_method_name = ''
            current_param_types = []
            continue
        decl = line[:-1]
        method_match = re.search(r'([A-Za-z_$][\w$]*)\s*\(', decl)
        if not method_match:
            current_method_name = ''
            current_param_types = []
            continue
        current_method_name = method_match.group(1)
        current_param_types = []
    metadata['methods'] = {
        method_name: dict(signatures)
        for method_name, signatures in metadata['methods'].items()
    }
    return metadata


def _normalize_class_reference(type_name):
    text = str(type_name or '').strip()
    if not text:
        return ''
    text = text.replace('...', '[]')
    text = text.replace('$', '.')
    text = re.sub(r'@\w+(?:\([^)]*\))?\s*', '', text)
    text = text.replace('?', '').replace('extends ', '').replace('super ', '').strip()
    if '<' in text:
        text = text.split('<', 1)[0].strip()
    while text.endswith('[]'):
        text = text[:-2].strip()
    if text in {'void', 'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double'}:
        return ''
    if '.' not in text or any(ch in text for ch in ' ,()'):
        return ''
    return text


def _ensure_coord_class_index(metadata, coord, jar_path):
    class_index_by_coord = metadata.setdefault('_class_index_by_coord', {})
    cached = class_index_by_coord.get(coord)
    if cached is not None:
        return cached
    class_index = {}
    with zipfile.ZipFile(jar_path) as zf:
        for entry in zf.namelist():
            if not entry.endswith('.class') or entry.startswith('META-INF/'):
                continue
            binary_name = entry[:-6].replace('/', '.')
            normalized_name = binary_name.replace('$', '.')
            class_index.setdefault(normalized_name, binary_name)
    class_index_by_coord[coord] = class_index
    return class_index


def _locate_jar_class(metadata, class_fqcn):
    class_locations = metadata.setdefault('_class_locations', {})
    if class_fqcn in class_locations:
        return class_locations[class_fqcn]
    for coord, jar_path in (metadata.get('jar_paths') or {}).items():
        class_index = _ensure_coord_class_index(metadata, coord, jar_path)
        binary_name = class_index.get(class_fqcn)
        if binary_name:
            located = (coord, jar_path, binary_name)
            class_locations[class_fqcn] = located
            return located
    class_locations[class_fqcn] = None
    return None


def hydrate_jar_metadata_for_classes(metadata, target_classes, source_known_classes=None):
    metadata = metadata or {}
    by_class = metadata.setdefault('by_class', {})
    by_coord = metadata.setdefault('by_coord', {})
    pending = deque()
    queued = set()
    source_known_classes = set(source_known_classes or [])

    for class_name in target_classes or []:
        normalized = _normalize_class_reference(class_name)
        if not normalized or normalized in source_known_classes or normalized in by_class:
            continue
        if normalized in queued:
            continue
        pending.append(normalized)
        queued.add(normalized)

    while pending:
        class_fqcn = pending.popleft()
        located = _locate_jar_class(metadata, class_fqcn)
        if not located:
            continue
        coord, jar_path, binary_name = located
        javap_text = _run_javap_for_class(jar_path, binary_name)
        if not javap_text:
            continue
        class_meta = _parse_javap_signature_block(javap_text, class_fqcn)
        by_class[class_fqcn] = class_meta
        coord_meta = by_coord.setdefault(
            coord,
            {
                'coord': coord,
                'version': '',
                'jar_path': jar_path,
                'classes': {},
            },
        )
        coord_meta['classes'][class_fqcn] = class_meta
        for parent in (class_meta.get('extends') or []) + (class_meta.get('implements') or []):
            normalized_parent = _normalize_class_reference(parent)
            if (
                normalized_parent
                and normalized_parent not in source_known_classes
                and normalized_parent not in by_class
                and normalized_parent not in queued
            ):
                pending.append(normalized_parent)
                queued.add(normalized_parent)


def build_jar_metadata_for_source_roots(source_roots, report_dir):
    coord_versions = _load_coord_versions(report_dir)
    metadata = {
        'by_coord': {},
        'by_class': {},
        'jar_paths': {},
    }
    dependency_coords = []
    seen_coords = set()
    for root in source_roots or []:
        if root.get('owner_type') != 'dependency':
            continue
        coord = str(root.get('owner_coord') or '').strip()
        if coord and coord not in seen_coords:
            seen_coords.add(coord)
            dependency_coords.append(coord)
    for coord in dependency_coords:
        version_row = coord_versions.get(coord, {})
        version = (
            str(version_row.get('new_version') or '').strip()
            or str(version_row.get('old_version') or '').strip()
        )
        jar_path = _find_maven_jar(coord, version)
        if not jar_path:
            continue
        metadata['jar_paths'][coord] = jar_path
        metadata['by_coord'][coord] = {
            'coord': coord,
            'version': version,
            'jar_path': jar_path,
            'classes': {},
        }
    return metadata


def _collect_external_class_candidates(class_info, all_methods, resolve_type_name, known_classes):
    candidates = set()
    known_classes = set(known_classes or [])
    for info in (class_info or {}).values():
        if info.get('owner_type') != 'business':
            continue
        owner_info = {
            'imports': info.get('imports', {}),
            'package_name': info.get('package_name', ''),
        }
        for raw_name in (info.get('extends_raw') or []) + (info.get('implements_raw') or []):
            normalized = _normalize_class_reference(resolve_type_name(raw_name, owner_info))
            if normalized and normalized not in known_classes:
                candidates.add(normalized)
    for method_def in all_methods or []:
        if getattr(method_def, 'owner_type', '') != 'business':
            continue
        for raw_name in (
            [getattr(method_def, 'return_type', '')]
            + list((getattr(method_def, 'param_types', {}) or {}).values())
            + list((getattr(method_def, 'field_types', {}) or {}).values())
            + list((getattr(method_def, 'local_var_types', {}) or {}).values())
        ):
            normalized = _normalize_class_reference(raw_name)
            if normalized and normalized not in known_classes:
                candidates.add(normalized)
    return candidates


def load_changed_apis(csv_path, jdk_scan_dir=""):
    """加载变更API列表"""
    rows = []

    # JDK removed API 过滤（来自Step3）
    excluded = set()
    if jdk_scan_dir:
        jdk_removed_path = os.path.join(jdk_scan_dir, 's3_jdk_removed_api.csv')
        if os.path.exists(jdk_removed_path):
            with open(jdk_removed_path, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    key = f"{row.get('package', '')}.{row.get('name', '')}"
                    excluded.add(key)

    with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            api = dict(row)
            # 过滤 JDK removed API
            coord = api.get('coord', '')
            api_name = api.get('api_name', '')
            key = f"{coord}:{api_name}"
            if key in excluded or api_name in excluded:
                continue
            rows.append(api)

    _step5_debug(
        'input_changed_apis',
        'loaded changed api rows',
        csv_path=os.path.abspath(csv_path),
        jdk_scan_dir=os.path.abspath(jdk_scan_dir) if jdk_scan_dir else '',
        total_rows=len(rows),
        excluded_count=len(excluded),
        sample_api_names=[item.get('api_name', '') for item in rows[:5]],
    )

    return rows


def _has_direct_business_usage(api_row, business_graph):
    """检查业务源码是否直接调用了变更API，不需要额外依赖源码映射即可证明影响。"""
    graph_type_metadata = getattr(business_graph, 'type_metadata', {}) or {}
    target_keys = build_api_target_keys(
        api_row,
        graph=business_graph,
        type_metadata=graph_type_metadata,
    )
    for key in target_keys:
        if not business_graph.reverse_edges.get(key):
            continue
        if key.startswith('class:'):
            continue
        for edge in business_graph.reverse_edges.get(key, []):
            method_def = business_graph.methods_by_id.get(edge.caller_symbol_id)
            if method_def and method_def.owner_type == 'business' and not method_def.is_test:
                return True
    return False


def _empty_graph_stats():
    return {
        'truncated': False,
        'truncation_reasons': [],
        'methods_indexed': 0,
        'reverse_edges_indexed': 0,
        'edge_cap_hits': 0,
        'edge_cap_keys': [],
        'parser_usage': {
            'tree_sitter': 0,
            'regex': 0,
        },
        'parser_fallback_reasons': {},
        'parser_fallback_files': [],
    }


def _record_parser_info(stats, file_path, parser_info):
    parser_info = parser_info or {}
    actual_parser = parser_info.get('actual_parser', 'regex')
    stats['parser_usage'][actual_parser] = stats['parser_usage'].get(actual_parser, 0) + 1
    fallback_reason = parser_info.get('fallback_reason')
    if fallback_reason:
        stats['parser_fallback_reasons'][fallback_reason] = (
            stats['parser_fallback_reasons'].get(fallback_reason, 0) + 1
        )
        if len(stats['parser_fallback_files']) < 20:
            stats['parser_fallback_files'].append({
                'file': file_path,
                'reason': fallback_reason,
            })


def _extract_declared_types(file_content):
    package_match = re.search(r'^\s*package\s+([A-Za-z_][\w.]*)\s*;?', file_content, re.MULTILINE)
    package_name = package_match.group(1) if package_match else ''
    imports = {}
    for import_match in re.finditer(r'^\s*import\s+([A-Za-z_][\w.]*)\s*;?', file_content, re.MULTILINE):
        fqcn = import_match.group(1)
        imports[fqcn.rsplit('.', 1)[-1]] = fqcn

    declared_types = {}
    lines = file_content.splitlines()
    for idx, line in enumerate(lines):
        decl_match = re.search(
            r'^\s*(?:public|protected|private|abstract|final|sealed|open|data|internal|static|\s)*'
            r'(class|interface|enum)\s+([A-Z][A-Za-z0-9_]*)\b([^{]*)\{?',
            line
        )
        if not decl_match:
            continue
        kind = decl_match.group(1)
        class_name = decl_match.group(2)
        tail = decl_match.group(3) or ''
        annotations = []
        for back_idx in range(idx - 1, max(idx - 10, -1), -1):
            prev = lines[back_idx].strip()
            if not prev:
                break
            if prev.startswith('@'):
                ann_match = re.match(r'@(\w+)', prev)
                if ann_match:
                    annotations.insert(0, ann_match.group(1))
                continue
            break
        extends_raw = []
        implements_raw = []
        if kind == 'interface':
            extends_match = re.search(r'\bextends\s+([^{]+)$', tail)
            if extends_match:
                extends_raw = [item.strip() for item in extends_match.group(1).split(',') if item.strip()]
        else:
            extends_match = re.search(r'\bextends\s+([^{]+?)(?:\bimplements\b|$)', tail)
            if extends_match:
                extends_raw = [extends_match.group(1).strip()] if extends_match.group(1).strip() else []
            implements_match = re.search(r'\bimplements\s+([^{]+)$', tail)
            if implements_match:
                implements_raw = [item.strip() for item in implements_match.group(1).split(',') if item.strip()]
        declared_types[class_name] = {
            'kind': kind,
            'annotations': annotations,
            'extends_raw': extends_raw,
            'implements_raw': implements_raw,
        }
    return package_name, imports, declared_types


def _analyze_source_file_entry(file_path, root):
    # Java sources should consistently prefer AST parsing for both business and
    # dependency roots. analyze_file() will still fall back to regex when the
    # runtime lacks tree-sitter support or the file cannot be parsed.
    prefer_tree_sitter = True
    methods, parser_info = analyze_file(
        file_path,
        root,
        prefer_tree_sitter=prefer_tree_sitter,
        return_diagnostics=True,
    )
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            file_content = f.read()
    except Exception:
        file_content = ''
    package_name, imports, declared_types = _extract_declared_types(file_content)
    return {
        'file_path': os.path.abspath(file_path),
        'root': dict(root),
        'methods': methods,
        'parser_info': parser_info,
        'package_name': package_name,
        'imports': imports,
        'declared_types': declared_types,
    }


def _collect_source_file_entries(source_roots, reused_analysis=None):
    skip_dirs = {
        '.git', 'target', 'build', '.gradle', 'out', 'bin',
        'node_modules', '.idea', '.upgrade-report', 'test'
    }
    entries = []
    seen_files = set()
    stats = _empty_graph_stats()

    for entry in sorted(
        reused_analysis or [],
        key=lambda item: os.path.abspath(str((item or {}).get('file_path') or '')),
    ):
        file_path = os.path.abspath(str(entry.get('file_path') or ''))
        if not file_path or file_path in seen_files:
            continue
        if entry.get('file_path') != file_path:
            copied = dict(entry)
            copied['file_path'] = file_path
            copied['root'] = dict(entry.get('root') or {})
            entries.append(copied)
        else:
            entries.append(entry)
        seen_files.add(file_path)
        _record_parser_info(stats, file_path, entry.get('parser_info') or {})

    for root in sorted(
        source_roots or [],
        key=lambda item: (
            str((item or {}).get('root') or ''),
            str((item or {}).get('owner_type') or ''),
            str((item or {}).get('owner_coord') or ''),
            str((item or {}).get('module') or ''),
        ),
    ):
        root_path = str((root or {}).get('root') or '').strip()
        if not root_path or not os.path.isdir(root_path):
            continue
        for current_root, dirs, files in os.walk(root_path):
            dirs[:] = sorted(d for d in dirs if d not in skip_dirs)
            for filename in sorted(files):
                if not (filename.endswith('.java') or filename.endswith('.kt')):
                    continue
                file_path = os.path.abspath(os.path.join(current_root, filename))
                if file_path in seen_files:
                    continue
                entry = _analyze_source_file_entry(file_path, root)
                entries.append(entry)
                seen_files.add(file_path)
                _record_parser_info(stats, file_path, entry.get('parser_info') or {})
    _step5_debug(
        'graph_source_collection',
        'collected source file entries for graph build',
        source_root_count=len(source_roots or []),
        reused_analysis_count=len(reused_analysis or []),
        collected_files=len(entries),
        parser_usage=stats.get('parser_usage', {}),
        parser_fallback_reasons=stats.get('parser_fallback_reasons', {}),
    )
    entries.sort(key=lambda item: os.path.abspath(str((item or {}).get('file_path') or '')))
    return entries, stats


def build_enhanced_source_graph(
    source_roots,
    max_methods=None,
    jar_metadata=None,
    reused_analysis=None,
    retain_analysis_cache=True,
):
    """
    构建增强型源码图

    改进：
      - 使用增强分析器（AST/增强正则）
      - Lambda/方法引用识别
      - 泛型类型完整解析
      - 填充type_metadata（关键修复）
    """
    from dataclasses import dataclass
    from collections import defaultdict

    @dataclass
    class SourceGraph:
        methods_by_id: dict
        methods_by_qualified: dict
        methods_by_simple: dict
        reverse_edges: dict
        lookup_keys_by_symbol: dict
        type_metadata: dict  # 必须填充，否则接口/继承分析失效

    methods_by_id = {}
    methods_by_qualified = defaultdict(list)
    methods_by_simple = defaultdict(list)
    reverse_edges = defaultdict(list)
    lookup_keys_by_symbol = {}
    type_metadata = {}  # 关键修复：必须填充
    all_methods = []

    # 类型信息收集器
    class_info = {}  # class_fqcn -> ClassInfo
    interface_implementations = defaultdict(list)  # interface -> 实现类列表

    file_entries, stats = _collect_source_file_entries(source_roots, reused_analysis=reused_analysis)
    _step5_debug(
        'graph_build_start',
        'starting enhanced source graph build',
        source_root_count=len(source_roots or []),
        reused_analysis_count=len(reused_analysis or []),
        retain_analysis_cache=bool(retain_analysis_cache),
        max_methods=max_methods,
    )

    def build_method_declared_signature(method_def):
        values = list((getattr(method_def, 'param_declared_types', {}) or {}).values())
        if not values:
            values = list((getattr(method_def, 'param_types', {}) or {}).values())
        normalized = []
        for value in values:
            text = str(value or '').strip()
            if not text:
                return ''
            text = text.replace('...', '[]')
            if '<' in text:
                text = text.split('<', 1)[0].strip()
            if '.' in text:
                text = text.rsplit('.', 1)[-1]
            normalized.append(text)
        return '(' + ', '.join(normalized) + ')' if normalized or values == [] else ''

    unique_signatures_by_qualified_key = defaultdict(set)
    unique_signatures_by_simple_key = defaultdict(set)

    def build_reverse_edge_keys(edge):
        keys = []
        for edge_key in [edge.callee_key, edge.callee_simple_key]:
            edge_key = (edge_key or '').strip()
            if not edge_key:
                continue
            keys.append(edge_key)
            if '(' in edge_key and edge_key.endswith(')'):
                keys.append(edge_key.split('(', 1)[0])
        # Method references like `this::toDto` do not carry explicit arg expressions.
        # If the referenced target has a single declared signature in source, index that
        # exact signature as well so Step5 can avoid unnecessary name-only fallback.
        if getattr(edge, 'evidence_type', '') == 'method_reference':
            for base_key, signature_map in [
                ((edge.callee_key or '').strip(), unique_signatures_by_qualified_key),
                ((edge.callee_simple_key or '').strip(), unique_signatures_by_simple_key),
            ]:
                if not base_key or '(' in base_key:
                    continue
                signatures = sorted(signature_map.get(base_key, set()))
                if len(signatures) == 1:
                    keys.append(f"{base_key}{signatures[0]}")
        return list(dict.fromkeys(keys))

    def method_sort_key(method_def):
        return (
            str(getattr(method_def, 'file', '') or ''),
            int(getattr(method_def, 'line', 0) or 0),
            str(getattr(method_def, 'qualified_key', '') or ''),
            str(getattr(method_def, 'symbol_id', '') or ''),
        )

    def edge_sort_key(edge):
        confidence_rank = {'high': 0, 'medium': 1, 'low': 2}.get(getattr(edge, 'confidence', ''), 9)
        owner_rank = 0 if getattr(edge, 'owner_type', '') == 'business' else 1
        return (
            confidence_rank,
            owner_rank,
            str(getattr(edge, 'caller_qualified_key', '') or ''),
            str(getattr(edge, 'callee_key', '') or ''),
            str(getattr(edge, 'file', '') or ''),
            int(getattr(edge, 'line', 0) or 0),
            str(getattr(edge, 'owner_coord', '') or ''),
            str(getattr(edge, 'module', '') or ''),
        )

    for entry in file_entries:
        methods = sorted(list(entry.get('methods') or []), key=method_sort_key)
        package_name = entry.get('package_name') or ''
        imports = dict(entry.get('imports') or {})
        declared_types = dict(entry.get('declared_types') or {})
        root_info = dict(entry.get('root') or {})

        for declared_name, declared in declared_types.items():
            class_fqcn = f"{package_name}.{declared_name}" if package_name else declared_name
            if class_fqcn not in class_info:
                class_info[class_fqcn] = {
                    'kind': 'interface' if declared.get('kind') == 'interface' else 'class',
                    'extends_raw': list(declared.get('extends_raw', []) or []),
                    'implements_raw': list(declared.get('implements_raw', []) or []),
                    'extends': [],
                    'implements': [],
                    'implementations': [],
                    'owner_type': root_info.get('owner_type', 'business'),
                    'package_name': package_name,
                    'imports': dict(imports),
                    'annotations': set(declared.get('annotations', []) or []),
                }
            else:
                class_info[class_fqcn]['annotations'].update(declared.get('annotations', []) or [])
                for parent in declared.get('extends_raw', []):
                    if parent and parent not in class_info[class_fqcn]['extends_raw']:
                        class_info[class_fqcn]['extends_raw'].append(parent)
                for interface in declared.get('implements_raw', []):
                    if interface and interface not in class_info[class_fqcn]['implements_raw']:
                        class_info[class_fqcn]['implements_raw'].append(interface)

        # 第一遍：收集类型信息
        for method_def in methods:
            class_fqcn = method_def.class_fqcn
            declared = declared_types.get(method_def.class_name, {})
            is_interface = method_def.is_interface or declared.get('kind') == 'interface'

            if class_fqcn not in class_info:
                class_info[class_fqcn] = {
                    'kind': 'interface' if is_interface else 'class',
                    'extends_raw': [],
                    'implements_raw': [],
                    'extends': [],
                    'implements': [],
                    'implementations': [],
                    'owner_type': method_def.owner_type,
                    'package_name': package_name,
                    'imports': dict(imports),
                    'annotations': set(declared.get('annotations', []) or method_def.class_annotations or []),
                }
            else:
                if is_interface:
                    class_info[class_fqcn]['kind'] = 'interface'
                class_info[class_fqcn]['annotations'].update(
                    declared.get('annotations', []) or method_def.class_annotations or []
                )
            for parent in declared.get('extends_raw', []):
                if parent and parent not in class_info[class_fqcn]['extends_raw']:
                    class_info[class_fqcn]['extends_raw'].append(parent)
            for interface in declared.get('implements_raw', []):
                if interface and interface not in class_info[class_fqcn]['implements_raw']:
                    class_info[class_fqcn]['implements_raw'].append(interface)

        for method_def in methods:
            if max_methods is not None and len(methods_by_id) >= max_methods:
                stats['truncated'] = True
                if 'max_methods' not in stats['truncation_reasons']:
                    stats['truncation_reasons'].append('max_methods')
                break
            methods_by_id[method_def.symbol_id] = method_def

            # 额外索引（兼容confidence_weighted_tracer）
            methods_by_qualified[method_def.qualified_key].append(method_def.symbol_id)
            methods_by_simple[method_def.simple_key].append(method_def.symbol_id)
            lookup_keys_by_symbol[method_def.symbol_id] = [
                method_def.qualified_key,
                method_def.simple_key,
                f"class:{method_def.class_fqcn}"
            ]
            all_methods.append(method_def)

            # 关键修复：更新class_info的kind（interface vs class）
            class_meta = class_info.get(method_def.class_fqcn, {})
            if method_def.is_interface:
                class_meta['kind'] = 'interface'
            if method_def.class_annotations:
                class_meta.setdefault('annotations', set()).update(method_def.class_annotations)

        if max_methods is not None and len(methods_by_id) >= max_methods:
            break

    stats['methods_indexed'] = len(methods_by_id)
    if max_methods is not None and len(methods_by_id) >= max_methods:
        stats['truncated'] = True
        if 'max_methods' not in stats['truncation_reasons']:
            stats['truncation_reasons'].append('max_methods')

    known_classes = set(class_info.keys())
    jar_metadata = jar_metadata or {}
    classes_by_simple = defaultdict(list)
    for class_fqcn in known_classes:
        classes_by_simple[class_fqcn.rsplit('.', 1)[-1]].append(class_fqcn)

    def resolve_type_name(raw_name, owner_info):
        name = (raw_name or '').strip()
        if not name:
            return ''
        name = re.sub(r'<[^>]+>', '', name).strip()
        name = name.replace('?', '').replace('extends ', '').replace('super ', '').strip()
        if not name:
            return ''
        if '.' in name:
            if name in known_classes:
                return name
            return name
        imports = owner_info.get('imports', {})
        if name in imports:
            return imports[name]
        package_name = owner_info.get('package_name', '')
        package_candidate = f"{package_name}.{name}" if package_name else name
        if package_candidate in known_classes:
            return package_candidate
        matches = classes_by_simple.get(name, [])
        if len(matches) == 1:
            return matches[0]
        if name == 'Object':
            return 'java.lang.Object'
        return package_candidate

    jar_class_candidates = _collect_external_class_candidates(
        class_info,
        all_methods,
        resolve_type_name,
        known_classes,
    )
    if jar_class_candidates and (jar_metadata.get('jar_paths') or {}):
        hydrate_jar_metadata_for_classes(
            jar_metadata,
            jar_class_candidates,
            source_known_classes=known_classes,
        )
    jar_classes = set((jar_metadata.get('by_class') or {}).keys())
    for class_fqcn in jar_classes:
        if class_fqcn not in known_classes:
            known_classes.add(class_fqcn)
            classes_by_simple[class_fqcn.rsplit('.', 1)[-1]].append(class_fqcn)

    for class_fqcn, info in class_info.items():
        info['extends'] = []
        info['implements'] = []
        for raw_parent in info.get('extends_raw', []):
            resolved = resolve_type_name(raw_parent, info)
            if resolved and resolved not in info['extends']:
                info['extends'].append(resolved)
        for raw_interface in info.get('implements_raw', []):
            resolved = resolve_type_name(raw_interface, info)
            if resolved and resolved not in info['implements']:
                info['implements'].append(resolved)

    for class_fqcn, jar_class_meta in (jar_metadata.get('by_class') or {}).items():
        jar_extends = [
            parent for parent in (jar_class_meta.get('extends') or [])
            if parent and parent not in {'java.lang.Object'}
        ]
        jar_implements = [item for item in (jar_class_meta.get('implements') or []) if item]
        existing = class_info.setdefault(
            class_fqcn,
            {
                'kind': 'interface' if jar_class_meta.get('kind') == 'interface' else 'class',
                'extends_raw': [],
                'implements_raw': [],
                'extends': [],
                'implements': [],
                'implementations': [],
                'owner_type': 'dependency',
                'package_name': class_fqcn.rsplit('.', 1)[0] if '.' in class_fqcn else '',
                'imports': {},
                'annotations': set(),
            },
        )
        for parent in jar_extends:
            if parent not in existing['extends']:
                existing['extends'].append(parent)
        for interface in jar_implements:
            if interface not in existing['implements']:
                existing['implements'].append(interface)

    # 关键修复：填充 interface_implementations（接口->实现类映射）
    # 这样 is_framework_boundary() 可以区分"有实现类"和"无实现类"
    for class_fqcn, info in class_info.items():
        # 如果是类（非接口），找出它实现的接口
        if info.get('kind') != 'interface':
            for interface in info.get('implements', []):
                interface_implementations[interface].append(class_fqcn)
        # 如果是类，检查它是否扩展了父类（父类的实现类也间接实现子接口）
        for parent in info.get('extends', []):
            parent_info = class_info.get(parent, {})
            if parent_info.get('kind') != 'interface':
                for interface in parent_info.get('implements', []):
                    if class_fqcn not in interface_implementations[interface]:
                        interface_implementations[interface].append(class_fqcn)

    # 关键修复：填充type_metadata
    # 为每个类构建完整的继承关系，包含 implementations 列表
    for class_fqcn, info in class_info.items():
        # 获取该类的所有父接口（含间接父接口）
        all_interfaces = set(info.get('implements', []))
        for parent in info.get('extends', []):
            parent_info = class_info.get(parent, {})
            all_interfaces.update(parent_info.get('implements', []))
        # 接口的实现类 = 所有实现了该接口的类（含间接实现）
        impls_for_interface = set(interface_implementations.get(class_fqcn, []))
        if info.get('kind') == 'interface':
            # 收集所有直接/间接实现类
            for other_fqcn, other_info in class_info.items():
                if other_info.get('kind') == 'class':
                    if class_fqcn in other_info.get('implements', []):
                        impls_for_interface.add(other_fqcn)
                    # 检查间接实现（通过父类）
                    for parent in other_info.get('extends', []):
                        parent_info = class_info.get(parent, {})
                        if class_fqcn in parent_info.get('implements', []):
                            impls_for_interface.add(other_fqcn)
        type_metadata[class_fqcn] = {
            'kind': info.get('kind', 'class'),
            'extends': info.get('extends', []),
            'implements': info.get('implements', []),
            'implementations': sorted(impls_for_interface),
            'subclasses': [],
            'annotations': sorted(info.get('annotations', set())),
        }

    for class_fqcn, meta in list(type_metadata.items()):
        for parent in meta.get('extends', []) or []:
            if parent in type_metadata and class_fqcn not in type_metadata[parent]['subclasses']:
                type_metadata[parent]['subclasses'].append(class_fqcn)

    def collect_interface_implementations(interface_fqcn, visited=None):
        if visited is None:
            visited = set()
        if interface_fqcn in visited:
            return set()
        visited.add(interface_fqcn)

        interface_meta = type_metadata.get(interface_fqcn, {}) or {}
        collected = set(interface_meta.get('implementations', []) or [])
        for child in interface_meta.get('subclasses', []) or []:
            child_meta = type_metadata.get(child, {}) or {}
            if child_meta.get('kind') != 'interface':
                continue
            collected.update(child_meta.get('implementations', []) or [])
            collected.update(collect_interface_implementations(child, visited))
        return collected

    for class_fqcn, meta in list(type_metadata.items()):
        if meta.get('kind') == 'interface':
            meta['implementations'] = sorted(collect_interface_implementations(class_fqcn))

    global_method_return_types = defaultdict(dict)
    global_method_return_types_by_signature = defaultdict(lambda: defaultdict(dict))
    for method_def in all_methods:
        if method_def.return_type:
            signature = _build_signature_from_params(method_def.param_declared_types.values())
            global_method_return_types[method_def.class_fqcn][method_def.method_name] = method_def.return_type
            global_method_return_types_by_signature[method_def.class_fqcn][method_def.method_name][signature] = (
                method_def.return_type
            )
    for class_fqcn, jar_class_meta in (jar_metadata.get('by_class') or {}).items():
        method_map = jar_class_meta.get('methods') or {}
        for method_name, signatures in method_map.items():
            existing = global_method_return_types.get(class_fqcn, {}).get(method_name)
            if not existing and signatures:
                if len(signatures) == 1:
                    global_method_return_types[class_fqcn][method_name] = next(iter(signatures.values()))
            for signature, return_type in signatures.items():
                global_method_return_types_by_signature[class_fqcn][method_name][signature] = return_type
    global_method_return_types = {
        class_fqcn: dict(return_types)
        for class_fqcn, return_types in global_method_return_types.items()
    }
    global_method_return_types_by_signature = {
        class_fqcn: {
            method_name: dict(signatures)
            for method_name, signatures in method_map.items()
        }
        for class_fqcn, method_map in global_method_return_types_by_signature.items()
    }
    local_method_return_types_by_class = defaultdict(lambda: defaultdict(dict))
    for candidate in all_methods:
        if not candidate.return_type:
            continue
        signature = _build_signature_from_params(candidate.param_declared_types.values())
        local_method_return_types_by_class[candidate.class_fqcn][candidate.method_name][signature] = (
            candidate.return_type
        )
    local_method_return_types_by_class = {
        class_fqcn: {
            method_name: dict(signatures)
            for method_name, signatures in method_map.items()
        }
        for class_fqcn, method_map in local_method_return_types_by_class.items()
    }
    all_methods = sorted(all_methods, key=method_sort_key)

    for method_def in all_methods:
        declared_signature = build_method_declared_signature(method_def)
        if declared_signature:
            unique_signatures_by_qualified_key[method_def.qualified_key].add(declared_signature)
            unique_signatures_by_simple_key[method_def.simple_key].add(declared_signature)
        method_def.local_method_return_types = local_method_return_types_by_class.get(
            method_def.class_fqcn,
            {},
        )
        method_def.known_method_return_types = global_method_return_types
        method_def.known_method_return_types_by_signature = global_method_return_types_by_signature
        method_def.known_type_metadata = type_metadata

    for method_def in all_methods:
        edges = extract_call_edges_enhanced(method_def, include_low_confidence=False)
        for edge in edges:
            edge_keys = build_reverse_edge_keys(edge)

            for edge_key in edge_keys:
                MAX_EDGES_PER_KEY = 10000
                existing = reverse_edges[edge_key]
                if len(existing) < MAX_EDGES_PER_KEY:
                    existing.append(edge)
                    stats['reverse_edges_indexed'] += 1
                else:
                    stats['edge_cap_hits'] += 1
                    if len(stats['edge_cap_keys']) < 20 and edge_key not in stats['edge_cap_keys']:
                        stats['edge_cap_keys'].append(edge_key)
                    # 使用确定性替换策略，避免同一输入多次运行结果不一致。
                    def edge_rank(item):
                        confidence_rank = {'high': 0, 'medium': 1, 'low': 2}.get(getattr(item, 'confidence', ''), 9)
                        owner_rank = 0 if getattr(item, 'owner_type', '') == 'business' else 1
                        file_rank = getattr(item, 'file', '') or ''
                        line_rank = int(getattr(item, 'line', 0) or 0)
                        return (confidence_rank, owner_rank, file_rank, line_rank)

                    worst_idx = max(range(len(existing)), key=lambda idx: edge_rank(existing[idx]))
                    if edge_rank(edge) < edge_rank(existing[worst_idx]):
                        existing[worst_idx] = edge

    for edge_key, edges in reverse_edges.items():
        edges.sort(key=edge_sort_key)

    graph = SourceGraph(
        methods_by_id=methods_by_id,
        methods_by_qualified=dict(methods_by_qualified),
        methods_by_simple=dict(methods_by_simple),
        reverse_edges=dict(reverse_edges),
        lookup_keys_by_symbol=lookup_keys_by_symbol,
        type_metadata=type_metadata  # 现在有数据了
    )
    _step5_debug(
        'graph_build_complete',
        'finished enhanced source graph build',
        methods_indexed=len(methods_by_id),
        reverse_edge_keys=len(reverse_edges),
        lookup_key_symbols=len(lookup_keys_by_symbol),
        type_metadata_count=len(type_metadata),
        stats=stats,
    )

    return {
        'graph': graph,
        'type_metadata': type_metadata,
        'stats': stats,
        'analysis_cache': file_entries if retain_analysis_cache else [],
    }


def write_skip_summary(output_dir, input_path):
    """写入跳过摘要"""
    summary = {
        'status': 'skipped',
        'skip_reason': 'no_changed_apis',
        'generated_at': datetime.now().isoformat(),
        'input_file': input_path,
        'total_apis': 0,
        'notes': [
            '调用链分析未执行，因 all_changed_apis.csv 为空',
            '这不等于"无风险"，请检查 Step4 的输出'
        ]
    }

    summary_path = os.path.join(output_dir, 'summary.json')
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)


def _normalize_multi_value_option(raw_values):
    """兼容 argparse 的单次多值和重复传参两种写法。"""
    normalized = []
    for item in raw_values or []:
        if isinstance(item, (list, tuple)):
            candidates = item
        else:
            candidates = [item]
        for candidate in candidates:
            text = str(candidate or '').strip()
            if text:
                normalized.append(text)
    return normalized


# ══════════════════════════════════════════════════════════════════
# 主入口
# ══════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description='Step 5集成版：调用链影响分析（增强型）'
    )

    ap.add_argument(
        '--all-changed-apis',
        default='',
        help='变更API文件路径（默认从report-dir读取）'
    )

    ap.add_argument(
        '--jdk-scan-dir',
        default='',
        help='JDK扫描目录（用于过滤JDK removed API）'
    )

    ap.add_argument(
        '--source-dirs',
        nargs='+',
        default=['src/main/java'],
        help='业务源码目录列表'
    )

    ap.add_argument(
        '--dependency-source-mappings',
        action='append',
        nargs='+',
        default=[],
        help='依赖源码映射（可选，系统自动发现）'
    )

    ap.add_argument(
        '--report-dir',
        default='',
        help='报告目录'
    )

    ap.add_argument(
        '--output-dir',
        default='',
        help='输出目录（默认report-dir/s5_call_chain）'
    )

    ap.add_argument(
        '--max-depth',
        type=int,
        default=5,
        help='最大追踪深度（默认5，与文档high confidence=最多5跳一致）'
    )

    ap.add_argument(
        '--allow-degraded',
        action='store_true',
        help='允许在缺少关键输入时继续执行'
    )

    ap.add_argument(
        '--max-methods',
        type=int,
        default=None,
        help='限制索引的方法数，用于回归测试和超大仓库保护'
    )
    ap.add_argument(
        '--debug-analysis',
        action='store_true',
        help='调试模式：输出Step5结构化调试日志（仅调试使用）'
    )
    ap.add_argument(
        '--debug-break',
        action='store_true',
        help='调试模式：遇到关键分析阻断时触发 breakpoint()（仅调试使用）'
    )

    args = ap.parse_args()
    args.dependency_source_mappings = _normalize_multi_value_option(args.dependency_source_mappings)

    try:
        return step5_integrated_main(args)
    except KeyboardInterrupt:
        print("\nStep 5 已被用户中断", file=sys.stderr)
        return 130
    except Exception as exc:
        print("\n❌ Step 5 执行失败：发生未捕获异常", file=sys.stderr)
        print(f"  异常类型：{type(exc).__name__}", file=sys.stderr)
        print(f"  异常信息：{exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1


def check_if_needs_bridge_sources(all_apis_path, report_dir, source_dirs=None, business_graph=None):
    """
    Check if dependency source mappings are needed (enhanced version)

    Extended rules:
      1. Business code直接命中变更 API 时，无需额外依赖源码映射
      2. 未命中直接调用且需要跨依赖边界时，要求依赖源码映射

    Improvements:
      - No longer solely dependent on coarse dependency classification
      - Only requires dependency source mappings if call chain actually needs to cross dependency boundary
      - If business code directly calls changed API, no extra mapping needed (can trace directly)
    """
    import csv

    # Read context
    context_path = os.path.join(report_dir, 's2_context.json')
    context_source_dirs = []
    if os.path.exists(context_path):
        with open(context_path, 'r', encoding='utf-8') as f:
            context = json.load(f)
            context_source_dirs = context.get('source_dirs') or []

    # Collect all changed API coords and their api_names
    changed_apis = []
    try:
        with open(all_apis_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                coord = row.get('coord', '')
                api_name = row.get('api_name', '')
                if coord and api_name:
                    changed_apis.append(dict(row))
    except Exception as e:
        print(f"Error checking APIs: {e}", file=sys.stderr)
        return False

    if not changed_apis:
        return False

    requirements = check_apis_that_need_bridge(
        changed_apis,
        report_dir,
        source_dirs if source_dirs else context_source_dirs,
        business_graph
    )
    return any(info.get('needs_bridge') for info in requirements.values())


def _valid_dependency_source_mapping_coords(dependency_source_mappings):
    coords = set()
    for item in dependency_source_mappings or []:
        if not isinstance(item, str) or '=' not in item:
            continue
        coord, path = item.split('=', 1)
        coord = coord.strip()
        path = path.strip()
        if coord and path and os.path.isdir(path):
            coords.add(coord)
    return coords


def business_graph_precheck_incomplete(graph_stats):
    graph_stats = graph_stats or {}
    return bool(
        graph_stats.get('truncated')
        or critical_parser_fallback_reasons(graph_stats)
        or int(graph_stats.get('edge_cap_hits') or 0) > 0
    )


def check_apis_that_need_bridge(
    all_apis_input,
    report_dir,
    source_dirs=None,
    business_graph=None,
    dependency_source_mappings=None,
    business_graph_stats=None,
    runtime_dependency_catalog=None,
):
    """
    Check which specific APIs need dependency source mappings (api-level decision)

    Returns dict: {coord: {'needs_bridge': bool, 'reason': str}}
    """
    # Read context
    context_path = os.path.join(report_dir, 's2_context.json')
    if os.path.exists(context_path):
        with open(context_path, 'r', encoding='utf-8') as f:
            context = json.load(f)
            # 如果没有传入 source_dirs，从上下文读取
            if source_dirs is None:
                source_dirs = context.get('source_dirs') or []

    available_mapping_coords = _valid_dependency_source_mapping_coords(dependency_source_mappings)
    available_runtime_coords = set((runtime_dependency_catalog or {}).get('by_coord', {}).keys())
    precheck_incomplete = business_graph_precheck_incomplete(business_graph_stats)

    result = {}
    if isinstance(all_apis_input, str):
        import csv
        try:
            with open(all_apis_input, 'r', encoding='utf-8') as f:
                all_apis = list(csv.DictReader(f))
        except Exception as e:
            print(f"Error checking APIs: {e}", file=sys.stderr)
            return result
    else:
        all_apis = list(all_apis_input or [])

    for row in all_apis:
        coord = row.get('coord', '')
        api_name = row.get('api_name', '')
        key = build_api_identity_key(row)
        has_packaged_bytecode_fallback = bool(available_runtime_coords)

        if not coord or not api_name:
            continue

        if api_name.startswith('org.apache.commons.lang'):
            _report_step5_debug_event(
                'A',
                's5_call_chain_engine_integrated.py:bridge-check',
                'bridge-check evaluated commons-lang api',
                data={
                    'coord': coord,
                    'api_name': api_name,
                    'identity_key': key,
                    'available_runtime_coord_count': len(available_runtime_coords),
                    'sample_runtime_coords': sorted(list(available_runtime_coords))[:8],
                    'has_dependency_source_mapping': coord in available_mapping_coords,
                    'has_packaged_bytecode_fallback': has_packaged_bytecode_fallback,
                },
            )

        # 【关键修复】只有业务图找到直接的 caller 才算 direct usage
        # 原因：import 只能证明类型可见，不能证明方法被调用
        # 例如：import com.example.Foo; 只能说明 Foo 类可见
        # 但如果变更的是 Foo.bar() 方法，还需要业务代码真的调用了 bar()
        # 只有当业务源码图能找到 Foo.bar() 的调用边时，才说明变更方法真的被使用
        if business_graph and _has_direct_business_usage(row, business_graph):
            result[key] = {
                'needs_bridge': False,
                'reason': 'direct_business_usage',
                'coord': coord,
                'has_dependency_source_mapping': True,
                'has_packaged_bytecode_fallback': has_packaged_bytecode_fallback,
            }
            continue

        if precheck_incomplete:
            result[key] = {
                'needs_bridge': False,
                'reason': 'business_graph_precheck_incomplete',
                'coord': coord,
                'has_dependency_source_mapping': coord in available_mapping_coords,
                'has_packaged_bytecode_fallback': has_packaged_bytecode_fallback,
                'precheck_incomplete': True,
            }
            continue

        # 【移除】exact_class_imported 逻辑
        # import 了变更类不等于方法被调用，以下场景都可能导致误判：
        #   1. 业务只使用类的静态常量，不调用变更的方法
        #   2. 业务通过反射/接口间接调用，静态分析找不到
        #   3. 业务通过动态代理调用，静态分析找不到
        # 只要业务图没找到直接的调用边，就应该要求跨依赖补充映射

        # 默认：业务图没找到直接调用，需要依赖源码映射才能确认是否影响系统
        result[key] = {
            'needs_bridge': True,
            'reason': 'no_direct_call_found',
            'coord': coord,
            'has_dependency_source_mapping': coord in available_mapping_coords,
            'has_packaged_bytecode_fallback': has_packaged_bytecode_fallback,
        }

    return result


if __name__ == '__main__':
    sys.exit(main())
