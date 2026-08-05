#!/usr/bin/env python3
"""正式流程进度日志工具。

向 stderr 输出面向使用者的进度，同时把完整结构化事件写入运行时目录，
供长任务排障和恢复审计使用；写日志失败不得中断正式分析。
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


STEP_LABELS = {
    "step1": "分析对象与依赖范围",
    "step2": "升级上下文",
    "step3": "兼容性线索",
    "step4": "依赖 API 变化",
    "step5": "系统触达证据",
    "step6": "分析报告",
}

PHASE_LABELS = {
    "plan": "准备",
    "preflight": "前置检查",
    "input": "读取输入",
    "discovery": "发现源码",
    "scan": "扫描",
    "dependency": "处理依赖",
    "gitdiff": "源码辅助对比",
    "japicmp": "制品 API 对比",
    "behavior-bytecode": "行为字节码核验",
    "graph": "构建调用图",
    "bridge-check": "跨依赖检查",
    "trace": "追踪系统触达",
    "edge-ledger": "构建运行时边台账",
    "bytecode-scan": "扫描依赖字节码",
    "bytecode-expand": "扩展依赖调用者",
    "diagnostic": "实时诊断",
    "perf": "性能状态",
    "report": "生成结果",
    "heartbeat": "运行中",
    "done": "完成",
}


def format_elapsed(seconds):
    if seconds is None:
        return ""
    seconds = max(0.0, float(seconds))
    if seconds < 1:
        return f"{seconds:.1f}s"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remain = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m{remain:04.1f}s"
    hours, minutes = divmod(int(minutes), 60)
    return f"{hours}h{minutes:02d}m{remain:04.1f}s"


def suggest_log_interval(total, target_updates=10, minimum=1):
    try:
        total = int(total or 0)
    except (TypeError, ValueError):
        return minimum
    if total <= 0:
        return minimum
    return max(minimum, total // max(1, int(target_updates)))


def should_log_progress(index, total, interval):
    try:
        index = int(index)
        total = int(total)
        interval = max(1, int(interval))
    except (TypeError, ValueError):
        return False
    return index <= 1 or index >= total or index % interval == 0


def _write_progress_event(payload, report_dir=None):
    report_dir = str(report_dir or os.environ.get("UPGRADE_REPORT_DIR", "")).strip()
    if not report_dir:
        return
    try:
        progress_path = (
            Path(report_dir).resolve()
            / ".runtime"
            / "observability"
            / "progress.jsonl"
        )
        progress_path.parent.mkdir(parents=True, exist_ok=True)
        with progress_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except (OSError, UnicodeError, TypeError, ValueError):
        # 可观测性不能成为正式分析的故障源。
        return


def _display_item(item, limit=120):
    value = str(item or "").strip()
    if len(value) <= limit:
        return value
    return "…" + value[-(limit - 1):]


def _estimate_remaining(current, total, elapsed):
    try:
        current = float(current)
        total = float(total)
        elapsed = float(elapsed)
    except (TypeError, ValueError):
        return None
    if current <= 0 or total <= current or elapsed <= 0:
        return None
    return max(0.0, elapsed * (total - current) / current)


def _progress_percentage(current, total):
    try:
        current = float(current)
        total = float(total)
    except (TypeError, ValueError):
        return None
    if total <= 0 or current < 0 or current > total:
        return None
    return 100.0 * current / total


def emit_progress(
    step_id,
    phase,
    message,
    current=None,
    total=None,
    elapsed=None,
    item=None,
    report_dir=None,
    estimate_remaining=True,
):
    step_id = str(step_id or "").strip()
    phase = str(phase or "").strip()
    message = str(message or "")
    elapsed_value = None if elapsed is None else max(0.0, float(elapsed))
    percentage = _progress_percentage(current, total)
    estimated_remaining = (
        _estimate_remaining(current, total, elapsed_value)
        if estimate_remaining
        else None
    )
    payload = {
        "schema": "java-upgrade-analyzer.progress.v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "step_id": step_id,
        "task": STEP_LABELS.get(step_id, step_id or "当前分析"),
        "phase": phase,
        "phase_label": PHASE_LABELS.get(phase, phase or "处理中"),
        "message": message,
        "current": current,
        "total": total,
        "percentage": round(percentage, 3) if percentage is not None else None,
        "elapsed_sec": round(elapsed_value, 3) if elapsed_value is not None else None,
        "estimated_remaining_sec": (
            round(estimated_remaining, 3) if estimated_remaining is not None else None
        ),
        "item": str(item or ""),
    }
    _write_progress_event(payload, report_dir=report_dir)

    prefix = f"[进度][{payload['task']}]"
    if phase:
        prefix += f"[{payload['phase_label']}]"
    parts = [prefix]
    if current is not None and total is not None:
        parts.append(f"[{current}/{total}]")
        if percentage is not None:
            parts.append(f"[{percentage:.1f}%]")
    elif current is not None:
        parts.append(f"[{current}]")
    if elapsed_value is not None:
        parts.append(f"[已用 {format_elapsed(elapsed_value)}]")
    if estimated_remaining is not None:
        parts.append(f"[预计剩余约 {format_elapsed(estimated_remaining)}]")
    if item:
        parts.append(f"[对象：{_display_item(item)}]")
    parts.append(message)
    print(" ".join(parts), file=sys.stderr, flush=True)


class PhaseTimer:
    def __init__(self, step_id, phase):
        self.step_id = step_id
        self.phase = phase
        self.started_at = time.perf_counter()

    def elapsed(self):
        return time.perf_counter() - self.started_at
