#!/usr/bin/env python3
"""正式流程进度日志工具。

向 stderr 输出面向使用者的进度，同时把完整结构化事件写入运行时目录，
供长任务排障和恢复审计使用；写日志失败不得中断正式分析。
"""

import json
import os
import sys
import threading
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
    "artifact-facts": "解析运行时制品事实",
    "reconcile": "重建目标运行时",
    "decision": "冻结变化裁决",
    "graph": "构建调用图",
    "bridge-check": "跨依赖检查",
    "trace": "追踪系统触达",
    "edge-ledger": "构建运行时边台账",
    "bytecode-scan": "扫描依赖字节码",
    "bytecode-expand": "扩展依赖调用者",
    "validation": "独立验证 generation",
    "validation-preflight": "验证工具链复核",
    "validation-inventory": "校验制品清单",
    "validation-direct-edges": "校验直接调用边",
    "validation-structural": "校验结构与指令",
    "validation-runtime": "校验目标 JVM 运行时结果",
    "validation-semantics": "校验跨版本语义",
    "validation-closed-world": "校验闭世界结果",
    "validation-write": "写入验证结果",
    "diagnostic": "实时诊断",
    "perf": "性能状态",
    "report": "生成结果",
    "heartbeat": "运行中",
    "done": "完成",
}

PROGRESS_LOG_MAX_BYTES = 8 * 1024 * 1024
PROGRESS_EVENT_MAX_BYTES = 256 * 1024
_PROGRESS_WRITE_LOCK = threading.Lock()


def _progress_event_line(payload):
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) <= PROGRESS_EVENT_MAX_BYTES:
        return encoded
    reduced = dict(payload)
    reduced["event_truncated"] = True
    reduced["original_event_bytes"] = len(encoded)
    for field in ("message", "item"):
        value = str(reduced.get(field) or "")
        if len(value) > 8192:
            reduced[field] = value[:8189] + "..."
    encoded = (
        json.dumps(reduced, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) <= PROGRESS_EVENT_MAX_BYTES:
        return encoded
    minimal = {
        key: reduced.get(key)
        for key in (
            "schema", "timestamp", "step_id", "phase", "current", "total",
        )
    }
    minimal.update({
        "message": "progress event exceeded bounded observability record",
        "event_truncated": True,
        "original_event_bytes": len(encoded),
    })
    return (
        json.dumps(minimal, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")


def _rotate_progress_log(progress_path):
    """Retain one bounded previous segment without reading the whole log."""
    archive_path = progress_path.with_name("progress.previous.jsonl")
    size = progress_path.stat().st_size
    if size <= PROGRESS_LOG_MAX_BYTES:
        os.replace(progress_path, archive_path)
        return

    temporary = archive_path.with_name(
        f"{archive_path.name}.{os.getpid()}.tmp"
    )
    try:
        with progress_path.open("rb") as source:
            start = max(0, size - PROGRESS_LOG_MAX_BYTES)
            source.seek(start)
            tail = source.read(PROGRESS_LOG_MAX_BYTES)
        if start:
            newline = tail.find(b"\n")
            tail = tail[newline + 1:] if newline >= 0 else b""
        with temporary.open("wb") as destination:
            destination.write(tail)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, archive_path)
        # The oversized source is an old unbounded observability artifact.
        # Truncating it after its bounded tail is retained must never affect an
        # analysis result.
        with progress_path.open("wb"):
            pass
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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
        event = _progress_event_line(payload)
        with _PROGRESS_WRITE_LOCK:
            current_size = (
                progress_path.stat().st_size if progress_path.exists() else 0
            )
            if current_size + len(event) > PROGRESS_LOG_MAX_BYTES:
                _rotate_progress_log(progress_path)
            with progress_path.open("ab") as handle:
                handle.write(event)
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
