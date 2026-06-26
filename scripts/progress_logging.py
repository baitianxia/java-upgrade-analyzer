#!/usr/bin/env python3
"""
正式流程进度日志工具。

只负责向 stderr 输出可读的阶段进度，不参与 main_state 或交互协议。
"""

import sys
import time


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


def emit_progress(step_id, phase, message, current=None, total=None, elapsed=None, item=None):
    prefix = f"[progress][{step_id}]"
    if phase:
        prefix += f"[{phase}]"
    parts = [prefix]
    if current is not None and total is not None:
        parts.append(f"[{current}/{total}]")
    elif current is not None:
        parts.append(f"[{current}]")
    if elapsed is not None:
        parts.append(f"[elapsed={format_elapsed(elapsed)}]")
    if item:
        parts.append(f"[item={item}]")
    parts.append(str(message))
    print(" ".join(parts), file=sys.stderr, flush=True)


class PhaseTimer:
    def __init__(self, step_id, phase):
        self.step_id = step_id
        self.phase = phase
        self.started_at = time.perf_counter()

    def elapsed(self):
        return time.perf_counter() - self.started_at
