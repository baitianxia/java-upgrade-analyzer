#!/usr/bin/env python3
"""Low-overhead Step5 process-memory and graph-size observations."""

from __future__ import annotations

import ctypes
import os
import platform
import resource
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping, Optional


_MIB = 1024.0 * 1024.0


class Step5ResourceBudgetExceeded(RuntimeError):
    """Raised after an observed hard limit is crossed, before more work starts."""


def _descendant_totals(processes, root_pid):
    children = {}
    for pid, item in processes.items():
        children.setdefault(int(item.get("ppid") or 0), []).append(pid)
    pending = list(children.get(root_pid, ()))
    descendants = set()
    while pending:
        pid = pending.pop()
        if pid in descendants:
            continue
        descendants.add(pid)
        pending.extend(children.get(pid, ()))
    rss_kb = sum(float(processes[pid].get("rss_kb") or 0.0) for pid in descendants)
    cpu_sec = sum(float(processes[pid].get("cpu_sec") or 0.0) for pid in descendants)
    root_rss_kb = float((processes.get(root_pid) or {}).get("rss_kb") or 0.0)
    return root_rss_kb, rss_kb, cpu_sec


def _directory_size_bytes(paths):
    total = 0
    for root in paths or ():
        path = Path(root)
        if not path.exists():
            continue
        for item in path.rglob("*"):
            try:
                if item.is_file():
                    total += item.stat().st_size
            except OSError:
                continue
    return total


def _linux_process_table(proc_root: Path | str = "/proc"):
    table = {}
    clock_ticks = float(os.sysconf("SC_CLK_TCK"))
    for stat_path in Path(proc_root).glob("[0-9]*/stat"):
        try:
            content = stat_path.read_text(encoding="ascii", errors="replace")
            close = content.rfind(")")
            pid = int(content[:content.find(" ")])
            fields = content[close + 2:].split()
            ppid = int(fields[1])
            cpu_sec = (float(fields[11]) + float(fields[12])) / clock_ticks
            rss_kb = 0.0
            for line in stat_path.with_name("status").read_text(
                encoding="ascii", errors="replace"
            ).splitlines():
                if line.startswith("VmRSS:"):
                    rss_kb = float(line.split()[1])
                    break
            table[pid] = {"ppid": ppid, "rss_kb": rss_kb, "cpu_sec": cpu_sec}
        except (IndexError, OSError, TypeError, ValueError):
            continue
    return table


def _parse_ps_cpu_seconds(value):
    text = str(value or "").strip()
    days = 0
    if "-" in text:
        day_text, text = text.split("-", 1)
        days = int(day_text)
    parts = [int(item) for item in text.split(":")]
    if len(parts) == 3:
        hours, minutes, seconds = parts
    elif len(parts) == 2:
        hours, (minutes, seconds) = 0, parts
    else:
        hours, minutes, seconds = 0, 0, parts[0]
    return float(days * 86400 + hours * 3600 + minutes * 60 + seconds)


def _darwin_process_table_with_libproc(root_pid=None):
    class RusageInfoV2(ctypes.Structure):
        _fields_ = [
            ("uuid", ctypes.c_ubyte * 16),
            *[(name, ctypes.c_uint64) for name in (
                "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups",
                "pageins", "wired_size", "resident_size", "phys_footprint",
                "proc_start_abstime", "proc_exit_abstime", "child_user_time",
                "child_system_time", "child_pkg_idle_wkups", "child_interrupt_wkups",
                "child_pageins", "child_elapsed_abstime", "diskio_bytesread",
                "diskio_byteswritten",
            )],
        ]

    libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    list_children = libproc.proc_listchildpids
    list_children.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    list_children.restype = ctypes.c_int
    pid_rusage = libproc.proc_pid_rusage
    pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    pid_rusage.restype = ctypes.c_int
    root = int(root_pid or os.getpid())
    table = {}
    pending = [(root, 0)]
    visited = set()
    while pending:
        pid, ppid = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        usage = RusageInfoV2()
        if pid_rusage(pid, 2, ctypes.byref(usage)) == 0:
            table[pid] = {
                "ppid": ppid,
                "rss_kb": float(usage.resident_size) / 1024.0,
                "cpu_sec": float(usage.user_time + usage.system_time) / 1_000_000_000.0,
            }
        child_buffer = (ctypes.c_int * 4096)()
        child_count = max(
            0, int(list_children(pid, child_buffer, ctypes.sizeof(child_buffer)))
        )
        pending.extend(
            (int(child_buffer[index]), pid)
            for index in range(min(child_count, len(child_buffer)))
            if int(child_buffer[index]) > 0
        )
    return table


def _darwin_process_table_with_ps():
    proc = subprocess.Popen(
        ["ps", "-axo", "pid=,ppid=,rss=,time="],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    stdout, _ = proc.communicate(timeout=5)
    table = {}
    for line in stdout.splitlines():
        try:
            pid_text, ppid_text, rss_text, cpu_text = line.split()
            pid = int(pid_text)
            if pid == proc.pid:
                continue
            table[pid] = {
                "ppid": int(ppid_text),
                "rss_kb": float(rss_text),
                "cpu_sec": _parse_ps_cpu_seconds(cpu_text),
            }
        except (TypeError, ValueError):
            continue
    return table


def _darwin_process_table():
    try:
        return _darwin_process_table_with_libproc()
    except (AttributeError, OSError, TypeError, ValueError):
        return _darwin_process_table_with_ps()


class ProcessTreeObserver:
    """Sample this process and every descendant with bounded, scalar state."""

    def __init__(
        self, *, platform_name=None, interval_sec=0.05, process_reader=None,
        temporary_paths=(), temporary_size_reader=None,
    ):
        self.platform_name = (platform_name or platform.system()).strip().lower()
        self.interval_sec = max(float(interval_sec), 0.01)
        self.process_reader = process_reader
        self.temporary_paths = tuple(str(Path(item)) for item in temporary_paths or ())
        self.temporary_size_reader = temporary_size_reader or _directory_size_bytes
        self.root_pid = os.getpid()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._started_at = 0.0
        self._self_cpu_start = 0.0
        self._child_cpu_start = 0.0
        self._tree_current_rss_mb = 0.0
        self._tree_peak_rss_mb = 0.0
        self._child_current_rss_mb = 0.0
        self._child_peak_rss_mb = 0.0
        self._active_child_cpu_sec = 0.0
        self._sample_count = 0
        self._sample_failures = 0
        self._command_serial = 0
        self._active_commands = {}
        self._external_process_count = 0
        self._external_process_wall_sec = 0.0
        self._tool_counts = {}
        self._peak_active_commands = 0
        self._temporary_current_bytes = 0
        self._temporary_peak_bytes = 0
        self._last_temporary_sample_at = 0.0

    @property
    def supported(self):
        return self.platform_name in {"linux", "darwin"} or self.process_reader is not None

    def start(self):
        if self._thread is not None:
            return self
        self._started_at = time.perf_counter()
        self_usage = resource.getrusage(resource.RUSAGE_SELF)
        child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        self._self_cpu_start = self_usage.ru_utime + self_usage.ru_stime
        self._child_cpu_start = child_usage.ru_utime + child_usage.ru_stime
        self._sample_once()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval_sec * 4))
        self._sample_once()
        return self.snapshot()

    def command_started(self, command):
        tool = Path(str((command or ["unknown"])[0] or "unknown")).name or "unknown"
        with self._lock:
            self._command_serial += 1
            token = self._command_serial
            self._active_commands[token] = time.perf_counter()
            self._peak_active_commands = max(
                self._peak_active_commands, len(self._active_commands)
            )
            self._external_process_count += 1
            self._tool_counts[tool] = self._tool_counts.get(tool, 0) + 1
            return token

    def command_finished(self, token):
        with self._lock:
            started = self._active_commands.pop(token, None)
            if started is not None:
                self._external_process_wall_sec += time.perf_counter() - started

    def _read_processes(self):
        if self.process_reader is not None:
            return self.process_reader()
        if self.platform_name == "linux":
            return _linux_process_table()
        if self.platform_name == "darwin":
            return _darwin_process_table()
        return {}

    def _sample_once(self, *, force_temporary=False):
        if not self.supported:
            return
        try:
            root_kb, child_kb, child_cpu = _descendant_totals(
                self._read_processes(), self.root_pid
            )
            tree_mb = (root_kb + child_kb) / 1024.0
            child_mb = child_kb / 1024.0
            with self._lock:
                self._tree_current_rss_mb = tree_mb
                self._child_current_rss_mb = child_mb
                self._tree_peak_rss_mb = max(self._tree_peak_rss_mb, tree_mb)
                self._child_peak_rss_mb = max(self._child_peak_rss_mb, child_mb)
                self._active_child_cpu_sec = child_cpu
                self._sample_count += 1
            now = time.monotonic()
            if self.temporary_paths and (
                force_temporary or now - self._last_temporary_sample_at >= 0.5
            ):
                temporary_bytes = int(
                    self.temporary_size_reader(self.temporary_paths) or 0
                )
                with self._lock:
                    self._temporary_current_bytes = temporary_bytes
                    self._temporary_peak_bytes = max(
                        self._temporary_peak_bytes, temporary_bytes
                    )
                    self._last_temporary_sample_at = now
        except (OSError, subprocess.SubprocessError, TypeError, ValueError):
            with self._lock:
                self._sample_failures += 1

    def _run(self):
        while not self._stop.wait(self.interval_sec):
            self._sample_once()

    def snapshot(self):
        self._sample_once(force_temporary=True)
        self_usage = resource.getrusage(resource.RUSAGE_SELF)
        child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        self_cpu = max(
            0.0, self_usage.ru_utime + self_usage.ru_stime - self._self_cpu_start
        )
        completed_child_cpu = max(
            0.0, child_usage.ru_utime + child_usage.ru_stime - self._child_cpu_start
        )
        with self._lock:
            active_wall = sum(
                max(0.0, time.perf_counter() - started)
                for started in self._active_commands.values()
            )
            return {
                "process_tree_observer_supported": self.supported,
                "process_tree_current_rss_mb": round(self._tree_current_rss_mb, 3),
                "process_tree_peak_rss_mb": round(self._tree_peak_rss_mb, 3),
                "child_process_current_rss_mb": round(self._child_current_rss_mb, 3),
                "child_process_peak_rss_mb": round(self._child_peak_rss_mb, 3),
                "self_cpu_sec": round(self_cpu, 3),
                "child_cpu_sec": round(completed_child_cpu + self._active_child_cpu_sec, 3),
                "observer_wall_sec": round(max(0.0, time.perf_counter() - self._started_at), 3),
                "external_process_count": self._external_process_count,
                "external_process_peak_concurrency": self._peak_active_commands,
                "external_process_wall_sec": round(
                    self._external_process_wall_sec + active_wall, 3
                ),
                "external_process_counts_by_tool": dict(sorted(self._tool_counts.items())),
                "process_tree_sample_count": self._sample_count,
                "process_tree_sample_failures": self._sample_failures,
                "temporary_file_current_bytes": self._temporary_current_bytes,
                "temporary_file_peak_bytes": self._temporary_peak_bytes,
                "temporary_file_current_mb": round(
                    self._temporary_current_bytes / _MIB, 3
                ),
                "temporary_file_peak_mb": round(
                    self._temporary_peak_bytes / _MIB, 3
                ),
            }


_ACTIVE_PROCESS_TREE_OBSERVER = None


def set_active_process_tree_observer(observer):
    global _ACTIVE_PROCESS_TREE_OBSERVER
    previous = _ACTIVE_PROCESS_TREE_OBSERVER
    _ACTIVE_PROCESS_TREE_OBSERVER = observer
    return previous


def active_process_tree_metrics():
    observer = _ACTIVE_PROCESS_TREE_OBSERVER
    return observer.snapshot() if observer is not None else {}


def evaluate_process_tree_budget(metrics, *, soft_limit_mb=0.0, hard_limit_mb=0.0):
    peak = float((metrics or {}).get("process_tree_peak_rss_mb") or 0.0)
    soft = max(float(soft_limit_mb or 0.0), 0.0)
    hard = max(float(hard_limit_mb or 0.0), 0.0)
    if hard and peak > hard:
        return {"status": "blocked", "reason_code": "STEP5_PROCESS_TREE_RSS_HARD_LIMIT_EXCEEDED", "peak_rss_mb": peak, "limit_mb": hard}
    if soft and peak > soft:
        return {"status": "warning", "reason_code": "STEP5_PROCESS_TREE_RSS_SOFT_LIMIT_EXCEEDED", "peak_rss_mb": peak, "limit_mb": soft}
    return {"status": "passed", "reason_code": "", "peak_rss_mb": peak, "limit_mb": hard or soft}


def _linux_current_rss_mb(path: Path | str = "/proc/self/status") -> float:
    try:
        for line in Path(path).read_text(encoding="ascii", errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                fields = line.split()
                if len(fields) >= 2:
                    return round(float(fields[1]) / 1024.0, 3)
    except (OSError, ValueError):
        return 0.0
    return 0.0


def _darwin_current_rss_mb() -> float:
    """Read resident memory through Mach without spawning a subprocess."""

    class MachTaskBasicInfo(ctypes.Structure):
        _fields_ = [
            ("virtual_size", ctypes.c_uint64),
            ("resident_size", ctypes.c_uint64),
            ("resident_size_max", ctypes.c_uint64),
            ("user_time_seconds", ctypes.c_int32),
            ("user_time_microseconds", ctypes.c_int32),
            ("system_time_seconds", ctypes.c_int32),
            ("system_time_microseconds", ctypes.c_int32),
            ("policy", ctypes.c_int32),
            ("suspend_count", ctypes.c_int32),
        ]

    try:
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        task_self = getattr(libc, "mach_task_self", None)
        if task_self is None:
            task_self = getattr(libc, "mach_task_self_", None)
        if task_self is None:
            return 0.0
        task_self.restype = ctypes.c_uint32
        task_info = libc.task_info
        task_info.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_int32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        info = MachTaskBasicInfo()
        count = ctypes.c_uint32(ctypes.sizeof(info) // ctypes.sizeof(ctypes.c_int32))
        mach_task_basic_info = 20
        result = task_info(
            task_self(),
            mach_task_basic_info,
            ctypes.cast(ctypes.byref(info), ctypes.POINTER(ctypes.c_int32)),
            ctypes.byref(count),
        )
        if result != 0:
            return 0.0
        return round(float(info.resident_size) / _MIB, 3)
    except (AttributeError, OSError, TypeError, ValueError):
        return 0.0


def current_rss_mb(
    *,
    platform_name: Optional[str] = None,
    linux_status_path: Path | str = "/proc/self/status",
    darwin_reader: Optional[Callable[[], float]] = None,
) -> float:
    system = (platform_name or platform.system()).strip().lower()
    try:
        if system == "linux":
            return _linux_current_rss_mb(linux_status_path)
        if system == "darwin":
            return round(float((darwin_reader or _darwin_current_rss_mb)()), 3)
    except (OSError, TypeError, ValueError):
        return 0.0
    return 0.0


def peak_rss_mb(*, platform_name: Optional[str] = None) -> float:
    try:
        peak = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        divisor = _MIB if (platform_name or platform.system()).lower() == "darwin" else 1024.0
        return round(peak / divisor, 3)
    except (OSError, TypeError, ValueError):
        return 0.0


def _safe_read(reader: Callable[[], float]) -> float:
    try:
        return round(float(reader()), 3)
    except (OSError, TypeError, ValueError):
        return 0.0


def record_step5_memory(
    graph_stats: MutableMapping[str, Any],
    phase: str,
    *,
    graph: Any = None,
    extra: Optional[Mapping[str, Any]] = None,
    current_reader: Callable[[], float] = current_rss_mb,
    peak_reader: Callable[[], float] = peak_rss_mb,
) -> dict[str, Any]:
    """Record scalar metrics only; never retain the graph or its collections."""
    methods = getattr(graph, "methods_by_id", {}) if graph is not None else {}
    reverse_edges = getattr(graph, "reverse_edges", {}) if graph is not None else {}
    reverse_edge_count = getattr(graph, "reverse_edge_count", None)
    if reverse_edge_count is None:
        reverse_edge_count = sum(len(edges) for edges in reverse_edges.values())
    process_metrics = active_process_tree_metrics()
    tool_counts = dict(process_metrics.get("external_process_counts_by_tool") or {})
    sample: dict[str, Any] = {
        "current_rss_mb": _safe_read(current_reader),
        "peak_rss_mb": _safe_read(peak_reader),
        "method_count": len(methods),
        "reverse_edge_key_count": len(reverse_edges),
        "reverse_edge_count": int(reverse_edge_count),
        **process_metrics,
        **{
            "external_process_count_" + "".join(
                character if character.isalnum() else "_" for character in tool
            ).strip("_").lower(): int(count)
            for tool, count in tool_counts.items()
        },
    }
    if extra:
        sample.update(extra)

    memory = graph_stats.setdefault("step5_perf", {}).setdefault("memory", {})
    for key, value in sample.items():
        memory[f"{phase}_{key}"] = value
    return sample


__all__ = [
    "ProcessTreeObserver",
    "Step5ResourceBudgetExceeded",
    "active_process_tree_metrics",
    "current_rss_mb",
    "evaluate_process_tree_budget",
    "peak_rss_mb",
    "record_step5_memory",
    "set_active_process_tree_observer",
]
