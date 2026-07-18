#!/usr/bin/env python3
"""Low-overhead Step5 process-memory and graph-size observations."""

from __future__ import annotations

import ctypes
import platform
import resource
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping, Optional


_MIB = 1024.0 * 1024.0


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
    sample: dict[str, Any] = {
        "current_rss_mb": _safe_read(current_reader),
        "peak_rss_mb": _safe_read(peak_reader),
        "method_count": len(methods),
        "reverse_edge_key_count": len(reverse_edges),
        "reverse_edge_count": sum(len(edges) for edges in reverse_edges.values()),
    }
    if extra:
        sample.update(extra)

    memory = graph_stats.setdefault("step5_perf", {}).setdefault("memory", {})
    for key, value in sample.items():
        memory[f"{phase}_{key}"] = value
    return sample


__all__ = ["current_rss_mb", "peak_rss_mb", "record_step5_memory"]
