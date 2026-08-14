"""Portable access to native process metrics missing from Python on Windows."""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import sys


@dataclass(frozen=True)
class WindowsProcessUsage:
    user_seconds: float
    system_seconds: float
    peak_rss_bytes: int


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("page_fault_count", wintypes.DWORD),
        ("peak_working_set_size", ctypes.c_size_t),
        ("working_set_size", ctypes.c_size_t),
        ("quota_peak_paged_pool_usage", ctypes.c_size_t),
        ("quota_paged_pool_usage", ctypes.c_size_t),
        ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
        ("quota_non_paged_pool_usage", ctypes.c_size_t),
        ("pagefile_usage", ctypes.c_size_t),
        ("peak_pagefile_usage", ctypes.c_size_t),
    ]


def _filetime_seconds(value: wintypes.FILETIME) -> float:
    ticks = (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)
    return ticks / 10_000_000.0


def windows_current_process_usage(
    platform_name: str | None = None,
) -> WindowsProcessUsage | None:
    """Read CPU time and peak working set for this native Windows process.

    ``resource.getrusage`` is unavailable on Windows. These values come from
    documented Win32 process APIs and intentionally cover the current analyzer
    process only; completed-child accounting remains zero and is labelled as
    such by callers.
    """
    platform_value = str(platform_name or sys.platform).lower()
    if platform_value not in {"nt", "win32", "windows"}:
        return None

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    get_current_process = kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = wintypes.HANDLE
    get_process_times = kernel32.GetProcessTimes
    get_process_times.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    get_process_times.restype = wintypes.BOOL
    get_process_memory_info = psapi.GetProcessMemoryInfo
    get_process_memory_info.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ProcessMemoryCounters),
        wintypes.DWORD,
    ]
    get_process_memory_info.restype = wintypes.BOOL

    handle = get_current_process()
    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if not get_process_times(
        handle,
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    memory = _ProcessMemoryCounters()
    memory.cb = ctypes.sizeof(memory)
    if not get_process_memory_info(
        handle, ctypes.byref(memory), ctypes.sizeof(memory),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return WindowsProcessUsage(
        user_seconds=_filetime_seconds(user),
        system_seconds=_filetime_seconds(kernel),
        peak_rss_bytes=int(memory.peak_working_set_size),
    )


__all__ = ["WindowsProcessUsage", "windows_current_process_usage"]
