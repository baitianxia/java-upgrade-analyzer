"""Portable access to native process metrics missing from Python on Windows."""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import os
import re
import subprocess
import sys

from compat import run_managed_subprocess


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


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
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


def system_available_memory_bytes(
    platform_name: str | None = None,
) -> int | None:
    """Return immediately available physical memory when the host exposes it."""

    platform_value = str(platform_name or sys.platform).lower()
    if platform_value in {"nt", "win32", "windows"}:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        global_memory_status = kernel32.GlobalMemoryStatusEx
        global_memory_status.argtypes = [ctypes.POINTER(_MemoryStatusEx)]
        global_memory_status.restype = wintypes.BOOL
        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(status)
        if not global_memory_status(ctypes.byref(status)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(status.ullAvailPhys)

    try:
        pages = int(os.sysconf("SC_AVPHYS_PAGES"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, OSError, TypeError, ValueError):
        if platform_value not in {"darwin", "mac", "macos"}:
            return None
        return _darwin_available_memory_bytes()
    if pages < 0 or page_size <= 0:
        return None
    return pages * page_size


def _darwin_available_memory_bytes() -> int | None:
    """Return reclaimable macOS pages from the native ``vm_stat`` probe.

    Darwin does not expose ``SC_AVPHYS_PAGES``. Treat free, inactive,
    speculative and purgeable pages as immediately reclaimable, matching the
    memory classes macOS can release before swapping. The probe is advisory:
    any unsupported output or command failure simply returns ``None``.
    """

    try:
        completed = run_managed_subprocess(
            ["/usr/bin/vm_stat"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    page_match = re.search(
        r"page size of\s+([0-9]+)\s+bytes", completed.stdout
    )
    if page_match is None:
        return None
    page_size = int(page_match.group(1))
    if page_size <= 0:
        return None
    counts = {}
    for name, value in re.findall(
        r"^Pages (free|inactive|speculative|purgeable):\s+([0-9]+)\.",
        completed.stdout,
        flags=re.MULTILINE,
    ):
        counts[name] = int(value)
    if "free" not in counts:
        return None
    available_pages = sum(counts.get(name, 0) for name in (
        "free", "inactive", "speculative", "purgeable",
    ))
    if available_pages < 0:
        return None
    return available_pages * page_size


__all__ = [
    "WindowsProcessUsage",
    "system_available_memory_bytes",
    "windows_current_process_usage",
]
