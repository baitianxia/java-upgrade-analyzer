"""Standard-library-only process-tree boundary for black-box test harnesses.

This module deliberately does not import analyzer production code.  Black-box
tests often launch the public workflow, Maven, Gradle, or JVM tools; a timeout
must therefore terminate the complete descendant tree rather than only the
direct Python/launcher process.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
import os
import signal
import subprocess
import threading
from typing import Any


IS_WINDOWS = os.name == "nt"
_JOB_HANDLE_ATTRIBUTE = "_blackbox_managed_job_handle"
_STATE_ATTRIBUTE = "_blackbox_managed_tree_state"
_LOCK_ATTRIBUTE = "_blackbox_managed_tree_lock"


def _platform_process_kwargs() -> dict[str, Any]:
    if IS_WINDOWS:
        return {
            "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        }
    return {"start_new_session": True}


def _attach_windows_job(process: subprocess.Popen) -> None:
    if not IS_WINDOWS:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = (
        wintypes.HANDLE, wintypes.HANDLE,
    )
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL

    job_handle = kernel32.CreateJobObjectW(None, None)
    if not job_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not kernel32.AssignProcessToJobObject(
            job_handle, wintypes.HANDLE(int(process._handle))
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        setattr(process, _JOB_HANDLE_ATTRIBUTE, int(job_handle))
    except BaseException:
        kernel32.CloseHandle(job_handle)
        raise


def _release_windows_job(process: subprocess.Popen, *, terminate: bool) -> None:
    raw_handle = getattr(process, _JOB_HANDLE_ATTRIBUTE, None)
    if not raw_handle or not IS_WINDOWS:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = wintypes.HANDLE(int(raw_handle))
    try:
        if terminate:
            kernel32.TerminateJobObject(handle, 1)
    finally:
        try:
            kernel32.CloseHandle(handle)
        finally:
            try:
                delattr(process, _JOB_HANDLE_ATTRIBUTE)
            except AttributeError:
                pass


def _claim_tree(process: subprocess.Popen, state: str) -> bool:
    lock = getattr(process, _LOCK_ATTRIBUTE, None)
    if lock is None:
        return False
    with lock:
        if getattr(process, _STATE_ATTRIBUTE, "") != "active":
            return False
        setattr(process, _STATE_ATTRIBUTE, state)
        return True


def _close_pipes(process: subprocess.Popen) -> None:
    for pipe in (
        getattr(process, "stdin", None),
        getattr(process, "stdout", None),
        getattr(process, "stderr", None),
    ):
        if pipe is None:
            continue
        try:
            pipe.close()
        except OSError:
            pass


def managed_popen(*popenargs, **kwargs) -> subprocess.Popen:
    """Start one synchronous black-box command in an owned process tree."""
    for key, value in _platform_process_kwargs().items():
        if key == "creationflags":
            kwargs[key] = int(kwargs.get(key, 0)) | int(value)
        elif key == "start_new_session":
            if key in kwargs and not kwargs[key]:
                raise ValueError("managed black-box process requires a new session")
            kwargs[key] = value
        else:
            kwargs[key] = value
    process = subprocess.Popen(*popenargs, **kwargs)
    setattr(process, _STATE_ATTRIBUTE, "active")
    setattr(process, _LOCK_ATTRIBUTE, threading.Lock())
    try:
        _attach_windows_job(process)
    except BaseException as error:
        terminate_process_tree(process)
        if not isinstance(error, Exception):
            raise
        raise OSError(
            "BLACKBOX_MANAGED_JOB_ASSIGNMENT_FAILED: "
            f"{type(error).__name__}: {error}"
        ) from error
    return process


def release_process_tree(process: subprocess.Popen) -> None:
    """Release tracking after communicate() proves normal tree completion."""
    if not _claim_tree(process, "released"):
        return
    _release_windows_job(process, terminate=False)


def terminate_process_tree(process: subprocess.Popen) -> None:
    """Terminate an owned tree exactly once and reap its direct process."""
    if not _claim_tree(process, "terminated"):
        return
    if IS_WINDOWS:
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
                creationflags=getattr(
                    subprocess, "CREATE_NO_WINDOW", 0x08000000
                ),
            )
        except BaseException:
            pass
        try:
            _release_windows_job(process, terminate=True)
        except BaseException:
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (AttributeError, OSError):
            pass

    try:
        running = process.poll() is None
    except (AttributeError, OSError):
        running = True
    if running:
        try:
            process.kill()
        except (AttributeError, OSError):
            pass
    try:
        process.wait(timeout=5)
    except (AttributeError, OSError, subprocess.SubprocessError):
        pass


def managed_communicate(
    process: subprocess.Popen, *, input=None, timeout: float | None = None,
):
    """Communicate with one managed process and close every exceptional path."""
    try:
        stdout, stderr = process.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        terminate_process_tree(process)
        try:
            cleanup_stdout, cleanup_stderr = process.communicate(timeout=5)
        except BaseException:
            cleanup_stdout = cleanup_stderr = None
            _close_pipes(process)
        if getattr(error, "output", None) is None:
            error.output = cleanup_stdout
        if getattr(error, "stderr", None) is None:
            error.stderr = cleanup_stderr
        raise
    except BaseException:
        terminate_process_tree(process)
        _close_pipes(process)
        raise
    release_process_tree(process)
    return stdout, stderr


def managed_run(
    command, *, input=None, capture_output=False, timeout=None, check=False,
    **popen_kwargs,
) -> subprocess.CompletedProcess:
    """Subset-compatible subprocess.run replacement with tree ownership."""
    if input is not None and popen_kwargs.get("stdin") is not None:
        raise ValueError("stdin and input arguments may not both be used")
    if capture_output:
        if popen_kwargs.get("stdout") is not None or popen_kwargs.get("stderr") is not None:
            raise ValueError(
                "stdout and stderr arguments may not be used with capture_output"
            )
        popen_kwargs["stdout"] = subprocess.PIPE
        popen_kwargs["stderr"] = subprocess.PIPE
    if input is not None:
        popen_kwargs["stdin"] = subprocess.PIPE

    process = managed_popen(command, **popen_kwargs)
    stdout, stderr = managed_communicate(
        process, input=input, timeout=timeout,
    )
    completed = subprocess.CompletedProcess(
        command, process.returncode, stdout, stderr
    )
    if check:
        completed.check_returncode()
    return completed


class ManagedProcessBatch(AbstractContextManager):
    """Own several concurrently running commands until all are communicated."""

    def __init__(self) -> None:
        self.processes: list[subprocess.Popen] = []

    def start(self, *popenargs, **kwargs) -> subprocess.Popen:
        process = managed_popen(*popenargs, **kwargs)
        self.processes.append(process)
        return process

    def communicate(self, process: subprocess.Popen, **kwargs):
        return managed_communicate(process, **kwargs)

    def terminate(self, process: subprocess.Popen) -> None:
        terminate_process_tree(process)

    def __exit__(self, _exc_type, _exc_value, _traceback) -> bool:
        for process in reversed(self.processes):
            terminate_process_tree(process)
            _close_pipes(process)
        return False


def managed_process_batch() -> ManagedProcessBatch:
    return ManagedProcessBatch()


__all__ = [
    "ManagedProcessBatch",
    "managed_communicate",
    "managed_popen",
    "managed_process_batch",
    "managed_run",
    "release_process_tree",
    "terminate_process_tree",
]
