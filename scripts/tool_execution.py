#!/usr/bin/env python3
"""Typed external-tool boundary shared by analysis stages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from compat import run_cmd


@dataclass(frozen=True, slots=True)
class ExternalToolFailure:
    stage: str
    reason_code: str
    command: tuple[str, ...]
    timeout_seconds: float
    stderr: str
    returncode: int
    blocking: bool = True
    error_type: str = ""

    def to_mapping(self) -> dict:
        return {
            "stage": self.stage,
            "reason_code": self.reason_code,
            "command": list(self.command),
            "timeout_seconds": self.timeout_seconds,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "blocking": self.blocking,
            "error_type": self.error_type,
        }


class ExternalToolError(RuntimeError):
    def __init__(self, failure: ExternalToolFailure):
        self.failure = failure
        super().__init__(
            f"{failure.reason_code}: stage={failure.stage}; "
            f"command={' '.join(failure.command)}; stderr={failure.stderr}"
        )


@dataclass(frozen=True, slots=True)
class ExternalToolResult:
    stdout: str
    stderr: str
    returncode: int
    failure: ExternalToolFailure | None = None

    @property
    def succeeded(self) -> bool:
        return self.failure is None and self.returncode == 0

    def require_success(self) -> "ExternalToolResult":
        if self.failure is not None:
            raise ExternalToolError(self.failure)
        return self


def _reason_for_failure(prefix: str, returncode: int, stderr: str) -> str:
    normalized = str(stderr or "").lower()
    if returncode == -1 and ("超时" in normalized or "timeout" in normalized):
        return f"{prefix}_TIMEOUT"
    if "命令未找到" in normalized or "not found" in normalized:
        return f"{prefix}_MISSING"
    if "权限不足" in normalized or "permission" in normalized:
        return f"{prefix}_PERMISSION_DENIED"
    return f"{prefix}_NONZERO_EXIT"


def execute_external_tool(
    command: Iterable[str],
    *,
    stage: str,
    reason_prefix: str,
    timeout_seconds: float,
    blocking: bool = True,
    require_stdout: bool = False,
    runner: Callable = run_cmd,
) -> ExternalToolResult:
    """Execute an argv-only command and convert every failure into one contract."""
    argv = tuple(str(item) for item in command)
    if not argv:
        raise ValueError("external tool command must not be empty")
    try:
        stdout, stderr, returncode = runner(list(argv), timeout=timeout_seconds)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        failure = ExternalToolFailure(
            stage=str(stage),
            reason_code=f"{reason_prefix}_START_FAILED",
            command=argv,
            timeout_seconds=float(timeout_seconds),
            stderr=str(exc),
            returncode=-1,
            blocking=bool(blocking),
            error_type=type(exc).__name__,
        )
        return ExternalToolResult("", str(exc), -1, failure)
    stdout = str(stdout or "")
    stderr = str(stderr or "")
    returncode = int(returncode)
    if returncode == 0 and require_stdout and not stdout.strip():
        failure = ExternalToolFailure(
            stage=str(stage),
            reason_code=f"{reason_prefix}_OUTPUT_EMPTY",
            command=argv,
            timeout_seconds=float(timeout_seconds),
            stderr=stderr,
            returncode=returncode,
            blocking=bool(blocking),
        )
        return ExternalToolResult(stdout, stderr, returncode, failure)
    if returncode == 0:
        return ExternalToolResult(stdout, stderr, returncode)
    failure = ExternalToolFailure(
        stage=str(stage),
        reason_code=_reason_for_failure(str(reason_prefix), returncode, stderr),
        command=argv,
        timeout_seconds=float(timeout_seconds),
        stderr=stderr[-4000:],
        returncode=returncode,
        blocking=bool(blocking),
    )
    return ExternalToolResult(stdout, stderr, returncode, failure)
