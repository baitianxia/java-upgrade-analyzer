#!/usr/bin/env python3
"""Typed argv-only subprocess boundary for binary-first production helpers."""

from __future__ import annotations

from dataclasses import dataclass
import subprocess
from pathlib import Path
from typing import Any, Callable, Iterable


@dataclass(frozen=True, slots=True)
class BinaryToolFailure:
    stage: str
    reason_code: str
    failure_kind: str
    command: tuple[str, ...]
    timeout_seconds: float
    returncode: int | None
    stderr: str
    error_type: str = ""
    blocking: bool = True

    def to_mapping(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "reason_code": self.reason_code,
            "failure_kind": self.failure_kind,
            "command": list(self.command),
            "timeout_seconds": self.timeout_seconds,
            "returncode": self.returncode,
            "stderr": self.stderr,
            "error_type": self.error_type,
            "blocking": self.blocking,
        }


@dataclass(frozen=True, slots=True)
class BinaryToolResult:
    stdout: str | bytes
    stderr: str | bytes
    returncode: int
    failure: BinaryToolFailure | None = None

    @property
    def succeeded(self) -> bool:
        return self.failure is None and self.returncode == 0


def _failure(
    *, stage: str, prefix: str, kind: str, command: tuple[str, ...],
    timeout_seconds: float, stderr: str, returncode: int | None,
    error_type: str = "", blocking: bool,
) -> BinaryToolFailure:
    return BinaryToolFailure(
        stage=str(stage),
        reason_code=f"{prefix}_{kind}",
        failure_kind=kind.lower(),
        command=command,
        timeout_seconds=float(timeout_seconds),
        returncode=returncode,
        stderr=str(stderr or "")[-4000:],
        error_type=error_type,
        blocking=bool(blocking),
    )


def execute_binary_tool(
    command: Iterable[str],
    *,
    stage: str,
    reason_prefix: str,
    timeout_seconds: float,
    input_data: str | bytes | None = None,
    text: bool = True,
    encoding: str = "utf-8",
    require_stdout: bool = False,
    blocking: bool = True,
    cwd: str | Path | None = None,
    runner: Callable[..., Any] = subprocess.run,
) -> BinaryToolResult:
    """Run an explicit argv and classify every process failure without guessing."""
    argv = tuple(str(value) for value in command)
    if not argv:
        raise ValueError("binary tool command must not be empty")
    kwargs: dict[str, Any] = {
        "input": input_data,
        "capture_output": True,
        "timeout": float(timeout_seconds),
        "check": False,
        "text": bool(text),
    }
    if text:
        kwargs.update({"encoding": encoding, "errors": "replace"})
    if cwd is not None:
        kwargs["cwd"] = str(Path(cwd).expanduser().resolve())
    try:
        completed = runner(list(argv), **kwargs)
    except subprocess.TimeoutExpired as error:
        failure = _failure(
            stage=stage, prefix=reason_prefix, kind="TIMEOUT", command=argv,
            timeout_seconds=timeout_seconds, stderr=str(error), returncode=None,
            error_type=type(error).__name__, blocking=blocking,
        )
        return BinaryToolResult("" if text else b"", "" if text else b"", -1, failure)
    except FileNotFoundError as error:
        failure = _failure(
            stage=stage, prefix=reason_prefix, kind="MISSING", command=argv,
            timeout_seconds=timeout_seconds, stderr=str(error), returncode=None,
            error_type=type(error).__name__, blocking=blocking,
        )
        return BinaryToolResult("" if text else b"", "" if text else b"", -1, failure)
    except PermissionError as error:
        failure = _failure(
            stage=stage, prefix=reason_prefix, kind="PERMISSION_DENIED", command=argv,
            timeout_seconds=timeout_seconds, stderr=str(error), returncode=None,
            error_type=type(error).__name__, blocking=blocking,
        )
        return BinaryToolResult("" if text else b"", "" if text else b"", -1, failure)
    except (OSError, TypeError, ValueError) as error:
        failure = _failure(
            stage=stage, prefix=reason_prefix, kind="START_FAILED", command=argv,
            timeout_seconds=timeout_seconds, stderr=str(error), returncode=None,
            error_type=type(error).__name__, blocking=blocking,
        )
        return BinaryToolResult("" if text else b"", "" if text else b"", -1, failure)

    stdout = completed.stdout if completed.stdout is not None else ("" if text else b"")
    stderr = completed.stderr if completed.stderr is not None else ("" if text else b"")
    returncode = int(completed.returncode)
    stderr_text = stderr if isinstance(stderr, str) else stderr.decode(encoding, errors="replace")
    if returncode != 0:
        failure = _failure(
            stage=stage, prefix=reason_prefix, kind="NONZERO_EXIT", command=argv,
            timeout_seconds=timeout_seconds, stderr=stderr_text,
            returncode=returncode, blocking=blocking,
        )
        return BinaryToolResult(stdout, stderr, returncode, failure)
    empty = not stdout.strip() if isinstance(stdout, (str, bytes)) else not stdout
    if require_stdout and empty:
        failure = _failure(
            stage=stage, prefix=reason_prefix, kind="OUTPUT_EMPTY", command=argv,
            timeout_seconds=timeout_seconds, stderr=stderr_text,
            returncode=returncode, blocking=blocking,
        )
        return BinaryToolResult(stdout, stderr, returncode, failure)
    return BinaryToolResult(stdout, stderr, returncode)


__all__ = ["BinaryToolFailure", "BinaryToolResult", "execute_binary_tool"]
