#!/usr/bin/env python3
"""Bounded-buffer JSON writers that preserve the repository's canonical bytes."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Iterable, TextIO


_DIRECTORY_FSYNC_UNSUPPORTED_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, "EINVAL", None),
        getattr(errno, "ENOSYS", None),
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
)


def _add_cleanup_note(primary: BaseException, note: str) -> None:
    """Attach cleanup diagnostics without requiring Python 3.11 ``add_note``."""

    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        try:
            add_note(note)
            return
        except Exception:
            # A custom exception can override add_note.  Cleanup diagnostics
            # must never replace the exception the caller is already handling.
            pass
    try:
        notes = list(getattr(primary, "__notes__", ()) or ())
        notes.append(note)
        setattr(primary, "__notes__", notes)
    except Exception:
        pass


def _finish_cleanups(
    primary: BaseException | None,
    errors: Iterable[tuple[str, BaseException]],
) -> None:
    failures = list(errors)
    if not failures:
        return
    if primary is not None:
        for label, error in failures:
            _add_cleanup_note(
                primary,
                f"cleanup failed ({label}): {type(error).__name__}: {error}",
            )
        return
    first_label, first = failures[0]
    for label, error in failures[1:]:
        _add_cleanup_note(
            first,
            f"additional cleanup failed ({label}): {type(error).__name__}: {error}",
        )
    _add_cleanup_note(first, f"cleanup operation: {first_label}")
    raise first


def fsync_directory(path: str | Path) -> bool:
    """Durably order a directory entry where the host exposes that operation.

    Windows has no equivalent directory ``fsync`` through Python's ``os`` API,
    and a small number of POSIX filesystems explicitly report the operation as
    unsupported.  Those cases return ``False``. Permission, media and other
    real I/O failures remain fatal so callers cannot claim durability that was
    never established.
    """

    if os.name == "nt":  # pragma: no cover - exercised by Windows CI.
        return False
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0) or 0)
    try:
        descriptor = os.open(Path(path), flags)
    except OSError as error:
        if error.errno in _DIRECTORY_FSYNC_UNSUPPORTED_ERRNOS:
            return False
        raise
    supported = True
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno in _DIRECTORY_FSYNC_UNSUPPORTED_ERRNOS:
                supported = False
            else:
                raise
    finally:
        primary = sys.exc_info()[1]
        cleanup_errors = []
        try:
            os.close(descriptor)
        except BaseException as error:
            cleanup_errors.append((f"close directory descriptor for {path}", error))
        _finish_cleanups(primary, cleanup_errors)
    return supported


def stream_json(
    value: Any,
    handle: TextIO,
    *,
    ensure_ascii: bool = False,
    sort_keys: bool = True,
    separators=(",", ":"),
    indent=None,
    newline: bool = True,
) -> None:
    encoder = json.JSONEncoder(
        ensure_ascii=ensure_ascii,
        sort_keys=sort_keys,
        separators=separators if indent is None else None,
        indent=indent,
        allow_nan=False,
    )
    for chunk in encoder.iterencode(value):
        handle.write(chunk)
    if newline:
        handle.write("\n")


def write_json_streaming(
    path: str | Path,
    value: Any,
    *,
    indent=None,
) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        stream_json(value, handle, indent=indent)
        handle.flush()
        os.fsync(handle.fileno())
    return destination


def files_equal(first: str | Path, second: str | Path) -> bool:
    first_path = Path(first)
    second_path = Path(second)
    try:
        if first_path.stat().st_size != second_path.stat().st_size:
            return False
        with first_path.open("rb") as left, second_path.open("rb") as right:
            while True:
                left_block = left.read(1024 * 1024)
                right_block = right.read(1024 * 1024)
                if left_block != right_block:
                    return False
                if not left_block:
                    return True
    except OSError:
        return False


def write_json_streaming_atomic(
    path: str | Path,
    value: Any,
    *,
    indent=None,
    collision_error=None,
) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        write_json_streaming(temporary, value, indent=indent)
        if destination.exists():
            if files_equal(destination, temporary):
                # A concurrent writer may have installed these exact bytes but
                # not yet made the directory entry durable.  Synchronize the
                # parent before treating equal content as a committed result.
                fsync_directory(destination.parent)
                return destination
            if collision_error is not None:
                raise collision_error
        os.replace(temporary, destination)
        fsync_directory(destination.parent)
        return destination
    finally:
        primary = sys.exc_info()[1]
        cleanup_errors = []
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except BaseException as error:
            cleanup_errors.append((f"unlink temporary JSON {temporary}", error))
        _finish_cleanups(primary, cleanup_errors)


__all__ = [
    "files_equal",
    "fsync_directory",
    "stream_json",
    "write_json_streaming",
    "write_json_streaming_atomic",
]
