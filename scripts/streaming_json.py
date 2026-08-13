#!/usr/bin/env python3
"""Bounded-buffer JSON writers that preserve the repository's canonical bytes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, TextIO


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
                return destination
            if collision_error is not None:
                raise collision_error
        os.replace(temporary, destination)
        return destination
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


__all__ = [
    "files_equal",
    "stream_json",
    "write_json_streaming",
    "write_json_streaming_atomic",
]
