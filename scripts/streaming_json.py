#!/usr/bin/env python3
"""Bounded-buffer JSON writers that preserve the repository's canonical bytes."""

from __future__ import annotations

import errno
import json
import mmap
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Callable, Iterable, Iterator, TextIO


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


class StreamingJsonReadError(ValueError):
    """Raised when a canonical generated sidecar cannot be streamed safely."""


_CANONICAL_VALUE_START_CACHE: dict[
    tuple[str, int, int, str], tuple[int, ...]
] = {}

# A complete JSON string can be removed in native ``re`` code without
# inspecting every payload byte in Python.  The structural cursor below uses
# this to prove that a requested key is a direct child of the root object.  It
# matters for correctness: a unique, identically named key inside a result row
# must never be mistaken for the requested top-level sidecar field.
_COMPLETE_JSON_STRING_RE = re.compile(rb'"(?:\\.|[^"\\])*"')


def _advance_json_structure(
    mapped: mmap.mmap,
    start: int,
    end: int,
    state: list[int | bool],
    *,
    chunk_bytes: int = 8 * 1024 * 1024,
) -> None:
    """Advance a bounded-memory lexical JSON nesting cursor.

    ``state`` is ``[depth, in_string, escaped_at_boundary]``.  Complete
    strings are stripped by the regex engine, leaving only outside-string
    braces and brackets to count in native byte operations.  A synthetic
    opening quote reconnects a string split across chunks; a synthetic
    backslash also reconnects an escape split exactly at a chunk boundary.
    """

    depth = int(state[0])
    in_string = bool(state[1])
    escaped_at_boundary = bool(state[2])
    cursor = max(0, int(start))
    limit = max(cursor, int(end))
    while cursor < limit:
        boundary = min(limit, cursor + max(64 * 1024, int(chunk_bytes)))
        payload = mapped[cursor:boundary]
        if in_string:
            prefix = b'"\\' if escaped_at_boundary else b'"'
            payload = prefix + payload
        stripped = _COMPLETE_JSON_STRING_RE.sub(b"", payload)
        incomplete = stripped.find(b'"')
        if incomplete >= 0:
            structural = stripped[:incomplete]
            in_string = True
            trailing_backslashes = len(payload) - len(payload.rstrip(b"\\"))
            escaped_at_boundary = bool(trailing_backslashes % 2)
        else:
            structural = stripped
            in_string = False
            escaped_at_boundary = False
        depth += structural.count(b"{") + structural.count(b"[")
        depth -= structural.count(b"}") + structural.count(b"]")
        if depth < 0:
            raise StreamingJsonReadError("invalid JSON nesting before field")
        cursor = boundary
    state[:] = (depth, in_string, escaped_at_boundary)


def prime_canonical_json_fields(
    path: str | Path,
    keys: Iterable[str],
) -> None:
    """Locate several canonical JSON fields in one native regex scan.

    Validation reads multiple independent arrays from the same multi-GiB
    sidecar. Searching the entire mapping once per field multiplied disk reads
    even though only byte offsets were needed. This shared index remains
    content-bound by size and mtime and retains only a few integer offsets.
    """

    source = Path(path)
    try:
        normalized_keys = tuple(dict.fromkeys(str(key) for key in keys))
        if not normalized_keys:
            return
        metadata = source.stat()
        resolved = str(source.resolve())
        missing = [
            key for key in normalized_keys
            if (
                resolved, metadata.st_size, metadata.st_mtime_ns, key
            ) not in _CANONICAL_VALUE_START_CACHE
        ]
        if not missing:
            return
        if metadata.st_size <= 0:
            raise StreamingJsonReadError(f"empty JSON sidecar: {source}")
        encoded_by_key = {
            key: json.dumps(key, ensure_ascii=False).encode("utf-8")
            for key in missing
        }
        alternatives = b"|".join(
            re.escape(value)
            for value in sorted(
                encoded_by_key.values(), key=len, reverse=True
            )
        )
        pattern = re.compile(rb"(?:" + alternatives + rb")\s*:\s*")
        found: dict[str, list[int]] = {key: [] for key in missing}
        encoded_to_key = {value: key for key, value in encoded_by_key.items()}
        with source.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                root = re.search(rb"\S", mapped)
                if root is None or mapped[root.start():root.start() + 1] != b"{":
                    raise StreamingJsonReadError(
                        f"canonical JSON sidecar root is not an object: {source}"
                    )
                structure_state: list[int | bool] = [0, False, False]
                structure_cursor = 0
                for match in pattern.finditer(mapped):
                    _advance_json_structure(
                        mapped,
                        structure_cursor,
                        match.start(),
                        structure_state,
                    )
                    structure_cursor = match.start()
                    colon = mapped.find(b":", match.start(), match.end())
                    encoded_key = bytes(mapped[match.start():colon]).rstrip()
                    # ``pattern`` is built only from ``encoded_to_key`` values
                    # and includes the trailing colon, so both lookups are
                    # construction invariants rather than input decisions.
                    key = encoded_to_key[encoded_key]
                    # Escaped quotes inside JSON strings cannot match the
                    # unescaped canonical key pattern.  The remaining input
                    # decision is whether the match is a direct root child.
                    if int(structure_state[0]) == 1:
                        found[key].append(match.end())
        if len(_CANONICAL_VALUE_START_CACHE) > 512:
            _CANONICAL_VALUE_START_CACHE.clear()
        for key, starts in found.items():
            _CANONICAL_VALUE_START_CACHE[
                resolved, metadata.st_size, metadata.st_mtime_ns, key
            ] = tuple(starts)
    except StreamingJsonReadError:
        raise
    except (OSError, OverflowError, ValueError) as error:
        raise StreamingJsonReadError(f"{source}: {error}") from error


def _canonical_json_value_starts(
    path_text: str,
    key: str,
    size: int,
    modified_ns: int,
) -> tuple[int, ...]:
    cache_key = (str(Path(path_text).resolve()), size, modified_ns, str(key))
    if cache_key not in _CANONICAL_VALUE_START_CACHE:
        prime_canonical_json_fields(path_text, (key,))
    return _CANONICAL_VALUE_START_CACHE.get(cache_key, ())


def _canonical_object_array_starts(
    path_text: str,
    key: str,
    size: int,
    modified_ns: int,
) -> tuple[int, ...]:
    source = Path(path_text)
    value_starts = _canonical_json_value_starts(
        path_text, key, size, modified_ns
    )
    with source.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            return tuple(
                start + 1
                for start in value_starts
                if mapped[start:start + 1] == b"["
            )


def iter_canonical_json_object_array(
    path: str | Path,
    key: str,
    *,
    progress_callback: Callable[[int, int], None] | None = None,
    progress_interval_bytes: int = 64 * 1024 * 1024,
) -> Iterator[dict[str, Any]]:
    """Iterate one top-level array of objects without materializing the file.

    Generation sidecars are emitted by :func:`stream_json` as canonical JSON.
    ``mmap.find`` locates candidate object boundaries in native code and the
    standard JSON decoder validates every yielded object.  Nested objects,
    arrays and delimiter-looking string contents are handled by advancing to
    the next candidate until a complete outer object decodes.  At most one
    array element is copied into Python memory at a time; mapping a multi-GiB
    file does not reserve an equally large Python heap buffer.

    This reader is deliberately narrow: the selected value must be exactly one
    object array.  A missing/duplicate key, non-object item or malformed array
    fails closed instead of silently returning partial evidence.
    """

    source = Path(path)
    try:
        metadata = source.stat()
        size = metadata.st_size
        if size <= 0:
            raise StreamingJsonReadError(f"empty JSON sidecar: {source}")
        with source.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                starts = _canonical_object_array_starts(
                    str(source.resolve()), key, size, metadata.st_mtime_ns
                )
                if len(starts) != 1:
                    raise StreamingJsonReadError(
                        f"expected one canonical object array {key!r} in {source}; "
                        f"found {len(starts)}"
                    )
                cursor = starts[0]
                last_progress = cursor
                if mapped[cursor:cursor + 1] == b"]":
                    if progress_callback is not None:
                        progress_callback(cursor + 1, size)
                    return
                while True:
                    if mapped[cursor:cursor + 1] != b"{":
                        raise StreamingJsonReadError(
                            f"non-object item in {key!r} at byte {cursor}: {source}"
                        )
                    candidate = cursor
                    while True:
                        separator = mapped.find(b"},{", candidate + 1)
                        terminator = mapped.find(b"}]", candidate + 1)
                        if separator < 0 and terminator < 0:
                            raise StreamingJsonReadError(
                                f"unterminated object array {key!r}: {source}"
                            )
                        if separator < 0 or (
                            terminator >= 0 and terminator < separator
                        ):
                            boundary = terminator + 1
                            final_item = True
                        else:
                            boundary = separator + 1
                            final_item = False
                        try:
                            value = json.loads(mapped[cursor:boundary])
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            candidate = boundary
                            continue
                        # The cursor was required to start at ``{`` above; a
                        # successful JSON decode therefore has object shape.
                        yield dict(value)
                        cursor = boundary + 1
                        if (
                            progress_callback is not None
                            and boundary - last_progress
                            >= max(1, int(progress_interval_bytes))
                        ):
                            progress_callback(boundary, size)
                            last_progress = boundary
                        if final_item:
                            if progress_callback is not None:
                                progress_callback(boundary + 1, size)
                            return
                        break
    except StreamingJsonReadError:
        raise
    except (OSError, OverflowError, ValueError) as error:
        raise StreamingJsonReadError(f"{source}: {error}") from error


def load_canonical_json_top_level_value(
    path: str | Path,
    key: str,
    *,
    initial_bytes: int = 4 * 1024,
    maximum_bytes: int = 16 * 1024 * 1024,
) -> Any:
    """Decode one bounded top-level value without loading a large sidecar.

    It is intended for compact metadata fields adjacent to very large arrays
    (coverage gaps, counts and schema values).  The explicit maximum prevents
    an accidentally selected bulk field from recreating the original
    multi-GiB ``json.load`` allocation.
    """

    source = Path(path)
    try:
        metadata = source.stat()
        size = metadata.st_size
        if size <= 0:
            raise StreamingJsonReadError(f"empty JSON sidecar: {source}")
        with source.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                starts = _canonical_json_value_starts(
                    str(source.resolve()),
                    str(key),
                    size,
                    metadata.st_mtime_ns,
                )
                if len(starts) != 1:
                    raise StreamingJsonReadError(
                        f"expected one top-level value {key!r} in {source}; "
                        f"found {len(starts)}"
                    )
                start = starts[0]
                decoder = json.JSONDecoder()
                length = max(64, int(initial_bytes))
                limit = max(length, int(maximum_bytes))
                while length <= limit:
                    raw = mapped[start:min(size, start + length)]
                    try:
                        text = raw.decode("utf-8")
                        value, _end = decoder.raw_decode(text)
                        return value
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        if start + length >= size:
                            break
                        length = min(limit + 1, length * 2)
                raise StreamingJsonReadError(
                    f"top-level value {key!r} exceeds {limit} bytes or is invalid: "
                    f"{source}"
                )
    except StreamingJsonReadError:
        raise
    except (OSError, OverflowError, ValueError) as error:
        raise StreamingJsonReadError(f"{source}: {error}") from error


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
    "StreamingJsonReadError",
    "files_equal",
    "fsync_directory",
    "iter_canonical_json_object_array",
    "load_canonical_json_top_level_value",
    "prime_canonical_json_fields",
    "stream_json",
    "write_json_streaming",
    "write_json_streaming_atomic",
]
