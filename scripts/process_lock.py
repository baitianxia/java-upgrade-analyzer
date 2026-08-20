#!/usr/bin/env python3
"""Small cross-process advisory lock used for report-owned state transitions."""

from __future__ import annotations

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import stat
import sys
import time
from typing import Iterator


def _add_cleanup_note(primary: BaseException, note: str) -> None:
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        try:
            add_note(note)
            return
        except Exception:
            pass
    try:
        notes = list(getattr(primary, "__notes__", ()) or ())
        notes.append(note)
        setattr(primary, "__notes__", notes)
    except Exception:
        pass


def _finish_cleanup_errors(
    primary: BaseException | None,
    errors: list[tuple[str, BaseException]],
) -> None:
    if not errors:
        return
    if primary is not None:
        for label, error in errors:
            _add_cleanup_note(
                primary,
                f"cleanup failed ({label}): {type(error).__name__}: {error}",
            )
        return
    first_label, first = errors[0]
    for label, error in errors[1:]:
        _add_cleanup_note(
            first,
            f"additional cleanup failed ({label}): {type(error).__name__}: {error}",
        )
    _add_cleanup_note(first, f"cleanup operation: {first_label}")
    raise first


def _try_lock(handle: int) -> bool:
    if os.name == "nt":  # pragma: no cover - exercised by Windows CI.
        import msvcrt

        os.lseek(handle, 0, os.SEEK_SET)
        try:
            msvcrt.locking(handle, msvcrt.LK_NBLCK, 1)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                return False
            raise
        return True

    try:
        import fcntl
    except ImportError as error:  # pragma: no cover - invalid POSIX runtime.
        raise OSError(errno.ENOSYS, "POSIX advisory locks are unavailable") from error

    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EAGAIN}:
            return False
        raise
    return True


def _unlock(handle: int) -> None:
    if os.name == "nt":  # pragma: no cover - exercised by Windows CI.
        import msvcrt

        os.lseek(handle, 0, os.SEEK_SET)
        msvcrt.locking(handle, msvcrt.LK_UNLCK, 1)
        return

    try:
        import fcntl
    except ImportError as error:  # pragma: no cover - invalid POSIX runtime.
        raise OSError(errno.ENOSYS, "POSIX advisory locks are unavailable") from error

    fcntl.flock(handle, fcntl.LOCK_UN)


def _same_file_identity(left, right) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_ISREG(left.st_mode)
        and stat.S_ISREG(right.st_mode)
        and left.st_nlink == 1
        and right.st_nlink == 1
    )


def _open_validated_lock_file(lock_path: Path) -> int:
    """Open one private regular lock inode without following a target symlink."""

    no_follow = int(getattr(os, "O_NOFOLLOW", 0) or 0)
    for _attempt in range(3):
        try:
            before = os.lstat(lock_path)
        except FileNotFoundError:
            before = None
        if before is not None and (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise OSError(errno.ELOOP, "unsafe lock path", str(lock_path))
        flags = os.O_RDWR | no_follow
        created = False
        try:
            if before is None:
                descriptor = os.open(
                    lock_path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                created = True
            else:
                descriptor = os.open(lock_path, flags)
        except FileExistsError:
            continue
        try:
            opened = os.fstat(descriptor)
            try:
                after = os.lstat(lock_path)
            except FileNotFoundError as error:
                raise OSError(
                    errno.ESTALE, "lock path changed while opening", str(lock_path)
                ) from error
            if not _same_file_identity(opened, after) or (
                before is not None and not _same_file_identity(before, opened)
            ):
                raise OSError(
                    errno.ELOOP, "lock path changed or is unsafe", str(lock_path)
                )
            if created or opened.st_size == 0:
                os.lseek(descriptor, 0, os.SEEK_SET)
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            return descriptor
        except BaseException as primary:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                _add_cleanup_note(
                    primary,
                    "cleanup failed (close rejected lock descriptor): "
                    f"{type(cleanup_error).__name__}: {cleanup_error}",
                )
            raise
    raise OSError(errno.EBUSY, "lock path changed repeatedly", str(lock_path))


@contextmanager
def exclusive_file_lock(
    path: str | Path,
    *,
    timeout_seconds: float,
    poll_seconds: float = 0.05,
) -> Iterator[Path]:
    """Hold one OS-released lock without deleting/replacing the lock inode."""

    lock_path = Path(os.path.abspath(str(path)))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = _open_validated_lock_file(lock_path)
    acquired = False
    try:
        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
        while True:
            if _try_lock(descriptor):
                acquired = True
                try:
                    current = os.lstat(lock_path)
                except FileNotFoundError as error:
                    raise OSError(
                        errno.ESTALE,
                        "lock path disappeared while locked",
                        str(lock_path),
                    ) from error
                if not _same_file_identity(os.fstat(descriptor), current):
                    raise OSError(
                        errno.ESTALE,
                        "lock path changed while locked",
                        str(lock_path),
                    )
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(str(lock_path))
            time.sleep(min(max(0.001, float(poll_seconds)), remaining))
        yield lock_path
    finally:
        primary = sys.exc_info()[1]
        cleanup_errors = []
        if acquired:
            try:
                _unlock(descriptor)
            except BaseException as error:
                cleanup_errors.append(("unlock lock descriptor", error))
        # Closing the descriptor is the final OS-level lock release on every
        # supported platform. It remains mandatory after an unlock failure.
        try:
            os.close(descriptor)
        except BaseException as error:
            cleanup_errors.append(("close lock descriptor", error))
        _finish_cleanup_errors(primary, cleanup_errors)


__all__ = ["exclusive_file_lock"]
