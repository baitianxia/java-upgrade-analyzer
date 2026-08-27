from __future__ import annotations

import errno
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import process_lock


def _stat(*, dev=1, ino=2, mode=stat.S_IFREG | 0o600, nlink=1, size=1):
    return SimpleNamespace(
        st_dev=dev,
        st_ino=ino,
        st_mode=mode,
        st_nlink=nlink,
        st_size=size,
    )


class ProcessLockTest(unittest.TestCase):
    def test_cleanup_notes_preserve_primary_and_raise_first_without_primary(self):
        self.assertIsNone(process_lock._finish_cleanup_errors(None, []))

        primary = RuntimeError("primary")
        process_lock._finish_cleanup_errors(
            primary,
            [("unlock", OSError("unlock failed")), ("close", OSError("close failed"))],
        )
        self.assertTrue(any("unlock failed" in note for note in primary.__notes__))
        self.assertTrue(any("close failed" in note for note in primary.__notes__))

        class BrokenAddNote(RuntimeError):
            def add_note(self, _note):
                raise RuntimeError("add_note unavailable")

        fallback = BrokenAddNote("fallback")
        process_lock._add_cleanup_note(fallback, "fallback note")
        self.assertEqual(fallback.__notes__, ["fallback note"])
        process_lock._add_cleanup_note(fallback, "second note")
        self.assertEqual(fallback.__notes__, ["fallback note", "second note"])

        without_add_note = SimpleNamespace(__notes__=None)
        process_lock._add_cleanup_note(without_add_note, "plain fallback")
        self.assertEqual(without_add_note.__notes__, ["plain fallback"])

        first = OSError("first")
        second = OSError("second")
        with self.assertRaises(OSError) as raised:
            process_lock._finish_cleanup_errors(
                None,
                [("first operation", first), ("second operation", second)],
            )
        self.assertIs(raised.exception, first)
        self.assertTrue(any("second operation" in note for note in first.__notes__))
        self.assertTrue(any("first operation" in note for note in first.__notes__))

    def test_lock_and_unlock_cover_windows_success_contention_and_native_failure(self):
        for error, expected in (
            (None, True),
            (OSError(errno.EACCES, "busy"), False),
            (OSError(errno.EAGAIN, "busy"), False),
            (OSError(errno.EDEADLK, "busy"), False),
        ):
            locking = MagicMock(side_effect=error)
            windows = SimpleNamespace(
                LK_NBLCK=1,
                LK_UNLCK=2,
                locking=locking,
            )
            with self.subTest(error=repr(error)), patch.object(
                process_lock.os,
                "name",
                "nt",
            ), patch.object(process_lock.os, "lseek") as seek, patch.dict(
                sys.modules,
                {"msvcrt": windows},
            ):
                self.assertEqual(process_lock._try_lock(9), expected)
                seek.assert_called_once_with(9, 0, os.SEEK_SET)

        unexpected = OSError(errno.EIO, "broken")
        windows = SimpleNamespace(
            LK_NBLCK=1,
            LK_UNLCK=2,
            locking=MagicMock(side_effect=unexpected),
        )
        with patch.object(process_lock.os, "name", "nt"), patch.object(
            process_lock.os,
            "lseek",
        ), patch.dict(sys.modules, {"msvcrt": windows}), self.assertRaises(
            OSError
        ) as raised:
            process_lock._try_lock(9)
        self.assertIs(raised.exception, unexpected)

        windows.locking = MagicMock()
        with patch.object(process_lock.os, "name", "nt"), patch.object(
            process_lock.os,
            "lseek",
        ) as seek, patch.dict(sys.modules, {"msvcrt": windows}):
            process_lock._unlock(9)
        seek.assert_called_once_with(9, 0, os.SEEK_SET)
        windows.locking.assert_called_once_with(9, windows.LK_UNLCK, 1)

    def test_lock_and_unlock_cover_posix_success_contention_and_failure(self):
        for error, expected in (
            (None, True),
            (OSError(errno.EACCES, "busy"), False),
            (OSError(errno.EAGAIN, "busy"), False),
        ):
            fcntl = SimpleNamespace(
                LOCK_EX=1,
                LOCK_NB=2,
                LOCK_UN=4,
                flock=MagicMock(side_effect=error),
            )
            with self.subTest(error=repr(error)), patch.object(
                process_lock.os,
                "name",
                "posix",
            ), patch.dict(sys.modules, {"fcntl": fcntl}):
                self.assertEqual(process_lock._try_lock(7), expected)

        unexpected = OSError(errno.EIO, "broken")
        fcntl = SimpleNamespace(
            LOCK_EX=1,
            LOCK_NB=2,
            LOCK_UN=4,
            flock=MagicMock(side_effect=unexpected),
        )
        with patch.object(process_lock.os, "name", "posix"), patch.dict(
            sys.modules,
            {"fcntl": fcntl},
        ), self.assertRaises(OSError) as raised:
            process_lock._try_lock(7)
        self.assertIs(raised.exception, unexpected)

        fcntl.flock = MagicMock()
        with patch.object(process_lock.os, "name", "posix"), patch.dict(
            sys.modules,
            {"fcntl": fcntl},
        ):
            process_lock._unlock(7)
        fcntl.flock.assert_called_once_with(7, fcntl.LOCK_UN)

    def test_same_file_identity_rejects_each_independent_safety_dimension(self):
        valid = _stat()
        self.assertTrue(process_lock._same_file_identity(valid, _stat()))
        variants = (
            (_stat(dev=9), valid),
            (_stat(ino=9), valid),
            (_stat(mode=stat.S_IFDIR | 0o700), valid),
            (valid, _stat(mode=stat.S_IFDIR | 0o700)),
            (_stat(nlink=2), valid),
            (valid, _stat(nlink=2)),
        )
        for left, right in variants:
            with self.subTest(left=left, right=right):
                self.assertFalse(process_lock._same_file_identity(left, right))

    def test_validated_open_covers_create_existing_retry_and_unsafe_paths(self):
        lock_path = Path("owned.lock")
        regular_empty = _stat(size=0)
        create_os = SimpleNamespace(
            O_NOFOLLOW=0,
            O_RDWR=os.O_RDWR,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
            SEEK_SET=os.SEEK_SET,
            lstat=MagicMock(side_effect=[FileNotFoundError(), regular_empty]),
            open=MagicMock(return_value=17),
            fstat=MagicMock(return_value=regular_empty),
            lseek=MagicMock(),
            write=MagicMock(),
            fsync=MagicMock(),
            close=MagicMock(),
        )
        with patch.object(process_lock, "os", create_os):
            self.assertEqual(process_lock._open_validated_lock_file(lock_path), 17)
        create_os.open.assert_called_once_with(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        create_os.write.assert_called_once_with(17, b"\0")

        regular_nonempty = _stat(size=4)
        existing_os = SimpleNamespace(
            O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
            O_RDWR=os.O_RDWR,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
            SEEK_SET=os.SEEK_SET,
            lstat=MagicMock(side_effect=[regular_nonempty, regular_nonempty]),
            open=MagicMock(return_value=18),
            fstat=MagicMock(return_value=regular_nonempty),
            lseek=MagicMock(),
            write=MagicMock(),
            fsync=MagicMock(),
            close=MagicMock(),
        )
        with patch.object(process_lock, "os", existing_os):
            self.assertEqual(process_lock._open_validated_lock_file(lock_path), 18)
        existing_os.open.assert_called_once_with(
            lock_path,
            os.O_RDWR | int(getattr(os, "O_NOFOLLOW", 0) or 0),
        )
        existing_os.write.assert_not_called()

        existing_empty = _stat(size=0)
        existing_empty_os = SimpleNamespace(
            O_NOFOLLOW=0,
            O_RDWR=os.O_RDWR,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
            SEEK_SET=os.SEEK_SET,
            lstat=MagicMock(side_effect=[existing_empty, existing_empty]),
            open=MagicMock(return_value=19),
            fstat=MagicMock(return_value=existing_empty),
            lseek=MagicMock(),
            write=MagicMock(),
            fsync=MagicMock(),
            close=MagicMock(),
        )
        with patch.object(process_lock, "os", existing_empty_os):
            self.assertEqual(process_lock._open_validated_lock_file(lock_path), 19)
        existing_empty_os.write.assert_called_once_with(19, b"\0")

        opened = _stat(dev=1)
        changed_after = _stat(dev=2)
        changed_after_os = SimpleNamespace(
            O_NOFOLLOW=0,
            O_RDWR=os.O_RDWR,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
            SEEK_SET=os.SEEK_SET,
            lstat=MagicMock(side_effect=[FileNotFoundError(), changed_after]),
            open=MagicMock(return_value=20),
            fstat=MagicMock(return_value=opened),
            close=MagicMock(),
        )
        with patch.object(process_lock, "os", changed_after_os), self.assertRaises(
            OSError
        ) as raised:
            process_lock._open_validated_lock_file(lock_path)
        self.assertEqual(raised.exception.errno, errno.ELOOP)
        changed_after_os.close.assert_called_once_with(20)

        before = _stat(dev=1)
        replacement = _stat(dev=2)
        changed_before_os = SimpleNamespace(
            O_NOFOLLOW=0,
            O_RDWR=os.O_RDWR,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
            SEEK_SET=os.SEEK_SET,
            lstat=MagicMock(side_effect=[before, replacement]),
            open=MagicMock(return_value=24),
            fstat=MagicMock(return_value=replacement),
            close=MagicMock(),
        )
        with patch.object(process_lock, "os", changed_before_os), self.assertRaises(
            OSError
        ) as raised:
            process_lock._open_validated_lock_file(lock_path)
        self.assertEqual(raised.exception.errno, errno.ELOOP)
        changed_before_os.close.assert_called_once_with(24)

        retry_os = SimpleNamespace(
            O_NOFOLLOW=0,
            O_RDWR=os.O_RDWR,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
            SEEK_SET=os.SEEK_SET,
            lstat=MagicMock(side_effect=FileNotFoundError()),
            open=MagicMock(side_effect=FileExistsError()),
        )
        with patch.object(process_lock, "os", retry_os), self.assertRaises(
            OSError
        ) as raised:
            process_lock._open_validated_lock_file(lock_path)
        self.assertEqual(raised.exception.errno, errno.EBUSY)
        self.assertEqual(retry_os.open.call_count, 3)

        unsafe_variants = (
            _stat(mode=stat.S_IFLNK | 0o777),
            _stat(mode=stat.S_IFDIR | 0o700),
            _stat(nlink=2),
        )
        for unsafe in unsafe_variants:
            unsafe_os = SimpleNamespace(
                O_NOFOLLOW=0,
                O_RDWR=os.O_RDWR,
                O_CREAT=os.O_CREAT,
                O_EXCL=os.O_EXCL,
                SEEK_SET=os.SEEK_SET,
                lstat=MagicMock(return_value=unsafe),
            )
            with self.subTest(unsafe=unsafe), patch.object(
                process_lock,
                "os",
                unsafe_os,
            ), self.assertRaises(OSError) as raised:
                process_lock._open_validated_lock_file(lock_path)
            self.assertEqual(raised.exception.errno, errno.ELOOP)

    def test_exclusive_lock_covers_retry_timeout_and_locked_path_tampering(self):
        identity = _stat()
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "state.lock"
            with patch.object(
                process_lock,
                "_open_validated_lock_file",
                return_value=21,
            ), patch.object(
                process_lock,
                "_try_lock",
                side_effect=(False, True),
            ), patch.object(
                process_lock,
                "_unlock",
            ) as unlock, patch.object(
                process_lock.os,
                "lstat",
                return_value=identity,
            ), patch.object(
                process_lock.os,
                "fstat",
                return_value=identity,
            ), patch.object(
                process_lock.os,
                "close",
            ) as close, patch.object(
                process_lock.time,
                "monotonic",
                side_effect=(10.0, 10.5),
            ), patch.object(process_lock.time, "sleep") as sleep:
                with process_lock.exclusive_file_lock(
                    lock,
                    timeout_seconds=2,
                    poll_seconds=0,
                ) as locked:
                    self.assertEqual(locked, lock.absolute())
            sleep.assert_called_once_with(0.001)
            unlock.assert_called_once_with(21)
            close.assert_called_once_with(21)

            with patch.object(
                process_lock,
                "_open_validated_lock_file",
                return_value=22,
            ), patch.object(process_lock, "_try_lock", return_value=False), patch.object(
                process_lock.os,
                "close",
            ), patch.object(
                process_lock.time,
                "monotonic",
                side_effect=(10.0, 10.0),
            ):
                with self.assertRaises(TimeoutError):
                    with process_lock.exclusive_file_lock(
                        lock,
                        timeout_seconds=-1,
                    ):
                        self.fail("timed out lock entered")

            for current in (
                FileNotFoundError(),
                _stat(ino=99),
            ):
                lstat = (
                    MagicMock(side_effect=current)
                    if isinstance(current, BaseException)
                    else MagicMock(return_value=current)
                )
                with self.subTest(current=repr(current)), patch.object(
                    process_lock,
                    "_open_validated_lock_file",
                    return_value=23,
                ), patch.object(process_lock, "_try_lock", return_value=True), patch.object(
                    process_lock,
                    "_unlock",
                ), patch.object(process_lock.os, "lstat", lstat), patch.object(
                    process_lock.os,
                    "fstat",
                    return_value=identity,
                ), patch.object(process_lock.os, "close"), self.assertRaises(OSError):
                    with process_lock.exclusive_file_lock(
                        lock,
                        timeout_seconds=1,
                    ):
                        self.fail("tampered lock entered")


if __name__ == "__main__":
    unittest.main()
