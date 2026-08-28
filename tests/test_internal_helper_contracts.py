from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import artifact_coordinates
import artifact_safety
import binary_decision_engine
import binary_performance_identity
import binary_report
from binary_entrypoint_discovery import BinaryEntrypointDiscoveryResult
from binary_fact_store import BinaryFactStore
import binary_output
from binary_platform_image import JdkPlatformImage
import binary_runtime_reconciler
import binary_semantic_overlay
import binary_validation_contract
import diagnostic_contract
import javap_session
import path_runtime
import process_lock
import progress_logging
import run_step
import runtime_contract
import s4_contract
import signature_utils


class InternalIdentityHelperContractTest(unittest.TestCase):
    def _compiled_javap_binding_fixture(self, root: Path):
        bin_dir = root / "jdk" / "bin"
        bin_dir.mkdir(parents=True)
        javap = bin_dir / "javap"
        java = bin_dir / "java"
        javap.write_bytes(b"pinned-javap")
        java.write_bytes(b"pinned-java")
        helper_source = root / "JavapSession.java"
        helper_source.write_bytes(b"final class JavapSession {}")
        output = root / "compiled"
        output.mkdir()
        helper_class = output / "JavapSession.class"
        helper_class.write_bytes(b"pinned-helper-bytecode")
        source_sha = hashlib.sha256(helper_source.read_bytes()).hexdigest()
        class_sha = hashlib.sha256(helper_class.read_bytes()).hexdigest()
        status = javap.stat()
        binding = javap_session.CompiledJavapSessionBinding(
            javap=str(javap.resolve()),
            javap_size=int(status.st_size),
            javap_mtime_ns=int(status.st_mtime_ns),
            java=str(java.resolve()),
            output=str(output.resolve()),
            helper_source_sha256=source_sha,
            helper_class_sha256=class_sha,
        )
        return javap.resolve(), helper_source, helper_class, binding

    def test_compiled_javap_binding_reuses_only_exact_parent_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            javap, helper_source, _helper_class, binding = (
                self._compiled_javap_binding_fixture(Path(temporary))
            )
            javap_session._EXTERNAL_COMPILED_HELPERS.clear()
            self.addCleanup(javap_session._EXTERNAL_COMPILED_HELPERS.clear)
            with patch.object(
                javap_session, "JAVA_HELPER", helper_source,
            ), patch.object(
                javap_session,
                "_CAPTURED_HELPER_SHA256",
                binding.helper_source_sha256,
            ), patch.object(javap_session, "_compile_helper") as compile_helper:
                javap_session.install_compiled_javap_session_binding(binding)
                compiled = javap_session._compiled_helper(javap)

            compile_helper.assert_not_called()
            self.assertEqual(compiled.output, Path(binding.output))
            self.assertEqual(compiled.java, binding.java)
            self.assertIsNone(compiled._owned_directory)

    def test_compiled_javap_binding_rejects_tampered_class_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            javap, helper_source, helper_class, binding = (
                self._compiled_javap_binding_fixture(Path(temporary))
            )
            helper_class.write_bytes(b"tampered-helper-bytecode")
            with patch.object(
                javap_session, "JAVA_HELPER", helper_source,
            ), patch.object(
                javap_session,
                "_CAPTURED_HELPER_SHA256",
                binding.helper_source_sha256,
            ):
                with self.assertRaises(javap_session.JavapSessionError):
                    javap_session.install_compiled_javap_session_binding(binding)

            self.assertNotIn(str(javap), javap_session._EXTERNAL_COMPILED_HELPERS)

    def test_idle_javap_sessions_use_bounded_protocol_shutdown(self):
        calls = []

        class IdleSession:
            def close(self, *, terminate=False):
                calls.append(terminate)

        pool = object.__new__(javap_session._SessionPool)
        pool._condition = threading.Condition()
        pool._idle = javap_session.queue.LifoQueue()
        pool._idle.put(IdleSession())
        pool._idle.put(IdleSession())
        pool._session_count = 2
        pool._closed = False

        pool.close()

        self.assertEqual(calls, [False, False])
        self.assertEqual(pool._session_count, 0)
        self.assertTrue(pool._closed)

    def test_compiled_javap_capture_rejects_every_bound_byte_and_path_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            javap, helper_source, helper_class, binding = (
                self._compiled_javap_binding_fixture(root)
            )
            compiled = javap_session._CompiledHelper(
                Path(binding.output), binding.java, None
            )
            with patch.object(
                javap_session, "JAVA_HELPER", helper_source
            ), patch.object(
                javap_session,
                "_CAPTURED_HELPER_SHA256",
                binding.helper_source_sha256,
            ), patch.object(
                javap_session, "_resolved_tool", return_value=javap
            ), patch.object(
                javap_session, "_compiled_helper", return_value=compiled
            ):
                self.assertEqual(
                    javap_session.capture_compiled_javap_session_binding(
                        str(javap)
                    ),
                    binding,
                )
            with patch.object(
                javap_session, "_resolved_tool", return_value=None
            ), self.assertRaises(javap_session.JavapSessionError):
                javap_session.capture_compiled_javap_session_binding("missing")
            with self.assertRaises(javap_session.JavapSessionError):
                javap_session.install_compiled_javap_session_binding(object())

            linked_output = root / "linked-output"
            linked_output.symlink_to(Path(binding.output), target_is_directory=True)
            empty_output = root / "empty-output"
            empty_output.mkdir()
            invalid = (
                replace(binding, javap=str(root / "different-javap")),
                replace(binding, javap_size=binding.javap_size + 1),
                replace(binding, javap_mtime_ns=binding.javap_mtime_ns + 1),
                replace(binding, java=str(root / "different-java")),
                replace(binding, output="relative"),
                replace(binding, output=str(linked_output)),
                replace(binding, helper_source_sha256="0" * 64),
                replace(binding, output=str(empty_output.resolve())),
                replace(binding, helper_class_sha256="0" * 64),
            )
            for index, changed in enumerate(invalid):
                with self.subTest(case=index), patch.object(
                    javap_session, "JAVA_HELPER", helper_source
                ), self.assertRaises(javap_session.JavapSessionError):
                    javap_session._compiled_from_binding(javap, changed)
            with patch.object(
                javap_session, "JAVA_HELPER", helper_source
            ), patch.object(
                javap_session, "_sibling_tool", return_value=None
            ), self.assertRaises(javap_session.JavapSessionError):
                javap_session._compiled_from_binding(javap, binding)

            self.assertEqual(javap_session._resolved_tool(str(javap)), javap)
            self.assertIsNone(
                javap_session._resolved_tool(str(root / "missing-tool"))
            )
            self.assertEqual(
                javap_session._sibling_tool(javap, "java"), Path(binding.java)
            )
            self.assertIsNone(javap_session._sibling_tool(javap, "missing"))
            self.assertTrue(helper_class.is_file())

    def test_javap_owned_directories_and_fork_state_are_process_local(self):
        calls = []
        path = Path("/private/owned-javap-test")
        javap_session._remove_owned_directory(
            path, 10, getpid=lambda: 11,
            rmtree=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
        self.assertEqual(calls, [])
        javap_session._remove_owned_directory(
            path, 10, getpid=lambda: 10,
            rmtree=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
        self.assertEqual(calls[0][0], (path,))

        with tempfile.TemporaryDirectory() as temporary:
            owned_path = Path(temporary) / "owned"

            def make_owned(**_kwargs):
                owned_path.mkdir()
                return owned_path

            with patch.object(
                javap_session, "make_short_temp_dir", side_effect=make_owned
            ):
                owned = javap_session._OwnedDirectory()
                self.assertTrue(owned.path.is_dir())
                owned.cleanup()
                self.assertFalse(owned.path.exists())

        javap_session._POOLS = {("old", 1, 1, "v"): object()}
        javap_session._EXTERNAL_COMPILED_HELPERS = {"old": object()}
        old_lock = javap_session._POOLS_LOCK
        javap_session._after_fork_in_child()
        self.assertEqual(javap_session._POOLS, {})
        self.assertEqual(javap_session._EXTERNAL_COMPILED_HELPERS, {})
        self.assertIsNot(javap_session._POOLS_LOCK, old_lock)

    def test_javap_protocol_readers_cover_chunking_and_length_bounds(self):
        class OneByteReader:
            def __init__(self, payload):
                self.payload = bytearray(payload)

            def read(self, _size):
                if not self.payload:
                    return b""
                return bytes((self.payload.pop(0),))

        self.assertEqual(
            javap_session._read_exact(OneByteReader(b"abc"), 3), b"abc"
        )
        with self.assertRaises(javap_session.JavapSessionError):
            javap_session._read_exact(OneByteReader(b"a"), 2)
        self.assertEqual(
            javap_session._read_payload(
                io.BytesIO((3).to_bytes(4, "big", signed=True) + b"abc"),
                "stdout",
            ),
            b"abc",
        )
        for length in (-1, javap_session.MAX_RESPONSE_BYTES + 1):
            with self.subTest(length=length), self.assertRaises(
                javap_session.JavapSessionError
            ):
                javap_session._read_payload(
                    io.BytesIO(length.to_bytes(4, "big", signed=True)),
                    "stdout",
                )

    def test_javap_helper_compile_session_start_and_public_fallback_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            javap = (bin_dir / "javap").resolve()
            java = (bin_dir / "java").resolve()
            javac = (bin_dir / "javac").resolve()
            source = (root / "JavapSession.java").resolve()
            for path, content in (
                (javap, b"javap"), (java, b"java"), (javac, b"javac"),
                (source, b"final class JavapSession {}"),
            ):
                path.write_bytes(content)
            source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            status = javap.stat()

            with patch.object(
                javap_session, "JAVA_HELPER", source
            ), self.assertRaises(javap_session.JavapSessionError):
                javap_session._compile_helper.__wrapped__(
                    str(javap), status.st_size, status.st_mtime_ns, "0" * 64
                )
            for missing in ("java", "javac"):
                def sibling(_javap, name, *, missing_name=missing):
                    if name == missing_name:
                        return None
                    return java if name == "java" else javac

                with self.subTest(missing=missing), patch.object(
                    javap_session, "JAVA_HELPER", source
                ), patch.object(
                    javap_session, "_sibling_tool", side_effect=sibling
                ), self.assertRaises(javap_session.JavapSessionError):
                    javap_session._compile_helper.__wrapped__(
                        str(javap), status.st_size, status.st_mtime_ns, source_sha
                    )

            def compile_result(returncode, *, create_class):
                def run(command, **_kwargs):
                    output = Path(command[command.index("-d") + 1])
                    if create_class:
                        (output / "JavapSession.class").write_bytes(b"class")
                    return SimpleNamespace(
                        returncode=returncode, stderr="stderr", stdout="stdout"
                    )
                return run

            for returncode, create_class in ((1, False), (0, False)):
                with self.subTest(
                    returncode=returncode, create_class=create_class
                ), patch.object(
                    javap_session, "JAVA_HELPER", source
                ), patch.object(
                    javap_session,
                    "run_managed_subprocess",
                    side_effect=compile_result(returncode, create_class=create_class),
                ), self.assertRaises(javap_session.JavapSessionError):
                    javap_session._compile_helper.__wrapped__(
                        str(javap), status.st_size, status.st_mtime_ns, source_sha
                    )

            def stdout_only_failure(_command, **_kwargs):
                return SimpleNamespace(
                    returncode=1, stderr="", stdout="stdout-only failure"
                )

            with patch.object(
                javap_session, "JAVA_HELPER", source
            ), patch.object(
                javap_session,
                "run_managed_subprocess",
                side_effect=stdout_only_failure,
            ), self.assertRaisesRegex(
                javap_session.JavapSessionError, "stdout-only failure"
            ):
                javap_session._compile_helper.__wrapped__(
                    str(javap), status.st_size, status.st_mtime_ns, source_sha
                )

            with patch.object(
                javap_session, "JAVA_HELPER", source
            ), patch.object(
                javap_session,
                "run_managed_subprocess",
                side_effect=compile_result(0, create_class=True),
            ):
                compiled = javap_session._compile_helper.__wrapped__(
                    str(javap), status.st_size, status.st_mtime_ns, source_sha
                )
            self.assertTrue((compiled.output / "JavapSession.class").is_file())
            compiled._owned_directory.cleanup()

            calls = []

            class EmptyThread:
                def __init__(self, *, target, **_kwargs):
                    self.target = target

                def start(self):
                    self.target()

            process = SimpleNamespace(
                stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO(),
                poll=lambda: 0,
            )
            with patch.object(
                javap_session, "JAVAP_STABLE_JVM_OPTIONS", ("-J-Xexact", "plain")
            ), patch.object(
                javap_session,
                "managed_popen",
                side_effect=lambda command, **_kwargs: calls.append(command) or process,
            ), patch.object(javap_session.threading, "Thread", EmptyThread):
                session = javap_session._Session(
                    javap_session._CompiledHelper(root, str(java), None)
                )
            self.assertIn("-Xexact", calls[0])
            self.assertNotIn("plain", calls[0])
            self.assertFalse(session.alive)

            cancelled = threading.Event()
            cancelled.set()
            self.assertIsNone(javap_session.run_persistent_javap(
                str(javap), (), "v", cancelled, time.perf_counter() + 1
            ))
            with patch.object(
                javap_session, "_resolved_tool", return_value=None
            ):
                self.assertIsNone(javap_session.run_persistent_javap(
                    "missing", (), "v", threading.Event(),
                    time.perf_counter() + 1,
                ))
            with patch.object(
                javap_session, "_resolved_tool", return_value=javap
            ), patch.object(
                javap_session, "_pool_key", return_value=("key", 1, 1, "v")
            ), patch.object(
                javap_session,
                "_SessionPool",
                side_effect=javap_session.JavapSessionError("expected"),
            ):
                javap_session._POOLS.clear()
                self.assertIsNone(javap_session.run_persistent_javap(
                    str(javap), (), "v", threading.Event(),
                    time.perf_counter() + 1,
                ))

    @staticmethod
    def _javap_response(returncode=0, stdout=b"ok", stderr=b""):
        return b"".join((
            javap_session._RESPONSE_MAGIC,
            int(returncode).to_bytes(4, "big", signed=True),
            len(stdout).to_bytes(4, "big", signed=True), stdout,
            len(stderr).to_bytes(4, "big", signed=True), stderr,
        ))

    def test_javap_session_exchange_and_close_fail_closed(self):
        def session_for(payload, *, poll=lambda: None, stdin=None, stdout=True):
            session = object.__new__(javap_session._Session)
            session._closed = False
            session._stderr_tail = bytearray(b"diagnostic")
            session.process = SimpleNamespace(
                stdin=io.BytesIO() if stdin is None else stdin,
                stdout=io.BytesIO(payload) if stdout is True else stdout,
                stderr=io.BytesIO(),
                poll=poll,
            )
            return session

        cancellation = threading.Event()
        success = session_for(self._javap_response(3, b"out", b"err"))
        result = success.exchange(
            ("-c", "demo.Sample"), cancellation, time.perf_counter() + 5
        )
        self.assertEqual((result.returncode, result.stdout, result.stderr), (3, "out", "err"))

        dead = session_for(self._javap_response(), poll=lambda: 1)
        with self.assertRaises(javap_session.JavapSessionError):
            dead.exchange((), cancellation, time.perf_counter() + 1)
        with patch.object(javap_session, "MAX_ARGUMENTS", 0), self.assertRaises(
            javap_session.JavapSessionError
        ):
            success.exchange(("one",), cancellation, time.perf_counter() + 1)
        with patch.object(
            javap_session, "MAX_ARGUMENT_BYTES", 0
        ), self.assertRaises(javap_session.JavapSessionError):
            success.exchange(("one",), cancellation, time.perf_counter() + 1)
        for stdin, stdout in ((None, io.BytesIO()), (io.BytesIO(), None)):
            missing = session_for(
                self._javap_response(), stdin=stdin, stdout=stdout
            )
            if stdin is None:
                missing.process.stdin = None
            with self.assertRaises(javap_session.JavapSessionError):
                missing.exchange((), cancellation, time.perf_counter() + 1)

        class BrokenWriter(io.BytesIO):
            def write(self, _value):
                raise BrokenPipeError("closed")

        broken = session_for(self._javap_response(), stdin=BrokenWriter())
        with self.assertRaises(javap_session.JavapSessionError):
            broken.exchange((), cancellation, time.perf_counter() + 1)
        bad_magic = session_for(b"BAD!" + self._javap_response()[4:])
        with self.assertRaises(javap_session.JavapSessionError):
            bad_magic.exchange((), cancellation, time.perf_counter() + 1)

        for cancelled, deadline in (
            (True, time.perf_counter() + 5),
            (False, time.perf_counter() - 1),
        ):
            pending = session_for(self._javap_response())
            event = threading.Event()
            if cancelled:
                event.set()

            class PendingThread:
                def __init__(self, **_kwargs):
                    pass

                def start(self):
                    pass

                def join(self, **_kwargs):
                    pass

            with self.subTest(cancelled=cancelled), patch.object(
                javap_session.threading, "Thread", PendingThread
            ), patch.object(pending, "close") as close, self.assertRaises(
                javap_session.JavapSessionError
            ):
                pending.exchange((), event, deadline)
            close.assert_called_once_with(terminate=True)

        class CloseHandle(io.BytesIO):
            def __init__(self, *, fail=False):
                super().__init__()
                self.fail = fail

            def close(self):
                if self.fail:
                    self.fail = False
                    raise OSError("expected")
                super().close()

        calls = []
        process = SimpleNamespace(
            stdin=CloseHandle(), stdout=CloseHandle(fail=True), stderr=None,
            poll=lambda: None,
            wait=lambda timeout: calls.append(("wait", timeout)),
        )
        closing = object.__new__(javap_session._Session)
        closing._closed = False
        closing._stderr_tail = bytearray()
        closing.process = process
        with patch.object(
            javap_session, "terminate_process_tree",
            side_effect=lambda _process: calls.append(("terminate", None)),
        ), patch.object(
            javap_session, "release_process_tree",
            side_effect=lambda _process: calls.append(("release", None)),
        ):
            closing.close(terminate=True)
            closing.close(terminate=False)
        self.assertIn(("terminate", None), calls)
        self.assertEqual(calls[-1], ("release", None))

        exited_process = SimpleNamespace(
            stdin=CloseHandle(), stdout=None, stderr=None,
            poll=lambda: 1,
            wait=lambda timeout: calls.append(("exited-wait", timeout)),
        )
        exited_closing = object.__new__(javap_session._Session)
        exited_closing._closed = False
        exited_closing._stderr_tail = bytearray()
        exited_closing.process = exited_process
        with patch.object(
            javap_session, "terminate_process_tree"
        ) as terminate, patch.object(javap_session, "release_process_tree"):
            exited_closing.close(terminate=True)
        terminate.assert_not_called()

        closed = session_for(self._javap_response())
        closed._closed = True
        self.assertFalse(closed.alive)

        for stderr in (None, io.BytesIO(b"x" * (70 * 1024))):
            draining = session_for(self._javap_response())
            draining.process.stderr = stderr
            draining._drain_stderr()
            if stderr is not None:
                self.assertEqual(len(draining._stderr_tail), 64 * 1024)

        class BrokenReader:
            def read(self, _size):
                raise OSError("expected")

        draining = session_for(self._javap_response())
        draining.process.stderr = BrokenReader()
        draining._drain_stderr()

        no_handles = session_for(self._javap_response(), poll=lambda: 1)
        no_handles.process.stdin = None
        no_handles.process.stdout = None
        no_handles.process.stderr = None
        no_handles.process.wait = lambda timeout: None
        with patch.object(javap_session, "release_process_tree") as release:
            no_handles.close(terminate=False)
        release.assert_called_once_with(no_handles.process)

    def test_javap_session_pool_covers_identity_lease_and_cleanup_matrix(self):
        cancellation = threading.Event()

        class FakeSession:
            def __init__(self, result=None, error=None, alive=True, close_error=None):
                self.result = result or javap_session.JavapSessionResult(0, "v", "")
                self.error = error
                self.alive = alive
                self.close_error = close_error
                self.closed = []

            def exchange(self, *_args):
                if self.error:
                    raise self.error
                return self.result

            def close(self, *, terminate):
                self.closed.append(terminate)
                if self.close_error:
                    raise self.close_error

        pool = object.__new__(javap_session._SessionPool)
        pool.expected_version = "v"
        pool._compiled = object()
        for result in (
            javap_session.JavapSessionResult(1, "v", ""),
            javap_session.JavapSessionResult(0, "wrong", ""),
        ):
            candidate = FakeSession(result=result)
            with patch.object(javap_session, "_Session", return_value=candidate), self.assertRaises(
                javap_session.JavapSessionError
            ):
                pool._new_session(cancellation, time.perf_counter() + 1)
            self.assertEqual(candidate.closed, [True])
        candidate = FakeSession()
        with patch.object(javap_session, "_Session", return_value=candidate):
            self.assertIs(
                pool._new_session(cancellation, time.perf_counter() + 1),
                candidate,
            )
        stderr_candidate = FakeSession(
            result=javap_session.JavapSessionResult(0, "", "v")
        )
        with patch.object(
            javap_session, "_Session", return_value=stderr_candidate
        ):
            self.assertIs(
                pool._new_session(cancellation, time.perf_counter() + 1),
                stderr_candidate,
            )

        lease = object.__new__(javap_session._SessionPool)
        lease._condition = threading.Condition()
        lease._idle = javap_session.queue.LifoQueue()
        lease._session_count = 0
        lease.max_sessions = 1
        lease._closed = False
        created = FakeSession()
        lease._new_session = lambda *_args: created
        self.assertIs(
            lease._acquire(cancellation, time.perf_counter() + 1), created
        )
        lease._idle.put(created)
        self.assertIs(
            lease._acquire(cancellation, time.perf_counter() + 1), created
        )
        lease._closed = True
        with self.assertRaises(javap_session.JavapSessionError):
            lease._acquire(cancellation, time.perf_counter() + 1)
        lease._closed = False
        lease._session_count = 1
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(javap_session.JavapSessionError):
            lease._acquire(cancelled, time.perf_counter() + 1)
        with self.assertRaises(javap_session.JavapSessionError):
            lease._acquire(threading.Event(), time.perf_counter() - 1)
        wait_event = threading.Event()

        def cancel_after_wait(*_args, **_kwargs):
            wait_event.set()

        with patch.object(
            lease._condition, "wait", side_effect=cancel_after_wait
        ), self.assertRaises(javap_session.JavapSessionError):
            lease._acquire(wait_event, time.perf_counter() + 1)
        self.assertTrue(wait_event.is_set())

        run_pool = object.__new__(javap_session._SessionPool)
        run_pool._condition = threading.Condition()
        run_pool._idle = javap_session.queue.LifoQueue()
        run_pool._session_count = 1
        run_pool._closed = False
        reusable = FakeSession(alive=True)
        run_pool._acquire = lambda *_args: reusable
        self.assertEqual(
            run_pool.run((), cancellation, time.perf_counter() + 1).stdout,
            "v",
        )
        self.assertIs(run_pool._idle.get_nowait(), reusable)
        run_pool._closed = True
        closed_reusable = FakeSession(alive=True)
        run_pool._acquire = lambda *_args: closed_reusable
        run_pool._session_count = 1
        run_pool.run((), cancellation, time.perf_counter() + 1)
        self.assertEqual(closed_reusable.closed, [True])
        self.assertEqual(run_pool._session_count, 0)
        run_pool._closed = False
        disposable = FakeSession(alive=False)
        run_pool._acquire = lambda *_args: disposable
        run_pool._session_count = 1
        run_pool.run((), cancellation, time.perf_counter() + 1)
        self.assertEqual(disposable.closed, [True])
        self.assertEqual(run_pool._session_count, 0)

        failure_pool = object.__new__(javap_session._SessionPool)
        failure_pool._condition = threading.Condition()
        failure_pool._idle = javap_session.queue.LifoQueue()
        failure_pool._session_count = 1
        failure_pool._closed = False
        failing = FakeSession(
            error=javap_session.JavapSessionError("expected"), alive=False
        )
        failure_pool._acquire = lambda *_args: failing
        with self.assertRaises(javap_session.JavapSessionError):
            failure_pool.run((), cancellation, time.perf_counter() + 1)
        self.assertEqual(failing.closed, [True])

        already_closed = object.__new__(javap_session._SessionPool)
        already_closed._condition = threading.Condition()
        already_closed._idle = javap_session.queue.LifoQueue()
        already_closed._session_count = 0
        already_closed._closed = True
        already_closed.close()
        close_failure = object.__new__(javap_session._SessionPool)
        close_failure._condition = threading.Condition()
        close_failure._idle = javap_session.queue.LifoQueue()
        close_failure._idle.put(FakeSession(close_error=RuntimeError("close")))
        close_failure._session_count = 1
        close_failure._closed = False
        with self.assertRaisesRegex(RuntimeError, "close"):
            close_failure.close()

    def test_javap_pool_registry_reuses_exact_tool_identity_and_closes_all(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            javap = root / "javap"
            javap.write_bytes(b"javap")
            compiled = javap_session._CompiledHelper(root, "java", None)
            with patch.object(
                javap_session, "_compiled_helper", return_value=compiled
            ):
                pool = javap_session._SessionPool(javap, "version", 999)
                self.assertEqual(pool.max_sessions, javap_session.MAX_SESSION_PROCESSES)
                self.assertIs(pool._compiled, compiled)
                small = javap_session._SessionPool(javap, "version", 0)
                self.assertEqual(small.max_sessions, 1)

            binding = object()
            with patch.object(
                javap_session, "_compile_helper", return_value=compiled
            ) as compile_helper:
                javap_session._EXTERNAL_COMPILED_HELPERS.clear()
                self.assertIs(javap_session._compiled_helper(javap), compiled)
            compile_helper.assert_called_once()
            with patch.object(
                javap_session, "_compiled_from_binding", return_value=compiled
            ) as from_binding:
                javap_session._EXTERNAL_COMPILED_HELPERS[str(javap)] = binding
                self.assertIs(javap_session._compiled_helper(javap), compiled)
            from_binding.assert_called_once_with(javap, binding)

            calls = []

            class FakePool:
                def __init__(self, *_args):
                    calls.append("created")

                def run(self, arguments, *_args):
                    calls.append(tuple(arguments))
                    return javap_session.JavapSessionResult(0, "ok", "")

                def close(self):
                    calls.append("closed")

            javap_session._POOLS.clear()
            event = threading.Event()
            with patch.object(
                javap_session, "_resolved_tool", return_value=javap
            ), patch.object(
                javap_session, "_pool_key", return_value=("key", 1, 1, "v")
            ), patch.object(javap_session, "_SessionPool", FakePool):
                self.assertEqual(
                    javap_session.run_persistent_javap(
                        str(javap), (), "v", event, time.perf_counter() + 1
                    ).stdout,
                    "ok",
                )
                self.assertEqual(
                    javap_session.run_persistent_javap(
                        str(javap), ("-c",), "v", event,
                        time.perf_counter() + 1,
                    ).stdout,
                    "ok",
                )
            self.assertEqual(calls.count("created"), 1)
            self.assertIn((), calls)
            self.assertIn(("-c",), calls)
            javap_session.close_persistent_javap_sessions()
            self.assertIn("closed", calls)
            javap_session.close_persistent_javap_sessions()

            with patch.object(
                javap_session.shutil, "which", return_value=str(javap)
            ):
                self.assertEqual(
                    javap_session._resolved_tool("javap"), javap.resolve()
                )
            windows_java = root / "java.exe"
            windows_java.write_bytes(b"java")
            with patch.object(javap_session.os, "name", "nt"):
                self.assertEqual(
                    javap_session._sibling_tool(javap, "java"), windows_java
                )

    def test_performance_identity_rejects_every_structural_boundary(self):
        valid_sha = "a" * 64
        valid_source_components = {
            "generation_source_identity": "1" * 64,
            "validator_source_identity": "2" * 64,
            "oracle_support_manifest_identity": "3" * 64,
            "harness_source_identity": "4" * 64,
        }
        valid_runtime_components = {
            "source_implementation_identity": "5" * 64,
            "pipeline_generation_implementation_identity": "6" * 64,
            "validator_implementation_identity": "7" * 64,
            "jdk_preflight_identity": "8" * 64,
        }

        invalid_record_sets = (
            [None],
            [{"path": "", "sha256": valid_sha}],
            [{"path": "@runtime/jdk", "sha256": valid_sha}],
        )
        for records in invalid_record_sets:
            with self.subTest(records=records), self.assertRaises(ValueError):
                binary_performance_identity.generation_source_identity(records)

        for builder, components in (
            (
                binary_performance_identity.source_implementation_identity,
                valid_source_components,
            ),
            (
                binary_performance_identity.runtime_implementation_identity,
                valid_runtime_components,
            ),
        ):
            with self.subTest(builder=builder.__name__), self.assertRaises(
                ValueError
            ):
                builder(None)

    def test_validation_identity_rejects_incomplete_sources_and_manifest_shape(self):
        incomplete = dict(
            binary_validation_contract._CAPTURED_VALIDATOR_SOURCE_DIGESTS
        )
        incomplete.pop(next(iter(incomplete)))

        for builder, args in (
            (
                binary_validation_contract._validator_implementation_payload,
                (
                    incomplete,
                    binary_validation_contract._CAPTURED_PYTHON_RUNTIME_IDENTITY,
                ),
            ),
            (
                binary_validation_contract._validator_source_identity_from_inputs,
                (incomplete,),
            ),
        ):
            with self.subTest(builder=builder.__name__), self.assertRaises(
                binary_validation_contract.BinaryValidationContractError
            ):
                builder(*args)

        with patch.object(
            binary_validation_contract.sys,
            "implementation",
            SimpleNamespace(name="cpython", cache_tag=None),
        ):
            self.assertEqual(
                binary_validation_contract._python_runtime_identity()["cache_tag"],
                "",
            )

        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "support.json"
            manifest.write_text(
                '{"oracle_support_manifest": []}',
                encoding="utf-8",
            )
            with patch.object(
                binary_validation_contract,
                "SUPPORT_MANIFEST_PATH",
                manifest,
            ), self.assertRaises(
                binary_validation_contract.BinaryValidationContractError
            ):
                binary_validation_contract._load_oracle_support_manifest()

    def test_runtime_and_checkpoint_configuration_loaders_are_deterministic(self):
        runtime_identity = binary_report._report_runtime_identity()
        self.assertEqual(runtime_identity["implementation"], sys.implementation.name)
        self.assertEqual(
            runtime_identity["version"],
            [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            requirements = root / "requirements.txt"
            requirements.write_text(
                "# exact runtime truth\nalpha-package==1.2.3\n\n"
                "beta-package==4.5.6\n",
                encoding="utf-8",
            )
            self.assertEqual(
                runtime_contract._load_required_packages(requirements),
                {
                    "alpha-package": "1.2.3",
                    "beta-package": "4.5.6",
                },
            )

            rules = root / "CHECKPOINT_RULES.md"
            rules.write_text(
                "# ignored heading\nfirst rule\n\nsecond rule\n",
                encoding="utf-8",
            )
            with patch.object(run_step, "CHECKPOINT_RULES_FILE", rules):
                self.assertEqual(
                    run_step.load_checkpoint_rules(),
                    ["first rule", "second rule"],
                )

    def test_classifier_boolean_and_constructor_normalization_boundaries(self):
        self.assertEqual(
            artifact_coordinates.artifact_classifier("g:a:test-fixtures"),
            "test-fixtures",
        )
        self.assertEqual(artifact_coordinates.artifact_classifier("g:a"), "")
        self.assertEqual(artifact_coordinates.artifact_classifier("broken"), "")

        coordinate_cases = (
            (None, ("", "", ""), "", ""),
            ("", ("", "", ""), "", ""),
            ("single", ("", "", ""), "", "single"),
            (":artifact", ("", "", ""), "", ":artifact"),
            ("group:", ("", "", ""), "", "group:"),
            (" group : artifact ", ("group", "artifact", ""), "group:artifact", "group:artifact"),
            (
                "group:artifact::tests:",
                ("group", "artifact", "tests"),
                "group:artifact",
                "group:artifact:tests",
            ),
        )
        for raw, split, ga, normalized in coordinate_cases:
            with self.subTest(coordinate=raw):
                self.assertEqual(artifact_coordinates.split_artifact_coord(raw), split)
                self.assertEqual(artifact_coordinates.artifact_ga(raw), ga)
                self.assertEqual(
                    artifact_coordinates.normalize_artifact_coord(raw),
                    normalized,
                )
        self.assertEqual(
            artifact_coordinates.normalize_artifact_coord(
                "group:artifact:declared", "ignored",
            ),
            "group:artifact:declared",
        )
        self.assertEqual(
            artifact_coordinates.normalize_artifact_coord(
                "group:artifact", " runtime ",
            ),
            "group:artifact:runtime",
        )
        self.assertEqual(
            artifact_coordinates.normalize_artifact_coord("group:artifact", ""),
            "group:artifact",
        )

        for value in (True, 1, -2, "TRUE", " yes ", "on"):
            self.assertTrue(binary_semantic_overlay._as_bool(value))
        for value in (False, 0, 0.0, None, "false", "off", ""):
            self.assertFalse(binary_semantic_overlay._as_bool(value))

        self.assertEqual(
            signature_utils._canonical_constructor_name("a.b.Widget.Widget"),
            "a.b.Widget.<init>",
        )
        self.assertEqual(
            signature_utils._canonical_constructor_name("a.b.Widget.<init>"),
            "a.b.Widget.<init>",
        )
        self.assertEqual(
            signature_utils._canonical_constructor_name("a.b.Outer$Inner"),
            "a.b.Outer.Inner.<init>",
        )
        self.assertEqual(signature_utils._canonical_constructor_name(""), "")
        self.assertEqual(
            signature_utils.canonical_api_identity_tuple({
                "coord": "g:a:1",
                "symbol_kind": "constructor",
                "api_name": "demo.Widget.Widget",
                "api_signature": "( java.lang.String )",
                "change_type": "removed",
            }),
            (
                "g:a:1",
                "demo.Widget.<init>",
                "(java.lang.String)",
                "constructor",
                "REMOVED",
            ),
        )

    def test_entrypoint_payload_is_a_stable_public_projection(self):
        result = BinaryEntrypointDiscoveryResult(
            exact_member_identities=("exact-1", "exact-2"),
            possible_member_identities=("possible-1",),
            records=({"kind": "main", "identity": "exact-1"},),
            coverage_status="partial",
            coverage_gaps=("FRAMEWORK_PROFILE_INCOMPLETE",),
            identity="discovery-identity",
        )

        self.assertEqual(result.as_payload(), {
            "schema": "java-upgrade-analyzer.binary-entrypoint-discovery.v1",
            "discovery_policy_version": (
                __import__("binary_entrypoint_discovery")
                .DISCOVERY_POLICY_VERSION
            ),
            "entrypoint_discovery_identity": "discovery-identity",
            "coverage_status": "partial",
            "coverage_gaps": ["FRAMEWORK_PROFILE_INCOMPLETE"],
            "exact_entrypoint_count": 2,
            "possible_entrypoint_count": 1,
            "records": [{"kind": "main", "identity": "exact-1"}],
        })

    def test_compact_rows_preserve_missing_values_and_mapping_union_order(self):
        class Row(binary_runtime_reconciler._CompactRow):
            FIELDS = ("left", "missing", "right")
            INDEX = {name: index for index, name in enumerate(FIELDS)}

        row = Row((1, binary_runtime_reconciler._MISSING_COMPACT_VALUE, 3))

        self.assertEqual(list(row), ["left", "right"])
        self.assertEqual(dict(row), {"left": 1, "right": 3})
        self.assertEqual(row | {"right": 4, "new": 5}, {
            "left": 1, "right": 4, "new": 5,
        })
        self.assertEqual({"left": 0, "first": -1} | row, {
            "left": 1, "first": -1, "right": 3,
        })
        with self.assertRaises(KeyError):
            _ = row["missing"]


class InternalFailureHelperContractTest(unittest.TestCase):
    def test_archive_changed_result_and_cache_reset_fail_closed(self):
        result = artifact_safety._changed_during_scan_result()
        self.assertFalse(result.safe)
        self.assertEqual(result.reason_codes, ("ARCHIVE_CHANGED_DURING_SCAN",))
        self.assertEqual(result.entry_count, 0)

        with artifact_safety._ARCHIVE_CACHE_CONDITION:
            before = artifact_safety._ARCHIVE_CACHE_GENERATION
            artifact_safety._ARCHIVE_SAFETY_CACHE[("x", "y", ())] = result
        artifact_safety.clear_archive_safety_cache()
        self.assertEqual(artifact_safety._ARCHIVE_SAFETY_CACHE, {})
        self.assertEqual(artifact_safety._ARCHIVE_CACHE_GENERATION, before + 1)

    def test_cached_archive_scan_rejects_post_scan_digest_change(self):
        safe = artifact_safety.ArchiveSafetyResult(
            safe=True,
            reason_codes=(),
            entry_count=1,
            total_uncompressed_bytes=1,
            nested_archives=0,
            max_observed_depth=0,
        )
        artifact_safety.clear_archive_safety_cache()
        try:
            with patch.object(
                artifact_safety, "_inspect_archive_source", return_value=safe,
            ), patch.object(
                artifact_safety, "_sha256_file", return_value="changed",
            ):
                result = artifact_safety._cached_archive_inspection(
                    "/definitely/not/read/by/the/patched/scanner.jar",
                    "expected",
                    (),
                )
        finally:
            artifact_safety.clear_archive_safety_cache()

        self.assertFalse(result.safe)
        self.assertEqual(
            result.reason_codes, ("ARCHIVE_CHANGED_DURING_SCAN",),
        )

    def test_require_safe_archive_inspects_missing_input_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.jar"
            with self.assertRaisesRegex(
                ValueError, "artifact_safety_violation:ARCHIVE_READ_FAILED",
            ):
                artifact_safety.require_safe_archive(missing)

    def test_unlink_helper_accepts_existing_and_already_missing_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned.txt"
            path.write_text("owned", encoding="utf-8")
            binary_output._unlink_missing_ok(path)
            self.assertFalse(path.exists())
            binary_output._unlink_missing_ok(path)

    def test_platform_failure_normalizes_class_name_before_lookup(self):
        image = object.__new__(JdkPlatformImage)
        image._facts = {}
        image._failures = {"java/lang/Missing": {"reason": "not found"}}
        image.ensure_classes = MagicMock()

        self.assertEqual(
            image.failure("java.lang.Missing"), {"reason": "not found"},
        )
        image.ensure_classes.assert_not_called()

    def test_diagnostic_mapping_is_shallow_immutable_and_canonical(self):
        source = {
            "reason_code": "binary pipeline timeout",
            "reason_codes": ["archive unsafe", "ARCHIVE_UNSAFE"],
            "nested": {"reason_code": "leave-me"},
        }
        normalized = diagnostic_contract.normalize_diagnostic_mapping(source)

        self.assertIsNot(normalized, source)
        self.assertEqual(source["reason_code"], "binary pipeline timeout")
        self.assertEqual(
            normalized["reason_code"],
            diagnostic_contract.canonical_reason_code(
                "binary pipeline timeout"
            ),
        )
        self.assertEqual(normalized["nested"], {"reason_code": "leave-me"})
        self.assertEqual(
            diagnostic_contract.normalize_diagnostic_mapping("raw"), "raw",
        )

        payload = diagnostic_contract.normalize_diagnostic_payload({
            "reason_codes": ["archive unsafe", "ARCHIVE_UNSAFE"],
        })
        self.assertEqual(payload["reason_codes"], ["ARCHIVE_UNSAFE"])

    def test_conditional_property_default_is_evaluated_through_boolean_policy(self):
        builder = object.__new__(binary_semantic_overlay._Builder)
        builder.profile = SimpleNamespace(payload={
            "active_profile_identities": [],
            "resolved_configuration_properties": {},
            "runtime_configuration_coverage_status": "complete",
        })
        builder.selected = {}
        fact = {
            "annotations": [{
                "descriptor": (
                    "Lorg/springframework/boot/autoconfigure/condition/"
                    "ConditionalOnProperty;"
                ),
                "visible": True,
                "values": [
                    ["name", "feature.enabled"],
                    ["matchIfMissing", True],
                ],
            }],
        }

        self.assertEqual(builder._condition_certainty("application", fact), "exact")

    def test_lock_open_preserves_primary_validation_error_and_close_failure(self):
        regular = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=stat.S_IFREG | 0o600,
            st_nlink=1,
            st_size=0,
        )
        lock_os = SimpleNamespace(
            O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
            O_RDWR=os.O_RDWR,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
            SEEK_SET=os.SEEK_SET,
            lstat=MagicMock(
                side_effect=[FileNotFoundError(), FileNotFoundError()],
            ),
            open=MagicMock(return_value=17),
            fstat=MagicMock(return_value=regular),
            close=MagicMock(side_effect=OSError("close denied")),
        )
        with patch.object(process_lock, "os", lock_os):
            with self.assertRaises(OSError) as raised:
                process_lock._open_validated_lock_file(Path("owned.lock"))

        self.assertEqual(raised.exception.errno, process_lock.errno.ESTALE)
        self.assertIn(
            "cleanup failed (close rejected lock descriptor): "
            "OSError: close denied",
            "\n".join(getattr(raised.exception, "__notes__", ()) or ()),
        )


class InternalPersistenceHelperContractTest(unittest.TestCase):
    def test_direct_seal_registry_replaces_same_operation_and_invalidates_root(self):
        root = Path("/private/test-output").resolve()
        snapshot = (1, 2, stat.S_IFREG | 0o600, 1, 10, 20)

        def capability(identity):
            return binary_output._DirectSealCapability(
                sequence=0,
                owner_process_identity=os.getpid(),
                owner_thread_identity=1,
                canonical_root=root,
                root_identity=(1, 2),
                probed_device=1,
                operation_key=("seal", "same-operation"),
                result_generation_identity=identity,
                validation_run_identity="b" * 64,
                validation_result_sha256="c" * 64,
                activation_identity="d" * 64,
                unsealed_descriptor_bytes=b"{}\n",
                predecessor_bytes=None,
                descriptor_before_identity=None,
                descriptor_after_identity=(3, 4),
                descriptor_snapshot=snapshot,
                publication_authority_bytes=None,
                directory_snapshots=(),
                file_snapshots=(),
            )

        binary_output._reset_direct_seal_fast_path_after_fork()
        try:
            binary_output._install_direct_seal_capability(capability("a" * 64))
            binary_output._DIRECT_SEAL_FAST_PATH_CONTEXT.set(None)
            binary_output._install_direct_seal_capability(capability("e" * 64))
            self.assertEqual(
                len(binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY), 1,
            )

            binary_output._DIRECT_SEAL_FAST_PATH_CONTEXT.set(None)
            binary_output._invalidate_direct_seal_capabilities_for_root(root)
            self.assertEqual(binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY, {})
            self.assertEqual(binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION, {})
        finally:
            binary_output._reset_direct_seal_fast_path_after_fork()

    def test_runtime_accumulator_flushes_at_the_configured_chunk_boundary(self):
        store = SimpleNamespace(add_reconciliation_payloads=MagicMock())
        with patch.object(
            binary_runtime_reconciler._ReconciliationAccumulator,
            "CHUNK_SIZE",
            1,
        ):
            accumulator = binary_runtime_reconciler._ReconciliationAccumulator(
                store,
                "analysis-context",
                retained_kinds={"linkage_resolution"},
            )
            accumulator.add("linkage_resolution", {
                "linkage_status": "resolved",
                "linkage_resolution_identity": "a" * 64,
            })

        store.add_reconciliation_payloads.assert_called_once()
        self.assertEqual(accumulator.pending["linkage_resolution"], [])

    def test_resource_selection_uses_platform_realm_when_parent_is_implicit(self):
        reconciler = object.__new__(binary_runtime_reconciler.RuntimeReconciler)
        reconciler.realms = {
            "platform-loader": {"kind": "platform"},
            "application-loader": {
                "kind": "application",
                "delegation": "parent_first",
            },
        }
        reconciler.resource_candidates_by_realm_name = {
            ("application-loader", "META-INF/services/demo.Service"): [
                {"physical_entry_identity": "resource-1"},
            ],
        }

        rows, gaps = reconciler._selected_resources(
            "application-loader",
            "META-INF/services/demo.Service",
            "ordered_all",
        )

        self.assertEqual(
            [row["physical_entry_identity"] for row in rows], ["resource-1"],
        )
        self.assertEqual(gaps, [])

    def test_symbolic_member_visited_path_delegates_to_cycle_safe_resolver(self):
        reconciler = object.__new__(binary_runtime_reconciler.RuntimeReconciler)

        self.assertEqual(
            reconciler._resolve_symbolic_member(
                "application-loader",
                "demo/Api",
                "method",
                "run",
                "()V",
                visited=(("application-loader", "demo/Api"),),
            ),
            (None, None),
        )

    def test_constant_dynamic_edge_payload_is_decoded_and_persisted(self):
        edge = {
            "direct_edge_identity": "edge-1",
            "caller_member_identity": "member-1",
            "caller_artifact_instance_identity": "artifact-1",
            "instruction_index": 0,
            "bytecode_offset": 0,
            "edge_kind": "ldc_constant_dynamic",
            "opcode": 18,
            "symbolic_owner": "",
            "symbolic_name": "constant",
            "symbolic_descriptor": "Ljava/lang/String;",
            "edge_json": '{"bootstrap":{"owner":"demo/Bootstrap"}}',
        }
        reconciler = object.__new__(binary_runtime_reconciler.RuntimeReconciler)
        reconciler.classes = [{
            "artifact_instance_identity": "artifact-1",
            "class_variant_identity": "variant-1",
            "class_name": "demo/Caller",
        }]
        reconciler.artifacts = {
            "artifact-1": {"loader_realm_identity": "application-loader"},
        }
        reconciler.member_by_identity = {
            "member-1": {"class_variant_identity": "variant-1"},
        }
        reconciler.profile = SimpleNamespace(
            complete=True,
            payload={"runtime_class_closure_coverage_status": "complete"},
        )
        reconciler.capability = SimpleNamespace(closed_world_dispatch=True)
        reconciler.coverage_gaps = set()
        reconciler.store = SimpleNamespace(
            connection=SimpleNamespace(execute=MagicMock(return_value=[edge])),
        )
        reconciler._provider = MagicMock(return_value={
            "class_provider_status": "resolved",
            "selected_class_variant_identity": "variant-1",
            "selected_defining_loader_realm_identity": "application-loader",
        })
        accumulator = SimpleNamespace(add=MagicMock())

        reconciler._resolve_edges((), accumulator)

        kind, record = accumulator.add.call_args.args
        self.assertEqual(kind, "linkage_resolution")
        self.assertEqual(record["payload"], {
            "bootstrap": {"owner": "demo/Bootstrap"},
        })
        self.assertEqual(record["linkage_status"], "represented_by_bootstrap_handles")

    def test_fact_store_descriptor_and_member_insert_contract(self):
        self.assertEqual(BinaryFactStore._descriptor_owner("[[Ldemo/Thing;"), "demo/Thing")
        self.assertEqual(BinaryFactStore._descriptor_owner("[I"), "")
        self.assertEqual(BinaryFactStore._descriptor_owner("Lbroken"), "")

        store = object.__new__(BinaryFactStore)
        store.connection = MagicMock()
        values = tuple(range(10))
        with patch.object(
            BinaryFactStore,
            "_member_values",
            return_value=("member-id", values),
        ) as member_values:
            identity = store._insert_member(
                "variant", "artifact", "demo/Thing", "method",
                {"name": "run", "descriptor": "()V"}, "digest",
            )

        self.assertEqual(identity, "member-id")
        member_values.assert_called_once()
        store.connection.execute.assert_called_once_with(
            "INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?)", values,
        )

    def test_provider_fingerprint_distinguishes_absent_and_exact_payload(self):
        engine = object.__new__(binary_decision_engine.BinaryDecisionEngine)
        with patch.object(
            binary_decision_engine.BinaryDecisionEngine,
            "_provider_outcome_payload",
            return_value=None,
        ):
            self.assertEqual(engine._provider_fingerprint(None, None, {}), "ABSENT")

        payload = {"status": "resolved", "class_name": "demo/Thing"}
        with patch.object(
            binary_decision_engine.BinaryDecisionEngine,
            "_provider_outcome_payload",
            return_value=payload,
        ):
            self.assertEqual(
                engine._provider_fingerprint(None, {}, {}),
                binary_decision_engine._identity(
                    "provider_outcome_fingerprint", payload,
                ),
            )

    def test_short_temporary_file_policy_bounds_prefix_and_returns_owned_fd(self):
        descriptor, name = path_runtime.make_temporary_file(
            prefix="x" * 200,
        )
        try:
            os.write(descriptor, b"owned")
            self.assertLessEqual(len(Path(name).name.split("-", 1)[0]), 24)
            self.assertEqual(Path(name).read_bytes(), b"owned")
        finally:
            os.close(descriptor)
            Path(name).unlink(missing_ok=True)


class InternalPresentationHelperContractTest(unittest.TestCase):
    def test_progress_interval_and_boundary_decisions_are_total(self):
        self.assertEqual(progress_logging.suggest_log_interval(None), 1)
        self.assertEqual(progress_logging.suggest_log_interval("bad", minimum=3), 3)
        self.assertEqual(progress_logging.suggest_log_interval(100, target_updates=10), 10)
        self.assertTrue(progress_logging.should_log_progress(1, 100, 10))
        self.assertTrue(progress_logging.should_log_progress(100, 100, 10))
        self.assertTrue(progress_logging.should_log_progress(20, 100, 10))
        self.assertFalse(progress_logging.should_log_progress(21, 100, 10))
        self.assertFalse(progress_logging.should_log_progress("bad", 100, 10))

    def test_step4_contract_rejects_invalid_rows_and_generates_safe_names(self):
        valid = {
            field: "value" for field in s4_contract.ALL_CHANGED_APIS_FIELDS
            if field not in s4_contract.OPTIONAL_FIELDS
        }
        valid.update({
            "change_type": "REMOVED",
            "severity": "P0",
            "source": "classfile_contract",
            "symbol_kind": "method",
            "confirmed": "true",
        })
        self.assertEqual(s4_contract.validate_row(valid), [])

        invalid = dict(valid, change_type="UNKNOWN", severity="P9")
        errors = s4_contract.validate_row(invalid)
        self.assertTrue(any("change_type" in error for error in errors))
        self.assertTrue(any("severity" in error for error in errors))

        api_name = s4_contract.make_api_filename(
            "demo.Thing.<init>()", "REMOVED",
        )
        self.assertEqual(api_name, "Thing_init_REMOVED.json")
        self.assertEqual(
            s4_contract.make_module_filename("CON"), "_CON_impacts.json",
        )
        self.assertNotIn("/", s4_contract.make_module_filename("a/b:c"))


if __name__ == "__main__":
    unittest.main()
