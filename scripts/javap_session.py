#!/usr/bin/env python3
"""Bounded reusable transport for the exact JDK javap ToolProvider."""

from __future__ import annotations

import atexit
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import queue
import shutil
import struct
import subprocess
import threading
import time
import weakref

from compat import (
    finalize_parallel_process_tree_cleanup,
    managed_popen,
    release_process_tree,
    run_managed_subprocess,
    terminate_process_tree,
)
from javap_contract import JAVAP_STABLE_JVM_OPTIONS
from path_runtime import make_short_temp_dir


JAVA_HELPER = Path(__file__).resolve().parent / "java" / "JavapSession.java"
MAX_SESSION_PROCESSES = 8
MAX_RESPONSE_BYTES = 512 * 1024 * 1024
MAX_ARGUMENTS = 4096
MAX_ARGUMENT_BYTES = 4 * 1024 * 1024
STARTUP_TIMEOUT_SECONDS = 15.0
_RESPONSE_MAGIC = b"JVP1"


class JavapSessionError(RuntimeError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


_CAPTURED_HELPER_SHA256 = _sha256_file(JAVA_HELPER)


def _remove_owned_directory(
    path: Path,
    owner_pid: int,
    getpid=os.getpid,
    rmtree=shutil.rmtree,
) -> None:
    if getpid() == owner_pid:
        rmtree(path, ignore_errors=True)


class _OwnedDirectory:
    def __init__(self) -> None:
        self.path = make_short_temp_dir(prefix="javap-session")
        self._finalizer = weakref.finalize(
            self,
            _remove_owned_directory,
            self.path,
            os.getpid(),
        )

    def cleanup(self) -> None:
        self._finalizer()


@dataclass(frozen=True)
class _CompiledHelper:
    output: Path
    java: str
    _owned_directory: _OwnedDirectory | None


@dataclass(frozen=True)
class CompiledJavapSessionBinding:
    """Content-bound handle to one parent-compiled transport helper."""

    javap: str
    javap_size: int
    javap_mtime_ns: int
    java: str
    output: str
    helper_source_sha256: str
    helper_class_sha256: str


@dataclass(frozen=True)
class JavapSessionResult:
    returncode: int
    stdout: str
    stderr: str


def _resolved_tool(path_or_name: str) -> Path | None:
    resolved = shutil.which(path_or_name)
    candidate = Path(resolved or path_or_name).expanduser()
    try:
        return candidate.resolve(strict=True)
    except OSError:
        return None


def _sibling_tool(javap: Path, name: str) -> Path | None:
    suffix = ".exe" if os.name == "nt" else ""
    candidate = javap.parent / f"{name}{suffix}"
    return candidate if candidate.is_file() else None


@lru_cache(maxsize=8)
def _compile_helper(
    javap_text: str,
    javap_size: int,
    javap_mtime_ns: int,
    helper_sha256: str,
) -> _CompiledHelper:
    del javap_size, javap_mtime_ns
    if _sha256_file(JAVA_HELPER) != helper_sha256:
        raise JavapSessionError(
            "javap session helper changed after the validator was loaded"
        )
    javap = Path(javap_text)
    java = _sibling_tool(javap, "java")
    javac = _sibling_tool(javap, "javac")
    if java is None or javac is None:
        raise JavapSessionError(
            f"matching java/javac not found beside {javap}"
        )
    owned = _OwnedDirectory()
    try:
        completed = run_managed_subprocess(
            [
                str(javac),
                "-encoding", "UTF-8",
                "-d", str(owned.path),
                str(JAVA_HELPER),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=60,
        )
        if completed.returncode != 0:
            raise JavapSessionError(
                "javap session helper compile failed: "
                + (completed.stderr or completed.stdout).strip()
            )
        if not (owned.path / "JavapSession.class").is_file():
            raise JavapSessionError(
                "javap session helper compile produced no main class"
            )
        return _CompiledHelper(owned.path, str(java), owned)
    except BaseException:
        owned.cleanup()
        raise


_COMPILE_LOCK = threading.Lock()
_EXTERNAL_COMPILED_HELPERS: dict[str, CompiledJavapSessionBinding] = {}


def _compiled_from_binding(
    javap: Path, binding: CompiledJavapSessionBinding,
) -> _CompiledHelper:
    status = javap.stat()
    java = _sibling_tool(javap, "java")
    output = Path(binding.output)
    class_file = output / "JavapSession.class"
    if (
        str(javap) != binding.javap
        or int(status.st_size) != binding.javap_size
        or int(status.st_mtime_ns) != binding.javap_mtime_ns
        or java is None
        or str(java.resolve()) != binding.java
        or not output.is_absolute()
        or str(output.resolve()) != binding.output
        or _sha256_file(JAVA_HELPER) != binding.helper_source_sha256
        or not class_file.is_file()
        or _sha256_file(class_file) != binding.helper_class_sha256
    ):
        raise JavapSessionError(
            "compiled javap session binding changed before worker use"
        )
    return _CompiledHelper(output, binding.java, None)


def capture_compiled_javap_session_binding(
    javap: str,
) -> CompiledJavapSessionBinding:
    """Compile once and bind bytes that isolated scan workers may reuse."""

    resolved = _resolved_tool(javap)
    if resolved is None:
        raise JavapSessionError(f"javap tool is unavailable: {javap}")
    compiled = _compiled_helper(resolved)
    status = resolved.stat()
    class_file = compiled.output / "JavapSession.class"
    return CompiledJavapSessionBinding(
        javap=str(resolved),
        javap_size=int(status.st_size),
        javap_mtime_ns=int(status.st_mtime_ns),
        java=str(Path(compiled.java).resolve()),
        output=str(compiled.output.resolve()),
        helper_source_sha256=_CAPTURED_HELPER_SHA256,
        helper_class_sha256=_sha256_file(class_file),
    )


def install_compiled_javap_session_binding(
    binding: CompiledJavapSessionBinding,
) -> None:
    """Install a verified parent compilation in one isolated worker."""

    if type(binding) is not CompiledJavapSessionBinding:
        raise JavapSessionError("compiled javap session binding is invalid")
    javap = Path(binding.javap)
    _compiled_from_binding(javap, binding)
    with _COMPILE_LOCK:
        _EXTERNAL_COMPILED_HELPERS[str(javap)] = binding


def _compiled_helper(javap: Path) -> _CompiledHelper:
    status = javap.stat()
    with _COMPILE_LOCK:
        binding = _EXTERNAL_COMPILED_HELPERS.get(str(javap))
        if binding is not None:
            return _compiled_from_binding(javap, binding)
        return _compile_helper(
            str(javap),
            int(status.st_size),
            int(status.st_mtime_ns),
            _CAPTURED_HELPER_SHA256,
        )


def _read_exact(handle, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        block = handle.read(remaining)
        if not block:
            raise JavapSessionError(
                f"javap session response truncated by {remaining} bytes"
            )
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def _read_int(handle) -> int:
    return struct.unpack(">i", _read_exact(handle, 4))[0]


def _read_payload(handle, label: str) -> bytes:
    length = _read_int(handle)
    if length < 0 or length > MAX_RESPONSE_BYTES:
        raise JavapSessionError(
            f"javap session {label} length {length} exceeds protocol bound"
        )
    return _read_exact(handle, length)


class _Session:
    def __init__(self, compiled: _CompiledHelper) -> None:
        jvm_options = tuple(
            option[2:]
            for option in JAVAP_STABLE_JVM_OPTIONS
            if option.startswith("-J")
        )
        self.process = managed_popen(
            [
                compiled.java,
                "-Xms16m",
                "-Xmx256m",
                *jvm_options,
                "-cp", str(compiled.output),
                "JavapSession",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._stderr_tail = bytearray()
        self._closed = False
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr,
            name="javap-session-stderr",
            daemon=True,
        )
        self._stderr_thread.start()

    @property
    def alive(self) -> bool:
        return not self._closed and self.process.poll() is None

    def _drain_stderr(self) -> None:
        handle = self.process.stderr
        if handle is None:
            return
        try:
            while True:
                block = handle.read(4096)
                if not block:
                    return
                self._stderr_tail.extend(block)
                if len(self._stderr_tail) > 64 * 1024:
                    del self._stderr_tail[:-64 * 1024]
        except (OSError, ValueError):
            return

    def exchange(
        self,
        arguments: tuple[str, ...],
        cancellation_event: threading.Event,
        deadline: float,
    ) -> JavapSessionResult:
        if not self.alive:
            raise JavapSessionError("javap session process is not alive")
        if len(arguments) > MAX_ARGUMENTS:
            raise JavapSessionError(
                f"javap argument count {len(arguments)} exceeds protocol bound"
            )
        encoded = []
        for argument in arguments:
            value = str(argument).encode("utf-8")
            if len(value) > MAX_ARGUMENT_BYTES:
                raise JavapSessionError("javap argument exceeds protocol bound")
            encoded.append(value)
        stdin = self.process.stdin
        stdout = self.process.stdout
        if stdin is None or stdout is None:
            raise JavapSessionError("javap session pipes are unavailable")
        try:
            stdin.write(struct.pack(">i", len(encoded)))
            for value in encoded:
                stdin.write(struct.pack(">i", len(value)))
                stdin.write(value)
            stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            raise JavapSessionError(
                f"javap session request write failed: {error}"
            ) from error

        completed = threading.Event()
        result: list[JavapSessionResult] = []
        failure: list[BaseException] = []

        def read_response() -> None:
            try:
                if _read_exact(stdout, 4) != _RESPONSE_MAGIC:
                    raise JavapSessionError("javap session response magic mismatch")
                returncode = _read_int(stdout)
                out = _read_payload(stdout, "stdout")
                err = _read_payload(stdout, "stderr")
                result.append(JavapSessionResult(
                    returncode=returncode,
                    stdout=out.decode("utf-8", errors="replace"),
                    stderr=err.decode("utf-8", errors="replace"),
                ))
            except BaseException as error:
                failure.append(error)
            finally:
                completed.set()

        reader = threading.Thread(
            target=read_response,
            name="javap-session-response",
            daemon=True,
        )
        reader.start()
        while not completed.wait(0.05):
            if cancellation_event.is_set() or time.perf_counter() >= deadline:
                self.close(terminate=True)
                reader.join(timeout=5)
                raise JavapSessionError("javap session request cancelled or timed out")
        reader.join()
        if failure:
            detail = bytes(self._stderr_tail).decode("utf-8", errors="replace")
            raise JavapSessionError(
                f"{failure[0]}; helper stderr={detail[-2000:]}"
            ) from failure[0]
        return result[0]

    def close(self, *, terminate: bool = False) -> None:
        if self._closed:
            return
        self._closed = True
        process = self.process
        try:
            if process.stdin is not None:
                process.stdin.close()
            if terminate and process.poll() is None:
                terminate_process_tree(process)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                terminate_process_tree(process)
                process.wait(timeout=5)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        finally:
            for handle in (process.stdout, process.stderr):
                if handle is not None:
                    try:
                        handle.close()
                    except OSError:
                        pass
            release_process_tree(process)


class _SessionPool:
    def __init__(
        self, javap: Path, expected_version: str, max_sessions: int,
    ) -> None:
        self.javap = javap
        self.expected_version = str(expected_version)
        self.max_sessions = max(1, min(MAX_SESSION_PROCESSES, max_sessions))
        self._compiled = _compiled_helper(javap)
        self._idle: queue.LifoQueue[_Session] = queue.LifoQueue()
        self._condition = threading.Condition()
        self._session_count = 0
        self._closed = False

    def _new_session(self, cancellation_event, deadline: float) -> _Session:
        session = _Session(self._compiled)
        try:
            startup_deadline = min(
                deadline, time.perf_counter() + STARTUP_TIMEOUT_SECONDS
            )
            observed = session.exchange(
                ("-version",), cancellation_event, startup_deadline
            )
            version = (observed.stdout or observed.stderr).strip()
            if observed.returncode != 0 or version != self.expected_version:
                raise JavapSessionError(
                    "javap ToolProvider identity mismatch: "
                    f"expected={self.expected_version!r}; actual={version!r}; "
                    f"returncode={observed.returncode}"
                )
            return session
        except BaseException:
            session.close(terminate=True)
            raise

    def _acquire(self, cancellation_event, deadline: float) -> _Session:
        while True:
            with self._condition:
                if self._closed:
                    raise JavapSessionError("javap session pool is closed")
                try:
                    return self._idle.get_nowait()
                except queue.Empty:
                    pass
                if self._session_count < self.max_sessions:
                    self._session_count += 1
                    break
                remaining = deadline - time.perf_counter()
                if cancellation_event.is_set() or remaining <= 0:
                    raise JavapSessionError(
                        "javap session lease cancelled or timed out"
                    )
                self._condition.wait(timeout=min(0.05, remaining))
        try:
            return self._new_session(cancellation_event, deadline)
        except BaseException:
            with self._condition:
                self._session_count -= 1
                self._condition.notify()
            raise

    def run(
        self,
        arguments: tuple[str, ...],
        cancellation_event: threading.Event,
        deadline: float,
    ) -> JavapSessionResult:
        session = self._acquire(cancellation_event, deadline)
        reusable = False
        try:
            result = session.exchange(arguments, cancellation_event, deadline)
            reusable = session.alive
            return result
        finally:
            with self._condition:
                if reusable and not self._closed:
                    self._idle.put(session)
                else:
                    session.close(terminate=True)
                    self._session_count -= 1
                self._condition.notify()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            sessions = []
            while True:
                try:
                    sessions.append(self._idle.get_nowait())
                except queue.Empty:
                    break
            self._session_count -= len(sessions)
            self._condition.notify_all()
        # These sessions are idle only after the complete javap response frame
        # has been read. EOF is the helper protocol's normal shutdown boundary;
        # use it instead of the comparatively expensive exceptional
        # process-tree termination path. ``_Session.close`` still applies a
        # bounded wait and force-terminates a helper that does not honour EOF.
        failures: list[BaseException] = []
        failure_lock = threading.Lock()

        def close_session(session: _Session) -> None:
            try:
                session.close(terminate=False)
            except BaseException as error:
                with failure_lock:
                    failures.append(error)

        threads = [
            threading.Thread(
                target=close_session,
                args=(session,),
                name="javap-session-close",
                daemon=True,
            )
            for session in sessions
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        finalize_parallel_process_tree_cleanup()
        if failures:
            raise failures[0]


_POOLS: dict[tuple[str, int, int, str], _SessionPool] = {}
_POOLS_LOCK = threading.Lock()


def _pool_key(javap: Path, version: str) -> tuple[str, int, int, str]:
    status = javap.stat()
    return (
        str(javap),
        int(status.st_size),
        int(status.st_mtime_ns),
        str(version),
    )


def run_persistent_javap(
    javap: str,
    arguments: tuple[str, ...],
    expected_version: str,
    cancellation_event: threading.Event,
    deadline: float,
    *,
    max_sessions: int = MAX_SESSION_PROCESSES,
) -> JavapSessionResult | None:
    """Run exact javap arguments in a reusable target-JDK JVM.

    ``None`` means the transport was unavailable or failed.  Callers must then
    execute the ordinary javap process; transport failure can never weaken or
    skip Oracle evidence.
    """
    resolved = _resolved_tool(javap)
    if resolved is None or cancellation_event.is_set():
        return None
    try:
        key = _pool_key(resolved, expected_version)
        with _POOLS_LOCK:
            pool = _POOLS.get(key)
            if pool is None:
                pool = _SessionPool(resolved, expected_version, max_sessions)
                _POOLS[key] = pool
        return pool.run(
            tuple(str(argument) for argument in arguments),
            cancellation_event,
            deadline,
        )
    except (JavapSessionError, OSError, subprocess.SubprocessError, ValueError):
        return None


def close_persistent_javap_sessions() -> None:
    with _POOLS_LOCK:
        pools = list(_POOLS.values())
        _POOLS.clear()
    for pool in pools:
        pool.close()


def _after_fork_in_child() -> None:
    # The child must never write to a protocol pipe owned by the parent. Do not
    # close inherited handles here: that could signal the still-running parent
    # helper; simply forget them and build child-owned sessions on demand.
    global _POOLS, _POOLS_LOCK, _EXTERNAL_COMPILED_HELPERS
    _POOLS = {}
    _POOLS_LOCK = threading.Lock()
    _EXTERNAL_COMPILED_HELPERS = {}
    _compile_helper.cache_clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
atexit.register(close_persistent_javap_sessions)


__all__ = [
    "CompiledJavapSessionBinding",
    "JavapSessionError",
    "JavapSessionResult",
    "capture_compiled_javap_session_binding",
    "close_persistent_javap_sessions",
    "install_compiled_javap_session_binding",
    "run_persistent_javap",
]
