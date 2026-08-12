#!/usr/bin/env python3
"""Shared short-path and Git workspace runtime for every analysis step."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from compat import IS_WINDOWS, git_cmd, run_cmd


SHORT_TEMP_ROOT_ENV = "JUA_SHORT_TEMP_ROOT"
LEGACY_STEP1_WORKTREE_ROOT_ENV = "JUA_STEP1_WORKTREE_ROOT"
WINDOWS_SAFE_PATH_LENGTH = 240
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_SHORT_TEMP_ROOT_CACHE = {}
_SHORT_TEMP_ROOT_LOCK = threading.Lock()
_WORKTREE_REPOSITORY_LOCKS = {}
_WORKTREE_REPOSITORY_LOCKS_GUARD = threading.Lock()
_WORKTREE_LOCK_RETRY_DELAYS = (0.1, 0.25, 0.5, 1.0)
_WORKTREE_LEASE_PREFIX = ".jua-worktree-lease-"
_WORKTREE_LEASE_VERSION = 2
_SUPPORTED_WORKTREE_LEASE_VERSIONS = {1, _WORKTREE_LEASE_VERSION}
_MAX_WORKTREE_LEASES_PER_ROOT = 256
DEFAULT_WORKTREE_TIMEOUT = 300
WORKTREE_CLEANUP_MARGIN_SECONDS = 30
_WORKTREE_LOCK_ERROR_MARKERS = (
    "another git process seems to be running",
    "could not lock config file",
    "couldn't lock config file",
    "cannot lock ref",
    "could not lock",
    "failed to lock",
    "index.lock",
    "config.lock",
    "locked by another process",
    "resource temporarily unavailable",
    "the process cannot access the file because it is being used by another process",
)
_WORKTREE_LOCK_ERROR_PATTERNS = (
    re.compile(r"unable to create .+\.lock"),
)
_WORKTREE_PATH_ERROR_MARKERS = (
    "filename too long",
    "file name too long",
    "path too long",
    "the specified path, file name, or both are too long",
    "cannot create a file when that file already exists",
)
_FULL_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")


class WorktreeRecoveryError(RuntimeError):
    """Raised when an analyzer-owned stale worktree cannot be cleaned safely."""

    def __init__(self, message, result=None):
        super().__init__(message)
        self.result = dict(result or {})


def _digest(value, length=10):
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()[:length]


def _sanitize_component(value, default="item"):
    text = str(value or "").strip()
    text = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", text)
    text = re.sub(r"\s+", "-", text).strip(" .-_")
    text = text or default
    stem = text.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        text = f"_{text}"
    return text


def bounded_path_component(
    value,
    max_length=48,
    default="item",
    always_hash=False,
    fallback=None,
):
    """Return one Windows-safe component with deterministic collision protection."""
    if fallback is not None:
        default = fallback
    max_length = max(16, int(max_length))
    safe = _sanitize_component(value, default=default)
    digest = _digest(value)
    if not always_hash and len(safe) <= max_length:
        return safe
    prefix_length = max(1, max_length - len(digest) - 1)
    return f"{safe[:prefix_length].rstrip(' .-_') or default}-{digest}"


def bounded_filename(value, max_length=64, default="artifact"):
    """Bound a file name while retaining its final suffix and stable identity."""
    name = _sanitize_component(Path(str(value or "")).name, default=default)
    if len(name) <= max_length:
        return name
    suffix = Path(name).suffix
    digest = _digest(value)
    suffix_budget = min(len(suffix), 12)
    suffix = suffix[-suffix_budget:] if suffix_budget else ""
    stem_budget = max(1, int(max_length) - len(digest) - len(suffix) - 1)
    stem = name[:-len(Path(name).suffix)] if Path(name).suffix else name
    return f"{stem[:stem_budget].rstrip(' .-_') or default}-{digest}{suffix}"


def named_temporary_file(*, prefix="jua-", **kwargs):
    """Create a temporary file without echoing an unbounded target name."""
    kwargs["prefix"] = (
        bounded_path_component(prefix, max_length=24, default="jua").rstrip("-")
        + "-"
    )
    return tempfile.NamedTemporaryFile(**kwargs)


def make_temporary_file(*, prefix="jua-", **kwargs):
    """mkstemp variant with the same bounded component policy."""
    kwargs["prefix"] = (
        bounded_path_component(prefix, max_length=24, default="jua").rstrip("-")
        + "-"
    )
    return tempfile.mkstemp(**kwargs)


def windows_short_path(path):
    """Return an existing 8.3 path when Windows exposes one."""
    resolved = str(Path(path).resolve())
    if not IS_WINDOWS:
        return resolved
    try:
        import ctypes

        get_short_path = ctypes.windll.kernel32.GetShortPathNameW
        required = get_short_path(resolved, None, 0)
        if required <= 0:
            return resolved
        buffer = ctypes.create_unicode_buffer(required)
        if get_short_path(resolved, buffer, required) <= 0:
            return resolved
        return buffer.value or resolved
    except (AttributeError, OSError, ValueError):
        return resolved


def short_temp_root_candidates(*, preferred_root=None, workspace=None):
    """Return de-duplicated private/fallback roots, shortest safe roots first."""
    candidates = []
    if preferred_root:
        candidates.append(Path(preferred_root))
    configured = os.environ.get(SHORT_TEMP_ROOT_ENV, "").strip()
    if configured:
        candidates.append(Path(os.path.expandvars(os.path.expanduser(configured))))
    legacy = os.environ.get(LEGACY_STEP1_WORKTREE_ROOT_ENV, "").strip()
    if legacy:
        candidates.append(Path(os.path.expandvars(os.path.expanduser(legacy))))

    system_temp = Path(tempfile.gettempdir()).resolve()
    if IS_WINDOWS:
        candidates.append(Path(windows_short_path(system_temp)))
    candidates.append(system_temp)
    if workspace:
        candidates.append(Path(workspace).resolve() / ".worktrees")

    unique = []
    seen = set()
    for candidate in candidates:
        normalized = os.path.normcase(os.path.abspath(str(candidate)))
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(candidate)
    return unique


def make_short_temp_dir(
    prefix="jua",
    *,
    preferred_root=None,
    workspace=None,
    strict_preferred=False,
):
    safe_prefix = bounded_path_component(
        str(prefix or "jua").strip("-"),
        max_length=20,
        default="jua",
    ) + "-"
    errors = []
    roots = (
        [Path(preferred_root)]
        if strict_preferred and preferred_root
        else short_temp_root_candidates(
            preferred_root=preferred_root,
            workspace=workspace,
        )
    )
    for root in roots:
        try:
            root.mkdir(parents=True, exist_ok=True)
            return Path(tempfile.mkdtemp(prefix=safe_prefix, dir=str(root)))
        except OSError as exc:
            errors.append(f"{root}:{type(exc).__name__}:{exc}")
    raise OSError("无法创建短临时目录：" + "；".join(errors))


@contextmanager
def short_temporary_directory(prefix="jua", *, preferred_root=None, workspace=None):
    path = make_short_temp_dir(
        prefix,
        preferred_root=preferred_root,
        workspace=workspace,
    )
    try:
        yield str(path)
    finally:
        shutil.rmtree(path, ignore_errors=True)


def short_temp_root(*, preferred_root=None, workspace=None):
    """Resolve one writable root for NamedTemporaryFile-style consumers."""
    cache_key = (
        str(preferred_root or ""),
        str(workspace or ""),
        os.environ.get(SHORT_TEMP_ROOT_ENV, ""),
        os.environ.get(LEGACY_STEP1_WORKTREE_ROOT_ENV, ""),
        tempfile.gettempdir(),
        IS_WINDOWS,
    )
    with _SHORT_TEMP_ROOT_LOCK:
        cached = _SHORT_TEMP_ROOT_CACHE.get(cache_key)
        if cached and Path(cached).is_dir():
            return Path(cached)
        probe = make_short_temp_dir(
            "jua-probe",
            preferred_root=preferred_root,
            workspace=workspace,
        )
        root = probe.parent
        shutil.rmtree(probe, ignore_errors=True)
        _SHORT_TEMP_ROOT_CACHE[cache_key] = str(root)
        return root


def runtime_storage_root(report_dir, namespace):
    """Keep path-expanding runtime data short on Windows, report-local elsewhere."""
    safe_namespace = bounded_path_component(
        namespace, max_length=24, default="runtime",
    )
    if IS_WINDOWS:
        root = (
            short_temp_root()
            / "jua-runtime"
            / safe_namespace
            / _digest(Path(report_dir).resolve(), length=12)
        )
    else:
        root = Path(report_dir) / ".runtime" / safe_namespace
    root.mkdir(parents=True, exist_ok=True)
    return root


def git_with_long_paths(command=None):
    command = list(command or git_cmd())
    if IS_WINDOWS and "core.longpaths=true" not in command:
        command.extend(["-c", "core.longpaths=true"])
    return command


def filesystem_git_repository_root(path):
    """Find a repository root without running Git during startup recovery."""
    raw = str(path or "").strip()
    if not raw or "://" in raw or raw.startswith("git@"):
        return None
    candidate = Path(os.path.expandvars(os.path.expanduser(raw)))
    try:
        candidate = candidate.resolve()
    except OSError:
        return None
    if candidate.is_file():
        candidate = candidate.parent
    if not candidate.is_dir():
        return None
    for current in (candidate, *candidate.parents):
        if (current / ".git").exists():
            return current
    return None


def _worktree_repository_key(repo_dir):
    """Return a process-local lock key shared by linked Git worktrees."""
    repo_dir = Path(repo_dir).resolve()
    dot_git = repo_dir / ".git"
    common_dir = dot_git
    try:
        if dot_git.is_file():
            first_line = dot_git.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()[0]
            if first_line.lower().startswith("gitdir:"):
                admin_dir = Path(first_line.split(":", 1)[1].strip())
                if not admin_dir.is_absolute():
                    admin_dir = (repo_dir / admin_dir).resolve()
                common_file = admin_dir / "commondir"
                if common_file.is_file():
                    common_dir = Path(common_file.read_text(
                        encoding="utf-8", errors="replace",
                    ).strip())
                    if not common_dir.is_absolute():
                        common_dir = (admin_dir / common_dir).resolve()
                else:
                    common_dir = admin_dir
    except (OSError, IndexError, ValueError):
        common_dir = dot_git
    return os.path.normcase(os.path.abspath(str(common_dir)))


def _worktree_repository_lock(repo_dir):
    key = _worktree_repository_key(repo_dir)
    with _WORKTREE_REPOSITORY_LOCKS_GUARD:
        return _WORKTREE_REPOSITORY_LOCKS.setdefault(key, threading.RLock())


def _worktree_lease_path(worktree):
    target = Path(worktree).resolve()
    return target.parent / (
        f"{_WORKTREE_LEASE_PREFIX}{_digest(target, length=20)}.json"
    )


def _write_worktree_lease(repo_dir, worktree):
    """Durably record ownership outside the worktree before Git registers it."""
    target = Path(worktree).resolve()
    lease = _worktree_lease_path(target)
    temporary = lease.with_name(f"{lease.name}.{os.getpid()}.tmp")
    payload = {
        "schema_version": _WORKTREE_LEASE_VERSION,
        "repository_key": _worktree_repository_key(repo_dir),
        "worktree": str(target),
        "pid": os.getpid(),
        "process_start_token": _process_start_token(os.getpid()),
        "created_at": time.time(),
    }
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, lease)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return lease


def _remove_worktree_lease(worktree):
    try:
        _worktree_lease_path(worktree).unlink()
    except FileNotFoundError:
        pass


def _windows_process_is_alive(pid):
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        open_process.restype = ctypes.c_void_p
        wait_for_single_object = kernel32.WaitForSingleObject
        wait_for_single_object.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        wait_for_single_object.restype = ctypes.c_uint32
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        handle = open_process(0x00100000, False, int(pid))  # SYNCHRONIZE
        if not handle:
            return False
        try:
            return wait_for_single_object(handle, 0) == 0x00000102
        finally:
            close_handle(handle)
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _process_is_alive(pid):
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if IS_WINDOWS:
        return _windows_process_is_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        # Unknown platform-specific errors must not authorize cleanup.
        return True
    return True


def _windows_process_start_token(pid):
    """Return the Windows creation FILETIME so PID reuse cannot retain a lease."""
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        open_process.restype = ctypes.c_void_p
        get_process_times = kernel32.GetProcessTimes
        get_process_times.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        get_process_times.restype = ctypes.c_int
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        handle = open_process(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ""
        try:
            creation = wintypes.FILETIME()
            exit_time = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not get_process_times(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return ""
            value = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
            return f"windows-filetime:{value}"
        finally:
            close_handle(handle)
    except (AttributeError, OSError, TypeError, ValueError):
        return ""


def _process_start_token(pid):
    """Return a stable process-birth token where the platform exposes one."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return ""
    if pid <= 0:
        return ""
    if IS_WINDOWS:
        return _windows_process_start_token(pid)
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        text = stat_path.read_text(encoding="utf-8", errors="replace")
        fields_after_command = text.rsplit(")", 1)[1].split()
        # /proc/<pid>/stat field 22 is process start time.  The first token
        # after the closing ')' is field 3, so field 22 is index 19.
        return f"proc-start:{fields_after_command[19]}"
    except (OSError, IndexError, ValueError):
        return ""


def _lease_owner_is_alive(payload):
    pid = (payload or {}).get("pid")
    if not _process_is_alive(pid):
        return False
    expected = str((payload or {}).get("process_start_token") or "").strip()
    if not expected:
        # Version-1 leases have no process identity. Preserve them whenever
        # their PID is live because deleting an active worktree is worse than
        # retaining one ambiguous legacy lease.
        return True
    observed = _process_start_token(pid)
    return not observed or observed == expected


def _is_worktree_lock_contention(stdout, stderr):
    text = f"{stdout or ''}\n{stderr or ''}".lower()
    return (
        any(marker in text for marker in _WORKTREE_LOCK_ERROR_MARKERS)
        or any(pattern.search(text) for pattern in _WORKTREE_LOCK_ERROR_PATTERNS)
    )


def _remaining_timeout(deadline):
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        return 0
    return remaining


def _run_worktree_mutation(command, *, repo_dir, runner, timeout, deadline=None):
    """Retry only Git's explicit lock-contention failures, on the same target."""
    deadline = (
        float(deadline)
        if deadline is not None
        else time.monotonic() + max(1, int(timeout or 1))
    )
    history = []
    for attempt in range(len(_WORKTREE_LOCK_RETRY_DELAYS) + 1):
        remaining = _remaining_timeout(deadline)
        if remaining <= 0:
            history.append({
                "attempt": attempt + 1,
                "rc": -1,
                "stdout": "",
                "stderr": "worktree operation deadline exceeded",
            })
            return "", "worktree operation deadline exceeded", -1, history
        stdout, stderr, rc = runner(
            command,
            cwd=str(Path(repo_dir).resolve()),
            timeout=min(max(1, int(timeout or 1)), remaining),
        )
        history.append({
            "attempt": attempt + 1,
            "rc": rc,
            "stdout": str(stdout or ""),
            "stderr": str(stderr or ""),
        })
        if rc == 0:
            return stdout, stderr, rc, history
        if (
            attempt >= len(_WORKTREE_LOCK_RETRY_DELAYS)
            or not _is_worktree_lock_contention(stdout, stderr)
        ):
            return stdout, stderr, rc, history
        delay = min(
            _WORKTREE_LOCK_RETRY_DELAYS[attempt],
            max(0.0, float(deadline) - time.monotonic()),
        )
        if delay <= 0:
            return stdout, stderr, rc, history
        time.sleep(delay)
    return stdout, stderr, rc, history


def _registered_worktree_path_values(stdout):
    """Parse path values from newline or ``-z`` worktree porcelain output."""
    text = str(stdout or "")
    records = text.split("\0") if "\0" in text else text.splitlines()
    return [
        Path(line[len("worktree "):].strip()).resolve()
        for line in records
        if line.startswith("worktree ") and line[len("worktree "):].strip()
    ]


def _registered_worktree_paths(stdout):
    """Return normalized identities for exact worktree registration checks."""
    return {
        os.path.normcase(os.path.realpath(os.path.abspath(str(path))))
        for path in _registered_worktree_path_values(stdout)
    }


def _worktree_registration_state(
    git, repo_dir, worktree, runner, *, deadline=None,
):
    timeout = (
        _remaining_timeout(deadline)
        if deadline is not None
        else DEFAULT_WORKTREE_TIMEOUT
    )
    if timeout <= 0:
        return None, "worktree registration check deadline exceeded", -1
    stdout, stderr, rc = runner(
        git + ["worktree", "list", "--porcelain", "-z"],
        cwd=str(Path(repo_dir).resolve()),
        timeout=timeout,
    )
    target = os.path.normcase(os.path.realpath(os.path.abspath(str(worktree))))
    registered = target in _registered_worktree_paths(stdout) if rc == 0 else None
    return registered, str(stderr or "").strip(), rc


def _mutation_diagnostic(history):
    if not history:
        return "attempts=0"
    last = history[-1]
    lock_attempts = sum(
        1
        for item in history
        if _is_worktree_lock_contention(item.get("stdout"), item.get("stderr"))
    )
    return (
        f"attempts={len(history)}, lock_contention_attempts={lock_attempts}, "
        f"last_rc={last.get('rc')}, "
        f"last_stdout={str(last.get('stdout') or '')[:300]}, "
        f"last_stderr={str(last.get('stderr') or '')[:500]}"
    )


def _resolve_worktree_commit(git, repo_dir, ref, runner, *, deadline):
    timeout = _remaining_timeout(deadline)
    if timeout <= 0:
        raise RuntimeError("git worktree revision resolution deadline exceeded")
    stdout, stderr, rc = runner(
        git + ["rev-parse", "--verify", f"{ref}^{{commit}}"],
        cwd=str(repo_dir),
        timeout=timeout,
    )
    commit = str(stdout or "").strip().splitlines()
    commit = commit[-1].strip() if rc == 0 and commit else ""
    if rc != 0 or not _FULL_COMMIT_RE.fullmatch(commit):
        raise RuntimeError(
            "git worktree 固定 revision 失败："
            f"ref={ref}, rc={rc}, stderr={str(stderr or stdout or '')[:500]}"
        )
    return commit.lower()


def _longest_tracked_path(git, repo_dir, ref, runner, *, deadline):
    timeout = _remaining_timeout(deadline)
    if timeout <= 0:
        raise RuntimeError("git ls-tree deadline exceeded before worktree creation")
    stdout, stderr, rc = runner(
        git + ["-c", "core.quotepath=false", "ls-tree", "-rz", "--name-only", ref],
        cwd=str(repo_dir),
        timeout=timeout,
    )
    if rc != 0:
        raise RuntimeError(
            "git ls-tree 无法读取固定 snapshot："
            f"ref={ref}, rc={rc}, stderr={str(stderr or stdout or '')[:500]}"
        )
    paths = [item for item in stdout.split("\0") if item]
    longest = max(paths, key=len, default="")
    return longest, len(longest)


def _cleanup_failed_worktree(
    git, repo_dir, worktree, runner, *, deadline=None,
):
    deadline = (
        float(deadline)
        if deadline is not None
        else time.monotonic() + DEFAULT_WORKTREE_TIMEOUT
    )
    _stdout, stderr, rc, history = _run_worktree_mutation(
        git + ["worktree", "remove", "--force", "--", str(worktree)],
        repo_dir=repo_dir,
        runner=runner,
        timeout=DEFAULT_WORKTREE_TIMEOUT,
        deadline=deadline,
    )
    if rc == 0:
        shutil.rmtree(worktree, ignore_errors=True)
        return ""

    registered, list_stderr, list_rc = _worktree_registration_state(
        git, repo_dir, worktree, runner, deadline=deadline,
    )
    if registered is False:
        shutil.rmtree(worktree, ignore_errors=True)
        return ""
    return (
        f"{_mutation_diagnostic(history)}, registered={registered}, "
        f"registration_check_rc={list_rc}, "
        f"registration_check_stderr={list_stderr[:300]}, "
        f"remove_stderr={str(stderr or '').strip()[:500]}"
    )


def _recover_stale_worktree_leases(
    git,
    repo_dir,
    roots,
    runner,
    *,
    deadline,
):
    """Recover only dead-process worktrees explicitly leased by this product."""
    repository_key = _worktree_repository_key(repo_dir)
    result = {
        "repository_key": repository_key,
        "checked_roots": [],
        "checked_leases": 0,
        "removed": [],
        "active": [],
        "ignored_other_repositories": 0,
        "ignored_invalid": [],
        "errors": [],
    }
    seen_roots = set()
    for raw_root in roots or []:
        root = Path(raw_root).resolve()
        normalized_root = os.path.normcase(str(root))
        if normalized_root in seen_roots or not root.is_dir():
            continue
        seen_roots.add(normalized_root)
        result["checked_roots"].append(str(root))
        try:
            leases = sorted(root.glob(f"{_WORKTREE_LEASE_PREFIX}*.json"))
        except OSError as exc:
            result["errors"].append(
                f"root={root}:lease_scan_failed:{type(exc).__name__}:{exc}"
            )
            continue
        if len(leases) > _MAX_WORKTREE_LEASES_PER_ROOT:
            result["errors"].append(
                f"root={root}:lease_scan_limit_exceeded:"
                f"{len(leases)}>{_MAX_WORKTREE_LEASES_PER_ROOT}"
            )
            leases = leases[:_MAX_WORKTREE_LEASES_PER_ROOT]
        for lease in leases:
            if _remaining_timeout(deadline) <= 0:
                result["errors"].append("lease_recovery_deadline_exceeded")
                return result
            result["checked_leases"] += 1
            try:
                payload = json.loads(lease.read_text(encoding="utf-8"))
                target_value = str(payload.get("worktree") or "").strip()
                if not target_value:
                    raise ValueError("missing_worktree_path")
                target = Path(target_value).resolve()
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                result["ignored_invalid"].append(
                    f"lease={lease}:invalid:{type(exc).__name__}:{exc}"
                )
                continue
            payload_repository_key = str(payload.get("repository_key") or "")
            if payload_repository_key != repository_key:
                result["ignored_other_repositories"] += 1
                continue
            if (
                payload.get("schema_version") not in _SUPPORTED_WORKTREE_LEASE_VERSIONS
                or target.parent != root
                or _worktree_lease_path(target) != lease
            ):
                result["errors"].append(
                    f"lease={lease}:owned_lease_identity_invalid"
                )
                continue
            if _lease_owner_is_alive(payload):
                result["active"].append(str(target))
                continue
            cleanup_error = _cleanup_failed_worktree(
                git,
                repo_dir,
                target,
                runner,
                deadline=deadline,
            )
            if cleanup_error:
                result["errors"].append(
                    f"path={target}:cleanup_failed:{cleanup_error}"
                )
                continue
            _remove_worktree_lease(target)
            result["removed"].append(str(target))
    return result


def _raise_worktree_recovery_errors(result):
    errors = list((result or {}).get("errors") or [])
    if not errors:
        return
    raise WorktreeRecoveryError(
        "分析器临时 Git worktree 恢复失败：" + "；".join(errors)[:2400],
        result=result,
    )


def recover_owned_stale_worktrees(
    repo_dir,
    *,
    roots=None,
    runner=None,
    git_command=None,
    timeout=DEFAULT_WORKTREE_TIMEOUT,
):
    """Clean stale analyzer-owned worktrees before any analysis Git operation."""
    repo_dir = Path(repo_dir).resolve()
    runner = runner or run_cmd
    git = git_with_long_paths(git_command)
    timeout = max(1, int(timeout or DEFAULT_WORKTREE_TIMEOUT))
    deadline = time.monotonic() + timeout
    candidate_roots = list(
        roots
        if roots is not None
        else short_temp_root_candidates(workspace=repo_dir)
    )

    with _worktree_repository_lock(repo_dir):
        remaining = _remaining_timeout(deadline)
        if remaining <= 0:
            result = {"errors": ["worktree_recovery_deadline_exceeded"]}
            _raise_worktree_recovery_errors(result)
        stdout, stderr, rc = runner(
            git + ["worktree", "list", "--porcelain", "-z"],
            cwd=str(repo_dir),
            timeout=remaining,
        )
        registered = _registered_worktree_path_values(stdout) if rc == 0 else []
        if rc != 0 or not registered:
            result = {
                "repository_key": _worktree_repository_key(repo_dir),
                "checked_roots": [],
                "checked_leases": 0,
                "removed": [],
                "active": [],
                "ignored_other_repositories": 0,
                "ignored_invalid": [],
                "registered_worktrees": [],
                "errors": [
                    "git_worktree_list_failed:"
                    f"rc={rc}:stderr={str(stderr or stdout or '<empty>')[:500]}"
                ],
            }
            _raise_worktree_recovery_errors(result)
        candidate_roots.extend(path.parent for path in registered)
        result = _recover_stale_worktree_leases(
            git,
            repo_dir,
            candidate_roots,
            runner,
            deadline=deadline,
        )
        result["registered_worktrees"] = [str(path) for path in registered]
        _raise_worktree_recovery_errors(result)
        return result


def create_detached_worktree(
    ref,
    repo_dir,
    *,
    label="jua",
    preferred_root=None,
    runner=None,
    git_command=None,
    timeout=DEFAULT_WORKTREE_TIMEOUT,
):
    """Create and verify one immutable detached worktree within one deadline."""
    repo_dir = Path(repo_dir).resolve()
    runner = runner or run_cmd
    git = git_with_long_paths(git_command)
    timeout = max(1, int(timeout or DEFAULT_WORKTREE_TIMEOUT))
    deadline = time.monotonic() + timeout
    ref_token = _digest(ref, length=8)
    prefix = (
        bounded_path_component(label, max_length=10, default="jua")
        + f"-{ref_token}"
    )
    attempts = []
    candidate_roots = short_temp_root_candidates(
        preferred_root=preferred_root,
        workspace=repo_dir,
    )

    with _worktree_repository_lock(repo_dir):
        recovery = _recover_stale_worktree_leases(
            git,
            repo_dir,
            candidate_roots,
            runner,
            deadline=deadline,
        )
        _raise_worktree_recovery_errors(recovery)
        # Recovery intentionally precedes even read-only Git commands. Stale
        # worktree metadata and locks from an interrupted run must not affect
        # revision resolution for the next run.
        expected_commit = _resolve_worktree_commit(
            git, repo_dir, ref, runner, deadline=deadline,
        )
        longest_entry, longest_entry_length = _longest_tracked_path(
            git, repo_dir, expected_commit, runner, deadline=deadline,
        )
        for root in candidate_roots:
            try:
                worktree = make_short_temp_dir(
                    prefix,
                    preferred_root=root,
                    strict_preferred=True,
                )
            except OSError as exc:
                attempts.append(f"root={root}:temp_create_failed:{exc}")
                continue
            try:
                _write_worktree_lease(repo_dir, worktree)
            except OSError as exc:
                shutil.rmtree(worktree, ignore_errors=True)
                attempts.append(
                    f"root={root}:lease_create_failed:{type(exc).__name__}:{exc}"
                )
                continue
            predicted_longest = (
                len(str(worktree)) + 1 + longest_entry_length
                if longest_entry_length
                else 0
            )
            _stdout, stderr, rc, history = _run_worktree_mutation(
                git + [
                    "worktree", "add", "--detach", "--",
                    str(worktree), expected_commit,
                ],
                repo_dir=repo_dir,
                runner=runner,
                timeout=timeout,
                deadline=deadline,
            )
            if rc == 0:
                verify_timeout = _remaining_timeout(deadline)
                if verify_timeout > 0:
                    actual_stdout, verify_stderr, verify_rc = runner(
                        git + ["rev-parse", "--verify", "HEAD^{commit}"],
                        cwd=str(worktree),
                        timeout=verify_timeout,
                    )
                    actual_lines = str(actual_stdout or "").strip().splitlines()
                    actual_commit = (
                        actual_lines[-1].strip().lower()
                        if verify_rc == 0 and actual_lines
                        else ""
                    )
                else:
                    verify_rc = -1
                    verify_stderr = "worktree verification deadline exceeded"
                    actual_commit = ""
                if verify_rc == 0 and actual_commit == expected_commit:
                    return worktree
                cleanup_deadline = max(
                    deadline,
                    time.monotonic() + WORKTREE_CLEANUP_MARGIN_SECONDS,
                )
                cleanup_error = _cleanup_failed_worktree(
                    git,
                    repo_dir,
                    worktree,
                    runner,
                    deadline=cleanup_deadline,
                )
                if not cleanup_error:
                    _remove_worktree_lease(worktree)
                raise RuntimeError(
                    "git worktree snapshot 完整性校验失败："
                    f"expected={expected_commit}, actual={actual_commit or '<empty>'}, "
                    f"verify_rc={verify_rc}, "
                    f"verify_stderr={str(verify_stderr or '')[:500]}, "
                    f"cleanup={cleanup_error or 'complete'}"
                )
            cleanup_deadline = max(
                deadline,
                time.monotonic() + WORKTREE_CLEANUP_MARGIN_SECONDS,
            )
            cleanup_error = _cleanup_failed_worktree(
                git,
                repo_dir,
                worktree,
                runner,
                deadline=cleanup_deadline,
            )
            if not cleanup_error:
                _remove_worktree_lease(worktree)
            attempt = (
                f"path={worktree}, predicted_longest_path={predicted_longest or 'unknown'}, "
                f"longest_entry={longest_entry[:200] or '<unknown>'}, "
                f"{_mutation_diagnostic(history)}, cleanup={cleanup_error or 'complete'}, "
                f"stderr={str(stderr or '')[:500]}"
            )
            attempts.append(attempt)
            if cleanup_error:
                raise RuntimeError(
                    "git worktree add 失败且本次注册无法安全清理，"
                    "为避免破坏 Git worktree 元数据已停止自动重试：" + attempt
                )
            if not any(
                marker in f"{_stdout or ''}\n{stderr or ''}".lower()
                for marker in _WORKTREE_PATH_ERROR_MARKERS
            ):
                # Changing the temp root only helps path-length/path-collision
                # failures.  Retrying auth, object, permission, or repository
                # errors at more roots merely multiplies the same failure.
                break
            if _remaining_timeout(deadline) <= 0:
                break

    budget = f", windows_safe_budget={WINDOWS_SAFE_PATH_LENGTH}" if IS_WINDOWS else ""
    raise RuntimeError(
        f"git worktree add {ref} 失败{budget}：" + "；".join(attempts)[:2400]
    )


def remove_detached_worktree(
    worktree,
    repo_dir,
    *,
    runner=None,
    git_command=None,
    timeout=DEFAULT_WORKTREE_TIMEOUT,
):
    runner = runner or run_cmd
    git = git_with_long_paths(git_command)
    repo_dir = Path(repo_dir).resolve()
    timeout = max(1, int(timeout or DEFAULT_WORKTREE_TIMEOUT))
    deadline = time.monotonic() + timeout
    with _worktree_repository_lock(repo_dir):
        _stdout, stderr, rc, history = _run_worktree_mutation(
            git + ["worktree", "remove", "--force", "--", str(worktree)],
            repo_dir=repo_dir,
            runner=runner,
            timeout=timeout,
            deadline=deadline,
        )
        registered = False
        list_stderr = ""
        list_rc = 0
        if rc != 0:
            registered, list_stderr, list_rc = _worktree_registration_state(
                git, repo_dir, worktree, runner, deadline=deadline,
            )
            if registered is not False:
                raise RuntimeError(
                    "git worktree remove 失败："
                    f"path={Path(worktree).resolve()}, "
                    f"{_mutation_diagnostic(history)}, registered={registered}, "
                    f"registration_check_rc={list_rc}, "
                    f"registration_check_stderr={list_stderr[:300]}, "
                    f"remove_stderr={str(stderr or '')[:500]}"
                )

        try:
            shutil.rmtree(worktree)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise RuntimeError(
                "Git worktree 注册已清理，但临时目录删除失败："
                f"path={Path(worktree).resolve()}, error={type(exc).__name__}:{exc}"
            ) from exc
        _remove_worktree_lease(worktree)
