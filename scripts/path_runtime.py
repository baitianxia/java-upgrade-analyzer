#!/usr/bin/env python3
"""Shared short-path and Git workspace runtime for every analysis step."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import threading
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


def _longest_tracked_path(git, repo_dir, ref, runner):
    stdout, _stderr, rc = runner(
        git + ["-c", "core.quotepath=false", "ls-tree", "-rz", "--name-only", ref],
        cwd=str(repo_dir),
        timeout=300,
    )
    if rc != 0:
        return "", 0
    paths = [item for item in stdout.split("\0") if item]
    longest = max(paths, key=len, default="")
    return longest, len(longest)


def _cleanup_failed_worktree(git, repo_dir, worktree, runner):
    _stdout, stderr, rc = runner(
        git + ["worktree", "remove", "--force", str(worktree)],
        cwd=str(repo_dir),
        timeout=300,
    )
    if rc == 0:
        shutil.rmtree(worktree, ignore_errors=True)
        return ""

    stdout, list_stderr, list_rc = runner(
        git + ["worktree", "list", "--porcelain"],
        cwd=str(repo_dir),
        timeout=300,
    )
    target = os.path.normcase(os.path.abspath(str(worktree)))
    registered = False
    if list_rc == 0:
        registered = any(
            os.path.normcase(os.path.abspath(line[len("worktree "):].strip()))
            == target
            for line in str(stdout or "").splitlines()
            if line.startswith("worktree ")
        )
    if not registered and list_rc == 0:
        shutil.rmtree(worktree, ignore_errors=True)
        return ""
    return (
        str(stderr or "").strip()
        or str(list_stderr or "").strip()
        or "worktree registration cleanup failed"
    )


def create_detached_worktree(
    ref,
    repo_dir,
    *,
    label="jua",
    preferred_root=None,
    runner=None,
    git_command=None,
):
    """Create a detached worktree with shared Windows path policy and retries."""
    repo_dir = Path(repo_dir).resolve()
    runner = runner or run_cmd
    git = git_with_long_paths(git_command)
    ref_token = _digest(ref, length=8)
    prefix = (
        bounded_path_component(label, max_length=10, default="jua")
        + f"-{ref_token}"
    )
    longest_entry, longest_entry_length = _longest_tracked_path(
        git, repo_dir, ref, runner,
    )
    attempts = []

    for root in short_temp_root_candidates(
        preferred_root=preferred_root,
        workspace=repo_dir,
    ):
        try:
            worktree = make_short_temp_dir(
                prefix,
                preferred_root=root,
                strict_preferred=True,
            )
        except OSError as exc:
            attempts.append(f"root={root}:temp_create_failed:{exc}")
            continue
        predicted_longest = (
            len(str(worktree)) + 1 + longest_entry_length
            if longest_entry_length
            else 0
        )
        _stdout, stderr, rc = runner(
            git + ["worktree", "add", "--detach", str(worktree), str(ref)],
            cwd=str(repo_dir),
            timeout=1800,
        )
        if rc == 0:
            return worktree
        cleanup_error = _cleanup_failed_worktree(
            git, repo_dir, worktree, runner,
        )
        attempt = (
            f"path={worktree}, predicted_longest_path={predicted_longest or 'unknown'}, "
            f"longest_entry={longest_entry[:200] or '<unknown>'}, "
            f"stderr={str(stderr or '')[:500]}, cleanup={cleanup_error or 'complete'}"
        )
        attempts.append(attempt)
        if cleanup_error:
            raise RuntimeError(
                "git worktree add 失败且本次注册无法安全清理，"
                "为避免破坏 Git worktree 元数据已停止自动重试：" + attempt
            )

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
):
    runner = runner or run_cmd
    git = git_with_long_paths(git_command)
    _stdout, stderr, rc = runner(
        git + ["worktree", "remove", "--force", str(worktree)],
        cwd=str(Path(repo_dir).resolve()),
        timeout=1800,
    )
    if rc != 0:
        raise RuntimeError(f"git worktree remove 失败：{str(stderr or '')[:500]}")
    shutil.rmtree(worktree, ignore_errors=True)
