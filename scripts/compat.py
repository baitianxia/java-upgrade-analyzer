"""
compat.py — 跨平台兼容层

解决 Windows / Linux / macOS 的以下差异：
  1. 子进程输出编码（Windows 默认 GBK/CP936，Linux/macOS 默认 UTF-8）
  2. 文件路径分隔符（Windows \\ vs Unix /）
  3. Maven/Git 在 Windows 下的编码输出
  4. stdout/stderr 本身的编码

使用方式：
  from compat import run_cmd, open_text, stdout_writer, IS_WINDOWS

所有脚本统一通过此模块调用子进程，不直接使用 subprocess.run(text=True)
"""

import os
import sys
import subprocess
import locale
import io
import re
import shlex
import signal
import shutil
import tempfile
import threading
import time
import safe_xml as ET
from pathlib import Path

# ── 平台检测 ──────────────────────────────────────────────────────
IS_WINDOWS = sys.platform == 'win32'


def subprocess_platform_kwargs(*, new_process_group=False, platform_name=None):
    """Return invisible, platform-safe process creation options.

    Python launched from a Windows GUI does not own a console.  Starting a
    console-subsystem executable (Git, Python, Java, Maven, and similar tools)
    without ``CREATE_NO_WINDOW`` makes Windows flash a new console for every
    command.  Keep that policy in one place so product subprocesses cannot
    accidentally regress to visible windows.

    Long-lived detached product tasks may additionally request an independent
    process group. POSIX Git commands use session isolation for ``killpg``;
    Windows Git commands deliberately stay on ``CREATE_NO_WINDOW`` alone and
    use ``taskkill /T`` for timeout cleanup.
    """
    normalized_platform = str(platform_name or '').strip().lower()
    windows = (
        IS_WINDOWS
        if not normalized_platform
        else normalized_platform in {'nt', 'win32', 'windows'}
    )
    if windows:
        create_no_window = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
        creation_flags = create_no_window
        if new_process_group:
            creation_flags |= getattr(
                subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x00000200
            )
        return {'creationflags': creation_flags}
    return {'start_new_session': True} if new_process_group else {}

# ── stdout/stderr 强制 UTF-8（Windows 默认 GBK 会导致中文乱码）──
def setup_utf8_io():
    """
    在脚本入口调用，确保 stdout/stderr 使用 UTF-8。
    Windows PowerShell / CMD 以及被继承的单字节编码会导致 print() 报错或乱码。
    """
    for name in ('stdout', 'stderr'):
        stream = getattr(sys, name)
        encoding = (getattr(stream, 'encoding', '') or '').replace('-', '').lower()
        if encoding == 'utf8':
            continue
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
        elif hasattr(stream, 'buffer'):
            setattr(sys, name, io.TextIOWrapper(
                stream.buffer, encoding='utf-8', errors='replace', line_buffering=True
            ))


# ── 检测子进程输出的实际编码 ──────────────────────────────────────
def _detect_subprocess_encoding():
    """
    检测当前系统上子进程（Maven/Git）输出使用的编码。
    
    优先级：
    1. 环境变量 JAVA_TOOL_OPTIONS 中指定的 -Dfile.encoding
    2. PYTHONIOENCODING 环境变量
    3. Windows：用 chcp 命令读取代码页
    4. 其他系统：locale 模块
    5. 兜底：utf-8
    """
    # 检查是否已通过环境变量强制指定
    java_opts = os.environ.get('JAVA_TOOL_OPTIONS', '') + os.environ.get('MAVEN_OPTS', '')
    if 'file.encoding=UTF-8' in java_opts or 'file.encoding=utf-8' in java_opts:
        return 'utf-8'

    py_enc = os.environ.get('PYTHONIOENCODING', '')
    if py_enc:
        return py_enc.split(':')[0].lower()

    if IS_WINDOWS:
        try:
            # chcp 返回当前代码页，如 "活动代码页: 65001" (65001 = UTF-8)
            result = subprocess.run(
                ['cmd', '/c', 'chcp'], capture_output=True, timeout=5,
                **subprocess_platform_kwargs(),
            )
            output = result.stdout.decode('mbcs', errors='replace')
            if '65001' in output:
                return 'utf-8'
            # 54936 already contains the substring 936.
            if '936' in output:
                return 'gbk'
            if '950' in output:
                return 'big5'
        except Exception:
            pass
        # Windows 兜底用 mbcs（即系统 ANSI 编码，会自动映射到正确的编码）
        return 'mbcs'

    # Linux/macOS
    enc = locale.getpreferredencoding(False)
    return enc if enc else 'utf-8'


# 模块加载时检测一次，后续复用
_SUBPROCESS_ENCODING = _detect_subprocess_encoding()
_PROCESS_OBSERVER = None
_GIT_EXECUTABLE_CACHE = {}
_GIT_EXECUTABLE_CACHE_LOCK = threading.RLock()

_GIT_REPOSITORY_ENV_KEYS = frozenset({
    'GIT_DIR',
    'GIT_WORK_TREE',
    'GIT_COMMON_DIR',
    'GIT_INDEX_FILE',
    'GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES',
    'GIT_NAMESPACE',
    'GIT_SHALLOW_FILE',
    'GIT_CONFIG',
    'GIT_CEILING_DIRECTORIES',
    'GIT_DISCOVERY_ACROSS_FILESYSTEM',
    'GIT_PREFIX',
    'GIT_IMPLICIT_WORK_TREE',
    'GIT_QUARANTINE_PATH',
    'GIT_REPLACE_REF_BASE',
    'GIT_GRAFT_FILE',
    'GIT_NO_REPLACE_OBJECTS',
    'GIT_EXEC_PATH',
    'GIT_TEMPLATE_DIR',
    'GIT_ATTR_NOSYSTEM',
    'GIT_ATTR_SOURCE',
    'GIT_EXTERNAL_DIFF',
})
_GIT_CONFIG_ENV_PREFIXES = (
    'GIT_CONFIG_KEY_',
    'GIT_CONFIG_VALUE_',
)
_GIT_CONFIG_ENV_KEYS = frozenset({
    'GIT_CONFIG_COUNT',
    'GIT_CONFIG_PARAMETERS',
})
_MAX_INHERITED_GIT_CONFIG_ITEMS = 1024


def _git_config_key_is_transport_safe(key):
    """Allow inherited config needed to reach/authenticate to a remote only."""
    normalized = str(key or '').strip().lower()
    if normalized.startswith(('http.', 'credential.')):
        return True
    if normalized in {'core.sshcommand', 'ssh.variant'}:
        return True
    if re.fullmatch(r'url\..+\.(?:insteadof|pushinsteadof)', normalized):
        return True
    if re.fullmatch(r'remote\..+\.(?:proxy|proxyauthmethod)', normalized):
        return True
    return bool(re.fullmatch(r'protocol\.(?:http|https|ssh|git)\.allow', normalized))


def _case_insensitive_env_items(environment):
    """Return the last value for each environment key, independent of case."""
    return {
        str(key or '').upper(): value
        for key, value in environment.items()
    }


def _parse_inherited_git_config(environment):
    """Extract only transport/auth config from Git's process-local config APIs."""
    normalized_environment = _case_insensitive_env_items(environment)
    inherited = []

    raw_count = str(normalized_environment.get('GIT_CONFIG_COUNT', '') or '').strip()
    try:
        count = int(raw_count) if raw_count else 0
    except (TypeError, ValueError):
        count = 0
    if 0 <= count <= _MAX_INHERITED_GIT_CONFIG_ITEMS:
        for index in range(count):
            key_name = f'GIT_CONFIG_KEY_{index}'
            value_name = f'GIT_CONFIG_VALUE_{index}'
            if key_name not in normalized_environment or value_name not in normalized_environment:
                continue
            key = str(normalized_environment[key_name] or '').strip()
            value = str(normalized_environment[value_name] or '')
            if _git_config_key_is_transport_safe(key):
                inherited.append((key, value))

    raw_parameters = str(
        normalized_environment.get('GIT_CONFIG_PARAMETERS', '') or ''
    ).strip()
    if raw_parameters:
        try:
            parameters = shlex.split(raw_parameters, posix=True)
        except ValueError:
            # Malformed quoting is untrusted process state. Fail closed rather
            # than passing an only-partially-understood config expression on.
            parameters = []
        for parameter in parameters[:_MAX_INHERITED_GIT_CONFIG_ITEMS]:
            key, separator, value = parameter.partition('=')
            key = key.strip()
            if separator and _git_config_key_is_transport_safe(key):
                inherited.append((key, value))

    deduped = []
    seen = set()
    for key, value in inherited:
        identity = (str(key).strip().lower(), str(value))
        if identity in seen:
            continue
        seen.add(identity)
        deduped.append((key, value))
    return deduped[:_MAX_INHERITED_GIT_CONFIG_ITEMS]


def _redact_git_text(value):
    """Remove credentials from Git diagnostics before they leave this boundary."""
    text = str(value or '')
    # Git may echo config in either ``key=value`` or ``key value`` form. Mask
    # the complete extraHeader value because it can carry arbitrary cookies or
    # private headers, not just an Authorization header.
    text = re.sub(
        r'(?im)(\bhttp\.[^\s=]*extraheader\b\s*(?:=|:|\s)\s*)[^\r\n]*',
        r'\1<redacted>',
        text,
    )
    text = re.sub(
        r'(?im)(\b(?:proxy-)?authorization\s*[:=]\s*)[^\r\n]*',
        r'\1<redacted>',
        text,
    )
    # Mask the entire URL userinfo component. Keeping even the username is
    # unsafe because tokens are commonly placed in that position.
    text = re.sub(
        r'(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]+@',
        r'\1<redacted>@',
        text,
    )
    text = re.sub(
        r'(?i)([?&](?:access[_-]?token|auth[_-]?token|private[_-]?token|'
        r'deploy[_-]?token|refresh[_-]?token|oauth2?[_-]?token|token|password|'
        r'passwd|secret)=)[^&#\s]+',
        r'\1<redacted>',
        text,
    )
    # SCP-style remotes have no URI scheme.  Require a command/log delimiter
    # before user@host:path so normal e-mail prose is not rewritten.
    text = re.sub(
        r'(^|[\s\'"(=])[^/@:\s]+@([^/:\s]+:[^\s\'"),]+)',
        r'\1<redacted>@\2',
        text,
    )
    return text


def _redact_git_command(command):
    return [_redact_git_text(argument) for argument in command]


def set_process_observer(observer):
    """Install an optional command lifecycle observer; return the previous one."""
    global _PROCESS_OBSERVER
    previous = _PROCESS_OBSERVER
    _PROCESS_OBSERVER = observer
    return previous


def _finish_observed_command(observer, token, result):
    if observer is not None and token is not None:
        try:
            observer.command_finished(token)
        except (AttributeError, TypeError, ValueError):
            pass
    return result


def _extract_maven_repo_local_from_opts(text):
    if not text:
        return ''
    m = re.search(r'-Dmaven\.repo\.local=("[^"]+"|\S+)', text)
    if not m:
        return ''
    val = m.group(1).strip()
    if val.startswith('"') and val.endswith('"'):
        val = val[1:-1]
    return val.strip()


def _read_maven_settings_local_repo():
    settings = Path.home() / '.m2' / 'settings.xml'
    if not settings.exists():
        return None
    try:
        text = settings.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return None
    try:
        root = ET.fromstring(text)
        for elem in root.iter():
            if (elem.tag or '').endswith('localRepository') and (elem.text or '').strip():
                return elem.text.strip()
    except Exception:
        m = re.search(r'<localRepository>\s*([^<]+)\s*</localRepository>', text)
        if m:
            return m.group(1).strip()
    return None


def maven_repo_dir():
    direct = os.environ.get('MAVEN_REPO_LOCAL', '').strip()
    if direct:
        return Path(os.path.expandvars(os.path.expanduser(direct)))

    repo_local = (
        _extract_maven_repo_local_from_opts(os.environ.get('MAVEN_OPTS', ''))
        or _extract_maven_repo_local_from_opts(os.environ.get('JAVA_TOOL_OPTIONS', ''))
    )
    if repo_local:
        return Path(os.path.expandvars(os.path.expanduser(repo_local)))

    settings_local = _read_maven_settings_local_repo()
    if settings_local:
        expanded = settings_local.replace('${user.home}', str(Path.home()))
        expanded = os.path.expandvars(os.path.expanduser(expanded))
        return Path(expanded)

    user_home = os.environ.get('MAVEN_USER_HOME', '').strip()
    if user_home:
        return Path(os.path.expandvars(os.path.expanduser(user_home))) / 'repository'

    return Path.home() / '.m2' / 'repository'


def _decode_subprocess_output(raw_bytes):
    if not raw_bytes:
        return ''
    for enc in ('utf-8', _SUBPROCESS_ENCODING):
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    # Latin-1 defines every byte value, so this final decode cannot fail and
    # does not need an unreachable retry/fallback branch.
    return raw_bytes.decode('latin-1')


def _normalized_executable_path(value):
    """Return a stable absolute executable path without requiring it to exist."""
    text = os.path.expandvars(os.path.expanduser(str(value or '').strip()))
    if not text:
        return ''
    candidate = Path(text)
    if not candidate.is_absolute() and candidate.parent == Path('.'):
        discovered = shutil.which(text)
        if discovered:
            text = discovered
    return os.path.abspath(text)


def _command_uses_git(cmd):
    """Return whether ``cmd`` targets the Git executable selected by this module."""
    if not isinstance(cmd, (list, tuple)) or not cmd:
        return False
    executable = str(cmd[0] or '').strip()
    if not executable:
        return False
    if Path(executable).name.lower() in {'git', 'git.exe'}:
        return True
    normalized_executable = os.path.normcase(_normalized_executable_path(executable))
    configured = os.environ.get('JUA_GIT_EXECUTABLE', '').strip()
    known_candidates = [configured] if configured else []
    with _GIT_EXECUTABLE_CACHE_LOCK:
        cached_candidates = tuple(_GIT_EXECUTABLE_CACHE.values())
    known_candidates.extend(
        candidate
        for candidate in cached_candidates
        if candidate
    )
    return any(
        normalized_executable
        == os.path.normcase(_normalized_executable_path(candidate))
        for candidate in known_candidates
    )


def _sanitize_git_environment(proc_env):
    """Remove inherited repository routing while preserving credential transport."""
    inherited_config = _parse_inherited_git_config(proc_env)
    for key in list(proc_env):
        normalized = str(key or '').upper()
        if (
            normalized in _GIT_REPOSITORY_ENV_KEYS
            or normalized in _GIT_CONFIG_ENV_KEYS
            or any(normalized.startswith(prefix) for prefix in _GIT_CONFIG_ENV_PREFIXES)
            or normalized.startswith('GIT_TRACE')
        ):
            proc_env.pop(key, None)

    if inherited_config:
        proc_env['GIT_CONFIG_COUNT'] = str(len(inherited_config))
        for index, (key, value) in enumerate(inherited_config):
            proc_env[f'GIT_CONFIG_KEY_{index}'] = key
            proc_env[f'GIT_CONFIG_VALUE_{index}'] = value

    # These values are deliberately assigned rather than setdefault: callers
    # must not make product Git commands interactive or locale-dependent.
    proc_env['GIT_TERMINAL_PROMPT'] = '0'
    proc_env['GCM_INTERACTIVE'] = 'Never'
    proc_env['GIT_PAGER'] = 'cat'
    proc_env['PAGER'] = 'cat'
    proc_env['GIT_MERGE_AUTOEDIT'] = 'no'
    proc_env['GIT_TRACE_REDACT'] = '1'
    proc_env['LC_ALL'] = 'C'
    proc_env['LANG'] = 'C'
    proc_env['LANGUAGE'] = 'C'
    return proc_env


def managed_foreground_process_kwargs():
    """Isolate every synchronous command so failure can reap its whole tree.

    ``run_cmd`` is the product's managed *foreground* command boundary.  A
    Maven/Gradle/Python/JVM launcher can create descendants just as Git can, so
    limiting process-group isolation to Git leaves those descendants alive
    after a timeout or interruption.

    POSIX starts the command in a new session, making the child PID a stable
    process-group ID for ``killpg``.  Windows keeps the existing invisible
    console policy; :func:`managed_popen` additionally assigns a Job Object so
    descendants remain addressable even if the root exits before a timeout.
    Detached/background launchers do not use this helper and retain their
    existing lifecycle.
    """
    if IS_WINDOWS:
        return subprocess_platform_kwargs()
    return subprocess_platform_kwargs(new_process_group=True)


_WINDOWS_JOB_HANDLE_ATTRIBUTE = "_jua_managed_job_handle"
_WINDOWS_JOB_ASSIGNMENT_RETRY_COUNT = 2
_WINDOWS_JOB_ASSIGNMENT_RETRY_DELAY_SECONDS = 0.05
_WINDOWS_ERROR_ACCESS_DENIED = 5
_MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE = "_jua_managed_process_tree_token"
_MANAGED_PROCESS_TREE_LOCK = threading.RLock()
_MANAGED_PROCESS_TREES = {}
_POSIX_MANAGED_PROCESS_GROUPS = set()
_MANAGED_SIGTERM_HANDLER_INSTALLED = False
_PREVIOUS_SIGTERM_HANDLER = None


def _managed_sigterm_handler(signum, frame):
    """Reap isolated foreground groups before preserving SIGTERM semantics."""
    global _MANAGED_SIGTERM_HANDLER_INSTALLED, _PREVIOUS_SIGTERM_HANDLER
    with _MANAGED_PROCESS_TREE_LOCK:
        groups = tuple(_POSIX_MANAGED_PROCESS_GROUPS)
        _POSIX_MANAGED_PROCESS_GROUPS.clear()
        records = tuple(_MANAGED_PROCESS_TREES.items())
        _MANAGED_PROCESS_TREES.clear()
        for token, (proc, _pid, _posix) in records:
            if getattr(proc, _MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE, None) is token:
                try:
                    delattr(proc, _MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE)
                except AttributeError:
                    pass
    for process_group in groups:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except (AttributeError, OSError):
            pass

    previous = _PREVIOUS_SIGTERM_HANDLER
    _MANAGED_SIGTERM_HANDLER_INSTALLED = False
    _PREVIOUS_SIGTERM_HANDLER = None
    if callable(previous):
        signal.signal(signum, previous)
        previous(signum, frame)
        return
    if previous == signal.SIG_IGN:
        signal.signal(signum, signal.SIG_IGN)
        return
    # Preserve the operating system's normal SIGTERM exit status instead of
    # translating process shutdown into an arbitrary Python exception.
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def _ensure_managed_sigterm_handler():
    global _MANAGED_SIGTERM_HANDLER_INSTALLED, _PREVIOUS_SIGTERM_HANDLER
    if (
        IS_WINDOWS
        or not hasattr(signal, "SIGTERM")
        or threading.current_thread() is not threading.main_thread()
    ):
        return
    with _MANAGED_PROCESS_TREE_LOCK:
        try:
            current = signal.getsignal(signal.SIGTERM)
            if current is _managed_sigterm_handler:
                _MANAGED_SIGTERM_HANDLER_INSTALLED = True
                return
            previous = current
            signal.signal(signal.SIGTERM, _managed_sigterm_handler)
        except (OSError, ValueError):
            return
        _PREVIOUS_SIGTERM_HANDLER = previous
        _MANAGED_SIGTERM_HANDLER_INSTALLED = True


def _restore_managed_sigterm_handler():
    global _MANAGED_SIGTERM_HANDLER_INSTALLED, _PREVIOUS_SIGTERM_HANDLER
    if IS_WINDOWS or threading.current_thread() is not threading.main_thread():
        return
    with _MANAGED_PROCESS_TREE_LOCK:
        if (
            _POSIX_MANAGED_PROCESS_GROUPS
            or not _MANAGED_SIGTERM_HANDLER_INSTALLED
        ):
            return
        try:
            if signal.getsignal(signal.SIGTERM) is _managed_sigterm_handler:
                signal.signal(signal.SIGTERM, _PREVIOUS_SIGTERM_HANDLER)
        except (OSError, ValueError):
            return
        _MANAGED_SIGTERM_HANDLER_INSTALLED = False
        _PREVIOUS_SIGTERM_HANDLER = None


def finalize_parallel_process_tree_cleanup():
    """Restore POSIX signal state after worker-owned process cleanup.

    A pool may wait for several independent children concurrently and release
    their process-tree registrations from those worker threads.  Python only
    permits the main thread to replace a signal handler, so the last worker
    cannot finish that part of the lifecycle.  Pool owners call this function
    after joining their cleanup workers; it is idempotent and a no-op while a
    managed process group is still live.
    """
    _restore_managed_sigterm_handler()


def _register_managed_process_tree(proc):
    if not IS_WINDOWS:
        _ensure_managed_sigterm_handler()
    try:
        process_group = int(proc.pid)
    except (AttributeError, TypeError, ValueError):
        if not IS_WINDOWS:
            raise ValueError("managed POSIX process is missing a valid pid")
        process_group = None
    token = object()
    with _MANAGED_PROCESS_TREE_LOCK:
        previous = getattr(
            proc, _MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE, None
        )
        if previous in _MANAGED_PROCESS_TREES:
            raise RuntimeError("process tree is already managed")
        setattr(proc, _MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE, token)
        _MANAGED_PROCESS_TREES[token] = (
            proc, process_group, not IS_WINDOWS,
        )
        if not IS_WINDOWS:
            _POSIX_MANAGED_PROCESS_GROUPS.add(process_group)


def _unregister_managed_process_tree(proc):
    released = _take_managed_process_tree(proc)
    if released is not None:
        _restore_managed_sigterm_handler()
        return True
    return False


def _take_managed_process_tree(proc):
    """Atomically consume ownership bound to this exact Popen instance."""
    with _MANAGED_PROCESS_TREE_LOCK:
        token = getattr(proc, _MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE, None)
        record = _MANAGED_PROCESS_TREES.get(token)
        if record is None or record[0] is not proc:
            return None
        del _MANAGED_PROCESS_TREES[token]
        try:
            delattr(proc, _MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE)
        except AttributeError:
            pass
        _owned_proc, process_group, posix = record
        if posix and not any(
            other_posix and other_group == process_group
            for _other_proc, other_group, other_posix
            in _MANAGED_PROCESS_TREES.values()
        ):
            _POSIX_MANAGED_PROCESS_GROUPS.discard(process_group)
        return record


def _claim_managed_process_tree(proc):
    """Claim this exact managed Popen tree for termination exactly once."""
    claimed = _take_managed_process_tree(proc)
    if claimed is None:
        return False
    _restore_managed_sigterm_handler()
    return True


def _attach_windows_managed_job(proc):
    """Assign a real Windows child to a retained Job Object.

    The job intentionally does not use ``KILL_ON_JOB_CLOSE``: a successful
    synchronous command may deliberately launch a fully detached background
    task.  Explicit timeout/interruption paths terminate the job, while normal
    completion merely releases our handle.
    """
    if not (IS_WINDOWS and os.name == "nt"):
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = (
        wintypes.HANDLE, wintypes.HANDLE,
    )
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL

    job_handle = kernel32.CreateJobObjectW(None, None)
    if not job_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        process_handle = wintypes.HANDLE(int(proc._handle))
        for attempt in range(_WINDOWS_JOB_ASSIGNMENT_RETRY_COUNT + 1):
            if kernel32.AssignProcessToJobObject(job_handle, process_handle):
                break
            error_code = ctypes.get_last_error()
            if (
                error_code != _WINDOWS_ERROR_ACCESS_DENIED
                or attempt >= _WINDOWS_JOB_ASSIGNMENT_RETRY_COUNT
            ):
                raise ctypes.WinError(error_code)
            # A bounded retry accommodates a genuinely transient denial
            # without treating every Job Object failure as transient.  Keep
            # the Job handle/process unchanged; other errors still fail closed
            # without delaying deterministic faults.
            time.sleep(
                _WINDOWS_JOB_ASSIGNMENT_RETRY_DELAY_SECONDS * (attempt + 1)
            )
        setattr(proc, _WINDOWS_JOB_HANDLE_ATTRIBUTE, int(job_handle))
    except BaseException:
        kernel32.CloseHandle(job_handle)
        raise


def _release_windows_managed_job(proc, *, terminate=False):
    """Release a retained Job Object; optionally terminate all its members."""
    raw_handle = getattr(proc, _WINDOWS_JOB_HANDLE_ATTRIBUTE, None)
    if not raw_handle or not (IS_WINDOWS and os.name == "nt"):
        return False

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = wintypes.HANDLE(int(raw_handle))
    terminated = False
    try:
        if terminate:
            terminated = bool(kernel32.TerminateJobObject(handle, 1))
    finally:
        try:
            kernel32.CloseHandle(handle)
        finally:
            try:
                delattr(proc, _WINDOWS_JOB_HANDLE_ATTRIBUTE)
            except AttributeError:
                pass
    return terminated


def managed_popen(*popenargs, **kwargs):
    """Start a synchronous child with cross-platform process-tree ownership."""
    if not IS_WINDOWS:
        # Install before process creation so an external SIGTERM cannot arrive
        # after the child exists but before the manager has any cleanup policy.
        # A tiny CreateProcess-return-to-registration window remains without a
        # thread-unsafe preexec hook; registration is the first post-spawn act.
        _ensure_managed_sigterm_handler()
    for key, value in managed_foreground_process_kwargs().items():
        if key == "creationflags":
            kwargs[key] = int(kwargs.get(key, 0)) | int(value)
        elif key == "start_new_session":
            if key in kwargs and not kwargs[key]:
                raise ValueError("managed foreground process requires a new session")
            kwargs[key] = value
        elif key in kwargs and kwargs[key] != value:
            raise ValueError(f"conflicting managed process option: {key}")
        else:
            kwargs[key] = value
    try:
        proc = subprocess.Popen(*popenargs, **kwargs)
    except BaseException:
        _restore_managed_sigterm_handler()
        raise
    registered = False
    try:
        _register_managed_process_tree(proc)
        registered = True
        _attach_windows_managed_job(proc)
    except BaseException as error:
        # Assignment failure means the advertised tree contract cannot be
        # honored.  Fail closed and reap the just-created process.
        _terminate_subprocess(proc, process_group=registered)
        if not isinstance(error, Exception):
            raise
        raise OSError(
            f"MANAGED_PROCESS_JOB_ASSIGNMENT_FAILED: {type(error).__name__}: {error}"
        ) from error
    return proc


def release_process_tree(proc):
    """Release tree-tracking resources after successful synchronous completion."""
    # Consume ownership before closing the Job handle. A timeout callback that
    # races or fires late then observes no token and cannot target a recycled
    # PID or a handle already released by the successful path.
    if _unregister_managed_process_tree(proc):
        _release_windows_managed_job(proc, terminate=False)


def _git_command_requires_stdout(command):
    """Return whether a successful Git command must produce semantic output."""
    arguments = [str(item or '') for item in (command or ())]
    if 'rev-parse' in arguments or 'symbolic-ref' in arguments:
        return True
    for parent, child in (
        ('worktree', 'list'),
        ('remote', 'get-url'),
    ):
        try:
            index = arguments.index(parent)
        except ValueError:
            continue
        if child in arguments[index + 1:]:
            return True
    return False


def _run_git_file_capture(
    cmd, *, cwd, timeout, input_bytes, env, process_group_kwargs,
):
    """Retry one read-only Git query without relying on a stdout pipe.

    Some Windows GUI-parent process configurations have returned exit code zero
    while losing Git's piped stdout. A temporary file uses an independent
    standard-handle path and lets callers distinguish a capture failure from a
    genuinely empty Git result.
    """
    with tempfile.TemporaryFile(mode='w+b') as stdout_file:
        proc = managed_popen(
            cmd,
            cwd=cwd,
            stdout=stdout_file,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            env=env,
            close_fds=True,
            **process_group_kwargs,
        )
        try:
            _ignored_stdout, stderr_bytes = proc.communicate(
                input=input_bytes,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            _terminate_subprocess(proc, process_group=True)
            _close_subprocess_pipes(proc)
            return '', f'Git 文件捕获重试超时（{timeout}秒）', -1
        except KeyboardInterrupt:
            _terminate_subprocess(proc, process_group=True)
            _close_subprocess_pipes(proc)
            raise
        except BaseException:
            # ``communicate`` may fail while copying input or draining a pipe.
            # The command is still live in that case, so never let it escape
            # the managed foreground boundary without reaping its descendants.
            _terminate_subprocess(proc, process_group=True)
            _close_subprocess_pipes(proc)
            raise
        release_process_tree(proc)
        stdout_file.seek(0)
        stdout_bytes = stdout_file.read()
    return (
        _decode_subprocess_output(stdout_bytes),
        _decode_subprocess_output(stderr_bytes),
        proc.returncode,
    )


def _terminate_subprocess(proc, *, process_group=False):
    """Best-effort process-tree cleanup for managed foreground commands."""
    claimed_process_group = bool(
        process_group and _claim_managed_process_tree(proc)
    )
    if process_group and not claimed_process_group:
        # Ownership may already have been released after success or consumed by
        # another timeout/interrupt path. In either case this call is stale and
        # must not act on a potentially recycled numeric PID.
        return
    if claimed_process_group and IS_WINDOWS:
        # A retained Job Object still owns descendants when the root PID has
        # already exited. Prefer that identity-stable handle and never pair it
        # with a numeric-PID taskkill that could race PID reuse.
        has_job = bool(getattr(proc, _WINDOWS_JOB_HANDLE_ATTRIBUTE, None))
        if has_job:
            try:
                _release_windows_managed_job(proc, terminate=True)
            except BaseException:
                pass
        else:
            # Assignment failure is the sole managed path without a Job. The
            # root has just been created, so use taskkill only while its Popen
            # handle still reports the original process as running.
            try:
                root_running = proc.poll() is None
            except (AttributeError, OSError):
                root_running = False
            if root_running:
                try:
                    subprocess.run(
                        ['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                        check=False,
                        **subprocess_platform_kwargs(),
                    )
                except BaseException:
                    pass
    elif claimed_process_group:
        try:
            # start_new_session=True makes the child PID the process-group ID.
            os.killpg(proc.pid, signal.SIGKILL)
        except (AttributeError, OSError):
            pass

    try:
        running = proc.poll() is None
    except (AttributeError, OSError):
        running = True
    if running:
        try:
            proc.kill()
        except (AttributeError, OSError):
            pass
    try:
        proc.wait(timeout=5)
    except (AttributeError, OSError, subprocess.SubprocessError):
        pass


def terminate_process_tree(proc):
    """Terminate and reap a process launched with managed foreground options.

    This public wrapper lets other synchronous ``Popen`` users share exactly
    the same POSIX/Windows tree-cleanup contract as ``run_cmd``.  Pipe owners
    remain responsible for closing or draining their own file objects.
    """
    _terminate_subprocess(proc, process_group=True)


def _close_subprocess_pipes(proc):
    """Close captured pipes after a forced exit when their output is discarded."""
    for pipe in (
        getattr(proc, "stdin", None),
        getattr(proc, "stdout", None),
        getattr(proc, "stderr", None),
    ):
        if pipe is None:
            continue
        try:
            pipe.close()
        except OSError:
            pass


def run_managed_subprocess(
    command, *, input=None, capture_output=False, timeout=None, check=False,
    **popen_kwargs,
):
    """A ``subprocess.run``-compatible foreground boundary with tree cleanup.

    Only the standard ``run`` arguments used by this project are surfaced;
    remaining process-creation arguments are forwarded to :class:`Popen`.
    Timeout, interruption, and pipe failures terminate the entire managed tree
    before the original exception is re-raised.
    """
    if input is not None and popen_kwargs.get("stdin") is not None:
        raise ValueError("stdin and input arguments may not both be used")
    if capture_output:
        if popen_kwargs.get("stdout") is not None or popen_kwargs.get("stderr") is not None:
            raise ValueError("stdout and stderr arguments may not be used with capture_output")
        popen_kwargs["stdout"] = subprocess.PIPE
        popen_kwargs["stderr"] = subprocess.PIPE
    if input is not None:
        popen_kwargs["stdin"] = subprocess.PIPE

    # These managed calls are the common boundary used by the quality and
    # evidence runners.  A Python child must not inherit a GBK/CP936 stdout
    # codec and turn a successfully completed Unicode test run into return
    # code 1 while printing its final JSON payload.
    provided_env = popen_kwargs.get("env")
    proc_env = dict(os.environ if provided_env is None else provided_env)
    for key in tuple(proc_env):
        if str(key).upper() == "PYTHONIOENCODING":
            proc_env.pop(key, None)
    proc_env["PYTHONIOENCODING"] = "utf-8"
    popen_kwargs["env"] = proc_env

    proc = managed_popen(command, **popen_kwargs)
    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        terminate_process_tree(proc)
        try:
            cleanup_stdout, cleanup_stderr = proc.communicate(timeout=5)
        except BaseException:
            cleanup_stdout = cleanup_stderr = None
            _close_subprocess_pipes(proc)
        if getattr(error, "output", None) is None:
            error.output = cleanup_stdout
        if getattr(error, "stderr", None) is None:
            error.stderr = cleanup_stderr
        raise
    except BaseException:
        terminate_process_tree(proc)
        _close_subprocess_pipes(proc)
        raise
    release_process_tree(proc)
    completed = subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)
    if check:
        completed.check_returncode()
    return completed


def run_cmd(
    cmd, cwd=None, timeout=300, input_text=None, env=None,
    stream_output=False, stream_stdout=True,
):
    """
    跨平台安全地运行子进程，正确处理编码。

    返回 (stdout: str, stderr: str, returncode: int)
    失败时 stdout/stderr 仍是字符串（不会因编码问题抛异常）。

    参数：
      cmd          命令列表，如 ['mvn', 'dependency:tree']
      cwd          工作目录
      timeout      超时秒数
      input_text   stdin 输入（字符串）
      env          额外的环境变量（合并到当前环境；PYTHONIOENCODING 始终强制为 UTF-8）
      stream_output 将子进程 stdout/stderr 实时转发到当前 stderr，同时仍完整捕获返回
      stream_stdout 流式模式下是否转发 stdout；协议型子进程可仅转发 stderr
    """
    raw_command_is_git = _command_uses_git(cmd)
    cmd = resolve_command(cmd)
    command_is_git = raw_command_is_git or _command_uses_git(cmd)
    process_group_kwargs = managed_foreground_process_kwargs()
    observer = _PROCESS_OBSERVER
    try:
        observed_command = _redact_git_command(cmd) if command_is_git else cmd
        observer_token = (
            observer.command_started(observed_command)
            if observer is not None else None
        )
    except (AttributeError, TypeError, ValueError):
        observer_token = None

    def finish(result):
        if command_is_git:
            stdout, stderr, returncode = result
            result = (
                stdout,
                _redact_git_text(stderr),
                returncode,
            )
        return _finish_observed_command(observer, observer_token, result)

    # 构建环境变量：强制 Maven/Git 使用 UTF-8 输出
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)

    # Inline Python helpers do not import this module, so they cannot rely on
    # setup_utf8_io(). Prevent Windows GBK consoles from rejecting Unicode output.
    proc_env['PYTHONIOENCODING'] = 'utf-8'

    # 强制 JVM 工具（Maven）使用 UTF-8
    # 不覆盖已有设置，只追加
    existing_opts = proc_env.get('JAVA_TOOL_OPTIONS', '')
    if 'file.encoding' not in existing_opts:
        proc_env['JAVA_TOOL_OPTIONS'] = (existing_opts + ' -Dfile.encoding=UTF-8').strip()

    if command_is_git:
        _sanitize_git_environment(proc_env)
    else:
        proc_env.setdefault('GIT_TERMINAL_PROMPT', '0')
        proc_env.setdefault('LC_ALL', 'en_US.UTF-8')
        proc_env.setdefault('LANG', 'en_US.UTF-8')

    try:
        if stream_output:
            deadline = (
                None
                if timeout is None
                else time.monotonic() + max(0.0, float(timeout))
            )

            def remaining_timeout():
                if deadline is None:
                    return None
                return max(0.0, deadline - time.monotonic())

            proc = managed_popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=(
                    subprocess.PIPE
                    if input_text is not None
                    else (subprocess.DEVNULL if command_is_git else None)
                ),
                env=proc_env,
                close_fds=True,
                **process_group_kwargs,
            )
            stdout_chunks = []
            stderr_chunks = []
            drain_errors = []
            termination_lock = threading.Lock()
            termination_started = False

            def terminate_tree_once():
                nonlocal termination_started
                with termination_lock:
                    if termination_started:
                        return
                    termination_started = True
                _terminate_subprocess(proc, process_group=True)

            def drain(pipe, chunks, relay):
                try:
                    while True:
                        chunk = pipe.readline()
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if relay:
                            relay_text = _decode_subprocess_output(chunk)
                            if command_is_git:
                                relay_text = _redact_git_text(relay_text)
                            sys.stderr.write(relay_text)
                            sys.stderr.flush()
                except Exception as error:  # pipe/relay failure must reap child tree
                    drain_errors.append(error)
                    terminate_tree_once()
                finally:
                    try:
                        pipe.close()
                    except OSError:
                        pass

            stdout_thread = threading.Thread(
                target=drain, args=(proc.stdout, stdout_chunks, stream_stdout), daemon=True,
            )
            stderr_thread = threading.Thread(
                target=drain, args=(proc.stderr, stderr_chunks, True), daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            try:
                if input_text is not None and proc.stdin is not None:
                    proc.stdin.write(input_text.encode('utf-8'))
                    proc.stdin.close()
                return_code = proc.wait(timeout=remaining_timeout())
            except subprocess.TimeoutExpired:
                terminate_tree_once()
                stdout_thread.join(timeout=5)
                stderr_thread.join(timeout=5)
                _close_subprocess_pipes(proc)
                return finish(('', f'命令超时（{timeout}秒）：{" ".join(str(c) for c in cmd)}', -1))
            except KeyboardInterrupt:
                terminate_tree_once()
                stdout_thread.join(timeout=5)
                stderr_thread.join(timeout=5)
                _close_subprocess_pipes(proc)
                raise
            except BaseException:
                terminate_tree_once()
                stdout_thread.join(timeout=5)
                stderr_thread.join(timeout=5)
                _close_subprocess_pipes(proc)
                raise

            stdout_thread.join(timeout=remaining_timeout())
            stderr_thread.join(timeout=remaining_timeout())
            if stdout_thread.is_alive() or stderr_thread.is_alive():
                # A launcher can exit while one of its descendants retains a
                # captured pipe.  Treat the complete tree as the foreground
                # command and enforce the same overall deadline.
                terminate_tree_once()
                stdout_thread.join(timeout=5)
                stderr_thread.join(timeout=5)
                _close_subprocess_pipes(proc)
                return finish(('', f'命令超时（{timeout}秒）：{" ".join(str(c) for c in cmd)}', -1))
            if drain_errors:
                raise drain_errors[0]
            release_process_tree(proc)
            return finish((
                _decode_subprocess_output(b''.join(stdout_chunks)),
                _decode_subprocess_output(b''.join(stderr_chunks)),
                return_code,
            ))
        input_bytes = input_text.encode('utf-8') if input_text is not None else None
        proc = managed_popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=(
                subprocess.PIPE
                if input_bytes is not None
                else (subprocess.DEVNULL if command_is_git else None)
            ),
            env=proc_env,
            close_fds=True,
            **process_group_kwargs,
        )
        try:
            stdout_bytes, stderr_bytes = proc.communicate(
                input=input_bytes,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            _terminate_subprocess(proc, process_group=True)
            _close_subprocess_pipes(proc)
            return finish(
                ('', f'命令超时（{timeout}秒）：{" ".join(str(c) for c in cmd)}', -1),
            )
        except KeyboardInterrupt:
            _terminate_subprocess(proc, process_group=True)
            _close_subprocess_pipes(proc)
            raise
        except BaseException:
            _terminate_subprocess(proc, process_group=True)
            _close_subprocess_pipes(proc)
            raise
        release_process_tree(proc)

        # 解码输出：先尝试 UTF-8，失败则用系统编码，再失败则替换非法字符
        stdout = _decode_subprocess_output(stdout_bytes)
        stderr = _decode_subprocess_output(stderr_bytes)
        if (
            command_is_git
            and proc.returncode == 0
            and not stdout.strip()
            and _git_command_requires_stdout(cmd)
        ):
            retry_stdout, retry_stderr, retry_rc = _run_git_file_capture(
                cmd,
                cwd=cwd,
                timeout=timeout,
                input_bytes=input_bytes,
                env=proc_env,
                process_group_kwargs=process_group_kwargs,
            )
            if retry_rc == 0 and retry_stdout.strip():
                return finish((retry_stdout, retry_stderr, retry_rc))
            if retry_rc == 0:
                detail = "GIT_REQUIRED_STDOUT_EMPTY: " \
                    "Git 两种捕获方式均返回成功但没有必要输出"
                if stderr or retry_stderr:
                    detail += f"；stderr={retry_stderr or stderr}"
                return finish(('', detail, -1))
            return finish((retry_stdout, retry_stderr or stderr, retry_rc))
        return finish((stdout, stderr, proc.returncode))

    except KeyboardInterrupt:
        finish(('', '', 130))
        raise
    except subprocess.TimeoutExpired:
        return finish(('', f'命令超时（{timeout}秒）：{" ".join(str(c) for c in cmd)}', -1))
    except FileNotFoundError:
        cmd_name = cmd[0] if cmd else '(空命令)'
        return finish(('', f'命令未找到：{cmd_name}（请确认已安装并在 PATH 中）', -1))
    except PermissionError:
        return finish(('', f'权限不足，无法执行：{cmd[0]}', -1))
    except Exception as e:
        return finish(('', f'执行异常：{type(e).__name__}: {e}', -1))


def open_text(path, mode='r', encoding='utf-8', errors='replace'):
    """
    跨平台打开文本文件，统一使用 UTF-8，错误字符替换而非崩溃。
    替代直接使用 open()，避免 Windows 默认 GBK 编码问题。
    """
    return open(path, mode, encoding=encoding, errors=errors, newline='' if 'w' in mode else None)


def write_text(path, content, encoding='utf-8'):
    """写文本文件，确保目录存在，统一 UTF-8 + LF 换行（跨平台一致）"""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding=encoding, errors='replace', newline='\n') as f:
        f.write(content)


def require_human_confirm(title, checklist_lines=None):
    mode = (os.environ.get("JUA_CONFIRM_MODE", "") or "").strip().lower() or "emit"
    try:
        is_tty = bool(sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty())
    except Exception:
        is_tty = False

    sys.stderr.write("\n" + "=" * 60 + "\n")
    sys.stderr.write(f"【人工确认】{(title or '').strip()}\n")
    sys.stderr.write("=" * 60 + "\n")
    sys.stderr.write("请按下面清单逐项确认（含需要打开查看的文件）：\n")
    if checklist_lines:
        for line in checklist_lines:
            if line is None:
                continue
            sys.stderr.write(f"- {str(line).rstrip()}\n")
    sys.stderr.write("\n")
    sys.stderr.write(f"确认模式：{mode}\n")
    if mode in ("prompt", "interactive"):
        if is_tty:
            sys.stderr.write("输入 YES 继续，输入其他任意内容将退出。\n")
        else:
            sys.stderr.write("当前为非交互环境（stdin 非 TTY），无法读取确认输入，将中止。\n")
    elif mode in ("block", "strict"):
        sys.stderr.write("已配置为严格模式（block）：将中止，待人工复核后再继续。\n")
    else:
        sys.stderr.write("已配置为输出模式（emit）：不阻塞执行，仅输出复核清单。\n")
    sys.stderr.write("=" * 60 + "\n")
    sys.stderr.flush()

    if mode in ("emit", "report", "log"):
        return True
    if mode in ("block", "strict"):
        return False
    if mode in ("prompt", "interactive") and not is_tty:
        return False

    try:
        answer = input("YES> ").strip().lower()
    except Exception:
        return False
    return answer == "yes"


def normalize_path(path):
    """
    规范化路径：Windows 上保持原样（Path 会处理），
    但确保返回的是 str 类型（兼容 subprocess 参数）。
    """
    return str(Path(path))


def _git_executable_works(path):
    """Return whether a Git candidate is executable without leaking tool errors."""
    candidate = str(path or '').strip()
    if not candidate or not Path(candidate).is_file():
        return False
    probe_environment = os.environ.copy()
    _sanitize_git_environment(probe_environment)
    try:
        completed = run_managed_subprocess(
            [candidate, '--version'],
            capture_output=True,
            timeout=5,
            check=False,
            env=probe_environment,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _git_platform_fallback_candidates():
    executable_name = 'git.exe' if IS_WINDOWS else 'git'
    candidates = [Path.home() / '.local' / 'bin' / executable_name]
    if sys.platform == 'darwin':
        candidates.extend((
            Path('/opt/homebrew/bin/git'),
            Path('/usr/local/bin/git'),
            Path('/usr/bin/git'),
        ))
    elif IS_WINDOWS:
        for root_name in ('ProgramFiles', 'ProgramFiles(x86)', 'LOCALAPPDATA'):
            root = os.environ.get(root_name, '').strip()
            if not root:
                continue
            root_path = Path(root)
            if root_name == 'LOCALAPPDATA':
                candidates.append(root_path / 'Programs' / 'Git' / 'cmd' / 'git.exe')
            else:
                candidates.extend((
                    root_path / 'Git' / 'cmd' / 'git.exe',
                    root_path / 'Git' / 'bin' / 'git.exe',
                ))
    else:
        candidates.extend((Path('/usr/local/bin/git'), Path('/usr/bin/git')))
    return [str(candidate) for candidate in candidates]


def _find_working_git():
    """Choose explicit Git, then current PATH, then platform fallbacks."""
    cache_key = (
        os.environ.get('JUA_GIT_EXECUTABLE', '').strip(),
        os.environ.get('PATH', ''),
        str(Path.home()),
        sys.platform,
        os.environ.get('ProgramFiles', ''),
        os.environ.get('ProgramFiles(x86)', ''),
        os.environ.get('LOCALAPPDATA', ''),
    )
    with _GIT_EXECUTABLE_CACHE_LOCK:
        if cache_key in _GIT_EXECUTABLE_CACHE:
            return _GIT_EXECUTABLE_CACHE[cache_key]

    candidates = [
        os.environ.get('JUA_GIT_EXECUTABLE', '').strip(),
        shutil.which('git') or '',
        *_git_platform_fallback_candidates(),
    ]

    seen = set()
    for candidate in candidates:
        normalized_candidate = _normalized_executable_path(candidate)
        normalized = os.path.normcase(normalized_candidate) if normalized_candidate else ''
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        if _git_executable_works(normalized_candidate):
            with _GIT_EXECUTABLE_CACHE_LOCK:
                _GIT_EXECUTABLE_CACHE[cache_key] = normalized_candidate
            return normalized_candidate
    with _GIT_EXECUTABLE_CACHE_LOCK:
        _GIT_EXECUTABLE_CACHE[cache_key] = None
    return None


def find_executable(name):
    """
    跨平台查找可执行文件。
    Windows 上会自动尝试加 .cmd/.bat/.exe 后缀。
    """
    normalized_name = str(name or '').strip()
    if not normalized_name:
        return None
    if normalized_name.lower() in {'git', 'git.exe'}:
        return _find_working_git()
    found = shutil.which(normalized_name)
    if found:
        return found
    if IS_WINDOWS:
        for ext in ['.cmd', '.bat', '.exe', '']:
            found = shutil.which(normalized_name + ext)
            if found:
                return found
    return None


def mvn_cmd(work_dir=None):
    """Prefer the project's Maven Wrapper, then fall back to system Maven."""
    if work_dir is not None:
        root = Path(work_dir).resolve()
        wrapper = root / ('mvnw.cmd' if IS_WINDOWS else 'mvnw')
        if wrapper.is_file():
            if IS_WINDOWS or os.access(wrapper, os.X_OK):
                return [str(wrapper)]
            shell = find_executable('sh') or 'sh'
            return [shell, str(wrapper)]
    mvn = find_executable('mvn')
    if mvn:
        return [mvn]
    return ['mvn']  # 让调用方收到 FileNotFoundError 并给出提示


def gradle_cmd(work_dir=None):
    """Prefer the project's Gradle Wrapper, then fall back to system Gradle."""
    root = Path(work_dir or '.').resolve()
    wrapper = root / ('gradlew.bat' if IS_WINDOWS else 'gradlew')
    if wrapper.is_file():
        if IS_WINDOWS or os.access(wrapper, os.X_OK):
            return [str(wrapper)]
        shell = find_executable('sh') or 'sh'
        return [shell, str(wrapper)]
    gradle = find_executable('gradle')
    if gradle:
        return [gradle]
    return ['gradle']


def git_cmd():
    """返回可用的 Git 命令；Windows 全局启用 Git 长路径实现。"""
    git = find_executable('git')
    command = [git] if git else ['git']
    if IS_WINDOWS:
        command.extend(['-c', 'core.longpaths=true'])
    return command


def resolve_command(cmd):
    """Resolve bare Git commands to the validated executable used by the product."""
    if not isinstance(cmd, (list, tuple)) or not cmd:
        return cmd
    first = str(cmd[0] or '')
    if first.lower() not in {'git', 'git.exe'}:
        return cmd
    resolved = find_executable('git')
    return [resolved, *cmd[1:]] if resolved else list(cmd)

def _xml_first_text(elem, local_tag):
    for child in list(elem):
        if (child.tag or '').endswith(local_tag) and (child.text or '').strip():
            return child.text.strip()
    return ''


def _parse_pom_coord(pom_path):
    try:
        root = ET.parse(pom_path).getroot()
    except Exception:
        return None
    artifact_id = _xml_first_text(root, 'artifactId')
    group_id = _xml_first_text(root, 'groupId')
    if not group_id:
        for child in list(root):
            if (child.tag or '').endswith('parent'):
                group_id = _xml_first_text(child, 'groupId')
                break
    if group_id and artifact_id:
        return f"{group_id}:{artifact_id}"
    return None


def _read_text_if_exists(path):
    path = Path(path)
    if not path.exists() or not path.is_file():
        return ''
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return ''

def _extract_gradle_group_from_text(text):
    if not text:
        return ''

    def is_valid_group_id(value):
        value = value.strip()
        if not value:
            return False
        if any(ch.isupper() for ch in value):
            return False
        return bool(re.fullmatch(r'[a-z0-9_.\-]+', value))

    patterns = [
        r'^\s*group\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'^\s*group\s+[\'"]([^\'"]+)[\'"]',
        r'^\s*group\s*=\s*([A-Za-z0-9_.\-]+)',
    ]
    for pattern in patterns:
        m = re.search(pattern, text, re.MULTILINE)
        if m:
            candidate = m.group(1).strip()
            if is_valid_group_id(candidate):
                return candidate
    return ''


def _extract_gradle_artifact_from_text(text):
    if not text:
        return ''
    patterns = [
        r'^\s*archivesBaseName\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'^\s*archivesName\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'^\s*artifactId\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'^\s*rootProject\.name\s*=\s*[\'"]([^\'"]+)[\'"]',
    ]
    for pattern in patterns:
        m = re.search(pattern, text, re.MULTILINE)
        if m:
            return m.group(1).strip()
    return ''


def _extract_group_from_gradle_properties(module_dir):
    current = Path(module_dir).resolve()
    for candidate in [current, *current.parents]:
        text = _read_text_if_exists(candidate / 'gradle.properties')
        if not text:
            continue
        m = re.search(r'^\s*group\s*=\s*([A-Za-z0-9_.\-]+)\s*$', text, re.MULTILINE)
        if m:
            return m.group(1).strip()
    return ''


def _extract_artifact_from_settings(module_dir):
    current = Path(module_dir).resolve()
    for candidate in [current, *current.parents]:
        for settings_name in ('settings.gradle', 'settings.gradle.kts'):
            text = _read_text_if_exists(candidate / settings_name)
            if not text:
                continue
            m = re.search(r'^\s*rootProject\.name\s*=\s*[\'"]([^\'"]+)[\'"]', text, re.MULTILINE)
            if m:
                return m.group(1).strip()
    return ''


def _artifact_id_from_gradle_build_file(build_file):
    build_file = Path(build_file).resolve()
    name = build_file.name
    if name in ('build.gradle', 'build.gradle.kts'):
        return ''
    if name.endswith('.gradle.kts'):
        return name[:-11].strip()
    if name.endswith('.gradle'):
        return name[:-7].strip()
    return ''


def _iter_gradle_build_files(module_dir):
    # Callers that scan repositories already pass an absolute path rooted at a
    # resolved repository directory.  Resolving every visited directory is
    # especially expensive on Windows, where Path.resolve() canonicalizes
    # reparse points through ntpath.realpath().
    module_dir = Path(module_dir)
    seen = set()
    for name in ('build.gradle', 'build.gradle.kts'):
        candidate = module_dir / name
        if candidate.exists():
            seen.add(candidate.name)
            yield candidate
    for pattern in ('*.gradle', '*.gradle.kts'):
        for candidate in sorted(module_dir.glob(pattern)):
            if candidate.name in seen:
                continue
            if candidate.name.startswith('settings.gradle'):
                continue
            seen.add(candidate.name)
            yield candidate


def _extract_gradle_group_from_file(file_path):
    text = _read_text_if_exists(file_path)
    if not text:
        return ''
    return _extract_gradle_group_from_text(text)


def _infer_gradle_group_from_ancestors(module_dir, repo_root):
    current = Path(module_dir).resolve()
    repo_root = Path(repo_root).resolve()
    for candidate in [current, *current.parents]:
        if candidate == repo_root.parent:
            break
        group_id = _extract_group_from_gradle_properties(candidate)
        if group_id:
            return group_id
        for build_path in _iter_gradle_build_files(candidate):
            group_id = _extract_gradle_group_from_file(build_path)
            if group_id:
                return group_id
        if candidate == repo_root:
            break
    return ''


def _parse_gradle_coord(build_file):
    build_file = Path(build_file).resolve()
    text = _read_text_if_exists(build_file)
    if not text:
        return None
    module_dir = build_file.parent
    group_id = _extract_gradle_group_from_text(text) or _extract_group_from_gradle_properties(module_dir)
    artifact_id = _extract_gradle_artifact_from_text(text)
    if not artifact_id:
        artifact_id = _artifact_id_from_gradle_build_file(build_file)
    if not artifact_id and any(
        (module_dir / name).is_file()
        for name in ('settings.gradle', 'settings.gradle.kts')
    ):
        # A root project's declared name is stable across temporary checkout
        # directories.  Do not search ancestor settings for nested modules:
        # their artifact identity remains the module/build-file name.
        artifact_id = _extract_artifact_from_settings(module_dir)
    if not artifact_id:
        artifact_id = module_dir.name
    if group_id and artifact_id:
        return f"{group_id}:{artifact_id}"
    return None


def _parse_gradle_coord_with_repo_context(build_file, repo_root):
    coord = _parse_gradle_coord(build_file)
    if coord:
        return coord
    module_dir = Path(build_file).resolve().parent
    group_id = _infer_gradle_group_from_ancestors(module_dir, repo_root)
    artifact_id = _artifact_id_from_gradle_build_file(build_file) or module_dir.name.strip()
    if group_id and artifact_id:
        return f"{group_id}:{artifact_id}"
    return None


def _resolve_repo_probe_roots(project_dir):
    path = Path(project_dir).expanduser()
    if not path.is_absolute():
        path = path.resolve()
    if path.is_file():
        if path.name == '.git':
            path = path.parent
        else:
            path = path.parent
    elif path.is_dir() and path.name == '.git':
        path = path.parent
    path = path.resolve()

    roots = []
    manifest_names = {
        'pom.xml',
        'build.gradle',
        'build.gradle.kts',
        'settings.gradle',
        'settings.gradle.kts',
        'gradle.properties',
    }
    for candidate in [path, *path.parents]:
        has_marker = any((candidate / name).exists() for name in manifest_names) or (candidate / '.git').exists()
        if not has_marker:
            continue
        roots.append(candidate.resolve())
    if not roots:
        roots.append(path)
    return roots


def resolve_repo_input_path(path_value):
    roots = _resolve_repo_probe_roots(path_value)
    return str((roots[0] if roots else Path(path_value).resolve()))


def _find_git_root(path_value):
    current = Path(path_value).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / '.git').exists():
            return candidate
    return None


def _is_embedded_resource_fixture_dir(path_value, repo_root):
    # Repository walkers pass paths derived from the same resolved root, so a
    # lexical relative check is sufficient and avoids a realpath call for every
    # directory and every child considered by os.walk().
    current = Path(path_value)
    base = Path(repo_root)
    try:
        rel_parts = current.relative_to(base).parts
    except Exception:
        rel_parts = current.parts
    for idx in range(len(rel_parts) - 2):
        if (
            rel_parts[idx] == 'src'
            and rel_parts[idx + 1] in ('main', 'test')
            and rel_parts[idx + 2] == 'resources'
        ):
            return True
    return False


def _has_child_module_manifests(root_path, max_depth=4):
    skip_dirs = {'.git', 'target', 'build', '.gradle', 'out', 'bin', '.idea', '.upgrade-report'}
    base = Path(root_path).resolve()
    if not base.exists() or not base.is_dir():
        return False
    for current_root, dirs, files in os.walk(str(base)):
        current = Path(current_root)
        if _is_embedded_resource_fixture_dir(current, base):
            dirs[:] = []
            continue
        try:
            rel_parts = current.relative_to(base).parts
        except Exception:
            rel_parts = ()
        if len(rel_parts) >= max_depth:
            dirs[:] = []
        else:
            dirs[:] = [
                d for d in dirs
                if d not in skip_dirs
                and not _is_embedded_resource_fixture_dir(current / d, base)
            ]
        if current == base:
            continue
        has_gradle_manifest = any(path.name in files for path in _iter_gradle_build_files(current))
        if 'pom.xml' in files or has_gradle_manifest:
            return True
    return False


def _looks_like_source_module(module_dir):
    base = Path(module_dir).resolve()
    source_markers = (
        'src/main/java',
        'src/main/kotlin',
        'src/java',
        'java/src',
    )
    return any((base / marker).is_dir() for marker in source_markers)


def infer_maven_coord_locations(
    project_dir,
    max_poms=None,
    *,
    max_depth=None,
    target_coords=None,
):
    normalized_root = resolve_repo_input_path(project_dir)
    if not normalized_root:
        return []
    probe_roots = [Path(normalized_root).resolve()]
    seen = set()
    locations = []
    skip_dirs = {'.git', 'target', 'build', '.gradle', 'out', 'bin', '.idea', '.upgrade-report'}
    count = 0
    target_coords = {
        normalized
        for item in (target_coords or [])
        if (normalized := str(item or "").strip())
    }

    def add_location(coord, module_dir, repo_root):
        if (
            not coord
            or coord in seen
            or (target_coords and coord not in target_coords)
        ):
            return
        seen.add(coord)
        locations.append(
            {
                "coord": coord,
                "module_dir": str(Path(module_dir).resolve()),
                "repo_root": str(Path(repo_root).resolve()),
            }
        )

    for probe_root in probe_roots:
        if not probe_root.exists():
            continue
        repo_root = _find_git_root(probe_root) or probe_root
        skip_probe_root_as_module = (
            _has_child_module_manifests(probe_root)
            and not _looks_like_source_module(probe_root)
        )
        direct_pom = probe_root / 'pom.xml'
        if direct_pom.exists() and not skip_probe_root_as_module:
            c = _parse_pom_coord(str(direct_pom))
            add_location(c, probe_root, repo_root)
        for direct_build in _iter_gradle_build_files(probe_root):
            if not skip_probe_root_as_module:
                c = _parse_gradle_coord_with_repo_context(str(direct_build), repo_root)
                add_location(c, probe_root, repo_root)

        for root, dirs, files in os.walk(probe_root):
            files = sorted(files)
            # probe_root is resolved once above and os.walk() preserves that
            # absolute prefix.  Avoid resolving every directory in the tree.
            current_root = Path(root)
            try:
                relative_depth = len(current_root.relative_to(probe_root).parts)
            except ValueError:
                relative_depth = 0
            if _is_embedded_resource_fixture_dir(current_root, probe_root):
                dirs[:] = []
                continue
            dirs[:] = [] if (
                max_depth is not None and relative_depth >= max_depth
            ) else [
                d for d in dirs
                if d not in skip_dirs
                and not _is_embedded_resource_fixture_dir(current_root / d, probe_root)
            ]
            dirs.sort()
            if 'pom.xml' in files:
                if skip_probe_root_as_module and current_root == probe_root:
                    pass
                else:
                    pom_path = Path(root) / 'pom.xml'
                    c = _parse_pom_coord(str(pom_path))
                    add_location(c, root, repo_root)
                    count += 1
            for build_path in _iter_gradle_build_files(current_root):
                if build_path.name not in files:
                    continue
                if skip_probe_root_as_module and current_root == probe_root:
                    continue
                c = _parse_gradle_coord_with_repo_context(str(build_path), repo_root)
                add_location(c, root, repo_root)
                count += 1
            if max_poms and count >= max_poms:
                break
            if target_coords and target_coords.issubset(seen):
                break
        if max_poms and count >= max_poms:
            break
    return locations


def infer_maven_coords(project_dir, max_poms=None):
    return [item.get("coord") for item in infer_maven_coord_locations(project_dir, max_poms=max_poms) if item.get("coord")]


# ── 模块加载时自动设置 UTF-8 IO ──────────────────────────────────
setup_utf8_io()

if __name__ == '__main__':
    # 诊断模式：输出当前平台的编码情况
    print(f"平台: {'Windows' if IS_WINDOWS else sys.platform}")
    print(f"Python 默认编码: {sys.getdefaultencoding()}")
    print(f"stdout 编码: {getattr(sys.stdout, 'encoding', 'unknown')}")
    print(f"stderr 编码: {getattr(sys.stderr, 'encoding', 'unknown')}")
    print(f"locale 偏好编码: {locale.getpreferredencoding(False)}")
    print(f"检测到子进程编码: {_SUBPROCESS_ENCODING}")
    print(f"Maven 命令: {mvn_cmd()}")
    print(f"Git 命令: {git_cmd()}")

    # 测试 Maven 输出解码
    print("\n测试 git --version 输出：")
    stdout, stderr, rc = run_cmd(git_cmd() + ['--version'])
    print(f"  stdout: {stdout.strip()}")
    print(f"  returncode: {rc}")
