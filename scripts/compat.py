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
import threading
import safe_xml as ET
from pathlib import Path

# ── 平台检测 ──────────────────────────────────────────────────────
IS_WINDOWS = sys.platform == 'win32'

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
                ['cmd', '/c', 'chcp'], capture_output=True, timeout=5
            )
            output = result.stdout.decode('mbcs', errors='replace')
            if '65001' in output:
                return 'utf-8'
            if '936' in output or '54936' in output:
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
                return (elem.text or '').strip()
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
    for enc in ['utf-8', _SUBPROCESS_ENCODING, 'latin-1']:
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode('utf-8', errors='replace')


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

    # 强制 Git 使用 UTF-8
    proc_env.setdefault('GIT_TERMINAL_PROMPT', '0')  # 禁止 git 弹出密码提示
    proc_env.setdefault('LC_ALL', 'en_US.UTF-8')
    proc_env.setdefault('LANG', 'en_US.UTF-8')

    try:
        if stream_output:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_text is not None else None,
                env=proc_env,
            )
            stdout_chunks = []
            stderr_chunks = []

            def drain(pipe, chunks, relay):
                try:
                    while True:
                        chunk = pipe.readline()
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if relay:
                            sys.stderr.write(_decode_subprocess_output(chunk))
                            sys.stderr.flush()
                finally:
                    pipe.close()

            stdout_thread = threading.Thread(
                target=drain, args=(proc.stdout, stdout_chunks, stream_stdout), daemon=True,
            )
            stderr_thread = threading.Thread(
                target=drain, args=(proc.stderr, stderr_chunks, True), daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            if input_text is not None and proc.stdin is not None:
                proc.stdin.write(input_text.encode('utf-8'))
                proc.stdin.close()
            try:
                return_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                stdout_thread.join(timeout=5)
                stderr_thread.join(timeout=5)
                return '', f'命令超时（{timeout}秒）：{" ".join(str(c) for c in cmd)}', -1
            stdout_thread.join()
            stderr_thread.join()
            return (
                _decode_subprocess_output(b''.join(stdout_chunks)),
                _decode_subprocess_output(b''.join(stderr_chunks)),
                return_code,
            )
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            capture_output=True,
            # 不使用 text=True，手动解码以控制错误处理
            env=proc_env,
            input=input_text.encode('utf-8') if input_text else None,
        )

        # 解码输出：先尝试 UTF-8，失败则用系统编码，再失败则替换非法字符
        stdout = _decode_subprocess_output(proc.stdout)
        stderr = _decode_subprocess_output(proc.stderr)
        return stdout, stderr, proc.returncode

    except subprocess.TimeoutExpired:
        return '', f'命令超时（{timeout}秒）：{" ".join(str(c) for c in cmd)}', -1
    except FileNotFoundError:
        cmd_name = cmd[0] if cmd else '(空命令)'
        return '', f'命令未找到：{cmd_name}（请确认已安装并在 PATH 中）', -1
    except PermissionError:
        return '', f'权限不足，无法执行：{cmd[0]}', -1
    except Exception as e:
        return '', f'执行异常：{type(e).__name__}: {e}', -1


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


def find_executable(name):
    """
    跨平台查找可执行文件。
    Windows 上会自动尝试加 .cmd/.bat/.exe 后缀。
    """
    import shutil
    found = shutil.which(name)
    if found:
        return found
    if IS_WINDOWS:
        for ext in ['.cmd', '.bat', '.exe', '']:
            found = shutil.which(name + ext)
            if found:
                return found
    return None


def mvn_cmd():
    """返回可用的 Maven 命令（Windows 上是 mvn.cmd）"""
    mvn = find_executable('mvn')
    if mvn:
        return [mvn]
    return ['mvn']  # 让调用方收到 FileNotFoundError 并给出提示


def git_cmd():
    """返回可用的 Git 命令"""
    git = find_executable('git')
    if git:
        return [git]
    return ['git']

def _xml_first_text(elem, local_tag):
    for child in list(elem):
        if (child.tag or '').endswith(local_tag) and (child.text or '').strip():
            return (child.text or '').strip()
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
        value = (value or '').strip()
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
            candidate = (m.group(1) or '').strip()
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
            return (m.group(1) or '').strip()
    return ''


def _extract_group_from_gradle_properties(module_dir):
    current = Path(module_dir).resolve()
    for candidate in [current, *current.parents]:
        text = _read_text_if_exists(candidate / 'gradle.properties')
        if not text:
            continue
        m = re.search(r'^\s*group\s*=\s*([A-Za-z0-9_.\-]+)\s*$', text, re.MULTILINE)
        if m:
            return (m.group(1) or '').strip()
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
                return (m.group(1) or '').strip()
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
        artifact_id = (
            _artifact_id_from_gradle_build_file(build_file)
            or module_dir.name
            or _extract_artifact_from_settings(module_dir)
        )
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
    seen = set()
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
        resolved = str(candidate.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
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


def infer_maven_coord_locations(project_dir, max_poms=None):
    normalized_root = resolve_repo_input_path(project_dir)
    if not normalized_root:
        return []
    probe_roots = [Path(normalized_root).resolve()]
    seen = set()
    locations = []
    skip_dirs = {'.git', 'target', 'build', '.gradle', 'out', 'bin', '.idea', '.upgrade-report'}
    count = 0

    def add_location(coord, module_dir, repo_root):
        if not coord or coord in seen:
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
            if direct_build.exists() and not skip_probe_root_as_module:
                c = _parse_gradle_coord_with_repo_context(str(direct_build), repo_root)
                add_location(c, probe_root, repo_root)

        for root, dirs, files in os.walk(probe_root):
            files = sorted(files)
            # probe_root is resolved once above and os.walk() preserves that
            # absolute prefix.  Avoid resolving every directory in the tree.
            current_root = Path(root)
            if _is_embedded_resource_fixture_dir(current_root, probe_root):
                dirs[:] = []
                continue
            dirs[:] = [
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
