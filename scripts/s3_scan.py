#!/usr/bin/env python3
"""
s3_scan.py — Step 3：静态扫描（替代全部 Shell 脚本，Windows/Linux/macOS 兼容）

合并了原来 7 个 Shell 脚本的功能：
  jdk_removed    — JDK 9~21 已移除/废弃的 API
  javax          — javax.* 引用（区分需迁移和不需迁移）
  jdk_internal   — JDK 内部 API（sun.* / jdk.internal.* 等）
  reflection     — 反射操作（JPMS 强封装影响）
  serialization  — Java 原生序列化兼容性
  sb_config      — Spring Boot 配置属性键
  sb_autoconfig  — 自动装配配置文件迁移

用法：
  # 单项扫描
  python s3_scan.py --type jdk_removed  --source-dir . --output .upgrade-report/s3_jdk_removed_api.csv
  python s3_scan.py --type javax        --source-dir . --output .upgrade-report/s3_jdk_javax_refs.csv
  python s3_scan.py --type jdk_internal --source-dir . --output .upgrade-report/s3_jdk_internal_api.csv
  python s3_scan.py --type reflection   --source-dir . --output .upgrade-report/s3_jdk_reflection.csv
  python s3_scan.py --type serialization --source-dir . --output .upgrade-report/s3_jdk_serialization.txt
  python s3_scan.py --type sb_config    --source-dir . --output .upgrade-report/s3_springboot_config.csv
  python s3_scan.py --type sb_autoconfig --source-dir . --output .upgrade-report/s3_springboot_autoconfig.txt

  # 全部一次运行
  python s3_scan.py --all --source-dir . --output-dir .upgrade-report/
"""

import argparse, csv, os, re, sys, time, zipfile
from pathlib import Path
from datetime import datetime
import json

sys.path.insert(0, str(Path(__file__).parent))
from compat import open_text, write_text, maven_repo_dir
from progress_logging import PhaseTimer, emit_progress


MAIN_STATE_FILE_NAME = "main_state.json"


def load_orchestrated_step3_input(report_dir):
    """正式流程下从 main_state 和 s2_context 读取 Step3 输入，单脚本 CLI 仅用于调试。"""
    if not os.environ.get("JUA_ORCHESTRATED"):
        return {}, {}
    state_path = Path(report_dir) / MAIN_STATE_FILE_NAME
    context_path = Path(report_dir) / "s2_context.json"
    main_state = {}
    context = {}
    if state_path.exists():
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                main_state = json.load(f)
        except Exception:
            main_state = {}
    if context_path.exists():
        try:
            with open(context_path, "r", encoding="utf-8") as f:
                context = json.load(f)
        except Exception:
            context = {}
    step_input = dict((((main_state or {}).get("step3") or {}).get("input")) or {})
    return step_input, dict(context or {})


DEP_COMPAT_INCLUDE_TEST_SCOPE = False
TARGET_JDK = None

# ── 跳过的目录（全平台一致）─────────────────────────────────────
SKIP_DIRS = {'.git', 'target', 'build', '.gradle', 'out', 'bin',
             '__pycache__', 'node_modules', '.upgrade-report', '.trae'}

# ── JDK 内置 javax 包（不需要迁移到 jakarta）──────────────────────
JDK_JAVAX_PKGS = {
    'javax.crypto', 'javax.net', 'javax.security.auth',
    'javax.security.cert', 'javax.security.sasl',
    'javax.sql', 'javax.management', 'javax.naming',
    'javax.swing', 'javax.imageio', 'javax.print',
    'javax.sound', 'javax.xml.crypto', 'javax.xml.namespace',
    'javax.xml.parsers', 'javax.xml.stream', 'javax.xml.transform',
    'javax.xml.validation', 'javax.xml.xpath',
}


def is_jdk_javax(pkg_prefix):
    """判断某个 javax 包是否属于 JDK 自身（不需要迁移）"""
    return any(pkg_prefix.startswith(j) for j in JDK_JAVAX_PKGS)


# ══════════════════════════════════════════════════════════════════
# 通用文件扫描工具
# ══════════════════════════════════════════════════════════════════

def iter_source_roots(source_input):
    """把单目录/多目录输入统一展开为去重后的目录列表"""
    if isinstance(source_input, (list, tuple, set)):
        raw_items = list(source_input)
    else:
        raw_items = [source_input]

    seen = set()
    for item in raw_items:
        path = str(item or '').strip()
        if not path or not os.path.isdir(path):
            continue
        normalized = os.path.abspath(path)
        if normalized in seen:
            continue
        seen.add(normalized)
        yield normalized


def walk_files(source_dir, extensions, skip_test=False):
    """递归遍历目录，生成所有指定扩展名的文件路径"""
    for source_root in iter_source_roots(source_dir):
        for root, dirs, files in os.walk(source_root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in extensions:
                    continue
                fpath = os.path.join(root, fname)
                if skip_test:
                    normalized = fpath.replace('\\', '/')
                    if any(
                        marker in normalized
                        for marker in (
                            '/src/test/',
                            '/src/it/',
                            '/src/integration-test/',
                            '/src/integrationTest/',
                        )
                    ):
                        continue
                    if fname.endswith(('IT.java', 'Tests.java')) or normalized.endswith('/Test.java'):
                        continue
                yield fpath


def scan_pattern(source_dir, pattern, extensions=('.java',),
                 skip_comment=True, skip_test=False, max_per_file=None):
    """
    在指定目录中搜索匹配 pattern 的行。
    返回 [(file, lineno, content), ...]
    纯 Python 实现，无需 grep，Windows 完全兼容。
    """
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        print(f"  正则编译失败 '{pattern}': {e}", file=sys.stderr)
        return []

    results = []
    for fpath in walk_files(source_dir, set(extensions), skip_test=skip_test):
        count = 0
        try:
            with open_text(fpath) as f:
                for lineno, line in enumerate(f, 1):
                    raw = line.rstrip('\r\n')
                    stripped = raw.strip()
                    # 跳过注释行
                    if skip_comment and (stripped.startswith('//') or
                                         stripped.startswith('*') or
                                         stripped.startswith('/*')):
                        continue
                    if compiled.search(raw):
                        results.append((fpath, lineno, stripped[:200]))
                        count += 1
                        if max_per_file and count >= max_per_file:
                            break
        except Exception:
            continue
    return results


def write_csv_results(rows, fieldnames, output_path):
    """写 CSV 结果文件"""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def write_text_results(lines, output_path):
    """写文本结果文件"""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    content = '\n'.join(lines) + '\n'
    write_text(output_path, content)
    return len(lines)


def load_dep_changes(csv_path):
    """读取 Step 1 输出，供依赖 jar 扫描使用"""
    rows = []
    if not csv_path or not os.path.exists(csv_path):
        return rows
    try:
        with open_text(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row:
                    continue
                normalized = {k: (v or '').strip() for k, v in row.items()}
                if normalized.get('resolution_status') == 'unresolved':
                    continue
                if normalized.get('coord'):
                    rows.append(normalized)
    except Exception:
        return []
    return rows


def resolve_dep_version(row):
    """优先扫描当前版本，没有则退回旧版本"""
    new_ver = row.get('new_version', '')
    old_ver = row.get('old_version', '')
    if new_ver and new_ver != '-':
        return new_ver
    if old_ver and old_ver != '-':
        return old_ver
    return None

def resolve_current_dep_version(row):
    """仅解析当前分支依赖版本（基于 new_version；被移除的依赖返回 None）"""
    new_ver = (row.get('new_version') or '').strip()
    if new_ver and new_ver != '-':
        return new_ver
    return None

def load_current_deps(csv_path):
    deps = []
    if not csv_path or not os.path.exists(csv_path):
        return deps
    try:
        with open_text(csv_path) as f:
            reader = csv.DictReader(f)
            fieldnames = set(reader.fieldnames or [])
            is_dep_changes = 'new_version' in fieldnames
            is_current_list = 'version' in fieldnames
            for row in reader:
                if not row:
                    continue
                normalized = {k: (v or '').strip() for k, v in row.items()}
                if normalized.get('resolution_status') == 'unresolved':
                    continue
                coord = (normalized.get('coord') or '').strip()
                if not coord:
                    continue
                scope = (normalized.get('scope') or 'compile').strip()
                if is_current_list:
                    version = (normalized.get('version') or '').strip()
                elif is_dep_changes:
                    version = resolve_current_dep_version(normalized)
                else:
                    version = ''
                if not version or version == '-':
                    continue
                deps.append({'coord': coord, 'version': version, 'scope': scope})
    except Exception:
        return []
    return deps


def find_maven_jar(coord, version):
    """在本地 Maven 仓库定位 jar，支持带 classifier 的坐标"""
    parts = coord.split(':')
    if len(parts) < 2 or not version:
        return None
    group_id, artifact_id = parts[0], parts[1]
    classifier = parts[2] if len(parts) >= 3 else None

    base = maven_repo_dir()
    for part in group_id.split('.'):
        base = base / part
    base = base / artifact_id / version
    if not base.exists():
        return None

    patterns = []
    if classifier:
        patterns.append(f"{artifact_id}-{version}-{classifier}.jar")
    patterns.extend([
        f"{artifact_id}-{version}.jar",
        f"{artifact_id}-{version}-*.jar",
    ])

    for pattern in patterns:
        matches = [m for m in base.glob(pattern)
                   if 'sources' not in m.name and 'javadoc' not in m.name]
        if matches:
            return str(matches[0])
    return None


def should_scan_dep_scope(scope):
    s = (scope or '').strip().lower()
    if DEP_COMPAT_INCLUDE_TEST_SCOPE:
        return True
    return s != 'test'

def classfile_major_to_java(major):
    mapping = {
        45: 1, 46: 2, 47: 3, 48: 4, 49: 5, 50: 6, 51: 7,
        52: 8, 53: 9, 54: 10, 55: 11, 56: 12, 57: 13,
        58: 14, 59: 15, 60: 16, 61: 17, 62: 18, 63: 19,
        64: 20, 65: 21,
    }
    return mapping.get(major)

def parse_class_major_version(data):
    if not data or len(data) < 8:
        return None
    if data[0:4] != b'\xCA\xFE\xBA\xBE':
        return None
    return int.from_bytes(data[6:8], byteorder='big', signed=False)


# ══════════════════════════════════════════════════════════════════
# 扫描规则定义
# ══════════════════════════════════════════════════════════════════

# JDK 升级相关 API 规则
# (pattern, api_name, affected_version, status)
JDK_REMOVED_RULES = [
    (r'javax\.xml\.bind',                   'JAXB',                'JDK11', 'REMOVED'),
    (r'javax\.xml\.ws',                     'JAX-WS',              'JDK11', 'REMOVED'),
    (r'javax\.activation',                  'Activation',          'JDK11', 'REMOVED'),
    (r'org\.omg\.|javax\.rmi\.',            'CORBA',               'JDK11', 'REMOVED'),
    (r'java\.rmi\.activation',              'RMI_Activation',      'JDK17', 'REMOVED'),
    (r'java\.applet|JApplet',               'Applet',              'JDK17', 'REMOVED'),
    (r'jdk\.nashorn|NashornScriptEngine',   'Nashorn',             'JDK15', 'REMOVED'),
    (r'runFinalizersOnExit',                'runFinalizersOnExit', 'JDK11', 'REMOVED'),
    (r'Class\.newInstance\(\)',             'Class.newInstance',   'JDK9',  'DEPRECATED'),
    (r'\bfinalize\s*\(\s*\)',               'finalize',            'JDK18', 'DEPRECATED_FOR_REMOVAL'),
    (r'new\s+URL\s*\(',                     'URL_constructor',     'JDK20', 'DEPRECATED'),
    (r'\b(?:System\.getSecurityManager|System\.setSecurityManager)\b', 'SecurityManager', 'JDK17', 'DEPRECATED_FOR_REMOVAL'),
]

# JDK 内部 API 扫描规则
JDK_INTERNAL_RULES = [
    (r'sun\.misc\.',              'sun.misc'),
    (r'sun\.reflect\.',           'sun.reflect'),
    (r'com\.sun\.(?:crypto\.provider\.|security\.|management\.|jndi\.|org\.apache\.xerces\.internal\.|org\.apache\.xalan\.internal\.|rowset\.)', 'com.sun.internal'),
    (r'jdk\.internal\.',          'jdk.internal'),
    (r'setAccessible\s*\(\s*true', 'setAccessible'),
    (r'\b(?:System\.getSecurityManager|System\.setSecurityManager|checkPermission|AccessController)\b', 'SecurityManager'),
]

# 反射操作扫描规则
REFLECTION_RULES = [
    (r'Class\.forName\s*\(',                     'Class.forName'),
    (r'\.getMethod\s*\(|\.getDeclaredMethod\s*\(', 'getMethod'),
    (r'\.getField\s*\(|\.getDeclaredField\s*\(',   'getField'),
    (r'\.getConstructor\s*\(|\.getDeclaredConstructor\s*\(', 'getConstructor'),
    (r'Proxy\.newProxyInstance\s*\(',             'DynamicProxy'),
    (r'MethodHandle|MethodHandles\.lookup',        'MethodHandle'),
    (r'extends\s+ClassLoader|new\s+URLClassLoader', 'CustomClassLoader'),
    (r'ServiceLoader\.load\s*\(',                 'ServiceLoader'),
]

JDK_RUNTIME_FLAG_RULES = [
    (r'--illegal-access(\b|=)', '--illegal-access', 'JDK17 移除该参数；升级后启动可能失败', 'JDK17'),
    (r'-Djava\.ext\.dirs(\b|=)', '-Djava.ext.dirs', 'JDK9 移除扩展机制；启动可能失败', 'JDK9'),
    (r'-Djava\.endorsed\.dirs(\b|=)', '-Djava.endorsed.dirs', 'JDK9 移除 endorsed 机制；启动可能失败', 'JDK9'),
    (r'-Xbootclasspath(/p|/a)?\b', '-Xbootclasspath*', 'JPMS 之后行为变化；需要确认是否仍生效', 'JDK9+'),
    (r'-XX:MaxPermSize(\b|=)', '-XX:MaxPermSize', 'JDK8 之后无效；可能导致误判或启动告警', 'JDK8'),
    (r'-XX:\+UseConcMarkSweepGC\b', '-XX:+UseConcMarkSweepGC', 'JDK14 移除 CMS；启动失败', 'JDK14'),
    (r'-XX:\+UseParNewGC\b', '-XX:+UseParNewGC', 'JDK14 移除 ParNew；启动失败', 'JDK14'),
    (r'-XX:\+UseBiasedLocking\b', '-XX:+UseBiasedLocking', 'JDK15 移除偏向锁；启动失败', 'JDK15'),
    (r'-XX:BiasedLockingStartupDelay(\b|=)', '-XX:BiasedLockingStartupDelay', 'JDK15 移除偏向锁相关参数；启动失败', 'JDK15'),
    (r'-XX:\+UnlockCommercialFeatures\b', '-XX:+UnlockCommercialFeatures', 'JDK11 移除商业特性开关；启动失败', 'JDK11'),
    (r'-Djava\.security\.manager(\b|=)', '-Djava.security.manager', 'JDK17+ 已弃用 SecurityManager；需评估后续移除影响', 'JDK17+'),
    (r'--add-opens(\b|=)', '--add-opens', 'JPMS 强封装相关；升级后需核对目标模块与包名', 'JDK9+'),
    (r'--add-exports(\b|=)', '--add-exports', 'JPMS 强封装相关；升级后需核对目标模块与包名', 'JDK9+'),
    (r'--add-modules(\b|=)', '--add-modules', 'JPMS 模块依赖相关；升级后需核对模块可用性', 'JDK9+'),
]


# ══════════════════════════════════════════════════════════════════
# 各扫描模块
# ══════════════════════════════════════════════════════════════════

def scan_jdk_removed(source_dir, output_path, _dep_changes_path=None):
    """扫描 JDK 9~21 已移除 API"""
    rows = []
    for pattern, api_name, removed_ver, status in JDK_REMOVED_RULES:
        hits = scan_pattern(source_dir, pattern, extensions=('.java',))
        for fpath, lineno, content in hits:
            rows.append({
                '文件': fpath,
                '行号': lineno,
                '内容': content.replace(',', ';'),
                'API':  api_name,
                '移除版本': removed_ver,
                '状态': status,
                '置信度': 'CONFIRMED' if status == 'REMOVED' else 'SUSPECT',
                '证据': f'pattern={pattern};status={status}',
            })

    rows.extend(scan_thread_lifecycle_calls(source_dir))
    count = write_csv_results(rows,
                               ['文件', '行号', '内容', 'API', '移除版本', '状态', '置信度', '证据'],
                               output_path)
    print(f"  jdk_removed: {count} 处命中 → {output_path}", file=sys.stderr)
    return count


def scan_thread_lifecycle_calls(source_dir):
    rows = []
    call_re = re.compile(
        r'(?P<recv>(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|this|'
        r'Thread\.currentThread\(\)|java\.lang\.Thread\.currentThread\(\)|'
        r'\(\(\s*(?:java\.lang\.)?Thread\s*\)\s*[^)]+\)))\s*\.\s*'
        r'(?P<meth>stop|suspend|resume)\s*\(',
        re.IGNORECASE
    )
    decl_re = re.compile(
        r'\b(?:java\.lang\.)?Thread\b\s*(?:<[^>;]+>\s*)?(?:\[\]\s*)?([A-Za-z_]\w*)\b'
    )
    extends_re = re.compile(r'\bclass\b[^{]*\bextends\b\s+(?:java\.lang\.)?Thread\b')

    for fpath in walk_files(source_dir, {'.java'}):
        try:
            with open_text(fpath) as f:
                lines = list(enumerate(f, 1))
        except Exception:
            continue

        extends_thread = any(extends_re.search((ln or '')) for _, ln in lines)
        thread_vars = set()
        for _, ln in lines:
            stripped = (ln or '').strip()
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                continue
            for m in decl_re.finditer(ln or ''):
                name = (m.group(1) or '').strip()
                if name:
                    thread_vars.add(name)

        for lineno, ln in lines:
            raw = (ln or '').rstrip('\r\n')
            stripped = raw.strip()
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                continue
            for m in call_re.finditer(raw):
                recv = (m.group('recv') or '').strip()
                meth = (m.group('meth') or '').strip().lower()
                api_name = f"java.lang.Thread.{meth}"
                removed_ver = 'JDK20'

                confidence = 'SUSPECT'
                evidence = 'unknown_receiver'

                recv_l = recv.lower()
                if recv_l in ('thread.currentthread()', 'java.lang.thread.currentthread()'):
                    confidence = 'CONFIRMED'
                    evidence = 'Thread.currentThread'
                elif recv_l.startswith('((thread)') or recv_l.startswith('((java.lang.thread)'):
                    confidence = 'CONFIRMED'
                    evidence = 'cast_to_Thread'
                else:
                    ident = recv.split('.')[-1]
                    if ident == 'this' and extends_thread:
                        confidence = 'CONFIRMED'
                        evidence = 'extends_Thread_this'
                    elif ident in thread_vars:
                        confidence = 'CONFIRMED'
                        evidence = f'declared_as_Thread:{ident}'

                # Calls like StopWatch.stop() are common and produce severe false positives
                # if we treat every unknown receiver as java.lang.Thread.stop(). Keep only
                # cases where the source text proves the receiver is actually a Thread.
                if evidence == 'unknown_receiver':
                    continue

                rows.append({
                    '文件': fpath,
                    '行号': lineno,
                    '内容': stripped[:200].replace(',', ';'),
                    'API': api_name,
                    '移除版本': removed_ver,
                    '置信度': confidence,
                    '证据': evidence,
                })

    return rows


def scan_javax(source_dir, output_path, _dep_changes_path=None):
    """
    扫描 javax.* 引用。
    区分：需要迁移到 jakarta 的（Java EE 包）和不需要的（JDK 自身 javax）。
    """
    rows = []

    # Java 源码中的 import 语句
    hits = scan_pattern(source_dir, r'import\s+javax\.', extensions=('.java',))
    for fpath, lineno, content in hits:
        # 提取包名
        m = re.search(r'import\s+(javax\.[\w.]+)', content)
        pkg = m.group(1) if m else 'javax.'
        needs_migrate = not is_jdk_javax(pkg)
        rows.append({
            '文件': fpath, '行号': lineno,
            '内容': content.replace(',', ';'),
            '引用类型': 'java_import',
            '需迁移': 'Y' if needs_migrate else 'N',
        })

    # Java 源码中的全限定名引用（非 import / 非注解）
    hits = scan_pattern(source_dir, r'\bjavax\.[\w.]+', extensions=('.java',))
    for fpath, lineno, content in hits:
        if re.search(r'^\s*import\s+javax\.', content):
            continue
        if re.search(r'@javax\.', content):
            continue
        m = re.search(r'\b(javax\.[\w.]+)', content)
        pkg = m.group(1) if m else 'javax.'
        rows.append({
            '文件': fpath, '行号': lineno,
            '内容': content.replace(',', ';'),
            '引用类型': 'java_fqn',
            '需迁移': 'N' if is_jdk_javax(pkg) else 'Y',
        })

    # 注解使用
    hits = scan_pattern(source_dir, r'@javax\.', extensions=('.java',))
    for fpath, lineno, content in hits:
        m = re.search(r'@(javax\.[\w.]+)', content)
        pkg = m.group(1) if m else 'javax.'
        rows.append({
            '文件': fpath, '行号': lineno,
            '内容': content.replace(',', ';'),
            '引用类型': 'java_annot',
            '需迁移': 'N' if is_jdk_javax(pkg) else 'Y',
        })

    # 配置文件
    for ext, ref_type in [('.xml', 'xml_config'), ('.properties', 'properties'),
                          ('.yml', 'yaml'), ('.yaml', 'yaml')]:
        hits = scan_pattern(source_dir, r'javax\.', extensions=(ext,))
        for fpath, lineno, content in hits:
            rows.append({
                '文件': fpath, '行号': lineno,
                '内容': content.replace(',', ';'),
                '引用类型': ref_type,
                '需迁移': 'Y',  # 配置文件里的 javax 通常是 Java EE 包
            })

    # SPI 文件（META-INF/services/）
    # SPI 文件名是完整的接口类名，如 javax.servlet.ServletContainerInitializer
    # os.path.splitext 会把最后一段当扩展名，所以不能用扩展名过滤
    # 改为直接遍历 META-INF/services/ 目录
    for source_root in iter_source_roots(source_dir):
        for root, dirs, files in os.walk(source_root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            normalized_root = root.replace('\\', '/')
            if 'META-INF/services' not in normalized_root:
                continue
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open_text(fpath) as f:
                        for lineno, line in enumerate(f, 1):
                            if 'javax.' in line:
                                rows.append({
                                    '文件': fpath, '行号': lineno,
                                    '内容': line.strip().replace(',', ';'),
                                    '引用类型': 'spi',
                                    '需迁移': 'Y',
                                })
                except Exception:
                    pass

    # spring.factories
    for fpath in walk_files(source_dir, {'.factories'}):
        try:
            with open_text(fpath) as f:
                for lineno, line in enumerate(f, 1):
                    if 'javax.' in line:
                        rows.append({
                            '文件': fpath, '行号': lineno,
                            '内容': line.strip().replace(',', ';'),
                            '引用类型': 'spring_factories',
                            '需迁移': 'Y',
                        })
        except Exception:
            pass

    count = write_csv_results(rows,
                               ['文件', '行号', '内容', '引用类型', '需迁移'],
                               output_path)
    migrate_count = sum(1 for r in rows if r['需迁移'] == 'Y')
    print(f"  javax: {count} 处命中（需迁移: {migrate_count}）→ {output_path}",
          file=sys.stderr)
    return count


def scan_jdk_internal(source_dir, output_path, _dep_changes_path=None):
    """扫描 JDK 内部 API 使用"""
    rows = []
    for pattern, api_type in JDK_INTERNAL_RULES:
        hits = scan_pattern(source_dir, pattern, extensions=('.java',),
                            skip_comment=True)
        for fpath, lineno, content in hits:
            rows.append({
                '文件': fpath, '行号': lineno,
                '内容': content.replace(',', ';'),
                'API类型': api_type,
            })
    count = write_csv_results(rows,
                               ['文件', '行号', '内容', 'API类型'],
                               output_path)
    print(f"  jdk_internal: {count} 处命中 → {output_path}", file=sys.stderr)
    return count


def scan_reflection(source_dir, output_path, _dep_changes_path=None):
    """扫描反射操作"""
    rows = []
    for pattern, reflect_type in REFLECTION_RULES:
        hits = scan_pattern(source_dir, pattern, extensions=('.java',))
        for fpath, lineno, content in hits:
            rows.append({
                '文件': fpath, '行号': lineno,
                '内容': content.replace(',', ';'),
                '反射类型': reflect_type,
            })
    count = write_csv_results(rows,
                               ['文件', '行号', '内容', '反射类型'],
                               output_path)
    print(f"  reflection: {count} 处命中 → {output_path}", file=sys.stderr)
    return count


def scan_serialization(source_dir, output_path, _dep_changes_path=None):
    """扫描 Java 原生序列化兼容性风险"""
    lines = [
        f"# 序列化兼容性扫描 | {datetime.now().isoformat()}",
        "# 用途：发现 Serializable / serialVersionUID 等潜在兼容性风险，供人工排查与回归测试。",
        "# 抽查：优先核对输出的类是否属于对外传输对象/落库对象；升级后执行反序列化回归用例。",
        "",
    ]

    # 找实现了 Serializable 的类
    serial_files = []
    pattern = re.compile(r'implements[^{;]*\bSerializable\b', re.IGNORECASE)
    for fpath in walk_files(source_dir, {'.java'}, skip_test=True):
        try:
            with open_text(fpath) as f:
                content = f.read()
            if pattern.search(content):
                serial_files.append(fpath)
        except Exception:
            continue

    if not serial_files:
        lines.append("✅ 未发现 Serializable 类（无跨JDK序列化风险）")
        write_text_results(lines, output_path)
        print(f"  serialization: 无风险 → {output_path}", file=sys.stderr)
        return 0

    lines.append(f"=== 实现 Serializable 的类（{len(serial_files)} 个）===")
    for f in serial_files[:30]:
        lines.append(f"  {f}")
    if len(serial_files) > 30:
        lines.append(f"  ... 还有 {len(serial_files)-30} 个")

    # 检查哪些没有 serialVersionUID
    lines.append("")
    lines.append("=== 未声明 serialVersionUID 的类（跨JDK升级存在反序列化风险）===")
    risk_files = []
    for fpath in serial_files:
        try:
            with open_text(fpath) as f:
                content = f.read()
            if 'serialVersionUID' not in content:
                risk_files.append(fpath)
                # 提取类名
                m = re.search(r'(public\s+)?(class|enum)\s+(\w+)', content)
                class_name = m.group(3) if m else '?'
                lines.append(f"  ⚠️  {fpath}  [{class_name}]")
        except Exception:
            continue

    # 高风险场景检测
    lines.append("")
    lines.append("=== 高风险场景（序列化对象可能存储在外部系统）===")

    for label, patterns in [
        ("Redis 缓存", [r'RedisTemplate|StringRedisTemplate|@Cacheable|@CachePut']),
        ("MQ 消息",   [r'@KafkaListener|@RabbitListener|@RocketMQMessageListener']),
        ("HttpSession", [r'HttpSession|@SessionAttribute|@SessionScope']),
    ]:
        hits = []
        for pat in patterns:
            hits += scan_pattern(source_dir, pat, skip_test=True)
        if hits:
            lines.append(f"  ⚠️  {label}：{len(hits)} 处使用")
            for fpath, lineno, content in hits[:5]:
                lines.append(f"    {fpath}:{lineno}")
        else:
            lines.append(f"  ✅ {label}：未发现")

    write_text_results(lines, output_path)
    print(f"  serialization: {len(risk_files)} 个风险类 → {output_path}", file=sys.stderr)
    return len(risk_files)

def scan_jdk_runtime_flags(source_dir, output_path, _dep_changes_path=None):
    rows = []
    exts = {
        '.sh', '.bash', '.zsh', '.cmd', '.bat', '.ps1',
        '.yaml', '.yml', '.properties', '.xml', '.conf', '.ini', '.env',
        '.gradle', '.kts', '.txt'
    }

    def is_interesting_filename(name):
        lower = name.lower()
        if lower == 'jenkinsfile':
            return True
        if lower.startswith('dockerfile'):
            return True
        if lower in {'procfile'}:
            return True
        return False

    def is_comment_like(line):
        stripped = line.strip()
        return stripped.startswith(('#', '//', '/*', '*', '<!--'))

    for source_root in iter_source_roots(source_dir):
        for root, dirs, files in os.walk(source_root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in exts and not is_interesting_filename(fname):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open_text(fpath) as f:
                        for lineno, line in enumerate(f, 1):
                            if not line.strip() or is_comment_like(line):
                                continue
                            for pattern, flag, risk, affected in JDK_RUNTIME_FLAG_RULES:
                                if re.search(pattern, line):
                                    rows.append({
                                        '文件': fpath,
                                        '行号': lineno,
                                        '内容': line.strip()[:200].replace(',', ';'),
                                        '参数': flag,
                                        '风险': risk,
                                        '影响版本': affected,
                                    })
                except Exception:
                    continue

    count = write_csv_results(rows,
                              ['文件', '行号', '内容', '参数', '风险', '影响版本'],
                              output_path)
    print(f"  jdk_runtime_flags: {count} 处命中 → {output_path}", file=sys.stderr)
    return count


def scan_sb_config(source_dir, output_path, _dep_changes_path=None):
    """扫描 Spring Boot 配置属性键"""
    rows = []

    # .properties 文件
    for fpath in walk_files(source_dir, {'.properties'}):
        try:
            with open_text(fpath) as f:
                for lineno, line in enumerate(f, 1):
                    line = line.rstrip('\r\n').strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        key = line.split('=', 1)[0].strip()
                        val = line.split('=', 1)[1].strip()
                        if key:
                            rows.append({'文件': fpath, '行号': lineno,
                                         '配置键': key,
                                         '当前值': val[:100].replace(',', ';')})
        except Exception:
            continue

    # .yml / .yaml 文件
    for fpath in walk_files(source_dir, {'.yml', '.yaml'}):
        try:
            with open_text(fpath) as f:
                for lineno, line in enumerate(f, 1):
                    raw = line.rstrip('\r\n')
                    m = re.match(r'^(\s*)([a-zA-Z][\w.\-]*)\s*:', raw)
                    if not m:
                        continue
                    key = m.group(2)
                    val_part = raw[m.end():].strip()
                    # 只记录叶节点（有值的行）
                    if val_part and not val_part.startswith('#'):
                        rows.append({'文件': fpath, '行号': lineno,
                                     '配置键': key,
                                     '当前值': val_part[:100].replace(',', ';')})
        except Exception:
            continue

    total = write_csv_results(rows,
                              ['文件', '行号', '配置键', '当前值'],
                              output_path)
    print(f"  sb_config: {total} 个配置键 → {output_path}", file=sys.stderr)
    return total


def scan_sb_autoconfig(source_dir, output_path, _dep_changes_path=None):
    """扫描自动装配配置文件迁移情况"""
    lines = [
        f"# 自动装配配置扫描 | {datetime.now().isoformat()}",
        "# 用途：提示 Spring Boot 2→3 自动装配元数据的迁移线索（spring.factories / AutoConfiguration.imports）。",
        "# 抽查：若发现 spring.factories 仍存在，需确认是否为自研 starter 或自维护依赖；检查是否已迁移到 imports。",
        "",
    ]

    # spring.factories
    lines.append("=== spring.factories 文件（Spring Boot 2 格式）===")
    factories_found = []
    for fpath in walk_files(source_dir, {'.factories'}):
        if 'spring.factories' in fpath:
            factories_found.append(fpath)
    if factories_found:
        for f in factories_found:
            lines.append(f"  发现: {f}")
            try:
                with open_text(f) as fp:
                    for line in fp:
                        line = line.strip()
                        if any(k in line for k in [
                            'EnableAutoConfiguration', 'AutoConfigurationImportFilter',
                            'ApplicationListener', 'EnvironmentPostProcessor'
                        ]):
                            lines.append(f"    {line[:120]}")
            except Exception:
                pass
    else:
        lines.append("  ✅ 无 spring.factories 文件")

    # AutoConfiguration.imports
    lines.append("")
    lines.append("=== AutoConfiguration.imports 文件（Spring Boot 3 格式）===")
    imports_found = []
    for fpath in walk_files(source_dir, {'.imports'}):
        if 'AutoConfiguration.imports' in fpath:
            imports_found.append(fpath)
    if imports_found:
        for f in imports_found:
            try:
                with open_text(f) as fp:
                    count = sum(1 for l in fp if l.strip())
                lines.append(f"  ✅ 发现: {f}（{count} 条）")
            except Exception:
                lines.append(f"  ✅ 发现: {f}")
    else:
        lines.append("  ❌ 未发现 AutoConfiguration.imports")

    # @AutoConfiguration 注解
    lines.append("")
    lines.append("=== @AutoConfiguration / @EnableAutoConfiguration 使用 ===")
    auto_config_hits = scan_pattern(source_dir,
                        r'@AutoConfiguration\b|@EnableAutoConfiguration\b',
                        extensions=('.java',), skip_test=True)
    if auto_config_hits:
        for fpath, lineno, content in auto_config_hits[:20]:
            lines.append(f"  {fpath}:{lineno}  {content[:80]}")
    else:
        lines.append("  未发现自定义自动装配类")

    # @ConstructorBinding（Spring Boot 3 语义变化）
    lines.append("")
    lines.append("=== @ConstructorBinding 使用（Spring Boot 3 需移到构造函数上）===")
    constructor_binding_hits = scan_pattern(source_dir, r'@ConstructorBinding',
                        extensions=('.java',), skip_test=True)
    if constructor_binding_hits:
        for fpath, lineno, content in constructor_binding_hits[:20]:
            lines.append(f"  {fpath}:{lineno}  {content[:80]}")
    else:
        lines.append("  未发现 @ConstructorBinding 使用")

    write_text_results(lines, output_path)
    total_signals = (
        len(factories_found)
        + len(imports_found)
        + len(auto_config_hits)
        + len(constructor_binding_hits)
    )
    print(
        f"  sb_autoconfig: spring.factories={len(factories_found)}, "
        f"imports={len(imports_found)}, annotations={len(auto_config_hits)}, "
        f"constructor_binding={len(constructor_binding_hits)} → {output_path}",
          file=sys.stderr)
    return total_signals


def scan_dependency_compat(_source_dir, output_path, dep_changes_path=None):
    """
    扫描本地 Maven 依赖 jar 的兼容性信号。

    目标：
      - 补充源码扫描看不到的第三方库风险
      - 提前发现 javax/jakarta、JDK 内部 API、Spring Boot 自动装配元数据等问题
    """
    dep_rows = load_current_deps(dep_changes_path)
    if not dep_rows:
        write_csv_results([], ['坐标', '版本', 'scope', '风险类型', '证据', 'jar路径'], output_path)
        print(f"  dep_compat: 未提供或无法读取依赖清单 → {output_path}", file=sys.stderr)
        return 0

    rows = []
    seen = set()

    for dep in dep_rows:
        coord = dep.get('coord', '')
        version = dep.get('version', '')
        scope = dep.get('scope', 'compile')
        if not should_scan_dep_scope(scope):
            continue
        if not coord or not version:
            continue

        jar_path = find_maven_jar(coord, version)
        key = (coord, version)
        if key in seen:
            continue
        seen.add(key)

        if not jar_path or not os.path.exists(jar_path):
            rows.append({
                '坐标': coord,
                '版本': version,
                'scope': scope,
                '风险类型': 'jar_missing',
                '证据': '本地 Maven 仓库未找到 jar',
                'jar路径': jar_path or '',
            })
            continue

        try:
            with zipfile.ZipFile(jar_path) as zf:
                names = zf.namelist()

                def add_row(risk_type, evidence):
                    rows.append({
                        '坐标': coord,
                        '版本': version,
                        'scope': scope,
                        '风险类型': risk_type,
                        '证据': evidence[:200],
                        'jar路径': jar_path,
                    })

                if 'META-INF/spring.factories' in names:
                    add_row('spring_factories', '发现 META-INF/spring.factories')
                if 'META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports' in names:
                    add_row('auto_configuration_imports',
                            '发现 AutoConfiguration.imports')

                binary_needles = [
                    (b'javax/', 'javax_reference'),
                    (b'sun/misc/Unsafe', 'jdk_internal_reference'),
                    (b'jdk/internal/', 'jdk_internal_reference'),
                    (b'com/sun/', 'jdk_internal_reference'),
                    (b'java/lang/SecurityManager', 'security_manager'),
                    (b'setAccessible', 'deep_reflection'),
                ]

                def iter_class_entries():
                    for n in names:
                        if not n.endswith('.class'):
                            continue
                        if n.startswith('META-INF/'):
                            if n.startswith('META-INF/versions/'):
                                yield n
                            continue
                        yield n

                def read_prefix(entry, limit_bytes=131072):
                    try:
                        with zf.open(entry) as fp:
                            return fp.read(limit_bytes)
                    except Exception:
                        return b''

                found_types = set()
                for entry in iter_class_entries():
                    if len(found_types) == len(binary_needles):
                        break
                    data = read_prefix(entry)
                    if not data:
                        continue
                    for needle, risk_type in binary_needles:
                        if risk_type in found_types:
                            continue
                        if needle in data:
                            add_row(risk_type, f'{entry} 命中 {needle.decode("utf-8", errors="ignore")}')
                            found_types.add(risk_type)

        except zipfile.BadZipFile:
            rows.append({
                '坐标': coord,
                '版本': version,
                'scope': scope,
                '风险类型': 'jar_unreadable',
                '证据': 'jar 文件无法读取或已损坏',
                'jar路径': jar_path,
            })

    count = write_csv_results(rows,
                              ['坐标', '版本', 'scope', '风险类型', '证据', 'jar路径'],
                              output_path)
    print(f"  dep_compat: {count} 处命中 → {output_path}", file=sys.stderr)
    return count

def scan_dependency_classfile_versions(_source_dir, output_path, dep_changes_path=None):
    dep_rows = load_current_deps(dep_changes_path)
    if not dep_rows:
        write_csv_results([],
                          ['坐标', '版本', 'scope', 'jar路径', 'multi_release', 'max_major_base', 'max_major_mr',
                           'max_java_base', 'max_java_mr', 'max_java_any', 'target_jdk', '风险'],
                          output_path)
        print(f"  dep_classfile: 未提供或无法读取依赖清单 → {output_path}", file=sys.stderr)
        return 0

    rows = []
    seen = set()
    risk_count = 0

    for dep in dep_rows:
        coord = dep.get('coord', '')
        version = dep.get('version', '')
        scope = dep.get('scope', 'compile')
        if not should_scan_dep_scope(scope):
            continue
        if not coord or not version:
            continue

        jar_path = find_maven_jar(coord, version)
        key = (coord, version)
        if key in seen:
            continue
        seen.add(key)

        if not jar_path or not os.path.exists(jar_path):
            rows.append({
                '坐标': coord,
                '版本': version,
                'scope': scope,
                'jar路径': jar_path or '',
                'multi_release': 'unknown',
                'max_major_base': '',
                'max_major_mr': '',
                'max_java_base': '',
                'max_java_mr': '',
                'max_java_any': '',
                'target_jdk': TARGET_JDK or '',
                '风险': 'jar_missing',
            })
            risk_count += 1
            continue

        max_major_base = None
        max_major_mr = None
        multi_release = False

        try:
            with zipfile.ZipFile(jar_path) as zf:
                for name in zf.namelist():
                    if not name.endswith('.class'):
                        continue
                    if name.startswith('META-INF/'):
                        if name.startswith('META-INF/versions/'):
                            multi_release = True
                        else:
                            continue

                    try:
                        data = zf.read(name, pwd=None)[:8]
                    except Exception:
                        continue
                    major = parse_class_major_version(data)
                    if major is None:
                        continue
                    if name.startswith('META-INF/versions/'):
                        if max_major_mr is None or major > max_major_mr:
                            max_major_mr = major
                    else:
                        if max_major_base is None or major > max_major_base:
                            max_major_base = major
        except zipfile.BadZipFile:
            rows.append({
                '坐标': coord,
                '版本': version,
                'scope': scope,
                'jar路径': jar_path,
                'multi_release': 'unknown',
                'max_major_base': '',
                'max_major_mr': '',
                'max_java_base': '',
                'max_java_mr': '',
                'max_java_any': '',
                'target_jdk': TARGET_JDK or '',
                '风险': 'jar_unreadable',
            })
            risk_count += 1
            continue

        max_major_any = max(
            [v for v in (max_major_base, max_major_mr) if v is not None],
            default=None
        )
        max_java_base = classfile_major_to_java(max_major_base) if max_major_base is not None else None
        max_java_mr = classfile_major_to_java(max_major_mr) if max_major_mr is not None else None
        max_java_any = classfile_major_to_java(max_major_any) if max_major_any is not None else None

        risk = ''
        if TARGET_JDK and max_java_any and max_java_any > TARGET_JDK:
            risk = f'需要JDK{max_java_any}+'
            risk_count += 1
        elif max_java_any is None and max_major_any is not None:
            risk = f'未知class版本{max_major_any}'
            risk_count += 1

        rows.append({
            '坐标': coord,
            '版本': version,
            'scope': scope,
            'jar路径': jar_path,
            'multi_release': 'Y' if multi_release else 'N',
            'max_major_base': max_major_base or '',
            'max_major_mr': max_major_mr or '',
            'max_java_base': max_java_base or '',
            'max_java_mr': max_java_mr or '',
            'max_java_any': max_java_any or '',
            'target_jdk': TARGET_JDK or '',
            '风险': risk,
        })

    write_csv_results(rows,
                      ['坐标', '版本', 'scope', 'jar路径', 'multi_release', 'max_major_base', 'max_major_mr',
                       'max_java_base', 'max_java_mr', 'max_java_any', 'target_jdk', '风险'],
                      output_path)
    print(f"  dep_classfile: {len(rows)} 个依赖扫描，风险 {risk_count} 个 → {output_path}", file=sys.stderr)
    return risk_count


# ══════════════════════════════════════════════════════════════════
# 主函数
# ══════════════════════════════════════════════════════════════════

SCAN_FUNCS = {
    'jdk_removed':   (scan_jdk_removed,   's3_jdk_removed_api.csv'),
    'javax':         (scan_javax,          's3_jdk_javax_refs.csv'),
    'jdk_internal':  (scan_jdk_internal,   's3_jdk_internal_api.csv'),
    'reflection':    (scan_reflection,     's3_jdk_reflection.csv'),
    'serialization': (scan_serialization,  's3_jdk_serialization.txt'),
    'jdk_runtime_flags': (scan_jdk_runtime_flags, 's3_jdk_runtime_flags.csv'),
    'sb_config':     (scan_sb_config,      's3_springboot_config.csv'),
    'sb_autoconfig': (scan_sb_autoconfig,  's3_springboot_autoconfig.txt'),
    'dep_compat':    (scan_dependency_compat, 's3_dependency_compat.csv'),
    'dep_classfile': (scan_dependency_classfile_versions, 's3_dependency_classfile.csv'),
}


def main():
    ap = argparse.ArgumentParser(
        description='Step 3：静态扫描（Windows/Linux/macOS 兼容）'
    )
    ap.add_argument('--type', choices=list(SCAN_FUNCS.keys()),
                    help='扫描类型（单项）')
    ap.add_argument('--all', action='store_true',
                    help='执行全部扫描')
    ap.add_argument('--source-dir',
                    help='源码目录（兼容单目录调用）')
    ap.add_argument('--source-dirs', nargs='+',
                    help='源码目录列表（Step3 会扫描全部目录）')
    ap.add_argument('--output',
                    help='输出文件路径（单项扫描时使用）')
    ap.add_argument('--output-dir', default='.upgrade-report',
                    help='输出目录（--all 时使用）')
    ap.add_argument('--dep-changes',
                    help='s1_dep_changes.csv 路径（依赖 jar 扫描时使用）')
    ap.add_argument('--dep-current',
                    help='s1_deps_current_resolved.csv 路径（仅当前依赖 jar 扫描时使用）')
    ap.add_argument('--include-test-scope', action='store_true',
                    help='依赖 jar 扫描时包含 test scope（默认跳过以减少误报）')
    ap.add_argument('--jdk-upgraded', action='store_true',
                    help='JDK 有升级（激活 jdk_* 扫描）')
    ap.add_argument('--sb-major-upgrade', action='store_true',
                    help='Spring Boot 大版本升级（激活 sb_* 扫描）')
    ap.add_argument('--target-jdk', default='',
                    help='目标运行 JDK 版本（用于依赖 classfile 兼容性判断，如 17/21）')
    args = ap.parse_args()
    report_dir = args.output_dir
    orchestrated_input, orchestrated_context = load_orchestrated_step3_input(report_dir)
    if orchestrated_input:
        if not args.source_dirs and not args.source_dir:
            args.source_dirs = list(orchestrated_input.get("source_dirs") or [])
        if not args.include_test_scope and orchestrated_input.get("include_test_scope"):
            args.include_test_scope = True
    if orchestrated_context:
        if not args.jdk_upgraded and orchestrated_context.get("jdk_upgraded"):
            args.jdk_upgraded = True
        if not args.sb_major_upgrade and orchestrated_context.get("springboot_major_upgrade"):
            args.sb_major_upgrade = True
        if not args.target_jdk:
            args.target_jdk = str(orchestrated_context.get("jdk_current") or "")

    if not args.type and not args.all:
        ap.print_help()
        sys.exit(1)

    step_timer = PhaseTimer("step3", "total")
    source_dir = args.source_dirs or args.source_dir
    source_roots = list(iter_source_roots(source_dir))
    if not source_roots:
        ap.error('the following arguments are required: --source-dir')
    print(f"\nStep 3 扫描：{len(source_roots)} 个源码目录", file=sys.stderr)
    for root in source_roots:
        print(f"  - {root}", file=sys.stderr)
    global DEP_COMPAT_INCLUDE_TEST_SCOPE
    DEP_COMPAT_INCLUDE_TEST_SCOPE = args.include_test_scope
    global TARGET_JDK
    TARGET_JDK = int(args.target_jdk) if str(args.target_jdk).strip().isdigit() else None
    dep_list_path = args.dep_current or args.dep_changes

    if args.all:
        # 根据升级类型决定运行哪些扫描
        to_run = []
        if args.jdk_upgraded:
            to_run += ['jdk_removed', 'javax', 'jdk_internal', 'reflection', 'serialization', 'jdk_runtime_flags']
        if args.sb_major_upgrade:
            to_run += ['javax', 'sb_config', 'sb_autoconfig']
        if dep_list_path:
            to_run += ['dep_compat', 'dep_classfile']
        if not to_run:
            # 没有指定升级类型，运行全部
            to_run = list(SCAN_FUNCS.keys())

        os.makedirs(args.output_dir, exist_ok=True)
        emit_progress(
            "step3",
            "plan",
            f"已生成扫描计划，将执行 {len(to_run)} 类扫描",
            current=len(source_roots),
            total=len(source_roots),
        )
        total = 0
        for idx, scan_type in enumerate(to_run, 1):
            func, default_fname = SCAN_FUNCS[scan_type]
            output = os.path.join(args.output_dir, default_fname)
            scan_timer = time.perf_counter()
            emit_progress(
                "step3",
                "scan",
                f"开始执行 {scan_type}",
                current=idx,
                total=len(to_run),
                item=default_fname,
            )
            matches = func(source_dir, output, dep_list_path) or 0
            total += matches
            emit_progress(
                "step3",
                "scan",
                f"完成 {scan_type}，命中 {matches} 处",
                current=idx,
                total=len(to_run),
                elapsed=time.perf_counter() - scan_timer,
                item=default_fname,
            )
        print(f"\nStep 3 完成：共 {total} 处命中", file=sys.stderr)
        emit_progress(
            "step3",
            "done",
            f"全部静态扫描完成，总命中 {total} 处",
            elapsed=step_timer.elapsed(),
        )

    else:
        func, default_fname = SCAN_FUNCS[args.type]
        output = args.output or os.path.join(args.output_dir, default_fname)
        emit_progress("step3", "scan", f"开始执行 {args.type}", item=default_fname)
        single_timer = time.perf_counter()
        matches = func(source_dir, output, dep_list_path) or 0
        emit_progress(
            "step3",
            "done",
            f"完成 {args.type}，命中 {matches} 处",
            elapsed=time.perf_counter() - single_timer,
            item=default_fname,
        )


if __name__ == '__main__':
    main()
