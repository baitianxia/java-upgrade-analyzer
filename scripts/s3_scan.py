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

import argparse, csv, io, os, re, sys, time, zipfile, hashlib
from pathlib import Path
from datetime import datetime
import json

sys.path.insert(0, str(Path(__file__).parent))
from compat import open_text, write_text, maven_repo_dir
from progress_logging import PhaseTimer, emit_progress
from pipeline_constants import (
    EVIDENCE_CONTEXT_DIRNAME,
    EVIDENCE_DIRNAME,
    RUNTIME_DIRNAME,
    RUNTIME_STATE_DIRNAME,
)
from s4_contract import (
    PER_DEPENDENCY_CANDIDATE_HITS_FILE,
    PER_DEPENDENCY_DIRNAME,
    PER_DEPENDENCY_SUMMARY_FILE,
    STEP3_RISK_CANDIDATES_FILE,
    get_per_dependency_dir,
)


MAIN_STATE_FILE_NAME = "main_state.json"
STEP3_DEPENDENCY_SOURCE_DIRS = []
STEP3_REPORT_DIR = ""
STEP3_SCAN_DIAGNOSTICS = []


def reset_scan_diagnostics():
    STEP3_SCAN_DIAGNOSTICS.clear()


def get_scan_diagnostics():
    return [dict(item) for item in STEP3_SCAN_DIAGNOSTICS]


def record_scan_diagnostic(*, stage, path, error):
    STEP3_SCAN_DIAGNOSTICS.append({
        'stage': str(stage),
        'path': str(path),
        'error_type': type(error).__name__,
        'message': str(error),
    })


def normalize_dependency_source_dirs(value):
    """Accept only the documented JSON-array form for dependency source roots.

    Step3 state is persisted outside this process.  Do not let a malformed
    state value (for example a number or a string) turn into an unhandled
    ``list(value)`` error, or worse, a list of characters that is later treated
    as source roots.  The diagnostic becomes part of Step3 coverage so the
    incomplete input is visible to the user.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        record_scan_diagnostic(
            stage='dependency_source_dirs_input',
            path='orchestrated_input.dependency_source_dirs',
            error=TypeError('dependency_source_dirs must be a JSON array'),
        )
        return []
    return [str(item) for item in value if isinstance(item, (str, os.PathLike)) and str(item).strip()]


def runtime_state_path(report_dir):
    return Path(report_dir) / RUNTIME_DIRNAME / RUNTIME_STATE_DIRNAME / MAIN_STATE_FILE_NAME


def context_path(report_dir):
    return Path(report_dir) / EVIDENCE_DIRNAME / EVIDENCE_CONTEXT_DIRNAME / "context.json"


def load_orchestrated_step3_input(report_dir):
    """正式流程下从 main_state 和 s2_context 读取 Step3 输入，单脚本 CLI 仅用于调试。"""
    if not os.environ.get("JUA_ORCHESTRATED"):
        return {}, {}
    state_path = runtime_state_path(report_dir)
    context_file = context_path(report_dir)
    main_state = {}
    context = {}
    if state_path.exists():
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                main_state = json.load(f)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            record_scan_diagnostic(
                stage='orchestrated_state_load', path=state_path, error=exc,
            )
            main_state = {}
    if context_file.exists():
        try:
            with open(context_file, "r", encoding="utf-8") as f:
                context = json.load(f)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            record_scan_diagnostic(
                stage='orchestrated_context_load', path=context_file, error=exc,
            )
            context = {}
    step_input = dict((((main_state or {}).get("step3") or {}).get("input")) or {})
    return step_input, dict(context or {})


DEP_COMPAT_INCLUDE_TEST_SCOPE = False
TARGET_JDK = None
BASE_JDK = None
BASE_SPRING_BOOT_MAJOR = None
TARGET_SPRING_BOOT_MAJOR = None
RULE_PACK_DIR = Path(__file__).resolve().parents[1] / 'references' / 'rules'

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
        except (OSError, UnicodeError) as exc:
            record_scan_diagnostic(
                stage='source_pattern_scan', path=fpath, error=exc,
            )
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
    except (OSError, UnicodeError, csv.Error) as exc:
        record_scan_diagnostic(stage='dependency_changes_load', path=csv_path, error=exc)
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
                coord = (normalized.get('coord') or '').strip()
                scope = (normalized.get('scope') or 'compile').strip()
                if is_current_list:
                    version = (normalized.get('version') or '').strip()
                elif is_dep_changes:
                    version = resolve_current_dep_version(normalized)
                else:
                    version = ''
                physical_entry = (
                    normalized.get('lib_entry')
                    or normalized.get('entry_id')
                    or ''
                ).strip()
                if is_current_list and physical_entry:
                    deps.append(normalized)
                    continue
                if not coord or not version or version == '-':
                    continue
                deps.append({
                    **normalized,
                    'coord': coord,
                    'version': version,
                    'scope': scope,
                })
    except (OSError, UnicodeError, csv.Error) as exc:
        record_scan_diagnostic(stage='current_dependencies_load', path=csv_path, error=exc)
        return []
    return deps


def _step3_build_provenance_candidates(dep_list_path):
    candidates = []
    if dep_list_path:
        candidates.append(Path(dep_list_path).resolve().parent / 'build_provenance.json')
    if STEP3_REPORT_DIR:
        report_dir = Path(STEP3_REPORT_DIR).resolve()
        candidates.extend([
            report_dir / EVIDENCE_DIRNAME / 'dependencies' / 'build_provenance.json',
            report_dir / 'dependencies' / 'build_provenance.json',
            report_dir / 'build_provenance.json',
        ])
    seen = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        yield candidate


def resolve_current_final_artifact_path(dep_list_path):
    """Return the Step1-retained current artifact; never consult a local repository."""
    provenance_path = next(
        (path for path in _step3_build_provenance_candidates(dep_list_path) if path.is_file()),
        None,
    )
    if provenance_path is None:
        return '', 'current_final_artifact_provenance_missing'
    try:
        payload = json.loads(provenance_path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        record_scan_diagnostic(
            stage='current_final_artifact_provenance_load', path=provenance_path, error=exc,
        )
        return '', 'current_final_artifact_provenance_unreadable'
    current = next(
        (item for item in payload.get('sides') or [] if item.get('side') == 'current'),
        {},
    )
    artifact_path = str(current.get('artifact_path') or '').strip()
    if not artifact_path or not Path(artifact_path).is_file():
        return artifact_path, 'current_final_artifact_missing'
    return str(Path(artifact_path).resolve()), ''


def iter_current_final_artifact_dependencies(dep_list_path):
    """Yield each physical current dependency JAR from the retained artifact.

    Each returned item contains ``dependency``, ``jar_bytes`` and ``error_code``.
    The outer artifact stays open while one nested JAR at a time is yielded, avoiding
    memory growth proportional to the number of dependencies. Failures remain explicit
    records so a read error can never masquerade as a clean scan.
    """
    physical_dep_list_path = dep_list_path
    if dep_list_path:
        provided_path = Path(dep_list_path)
        sibling_current = provided_path.parent / 'deps_current_resolved.csv'
        if provided_path.name != sibling_current.name and sibling_current.is_file():
            physical_dep_list_path = str(sibling_current)
    dep_rows = load_current_deps(physical_dep_list_path)
    if not dep_rows:
        return
    artifact_path, artifact_error = resolve_current_final_artifact_path(dep_list_path)
    if artifact_error:
        for dep in dep_rows:
            yield {'dependency': dep, 'jar_bytes': None, 'error_code': artifact_error}
        return
    try:
        with zipfile.ZipFile(artifact_path) as outer:
            available_entries = set(outer.namelist())
            seen_entries = set()
            for dep in dep_rows:
                entry = str(dep.get('lib_entry') or dep.get('entry_id') or '').strip()
                if not entry:
                    yield {
                        'dependency': dep,
                        'jar_bytes': None,
                        'error_code': 'dependency_artifact_entry_missing',
                    }
                    continue
                if entry in seen_entries:
                    continue
                seen_entries.add(entry)
                if entry not in available_entries:
                    yield {
                        'dependency': dep,
                        'jar_bytes': None,
                        'error_code': 'current_final_artifact_entry_missing',
                    }
                    continue
                try:
                    jar_bytes = outer.read(entry)
                except (OSError, RuntimeError, KeyError, zipfile.BadZipFile) as exc:
                    record_scan_diagnostic(
                        stage='current_final_artifact_dependency_read',
                        path=f'{artifact_path}!/{entry}',
                        error=exc,
                    )
                    yield {
                        'dependency': dep,
                        'jar_bytes': None,
                        'error_code': 'current_final_artifact_entry_unreadable',
                    }
                    continue
                yield {
                    'dependency': dep,
                    'jar_bytes': jar_bytes,
                    'error_code': '',
                }
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        record_scan_diagnostic(
            stage='current_final_artifact_open', path=artifact_path, error=exc,
        )
        for dep in dep_rows:
            yield {
                'dependency': dep,
                'jar_bytes': None,
                'error_code': 'current_final_artifact_unreadable',
            }


FINAL_ARTIFACT_SCAN_FAILURE_MESSAGES = {
    'current_final_artifact_provenance_missing': '未完成：找不到 Step1 的 current 最终制品来源记录',
    'current_final_artifact_provenance_unreadable': '未完成：无法读取 Step1 的 current 最终制品来源记录',
    'current_final_artifact_missing': '未完成：Step1 留存的 current 最终制品不存在',
    'current_final_artifact_unreadable': '未完成：Step1 留存的 current 最终制品无法读取',
    'dependency_artifact_entry_missing': '未完成：依赖清单缺少最终制品内路径',
    'current_final_artifact_entry_missing': '未完成：current 最终制品内找不到该依赖条目',
    'current_final_artifact_entry_unreadable': '未完成：current 最终制品内的依赖条目无法读取',
    'nested_jar_unreadable': '未完成：current 最终制品内的依赖 JAR 已损坏或无法读取',
}


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


def _change_type_to_contract(change_type):
    text = str(change_type or '').strip()
    if text in {'移除', 'removed'}:
        return 'REMOVED'
    if text in {'新增', 'added'}:
        return 'ADDED'
    if text in {'大版本升级', '小版本升级', '补丁升级', '版本格式不规则', '已变更', 'upgraded'}:
        return 'CHANGED'
    return text or 'CHANGED'


def _safe_read_lines(path, limit=500):
    rows = []
    try:
        with open_text(path) as f:
            for lineno, line in enumerate(f, 1):
                if len(rows) >= limit:
                    break
                text = line.rstrip('\r\n')
                if text.strip():
                    rows.append((lineno, text[:300]))
    except (OSError, UnicodeError) as exc:
        record_scan_diagnostic(stage='safe_line_read', path=path, error=exc)
        return []
    return rows


def _iter_candidate_scan_files(source_dirs):
    exts = {
        '.java', '.kt', '.xml', '.properties', '.yml', '.yaml',
        '.txt', '.factories', '.imports'
    }
    for source_root in iter_source_roots(source_dirs):
        for root, dirs, files in os.walk(source_root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in exts or fname in {'spring.factories', 'AutoConfiguration.imports'}:
                    yield os.path.join(root, fname)


def _iter_jar_class_names(jar_path, max_classes=160):
    classes = []
    if not jar_path or not os.path.exists(jar_path):
        return classes
    try:
        with zipfile.ZipFile(jar_path) as zf:
            for entry in sorted(zf.namelist()):
                if len(classes) >= max_classes:
                    break
                if not entry.endswith('.class') or entry.startswith('META-INF/'):
                    continue
                if entry.endswith('module-info.class') or entry.endswith('package-info.class'):
                    continue
                classes.append(entry[:-6].replace('/', '.'))
    except Exception:
        return []
    return classes


def _build_coord_scan_tokens(dep_row):
    coord = str(dep_row.get('coord') or '').strip()
    old_version = str(dep_row.get('old_version') or '').strip()
    new_version = str(dep_row.get('new_version') or '').strip()
    version = new_version if new_version and new_version != '-' else old_version
    jar_path = find_maven_jar(coord, version) if version and version != '-' else None
    class_names = _iter_jar_class_names(jar_path)
    package_prefixes = []
    for fqcn in class_names:
        if '.' not in fqcn:
            continue
        package_name = fqcn.rsplit('.', 1)[0]
        if package_name not in package_prefixes:
            package_prefixes.append(package_name)
        if len(package_prefixes) >= 40:
            break
    simple_names = []
    for fqcn in class_names:
        simple = fqcn.rsplit('.', 1)[-1]
        if simple not in simple_names:
            simple_names.append(simple)
        if len(simple_names) >= 120:
            break
    return {
        'coord': coord,
        'jar_path': jar_path or '',
        'class_names': class_names,
        'package_prefixes': package_prefixes,
        'simple_names': simple_names,
    }


def _class_usage_match_kind(file_path, line_text, fqcn, simple_name):
    normalized = file_path.replace('\\', '/').lower()
    text = str(line_text or '')
    if normalized.endswith(('.xml', '.properties', '.yml', '.yaml', '.txt', '.factories', '.imports')):
        return 'resource_reference', 'RESOURCE_OR_REFLECTION', 'weak'
    if re.search(r'Class\.forName\s*\(\s*"[^"]*' + re.escape(fqcn) + r'[^"]*"', text):
        return 'reflection_string', 'RESOURCE_OR_REFLECTION', 'weak'
    identifier_boundary = r'[A-Za-z0-9_$]'
    source_fqcn = str(fqcn or '').replace('$', '.')
    source_simple = str(simple_name or '').replace('$', '.')
    fqcn_pattern = '(?:' + '|'.join({re.escape(fqcn), re.escape(source_fqcn)}) + ')'
    simple_pattern = '(?:' + '|'.join({re.escape(simple_name), re.escape(source_simple)}) + ')'
    if re.search(r'\bimport\s+static\s+' + fqcn_pattern + r'\.', text):
        return 'static_import', 'CLASS_USAGE_ONLY', 'medium'
    if re.search(r'\bimport\s+' + fqcn_pattern + r'(?!' + identifier_boundary + r')', text):
        return 'import_reference', 'CLASS_USAGE_ONLY', 'medium'
    if re.search(r'\b(?:new|extends|implements|instanceof)\s+' + simple_pattern
                 + r'(?!' + identifier_boundary + r')', text):
        return 'class_reference', 'CLASS_USAGE_ONLY', 'strong'
    if re.search(r'(?<!' + identifier_boundary + r')' + simple_pattern + r'\s*\.class\b', text):
        return 'class_literal', 'CLASS_USAGE_ONLY', 'strong'
    if re.search(r'(?<!' + identifier_boundary + r')' + simple_pattern + r'\s*\.', text):
        return 'qualified_reference', 'CLASS_USAGE_ONLY', 'medium'
    return 'string_reference', 'RESOURCE_OR_REFLECTION', 'weak'


def _candidate_row_from_hit(dep_row, fqcn, file_path, lineno, line_text, bucket):
    simple_name = fqcn.rsplit('.', 1)[-1]
    candidate_kind, reason_code, evidence_level = _class_usage_match_kind(file_path, line_text, fqcn, simple_name)
    return {
        'coord': str(dep_row.get('coord') or '').strip(),
        'old_version': str(dep_row.get('old_version') or '').strip(),
        'new_version': str(dep_row.get('new_version') or '').strip(),
        'change_type': _change_type_to_contract(dep_row.get('change_type')),
        'api_name': fqcn,
        'api_simple': simple_name,
        'symbol_kind': 'class',
        'api_signature': '',
        'confirmed': 'false',
        'severity': 'P1' if str(dep_row.get('new_version') or '').strip() == '-' else 'P2',
        'source': 'candidate_scan',
        'analysis_scope': 'class_usage',
        'candidate_bucket': bucket,
        'candidate_kind': candidate_kind,
        'reason_code': reason_code,
        'reason': f'{bucket} 命中 {candidate_kind}',
        'evidence_level': evidence_level,
        'matched_class': fqcn,
        'file': file_path,
        'line': lineno,
        'content': str(line_text or '')[:240],
    }


def _write_candidate_rows(path, rows):
    fieldnames = [
        'coord', 'old_version', 'new_version', 'change_type',
        'api_name', 'api_simple', 'symbol_kind', 'api_signature',
        'confirmed', 'severity', 'source', 'analysis_scope',
        'candidate_bucket', 'candidate_kind', 'reason_code', 'reason',
        'evidence_level', 'matched_class', 'file', 'line', 'content',
    ]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows or [])


def cleanup_step3_outputs(report_dir):
    report_root = Path(report_dir)
    if not report_root.exists():
        return

    for _, default_fname in SCAN_FUNCS.values():
        output_path = report_root / default_fname
        if output_path.exists():
            output_path.unlink()

    # Step5 consumes these bridge artifacts directly, so stale Step3 leftovers
    # must be removed before a rerun narrows the dependency set.
    aggregate_path = report_root / STEP3_RISK_CANDIDATES_FILE
    if aggregate_path.exists():
        aggregate_path.unlink()

    per_dependency_root = report_root / PER_DEPENDENCY_DIRNAME
    if not per_dependency_root.exists():
        return

    for dep_dir in per_dependency_root.iterdir():
        if not dep_dir.is_dir():
            continue
        candidate_hits_path = dep_dir / PER_DEPENDENCY_CANDIDATE_HITS_FILE
        if candidate_hits_path.exists():
            candidate_hits_path.unlink()
        summary_path = dep_dir / PER_DEPENDENCY_SUMMARY_FILE
        if not summary_path.exists():
            continue
        try:
            summary = json.loads(summary_path.read_text(encoding='utf-8'))
        except Exception:
            continue
        # Remove only Step3-owned keys and keep the Step4/Step5 summary payload.
        summary.pop('step3', None)
        artifacts = dict(summary.get('artifacts') or {})
        artifacts.pop('candidate_hits_csv', None)
        if artifacts:
            summary['artifacts'] = artifacts
        else:
            summary.pop('artifacts', None)
        if summary:
            write_text(summary_path, json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
        else:
            summary_path.unlink()


def build_per_dependency_candidate_outputs(source_dirs, dep_changes_path, report_dir, dependency_source_dirs=None):
    dep_rows = load_dep_changes(dep_changes_path)
    if not dep_rows or not report_dir:
        return 0

    source_dirs = list(iter_source_roots(source_dirs))
    dependency_source_dirs = list(iter_source_roots(dependency_source_dirs))
    aggregate_rows = []

    for dep_row in dep_rows:
        coord = str(dep_row.get('coord') or '').strip()
        if not coord:
            continue
        token_bundle = _build_coord_scan_tokens(dep_row)
        class_names = token_bundle.get('class_names') or []
        if not class_names:
            continue
        interesting_classes = class_names[:80]
        row_hits = []
        seen_hits = set()

        def scan_roots(paths, bucket):
            for file_path in _iter_candidate_scan_files(paths):
                try:
                    with open_text(file_path) as f:
                        for lineno, line in enumerate(f, 1):
                            text = line.rstrip('\r\n')
                            if not text.strip():
                                continue
                            for fqcn in interesting_classes:
                                simple = fqcn.rsplit('.', 1)[-1]
                                if fqcn in text or re.search(r'\b' + re.escape(simple) + r'\b', text):
                                    key = (fqcn, file_path, lineno, bucket)
                                    if key in seen_hits:
                                        continue
                                    seen_hits.add(key)
                                    row_hits.append(_candidate_row_from_hit(dep_row, fqcn, file_path, lineno, text, bucket))
                                    break
                except Exception:
                    continue

        scan_roots(source_dirs, 'system_source')
        if dependency_source_dirs:
            scan_roots(dependency_source_dirs, 'dependency_with_source')

        dep_compat_path = Path(report_dir) / 's3_dependency_compat.csv'
        if dep_compat_path.exists():
            for row in load_csv_rows(str(dep_compat_path)):
                if str(row.get('坐标') or '').strip() != coord:
                    continue
                row_hits.append(
                    {
                        'coord': coord,
                        'old_version': str(dep_row.get('old_version') or '').strip(),
                        'new_version': str(dep_row.get('new_version') or '').strip(),
                        'change_type': _change_type_to_contract(dep_row.get('change_type')),
                        'api_name': '',
                        'api_simple': '',
                        'symbol_kind': 'class',
                        'api_signature': '',
                        'confirmed': 'false',
                        'severity': 'P2',
                        'source': 'candidate_scan',
                        'analysis_scope': 'class_usage',
                        'candidate_bucket': 'dependency_without_source',
                        'candidate_kind': str(row.get('风险类型') or '').strip(),
                        'reason_code': 'RESOURCE_OR_REFLECTION',
                        'reason': str(row.get('证据') or '').strip(),
                        'evidence_level': 'weak',
                        'matched_class': '',
                        'file': str(
                            row.get('最终制品内路径') or row.get('jar路径') or ''
                        ).strip(),
                        'line': '',
                        'content': str(row.get('证据') or '').strip()[:240],
                    }
                )

        per_dependency_dir = get_per_dependency_dir(report_dir, coord)
        os.makedirs(per_dependency_dir, exist_ok=True)
        candidate_hits_path = per_dependency_dir / PER_DEPENDENCY_CANDIDATE_HITS_FILE
        _write_candidate_rows(candidate_hits_path, row_hits)

        summary_path = per_dependency_dir / 'summary.json'
        summary = {}
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding='utf-8'))
            except Exception:
                summary = {}
        bucket_counts = {}
        for item in row_hits:
            bucket = str(item.get('candidate_bucket') or '').strip()
            bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        summary['coord'] = coord
        summary['step3'] = {
            'status': 'done',
            'candidate_hit_count': len(row_hits),
            'bucket_counts': bucket_counts,
            'class_sample_count': len(interesting_classes),
            'artifacts': {
                'candidate_hits_csv': str(candidate_hits_path),
            },
        }
        summary.setdefault('artifacts', {})
        summary['artifacts']['candidate_hits_csv'] = str(candidate_hits_path)
        write_text(summary_path, json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
        aggregate_rows.extend(row_hits)

    aggregate_path = Path(report_dir) / STEP3_RISK_CANDIDATES_FILE
    _write_candidate_rows(aggregate_path, aggregate_rows)
    return len(aggregate_rows)


def load_csv_rows(path):
    rows = []
    if not path or not os.path.exists(path):
        return rows
    try:
        with open_text(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row:
                    rows.append({k: (v or '').strip() for k, v in row.items()})
    except Exception:
        return []
    return rows


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


def load_rule_pack(pack_id):
    path = RULE_PACK_DIR / f'{pack_id}.json'
    with open(path, 'r', encoding='utf-8') as handle:
        payload = json.load(handle)
    if payload.get('schema') != 'java-upgrade-analyzer.rule-pack.v1':
        raise ValueError(f'不支持的规则包 schema：{payload.get("schema")}')
    for field in ('id', 'version', 'source', 'last_verified', 'rules'):
        if not payload.get(field):
            raise ValueError(f'规则包 {pack_id} 缺少字段：{field}')
    seen = set()
    for rule in payload.get('rules') or []:
        if not rule.get('id') or rule.get('id') in seen or not rule.get('kind') or not rule.get('pattern'):
            raise ValueError(f'规则包 {pack_id} 存在无效或重复规则：{rule.get("id")}')
        seen.add(rule['id'])
        rule.setdefault('source', payload['source'])
        rule.setdefault('last_verified', payload['last_verified'])
    payload['_path'] = str(path)
    payload['_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return payload


def rule_applies_to_major_interval(rule, base_major=None, target_major=None):
    affected = int(rule.get('affected_major') or 0)
    if not affected or base_major is None or target_major is None:
        return True
    return int(base_major) < affected <= int(target_major)


def rule_applies_to_jdk_interval(rule, base_jdk=None, target_jdk=None):
    affected = int(rule.get('affected_version') or 0)
    if not affected or not base_jdk or not target_jdk:
        return True
    return int(base_jdk) < affected <= int(target_jdk)


def active_jdk_removed_rules(base_jdk=None, target_jdk=None):
    try:
        pack = load_rule_pack('jdk')
        return [
            (rule, pack)
            for rule in pack.get('rules') or []
            if rule.get('kind') == 'removed_api'
            and rule_applies_to_jdk_interval(rule, base_jdk, target_jdk)
        ]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'  ⚠️ JDK 规则包不可用，回退内置规则：{exc}', file=sys.stderr)
        return [
            ({
                'id': f'legacy-{idx}', 'pattern': pattern, 'name': api_name,
                'affected_version': int(re.sub(r'\D', '', affected) or 0), 'status': status,
            }, {'id': 'legacy-inline', 'version': 'compat', '_path': __file__})
            for idx, (pattern, api_name, affected, status) in enumerate(JDK_REMOVED_RULES, 1)
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
    for rule, pack in active_jdk_removed_rules(BASE_JDK, TARGET_JDK):
        pattern = rule['pattern']
        api_name = rule['name']
        removed_ver = f"JDK{rule['affected_version']}"
        status = rule['status']
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
                '规则ID': rule.get('id', ''),
                '规则包': f"{pack.get('id')}@{pack.get('version')}",
            })

    rows.extend(scan_thread_lifecycle_calls(source_dir))
    count = write_csv_results(rows,
                               ['文件', '行号', '内容', 'API', '移除版本', '状态', '置信度', '证据', '规则ID', '规则包'],
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

        full_text = ''.join(line for _, line in lines)
        extends_thread = bool(extends_re.search(full_text))
        thread_vars = set()
        for m in decl_re.finditer(full_text):
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
                except (OSError, UnicodeError) as exc:
                    rows.append({
                        '文件': fpath, '行号': 0,
                        '内容': f'读取失败：{type(exc).__name__}',
                        '引用类型': 'spi_scan_incomplete',
                        '需迁移': 'UNKNOWN',
                    })

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
        except (OSError, UnicodeError) as exc:
            rows.append({
                '文件': fpath, '行号': 0,
                '内容': f'读取失败：{type(exc).__name__}',
                '引用类型': 'spring_factories_scan_incomplete',
                '需迁移': 'UNKNOWN',
            })

    try:
        jakarta_pack = load_rule_pack('jakarta')
        jakarta_rules = [
            rule for rule in jakarta_pack.get('rules') or []
            if rule.get('kind') == 'namespace_migration'
            and rule_applies_to_major_interval(rule, BASE_SPRING_BOOT_MAJOR, TARGET_SPRING_BOOT_MAJOR)
        ]
    except (OSError, ValueError, json.JSONDecodeError):
        jakarta_pack, jakarta_rules = {'id': 'jakarta-inline', 'version': 'compat'}, []
    for row in rows:
        if row.get('需迁移') != 'Y':
            row['规则ID'] = 'jdk-javax-no-migration'
            row['规则包'] = 'jdk-platform'
            row['建议命名空间'] = ''
            continue
        matched = next(
            (rule for rule in jakarta_rules if re.search(rule.get('pattern') or r'$.', row.get('内容') or '')),
            None,
        )
        row['规则ID'] = (matched or {}).get('id', 'jakarta-generic-review')
        row['规则包'] = f"{jakarta_pack.get('id')}@{jakarta_pack.get('version')}"
        row['建议命名空间'] = (matched or {}).get('replacement', 'jakarta.*（人工确认）')

    count = write_csv_results(rows,
                               ['文件', '行号', '内容', '引用类型', '需迁移', '规则ID', '规则包', '建议命名空间'],
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

    def add_incomplete(fpath, lineno, reason):
        rows.append({
            '文件': fpath,
            '行号': lineno,
            '配置键': '',
            '当前值': f'未完成：{reason}',
            '扫描状态': '未完成',
        })

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
        except (OSError, UnicodeError) as exc:
            add_incomplete(fpath, 0, f'properties 文件无法读取（{type(exc).__name__}）')
            continue

    # .yml / .yaml 文件
    for fpath in walk_files(source_dir, {'.yml', '.yaml'}):
        try:
            with open_text(fpath) as f:
                key_stack = []
                block_scalar_indent = None
                incomplete_reported = False
                for lineno, line in enumerate(f, 1):
                    raw = line.rstrip('\r\n')
                    if not raw.strip() or raw.lstrip().startswith('#'):
                        continue
                    leading = raw[:len(raw) - len(raw.lstrip(' \t'))]
                    if '\t' in leading:
                        if not incomplete_reported:
                            add_incomplete(fpath, lineno, 'YAML 缩进包含 Tab，无法可靠计算层级')
                            incomplete_reported = True
                        continue
                    indent = len(raw) - len(raw.lstrip(' '))
                    if block_scalar_indent is not None:
                        if indent > block_scalar_indent:
                            continue
                        block_scalar_indent = None
                    content = raw.lstrip(' ')
                    if '{' in content or '[' in content:
                        if not incomplete_reported:
                            add_incomplete(fpath, lineno, 'YAML flow-style 映射或列表未完成层级展开')
                            incomplete_reported = True
                        continue
                    if content.startswith('- '):
                        content = content[2:].lstrip()
                        indent += 2
                    m = re.match(r'(?P<key>[a-zA-Z_][\w.\-]*|"[^"]+"|\'[^\']+\')\s*:', content)
                    if not m:
                        continue
                    key = m.group('key').strip('"\'')
                    val_part = content[m.end():].strip()
                    while key_stack and key_stack[-1][0] >= indent:
                        key_stack.pop()
                    full_key = '.'.join([item[1] for item in key_stack] + [key])
                    # YAML anchors may decorate a mapping node, e.g.
                    # `profiles: &profiles`.  The anchor itself is not this
                    # key's scalar value; retain the node so nested keys keep
                    # their full configuration path.
                    anchor_only = bool(re.fullmatch(
                        r'&[A-Za-z0-9_-]+(?:\s+#.*)?', val_part
                    ))
                    # 只记录叶节点（有值的行）
                    if val_part and not val_part.startswith('#'):
                        if val_part in {'|', '>', '|-', '>-', '|+', '>+'}:
                            block_scalar_indent = indent
                            continue
                        if anchor_only:
                            key_stack.append((indent, key))
                            continue
                        rows.append({'文件': fpath, '行号': lineno,
                                     '配置键': full_key,
                                     '当前值': val_part[:100].replace(',', ';')})
                    else:
                        key_stack.append((indent, key))
        except (OSError, UnicodeError) as exc:
            add_incomplete(fpath, 0, f'YAML 文件无法读取（{type(exc).__name__}）')
            continue

    total = write_csv_results(rows,
                              ['文件', '行号', '配置键', '当前值', '扫描状态'],
                              output_path)
    print(f"  sb_config: {total} 个配置键 → {output_path}", file=sys.stderr)
    return total


def scan_sb_autoconfig(source_dir, output_path, _dep_changes_path=None):
    """扫描自动装配配置文件迁移情况"""
    try:
        spring_pack = load_rule_pack('spring-boot')
        spring_pack_label = f"{spring_pack.get('id')}@{spring_pack.get('version')}"
        active_rules = [rule for rule in spring_pack.get('rules') or []
                        if rule_applies_to_major_interval(rule, BASE_SPRING_BOOT_MAJOR, TARGET_SPRING_BOOT_MAJOR)]
    except (OSError, ValueError, json.JSONDecodeError):
        spring_pack_label = 'spring-boot-inline@compat'
        active_rules = []
    lines = [
        f"# 自动装配配置扫描 | {datetime.now().isoformat()}",
        f"# 规则包: {spring_pack_label}",
        f"# 激活规则: {','.join(rule.get('id', '') for rule in active_rules) or 'none'}",
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
            except (OSError, UnicodeError) as exc:
                lines.append(f"    无法读取：{type(exc).__name__}；该文件未完成分析")
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
    扫描 Step1 留存的 current 最终制品内依赖 JAR 的兼容性信号。

    目标：
      - 补充源码扫描看不到的第三方库风险
      - 提前发现 javax/jakarta、JDK 内部 API、Spring Boot 自动装配元数据等问题
    """
    fields = ['坐标', '版本', '依赖范围', '风险类型', '证据', '最终制品内路径']

    rows = []
    input_count = 0
    for scan_input in iter_current_final_artifact_dependencies(dep_changes_path):
        input_count += 1
        dep = scan_input['dependency']
        coord = dep.get('coord', '')
        version = dep.get('version', '')
        scope = dep.get('scope', 'compile')
        lib_entry = str(dep.get('lib_entry') or dep.get('entry_id') or '').strip()
        if not should_scan_dep_scope(scope):
            continue
        error_code = scan_input.get('error_code') or ''
        if error_code:
            rows.append({
                '坐标': coord or '未解析',
                '版本': version or '未解析',
                '依赖范围': scope,
                '风险类型': error_code,
                '证据': FINAL_ARTIFACT_SCAN_FAILURE_MESSAGES.get(error_code, error_code),
                '最终制品内路径': lib_entry,
            })
            continue

        try:
            with zipfile.ZipFile(io.BytesIO(scan_input['jar_bytes'])) as zf:
                names = zf.namelist()

                def add_row(risk_type, evidence):
                    rows.append({
                        '坐标': coord or '未解析',
                        '版本': version or '未解析',
                        '依赖范围': scope,
                        '风险类型': risk_type,
                        '证据': evidence[:200],
                        '最终制品内路径': lib_entry,
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
                    except (OSError, RuntimeError, KeyError, zipfile.BadZipFile) as exc:
                        record_scan_diagnostic(
                            stage='dependency_compat_class_read',
                            path=f'{lib_entry}!/{entry}',
                            error=exc,
                        )
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

        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            record_scan_diagnostic(
                stage='dependency_compat_nested_jar_open', path=lib_entry, error=exc,
            )
            rows.append({
                '坐标': coord or '未解析',
                '版本': version or '未解析',
                '依赖范围': scope,
                '风险类型': 'nested_jar_unreadable',
                '证据': FINAL_ARTIFACT_SCAN_FAILURE_MESSAGES['nested_jar_unreadable'],
                '最终制品内路径': lib_entry,
            })

    count = write_csv_results(rows, fields, output_path)
    if not input_count:
        print(f"  dep_compat: 未提供或无法读取依赖清单 → {output_path}", file=sys.stderr)
        return 0
    print(f"  dep_compat: {count} 处命中 → {output_path}", file=sys.stderr)
    return count

def scan_dependency_classfile_versions(_source_dir, output_path, dep_changes_path=None):
    fields = [
        '依赖坐标', '版本', '依赖范围', '最终制品内路径', '是否为多版本JAR',
        '基础区最高Class版本', '多版本区最高Class版本', '基础区所需Java版本',
        '多版本区所需Java版本', '最高所需Java版本', '目标JDK版本', '扫描结论',
    ]
    rows = []
    risk_count = 0

    for scan_input in iter_current_final_artifact_dependencies(dep_changes_path):
        dep = scan_input['dependency']
        coord = dep.get('coord', '')
        version = dep.get('version', '')
        scope = dep.get('scope', 'compile')
        lib_entry = str(dep.get('lib_entry') or dep.get('entry_id') or '').strip()
        if not should_scan_dep_scope(scope):
            continue
        error_code = scan_input.get('error_code') or ''
        if error_code:
            rows.append({
                '依赖坐标': coord or '未解析',
                '版本': version or '未解析',
                '依赖范围': scope,
                '最终制品内路径': lib_entry,
                '是否为多版本JAR': '无法判断',
                '基础区最高Class版本': '',
                '多版本区最高Class版本': '',
                '基础区所需Java版本': '',
                '多版本区所需Java版本': '',
                '最高所需Java版本': '',
                '目标JDK版本': TARGET_JDK or '',
                '扫描结论': FINAL_ARTIFACT_SCAN_FAILURE_MESSAGES.get(error_code, error_code),
            })
            risk_count += 1
            continue

        max_major_base = None
        max_major_mr = None
        multi_release = False
        class_read_failures = 0

        try:
            with zipfile.ZipFile(io.BytesIO(scan_input['jar_bytes'])) as zf:
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
                    except (OSError, RuntimeError, KeyError, zipfile.BadZipFile) as exc:
                        class_read_failures += 1
                        record_scan_diagnostic(
                            stage='dependency_classfile_entry_read',
                            path=f'{lib_entry}!/{name}',
                            error=exc,
                        )
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
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            record_scan_diagnostic(
                stage='dependency_classfile_nested_jar_open', path=lib_entry, error=exc,
            )
            rows.append({
                '依赖坐标': coord or '未解析',
                '版本': version or '未解析',
                '依赖范围': scope,
                '最终制品内路径': lib_entry,
                '是否为多版本JAR': '无法判断',
                '基础区最高Class版本': '',
                '多版本区最高Class版本': '',
                '基础区所需Java版本': '',
                '多版本区所需Java版本': '',
                '最高所需Java版本': '',
                '目标JDK版本': TARGET_JDK or '',
                '扫描结论': FINAL_ARTIFACT_SCAN_FAILURE_MESSAGES['nested_jar_unreadable'],
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

        conclusion = '扫描完成，未发现字节码版本风险'
        if TARGET_JDK and max_java_any and max_java_any > TARGET_JDK:
            conclusion = f'存在风险：该依赖至少需要 JDK {max_java_any}'
            risk_count += 1
        elif max_java_any is None and max_major_any is not None:
            conclusion = f'未完成：无法识别 Class 版本 {max_major_any}'
            risk_count += 1
        elif class_read_failures:
            conclusion = f'未完成：有 {class_read_failures} 个 Class 条目无法读取'
            risk_count += 1

        rows.append({
            '依赖坐标': coord or '未解析',
            '版本': version or '未解析',
            '依赖范围': scope,
            '最终制品内路径': lib_entry,
            '是否为多版本JAR': '是' if multi_release else '否',
            '基础区最高Class版本': max_major_base or '',
            '多版本区最高Class版本': max_major_mr or '',
            '基础区所需Java版本': max_java_base or '',
            '多版本区所需Java版本': max_java_mr or '',
            '最高所需Java版本': max_java_any or '',
            '目标JDK版本': TARGET_JDK or '',
            '扫描结论': conclusion,
        })

    write_csv_results(rows, fields, output_path)
    if not rows:
        print(f"  dep_classfile: 未提供或无法读取依赖清单 → {output_path}", file=sys.stderr)
        return 0
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


def write_step3_coverage(output_dir, source_roots, planned_scans, executed_scans, coverage_output=''):
    extension_counts = {}
    read_failures = []
    scanned_files = 0
    relevant_extensions = {
        '.java', '.kt', '.kts', '.xml', '.properties', '.yml', '.yaml',
        '.factories', '.imports', '.sh', '.bat', '.cmd', '.ps1', '.conf', '.env',
    }
    for path in walk_files(source_roots, relevant_extensions):
        scanned_files += 1
        extension = Path(path).suffix.lower() or '<none>'
        extension_counts[extension] = extension_counts.get(extension, 0) + 1
        try:
            with open_text(path) as handle:
                handle.read(1)
        except Exception as exc:
            read_failures.append({'file': path, 'reason': type(exc).__name__})
    planned = list(dict.fromkeys(planned_scans or []))
    executed = list(dict.fromkeys(executed_scans or []))
    missing = [item for item in planned if item not in executed]
    status = 'complete' if not missing and not read_failures else ('partial' if executed else 'insufficient')
    scan_diagnostics = get_scan_diagnostics()
    if scan_diagnostics:
        status = 'partial' if executed else 'insufficient'
    payload = {
        'schema': 'java-upgrade-analyzer.step3-coverage.v1',
        'status': status,
        'reason_codes': (
            (['planned_scan_not_executed'] if missing else [])
            + (['source_file_read_failures'] if read_failures else [])
            + (['scan_operation_failures'] if scan_diagnostics else [])
        ),
        'source_roots': list(source_roots or []),
        'planned_scans': planned,
        'executed_scans': executed,
        'not_applicable_scans': [item for item in SCAN_FUNCS if item not in planned],
        'metrics': {
            'source_roots': len(source_roots or []),
            'files_scanned': scanned_files,
            'extension_counts': extension_counts,
            'read_failures': len(read_failures),
        },
        'failures': read_failures,
        'scan_diagnostics': scan_diagnostics,
    }
    packs = []
    for pack_id in ('jdk', 'jakarta', 'spring-boot'):
        try:
            pack = load_rule_pack(pack_id)
            packs.append({
                'id': pack['id'], 'version': pack['version'], 'sha256': pack['_sha256'],
                'source': pack['source'], 'last_verified': pack['last_verified'],
                'rules': len(pack.get('rules') or []),
            })
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            packs.append({'id': pack_id, 'status': 'unavailable', 'reason': str(exc)})
            payload['status'] = 'partial' if executed else 'insufficient'
            payload['reason_codes'].append('rule_pack_unavailable')
    payload['rule_packs'] = packs
    output_path = Path(coverage_output) if coverage_output else Path(output_dir) / 's3_coverage.json'
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    return payload


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
    ap.add_argument('--report-dir', default='',
                    help='升级报告根目录；编排模式下用于读取 .runtime/state 与 evidence/context')
    ap.add_argument('--coverage-output', default='',
                    help='Step3 覆盖率 JSON 输出路径；编排模式下写入 .runtime/coverage')
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
    report_dir = args.report_dir or args.output_dir
    orchestrated_input, orchestrated_context = load_orchestrated_step3_input(report_dir)
    if orchestrated_input:
        if not args.source_dirs and not args.source_dir:
            args.source_dirs = list(orchestrated_input.get("source_dirs") or [])
        if not args.include_test_scope and orchestrated_input.get("include_test_scope"):
            args.include_test_scope = True
    global STEP3_DEPENDENCY_SOURCE_DIRS
    STEP3_DEPENDENCY_SOURCE_DIRS = normalize_dependency_source_dirs(
        orchestrated_input.get("dependency_source_dirs") if orchestrated_input else None
    )
    global STEP3_REPORT_DIR
    STEP3_REPORT_DIR = report_dir
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
    global BASE_JDK
    base_jdk_value = str((orchestrated_context or {}).get('jdk_base') or '')
    BASE_JDK = int(base_jdk_value) if base_jdk_value.isdigit() else None
    global BASE_SPRING_BOOT_MAJOR, TARGET_SPRING_BOOT_MAJOR
    base_spring = str((orchestrated_context or {}).get('springboot_base') or '')
    current_spring = str((orchestrated_context or {}).get('springboot_current') or '')
    BASE_SPRING_BOOT_MAJOR = int(base_spring.split('.', 1)[0]) if base_spring[:1].isdigit() else None
    TARGET_SPRING_BOOT_MAJOR = int(current_spring.split('.', 1)[0]) if current_spring[:1].isdigit() else None
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

        reset_scan_diagnostics()
        cleanup_step3_outputs(args.output_dir)
        os.makedirs(args.output_dir, exist_ok=True)
        emit_progress(
            "step3",
            "plan",
            f"已生成扫描计划，将执行 {len(to_run)} 类扫描",
            current=len(source_roots),
            total=len(source_roots),
        )
        total = 0
        executed_scans = []
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
            executed_scans.append(scan_type)
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
        write_step3_coverage(args.output_dir, source_roots, to_run, executed_scans, args.coverage_output)
        print(f"\nStep 3 完成：共 {total} 处命中", file=sys.stderr)
        emit_progress(
            "step3",
            "done",
            f"全部静态扫描完成，总命中 {total} 处",
            elapsed=step_timer.elapsed(),
        )

    else:
        reset_scan_diagnostics()
        func, default_fname = SCAN_FUNCS[args.type]
        output = args.output or os.path.join(args.output_dir, default_fname)
        emit_progress("step3", "scan", f"开始执行 {args.type}", item=default_fname)
        single_timer = time.perf_counter()
        matches = func(source_dir, output, dep_list_path) or 0
        write_step3_coverage(args.output_dir, source_roots, [args.type], [args.type], args.coverage_output)
        emit_progress(
            "step3",
            "done",
            f"完成 {args.type}，命中 {matches} 处",
            elapsed=time.perf_counter() - single_timer,
            item=default_fname,
        )


if __name__ == '__main__':
    main()
