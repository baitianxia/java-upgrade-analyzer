#!/usr/bin/env python3
"""
s2_context_from_deps.py — Step 2：从依赖树推断项目上下文

为什么从依赖树推断而不是直接读 pom.xml：
  - 依赖树是构建工具实际执行后的结果，BOM 已展开，版本仲裁已完成
  - Spring Boot 版本从依赖树里找实际使用的版本，比 pom.xml 的 parent 声明更准确
  - 技术栈检测（Lombok/Spring Cloud 等）基于实际存在的依赖，不会漏掉传递引入的

输入：
  s1_dep_changes.csv        依赖变更清单（Step 1 输出）
  git（只读，不切换分支）    读取 pom.xml 获取 JDK 版本等 git 只能读到的信息

输出：
  s2_context.json           项目上下文（供后续所有步骤共享）

Windows 兼容：通过 compat.py 处理编码和 subprocess 调用。
"""

import argparse, csv, json, os, re, sys, zipfile
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).parent))
from compat import run_cmd, open_text, git_cmd, mvn_cmd
from csv_io import open_csv_read
from path_runtime import create_detached_worktree, remove_detached_worktree


MAIN_STATE_FILE_NAME = "main_state.json"
PINNED_SOURCE_SNAPSHOT_SCHEMA = "java-upgrade-analyzer.pinned-source-snapshot.v1"
_FULL_GIT_COMMIT_RE = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})')


def load_orchestrated_step2_input(output_path=""):
    """正式流程下从 main_state 读取 Step2 输入，单脚本 CLI 仅用于调试。"""
    if not os.environ.get("JUA_ORCHESTRATED"):
        return {}
    report_dir = os.environ.get("UPGRADE_REPORT_DIR", "").strip()
    if not report_dir and output_path:
        report_dir = str(Path(output_path).resolve().parent)
    if not report_dir:
        return {}
    state_path = Path(report_dir) / ".runtime" / "state" / MAIN_STATE_FILE_NAME
    if not state_path.exists():
        return {}
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            main_state = json.load(f)
    except Exception:
        return {}
    return dict((((main_state or {}).get("step2") or {}).get("input")) or {})


def _normalize_pinned_relative_path(value, *, allow_root=True):
    text = str(value or '').strip().replace('\\', '/')
    if text in ('', '.', './'):
        return '.' if allow_root else ''
    if text.startswith('/') or re.match(r'^[A-Za-z]:/', text):
        return ''
    parts = [part for part in text.split('/') if part not in ('', '.')]
    if not parts or any(part == '..' for part in parts):
        return ''
    return '/'.join(parts)


def _valid_pinned_source_snapshot(orchestrated_input, current_revision):
    snapshot = (orchestrated_input or {}).get('pinned_source_snapshot')
    if not isinstance(snapshot, dict):
        return {}
    commit = str(snapshot.get('commit') or '').strip().lower()
    if (
        snapshot.get('schema') != PINNED_SOURCE_SNAPSHOT_SCHEMA
        or not _FULL_GIT_COMMIT_RE.fullmatch(commit)
        or commit != str(current_revision or '').strip().lower()
        or not _normalize_pinned_relative_path(
            snapshot.get('project_path'), allow_root=True,
        )
    ):
        return {}
    roots = []
    for value in snapshot.get('source_roots') or []:
        normalized = _normalize_pinned_relative_path(value, allow_root=True)
        if not normalized:
            return {}
        roots.append(normalized)
    normalized = dict(snapshot)
    normalized['commit'] = commit
    normalized['project_path'] = _normalize_pinned_relative_path(
        snapshot.get('project_path'), allow_root=True,
    )
    normalized['source_roots'] = list(dict.fromkeys(roots))
    return normalized


def _pinned_source_repository(orchestrated_input, work_dir):
    binding = (orchestrated_input or {}).get('current_ref_binding')
    if isinstance(binding, dict):
        value = str(binding.get('repo_dir') or '').strip()
        if value:
            return Path(value).expanduser().resolve()
    value = str(
        (orchestrated_input or {}).get('current_source_project_dir') or ''
    ).strip()
    return (
        Path(value).expanduser().resolve()
        if value
        else Path(work_dir).expanduser().resolve()
    )


@contextmanager
def materialize_pinned_step2_source_workspace(
    orchestrated_input,
    current_revision,
    work_dir,
):
    """Materialize Step1's logical roots without persisting temp paths."""
    snapshot = _valid_pinned_source_snapshot(
        orchestrated_input, current_revision,
    )
    if not snapshot:
        yield None
        return
    repo_dir = _pinned_source_repository(orchestrated_input, work_dir)
    git_root = Path(get_git_root(repo_dir, strict_git=True)).resolve()
    worktree = None
    try:
        worktree = create_detached_worktree(
            snapshot['commit'],
            git_root,
            label='s2-src',
            runner=run_cmd,
            git_command=git_cmd(),
        )
        project_root = (
            worktree
            if snapshot['project_path'] == '.'
            else worktree / snapshot['project_path']
        )
        if not project_root.is_dir():
            raise RuntimeError(
                'STEP2_PINNED_PROJECT_MISSING_AT_COMMIT:'
                f"{snapshot['project_path']}:{snapshot['commit']}"
            )
        mapped_source_dirs = []
        stable_source_dirs = []
        stable_project_root = repo_dir
        for relative in snapshot.get('source_roots') or []:
            mapped = project_root if relative == '.' else project_root / relative
            if not mapped.is_dir():
                raise RuntimeError(
                    'STEP2_PINNED_SOURCE_DIR_MISSING_AT_COMMIT:'
                    f"{relative}:{snapshot['commit']}"
                )
            mapped_source_dirs.append(str(mapped.resolve()))
            stable = (
                stable_project_root
                if relative == '.'
                else stable_project_root / relative
            )
            stable_source_dirs.append(str(stable.resolve()))
        yield {
            'snapshot': snapshot,
            'git_root': git_root,
            'worktree': worktree,
            'project_root': project_root.resolve(),
            'mapped_source_dirs': mapped_source_dirs,
            'stable_source_dirs': stable_source_dirs,
        }
    finally:
        if worktree is not None:
            remove_detached_worktree(
                worktree,
                git_root,
                runner=run_cmd,
                git_command=git_cmd(),
            )


# ══════════════════════════════════════════════════════════════════
# 读取依赖变更 CSV
# ══════════════════════════════════════════════════════════════════

def load_dep_changes(csv_path):
    """读取 s1_dep_changes.csv，返回 {coord: row_dict} 字典"""
    if not os.path.exists(csv_path):
        print(f"❌ 依赖变更文件不存在：{csv_path}", file=sys.stderr)
        sys.exit(1)

    deps = {}
    with open_csv_read(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row:
                continue
            normalized = {k: (v or '').strip() for k, v in row.items()}
            if normalized.get('resolution_status') == 'unresolved':
                continue
            coord = normalized.get('coord', '').strip()
            if coord and not coord.startswith('#'):
                if coord in deps:
                    previous = deps[coord]
                    raise ValueError(
                        "duplicate dependency identity in Step1 output: "
                        f"{coord}; entries="
                        f"{previous.get('base_lib_entry') or previous.get('current_lib_entry') or '<unknown>'},"
                        f"{normalized.get('base_lib_entry') or normalized.get('current_lib_entry') or '<unknown>'}. "
                        "Preserve Maven classifier in coord instead of collapsing physical artifacts."
                    )
                deps[coord] = normalized

    if not deps:
        print(f"❌ {csv_path} 解析结果为空，请检查文件格式", file=sys.stderr)
        sys.exit(1)

    print(f"  读取到 {len(deps)} 个依赖", file=sys.stderr)
    return deps


def get_pom_deps_from_m2(group_id, artifact_id, version):
    """Deprecated compatibility hook; raw repository POMs are not analysis evidence."""
    _ = group_id, artifact_id, version
    return []


def topological_sort(target_coords, edges):
    in_degree = defaultdict(int)
    adjacency = defaultdict(list)

    for from_coord, to_coord in edges:
        adjacency[from_coord].append(to_coord)
        in_degree[to_coord] += 1

    queue = [coord for coord in target_coords if in_degree[coord] == 0]
    order = []

    while queue:
        node = queue.pop(0)
        order.append(node)
        for neighbor in adjacency[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    remaining = [coord for coord in target_coords if coord not in order]
    if remaining:
        print(f"⚠️  检测到循环依赖，涉及：{remaining}", file=sys.stderr)
        order.extend(remaining)

    return order


def build_dep_graph(deps):
    changed_deps = {}
    for coord, row in deps.items():
        change_type = row.get('change_type', '')
        old_version = row.get('old_version', '-')
        new_version = row.get('new_version', '-')
        if change_type in ('', '未变'):
            continue
        if old_version == '-' and new_version == '-':
            continue
        parts = coord.split(':')
        if len(parts) >= 2:
            changed_deps[coord] = {
                'coord': coord,
                'group_id': parts[0],
                'artifact_id': parts[1],
                'old_version': old_version,
                'new_version': new_version,
                'change_type': change_type,
                'scope': row.get('scope', 'compile'),
            }

    if not changed_deps:
        return {
            'dependencies': [],
            'edges': [],
            'analysis_order': [],
            'total_dependencies': 0,
            'note': '未找到发生版本变化的依赖，关系图为空',
        }

    # Do not infer effective dependency edges from an artifact's raw POM.  The
    # consuming project's exclusions and dependencyManagement/BOM mediation
    # live outside that POM, so such edges can describe a relationship Maven
    # explicitly removed.  Step1's packaged artifacts remain authoritative for
    # dependency presence/version; until a resolved dependency:tree is supplied
    # this contextual graph deliberately leaves relationships unknown.
    edges = []

    analysis_order = topological_sort(
        list(changed_deps.keys()),
        [(edge['from'], edge['to']) for edge in edges],
    )

    from_nodes = {edge['from'] for edge in edges}
    to_nodes = {edge['to'] for edge in edges}
    dependencies = []
    for index, coord in enumerate(analysis_order):
        dep = changed_deps[coord]
        is_leaf = coord not in from_nodes
        is_root = coord not in to_nodes
        dependencies.append(
            {
                **dep,
                'analysis_index': index,
                'is_leaf': is_leaf,
                'is_root': is_root,
                'layer': 'leaf' if is_leaf else ('root' if is_root else 'middle'),
            }
        )

    return {
        'dependencies': dependencies,
        'edges': edges,
        'analysis_order': analysis_order,
        'total_dependencies': len(changed_deps),
        'relationship_status': 'not_inferred_without_resolved_tree',
        'note': (
            f'共 {len(changed_deps)} 个变更依赖；未获得 Maven/Gradle 最终解析的依赖树，'
            '不从原始 POM 推测父子边，以避免 BOM 仲裁或 exclusions 造成幽灵关系'
        ),
        'meta': {
            'what': '升级依赖关系图（只关注发生版本变化的依赖之间的关系）',
            'why': '用于理解升级依赖之间的传播关系与推荐分析顺序（叶→根）',
            'how_to_read': [
                'analysis_order 仅是稳定的变更依赖顺序，不表示未经证明的传递关系',
                'edges 只能承载构建工具最终解析后的关系；当前无该证据时保持为空',
                'dependencies 只包含发生版本变化的依赖，不再区分内部库/第三方库',
            ],
        },
    }


# ══════════════════════════════════════════════════════════════════
# 业务源码目录递归发现（多模块支持）
# ══════════════════════════════════════════════════════════════════

def auto_detect_source_dirs(project_root, build_tool):
    """
    自动检测业务源码目录（递归多模块支持）

    检测策略：
    - 递归查找所有模块下的 src/main/java, src/main/kotlin, src/main/groovy
    - 排除构建产物：target/, build/, out/, .git/, .idea/, .upgrade-report/
    - 保留绝对路径，标记模块归属

    Args:
        project_root: 项目根目录
        build_tool: 'maven' 或 'gradle'

    Returns:
        List[str]: 源码目录绝对路径列表
    """
    if not project_root:
        return []

    root = project_root if os.path.isabs(project_root) else os.path.abspath(project_root)

    # 排除目录
    skip_dirs = {
        'target', 'build', 'out', '.git', '.idea', '.gradle', 'node_modules',
        '.upgrade-report', '__pycache__', '.mvn', 'cache', 'tmp'
    }

    # 递归查找所有包含 src/main 的目录
    detected = []

    for current_root, dirs, files in os.walk(root, topdown=True):
        # 优化：在遍历时动态修改 dirs，跳过排除目录
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        # 检查当前目录是否包含标准源码结构
        for src_type in ['java', 'kotlin', 'groovy']:
            src_main = os.path.join(current_root, f'src/main/{src_type}')
            if os.path.isdir(src_main):
                # 检查是否真的有源文件（避免空目录）
                has_files = False
                try:
                    for _, _, filenames in os.walk(src_main):
                        for f in filenames:
                            if f.endswith(f'.{src_type}') or f.endswith('.kt'):
                                has_files = True
                                break
                        if has_files:
                            break
                except:
                    pass

                if has_files:
                    detected.append(src_main)

    # 去重（绝对路径）
    seen = set()
    unique = []
    for d in detected:
        if d not in seen:
            seen.add(d)
            unique.append(d)

    return unique


# ══════════════════════════════════════════════════════════════════
# 从依赖树推断各项信息
# ══════════════════════════════════════════════════════════════════

def detect_spring_boot_version(deps):
    """
    从依赖树中找 Spring Boot 的实际使用版本。
    优先使用 spring-boot:spring-boot（核心包），它的版本就是 Spring Boot 版本。
    """
    candidates = [
        'org.springframework.boot:spring-boot',
        'org.springframework.boot:spring-boot-autoconfigure',
        'org.springframework.boot:spring-boot-starter',
    ]
    for coord in candidates:
        row = deps.get(coord)
        if row:
            old_ver = row.get('old_version', '-')
            new_ver = row.get('new_version', '-')
            return (
                old_ver if old_ver != '-' else None,
                new_ver if new_ver != '-' else None,
                'step1_scope'  # 来源标注
            )
    return None, None, 'not_found'


def detect_spring_cloud(deps):
    """检测是否使用了 Spring Cloud"""
    sc_coords = [
        'org.springframework.cloud:spring-cloud-context',
        'org.springframework.cloud:spring-cloud-commons',
        'org.springframework.cloud:spring-cloud-starter',
    ]
    for coord in deps:
        if any(coord.startswith(sc) for sc in sc_coords):
            row = deps[coord]
            ver = row.get('new_version') or row.get('old_version', '')
            return True, ver
    return False, None


def detect_tech_flags(deps):
    """
    从依赖树检测特殊技术点。
    基于实际存在的依赖（含传递依赖），比 pom.xml 关键词匹配更准确。
    """
    # {flag_name: [匹配前缀列表]}
    checks = {
        'lombok':     ['org.projectlombok:lombok'],
        'jaxb':       ['jakarta.xml.bind:jakarta.xml.bind-api',
                       'javax.xml.bind:jaxb-api',
                       'com.sun.xml.bind:jaxb-impl',
                       'org.glassfish.jaxb:jaxb-runtime'],
        'bytebuddy':  ['net.bytebuddy:byte-buddy'],
        'javassist':  ['org.javassist:javassist'],
        'aspectj':    ['org.aspectj:aspectjweaver', 'org.aspectj:aspectjrt'],
        'dubbo':      ['org.apache.dubbo:dubbo', 'com.alibaba:dubbo'],
        'netty':      ['io.netty:netty-all', 'io.netty:netty-common'],
        'grpc':       ['io.grpc:grpc-core', 'io.grpc:grpc-stub'],
        'spring_cloud': ['org.springframework.cloud:'],
        'fastjson':   ['com.alibaba:fastjson', 'com.alibaba.fastjson2:fastjson2'],
        'mapstruct':  ['org.mapstruct:mapstruct'],
        'mybatis':    ['org.mybatis:mybatis',
                       'org.mybatis.spring.boot:mybatis-spring-boot-starter',
                       'com.baomidou:mybatis-plus'],
        'nacos':      ['com.alibaba.nacos:nacos-client',
                       'com.alibaba.cloud:spring-cloud-starter-alibaba-nacos-discovery'],
        'sentinel':   ['com.alibaba.csp:sentinel-core',
                       'com.alibaba.cloud:spring-cloud-starter-alibaba-sentinel'],
        'rocketmq':   ['org.apache.rocketmq:rocketmq-client',
                       'org.apache.rocketmq:rocketmq-spring-boot-starter'],
        'kafka':      ['org.apache.kafka:kafka-clients',
                       'org.springframework.kafka:spring-kafka'],
        'elasticsearch': ['org.elasticsearch.client:',
                          'co.elastic.clients:elasticsearch-java'],
        'redis':      ['io.lettuce:lettuce-core',
                       'redis.clients:jedis'],
    }

    flags = {}
    for flag, prefixes in checks.items():
        matched = False
        for coord in deps:
            if any(coord.startswith(p) for p in prefixes):
                matched = True
                break
        flags[flag] = matched

    return flags


def collect_changed_dependencies(deps):
    """收集发生版本变化的依赖，供后续步骤决定哪些依赖值得重点补源码与深分析。"""
    changed = []
    for coord, row in deps.items():
        change_type = row.get('change_type', '')
        old_version = row.get('old_version', '-')
        new_version = row.get('new_version', '-')
        if change_type in ('', '未变'):
            continue
        if old_version == '-' and new_version == '-':
            continue
        parts = coord.split(':')
        changed.append({
            'coord': coord,
            'group_id': parts[0] if len(parts) >= 1 else '',
            'artifact_id': parts[1] if len(parts) >= 2 else '',
            'old_version': old_version,
            'new_version': new_version,
            'change_type': change_type,
            'scope': row.get('scope', 'compile'),
        })
    return changed


def compute_version_flags(sb_base, sb_cur, jdk_base, jdk_cur):
    """计算升级标志位"""
    def major(v):
        if not v or v in ('-', 'unknown'):
            return None
        try:
            return int(str(v).split('.')[0])
        except (ValueError, IndexError):
            return None

    sb_upgraded = bool(sb_base and sb_cur and sb_base != sb_cur
                       and sb_base != '-' and sb_cur != '-')
    sb_base_major = major(sb_base)
    sb_cur_major  = major(sb_cur)
    sb_major_upgrade = bool(sb_upgraded and sb_base_major and sb_cur_major
                            and sb_cur_major > sb_base_major)

    jdk_upgraded = bool(jdk_base and jdk_cur and jdk_base != jdk_cur
                        and jdk_base not in ('', 'unknown')
                        and jdk_cur  not in ('', 'unknown'))

    return sb_upgraded, sb_major_upgrade, jdk_upgraded


# ══════════════════════════════════════════════════════════════════
# 从 git 补充读取（只读，不切换分支）
# ══════════════════════════════════════════════════════════════════

_GIT_PATH_ABSENT_PATTERNS = (
    "does not exist in",
    "exists on disk, but not in",
    "path not in the working tree",
)


def _git_path_is_absent(stderr):
    text = str(stderr or '').strip().lower()
    return any(pattern in text for pattern in _GIT_PATH_ABSENT_PATTERNS)


def git_show_file(branch, file_path, work_dir='.', *, strict_git=False):
    """Read one path from a revision; distinguish absence from Git failure."""
    stdout, stderr, rc = run_cmd(
        git_cmd() + ['show', f'{branch}:{file_path}'],
        cwd=work_dir, timeout=30
    )
    if rc == 0:
        return stdout
    if strict_git and not _git_path_is_absent(stderr):
        raise RuntimeError(
            "STEP2_GIT_SHOW_FAILED:"
            f"{branch}:{file_path}:"
            f"{str(stderr or stdout or f'git exited with {rc}').strip()}"
        )
    return ''


def require_pinned_git_commit(revision, work_dir='.', side=''):
    """Validate the immutable Step1 object before any Step2 Git query."""
    revision = str(revision or '').strip().lower()
    if not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', revision):
        raise RuntimeError(
            f"STEP2_{str(side or 'SOURCE').upper()}_COMMIT_NOT_PINNED:{revision}"
        )
    stdout, stderr, rc = run_cmd(
        git_cmd() + ['rev-parse', '--verify', f'{revision}^{{commit}}'],
        cwd=work_dir,
        timeout=30,
    )
    resolved = str(stdout or '').strip().lower()
    if rc != 0 or resolved != revision:
        raise RuntimeError(
            f"STEP2_{str(side or 'SOURCE').upper()}_COMMIT_UNAVAILABLE:"
            f"{revision}:{str(stderr or stdout or f'git exited with {rc}').strip()}"
        )
    return revision


def is_git_repo(work_dir='.', *, strict_git=False):
    """检测当前目录是否为 Git worktree；严格模式保留失败证据。"""
    stdout, stderr, rc = run_cmd(
        git_cmd() + ['rev-parse', '--is-inside-work-tree'],
        cwd=work_dir, timeout=10
    )
    inside = rc == 0 and str(stdout or '').strip().lower() == 'true'
    if strict_git and not inside:
        raise RuntimeError(
            "STEP2_GIT_REPOSITORY_PROBE_FAILED:"
            f"{work_dir}:"
            f"{str(stderr or stdout or f'git exited with {rc}').strip()}"
        )
    return inside


def get_git_root(work_dir='.', *, strict_git=False):
    """返回 Git 仓库根目录；严格模式不吞掉 Git/路径失败。"""
    stdout, stderr, rc = run_cmd(
        git_cmd() + ['rev-parse', '--show-toplevel'],
        cwd=work_dir, timeout=10
    )
    root = str(stdout or '').strip() if rc == 0 else ''
    if strict_git and not root:
        raise RuntimeError(
            "STEP2_GIT_ROOT_DISCOVERY_FAILED:"
            f"{work_dir}:"
            f"{str(stderr or stdout or f'git exited with {rc}').strip()}"
        )
    return root


def get_repo_relative_prefix(work_dir='.', *, strict_git=False):
    """
    返回 work_dir 相对于 Git 仓库根目录的相对路径。
    例：/repo/module-a -> module-a
    """
    git_root = get_git_root(work_dir, strict_git=strict_git)
    if not git_root:
        return ''
    try:
        rel = os.path.relpath(
            os.path.realpath(work_dir),
            os.path.realpath(git_root)
        )
    except ValueError as exc:
        if strict_git:
            raise RuntimeError(
                f"STEP2_GIT_WORKDIR_OUTSIDE_ROOT:{work_dir}:{git_root}:{exc}"
            ) from exc
        return ''
    return '' if rel == '.' else rel.replace('\\', '/')


def build_manifest_candidates(work_dir='.', *filenames, strict_git=False):
    """按 work_dir 优先级构造构建文件候选路径"""
    prefix = get_repo_relative_prefix(work_dir, strict_git=strict_git)
    candidates = []
    for name in filenames:
        if prefix:
            candidates.append(f"{prefix}/{name}")
        candidates.append(name)
    seen = set()
    ordered = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def read_local_file(work_dir, *candidates):
    """按候选路径顺序读取当前工作区文件，找不到返回空字符串"""
    base = Path(work_dir)
    for rel in candidates:
        path = base / rel
        if path.exists() and path.is_file():
            try:
                with open_text(path) as f:
                    return f.read()
            except Exception:
                continue
    return ''


def normalize_jdk_version(ver):
    if ver is None:
        return None
    ver = str(ver).strip().strip('"\'').replace('_', '.')
    if not ver or ver.lower() in ('null', 'none', 'unknown'):
        return None
    if ver.startswith('1.'):
        ver = ver[2:]
    match = re.fullmatch(r'(\d+)(?:\.0+)?', ver)
    if not match:
        return None
    major = int(match.group(1))
    if major <= 0 or major > 99:
        return None
    return str(major)


def _xml_local_name(tag):
    return str(tag or '').rsplit('}', 1)[-1]


def _resolve_maven_property(value, properties):
    """解析 Maven 属性链；无法收敛为明确 JDK 主版本时返回 None。"""
    current = str(value or '').strip()
    visited = set()
    for _ in range(12):
        prop_match = re.fullmatch(r'\$\{([^}]+)\}', current)
        if not prop_match:
            return normalize_jdk_version(current)
        key = prop_match.group(1).strip()
        if not key or key in visited or key not in properties:
            return None
        visited.add(key)
        current = str(properties.get(key) or '').strip()
    return None


def _direct_xml_child(parent, name):
    if parent is None:
        return None
    for child in list(parent):
        if _xml_local_name(child.tag) == name:
            return child
    return None


def detect_jdk_from_pom(pom_content):
    """从 pom.xml 内容提取 JDK 目标版本"""
    if not pom_content:
        return None

    try:
        root = ET.fromstring(pom_content)
    except ET.ParseError:
        root = None

    if root is not None:
        properties = {}
        properties_node = _direct_xml_child(root, 'properties')
        if properties_node is not None:
            for child in list(properties_node):
                key = _xml_local_name(child.tag)
                value = ''.join(child.itertext()).strip()
                if key and value:
                    properties[key] = value

        plugin_values = {
            'maven-compiler-plugin': {},
            'kotlin-maven-plugin': {},
        }
        build = _direct_xml_child(root, 'build')
        if build is not None:
            for plugin in build.iter():
                if _xml_local_name(plugin.tag) != 'plugin':
                    continue
                artifact_node = _direct_xml_child(plugin, 'artifactId')
                artifact_id = (
                    ''.join(artifact_node.itertext()).strip()
                    if artifact_node is not None else ''
                )
                if artifact_id not in ('maven-compiler-plugin', 'kotlin-maven-plugin'):
                    continue
                field_order = (
                    ('release', 'target', 'source')
                    if artifact_id == 'maven-compiler-plugin'
                    else ('jvmTarget',)
                )
                for configuration in plugin.iter():
                    if _xml_local_name(configuration.tag) != 'configuration':
                        continue
                    for node in configuration.iter():
                        name = _xml_local_name(node.tag)
                        if name in field_order and name not in plugin_values[artifact_id]:
                            plugin_values[artifact_id][name] = ''.join(
                                node.itertext()
                            ).strip()

        # Explicit compiler configuration is the effective task input and wins
        # over shorthand properties. release/target describe produced bytecode
        # more directly than source; java.version is only a final convention.
        java_candidate_values = (
            plugin_values['maven-compiler-plugin'].get('release'),
            properties.get('maven.compiler.release'),
            plugin_values['maven-compiler-plugin'].get('target'),
            properties.get('maven.compiler.target'),
            plugin_values['maven-compiler-plugin'].get('source'),
            properties.get('maven.compiler.source'),
        )
        kotlin_candidate_values = (
            plugin_values['kotlin-maven-plugin'].get('jvmTarget'),
            properties.get('kotlin.compiler.jvmTarget'),
        )
        detected_languages = []
        for candidate_group in (java_candidate_values, kotlin_candidate_values):
            for value in candidate_group:
                detected = _resolve_maven_property(value, properties)
                if detected:
                    detected_languages.append(detected)
                    break
        if detected_languages:
            return str(max(int(item) for item in detected_languages))

        for value in (
            properties.get('java.version'),
            properties.get('jdk.version'),
            properties.get('javaVersion'),
        ):
            detected = _resolve_maven_property(value, properties)
            if detected:
                return detected

    # Keep a narrow fallback for XML fragments used by diagnostics/tests.
    patterns = [
        r'<maven\.compiler\.release>\s*(1[._]\d+|\d+)\s*</maven\.compiler\.release>',
        r'<maven\.compiler\.target>\s*(1[._]\d+|\d+)\s*</maven\.compiler\.target>',
        r'<maven\.compiler\.source>\s*(1[._]\d+|\d+)\s*</maven\.compiler\.source>',
        r'<java\.version>\s*(1[._]\d+|\d+)\s*</java\.version>',
        r'<jdk\.version>\s*(1[._]\d+|\d+)\s*</jdk\.version>',
        r'<jvmTarget>\s*(1[._]\d+|\d+)\s*</jvmTarget>',
    ]
    for pattern in patterns:
        match = re.search(pattern, pom_content, re.DOTALL)
        if match:
            return normalize_jdk_version(match.group(1))
    return None


def detect_jdk_from_gradle(gradle_content):
    """从 build.gradle 内容提取 JDK 目标版本"""
    if not gradle_content:
        return None

    content = re.sub(r'/\*.*?\*/', ' ', gradle_content, flags=re.DOTALL)
    content = re.sub(r'(?m)//.*$', ' ', content)

    def expression_version(expression):
        expression = str(expression or '').strip()
        direct = normalize_jdk_version(expression)
        if direct:
            return direct
        for pattern in (
            r'JavaVersion\.VERSION_(1_\d+|\d+)',
            r'JavaLanguageVersion\.of\(\s*[\'"]?(1[._]\d+|\d+)[\'"]?\s*\)',
            r'JvmTarget\.JVM_(1_\d+|\d+)',
            r'JavaVersion\.toVersion\(\s*[\'"]?(1[._]\d+|\d+)[\'"]?\s*\)',
        ):
            match = re.fullmatch(pattern, expression)
            if match:
                return normalize_jdk_version(match.group(1))
        return None

    variables = {}
    assignment_pattern = re.compile(
        r'(?m)^\s*(?:def|val|var)?\s*([A-Za-z_]\w*)\s*=\s*([^\n;]+)'
    )
    pending = [(match.group(1), match.group(2).strip()) for match in assignment_pattern.finditer(content)]
    for _ in range(4):
        changed = False
        for name, expression in pending:
            detected = expression_version(expression)
            if not detected and re.fullmatch(r'[A-Za-z_]\w*', expression):
                detected = variables.get(expression)
            if detected and variables.get(name) != detected:
                variables[name] = detected
                changed = True
        if not changed:
            break

    def detect_first(patterns):
        for pattern in patterns:
            match = re.search(pattern, content, re.DOTALL)
            if not match:
                continue
            expression = match.group(1).strip()
            detected = expression_version(expression)
            if not detected and re.fullmatch(r'[A-Za-z_]\w*', expression):
                detected = variables.get(expression)
            if detected:
                return detected
        return None

    # Java and Kotlin can have separate bytecode targets. The application needs
    # the higher one; a toolchain is only a fallback when neither target exists.
    java_target = detect_first([
        r'options\.release\.set\(\s*([^)]+)\s*\)',
        r'options\.release\s*=\s*([^\s;\n}]+)',
        r'targetCompatibility\s*=\s*([^\s;\n}]+)',
        r'targetCompatibility\s+([^\s;\n}]+)',
        r'sourceCompatibility\s*=\s*([^\s;\n}]+)',
        r'sourceCompatibility\s+([^\s;\n}]+)',
    ])
    kotlin_target = detect_first([
        r'jvmTarget\s*=\s*([^\s;\n}]+)',
        r'jvmTarget\.set\(\s*([^)]+)\s*\)',
    ])
    language_targets = [
        item for item in (java_target, kotlin_target) if item
    ]
    if language_targets:
        return str(max(int(item) for item in language_targets))

    toolchain_target = detect_first([
        r'languageVersion\.set\(\s*(JavaLanguageVersion\.of\([^)]+\)|[A-Za-z_]\w*)\s*\)',
        r'languageVersion\s*=\s*(JavaLanguageVersion\.of\([^)]+\)|[A-Za-z_]\w*)',
        r'jvmToolchain\(\s*([^)]+)\s*\)',
    ])
    if toolchain_target:
        return toolchain_target

    # Common Kotlin compiler form nests JvmTarget inside .set(...), which the
    # generic capture above intentionally keeps conservative.
    match = re.search(r'JvmTarget\.JVM_(1_\d+|\d+)', content)
    if match:
        return normalize_jdk_version(match.group(1))
    return None


def jdk_version_from_class_major(class_major):
    """JVMS class major 52 -> Java 8, 61 -> Java 17。"""
    try:
        major = int(class_major)
    except (TypeError, ValueError):
        return None
    if major < 45 or major > 143:
        return None
    return str(major - 44)


def detect_jdk_from_artifact(artifact_path):
    """
    从最终 JAR/WAR 的业务 class 文件推断实际最低运行 JDK。

    Spring Boot/WAR 只读取 BOOT-INF/classes 或 WEB-INF/classes，明确排除
    嵌套依赖；普通 JAR 读取自身 class，并排除 multi-release 覆盖层。
    """
    path = Path(str(artifact_path or '')).expanduser()
    result = {
        'version': None,
        'source': 'final_artifact_bytecode',
        'artifact_path': str(path),
        'class_count': 0,
        'class_major_min': None,
        'class_major_max': None,
        'class_versions': [],
        'status': 'not_found',
    }
    if not path.is_file():
        result['status'] = 'artifact_missing'
        return result

    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename.replace('\\', '/') for info in infos]
            if any(name.startswith('BOOT-INF/classes/') for name in names):
                class_prefix = 'BOOT-INF/classes/'
            elif any(name.startswith('WEB-INF/classes/') for name in names):
                class_prefix = 'WEB-INF/classes/'
            else:
                class_prefix = ''

            majors = []
            for info in infos:
                name = info.filename.replace('\\', '/')
                if info.is_dir() or not name.endswith('.class'):
                    continue
                if class_prefix:
                    if not name.startswith(class_prefix):
                        continue
                elif (
                    name.startswith('META-INF/')
                    or name.startswith('BOOT-INF/lib/')
                    or name.startswith('WEB-INF/lib/')
                ):
                    continue
                try:
                    with archive.open(info) as class_file:
                        header = class_file.read(8)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue
                if len(header) != 8 or header[:4] != b'\xca\xfe\xba\xbe':
                    continue
                major = int.from_bytes(header[6:8], byteorder='big')
                if jdk_version_from_class_major(major):
                    majors.append(major)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        result['status'] = 'invalid_archive'
        return result

    if not majors:
        result['status'] = 'no_application_classes'
        return result
    distinct_majors = sorted(set(majors))
    result.update({
        'version': jdk_version_from_class_major(max(distinct_majors)),
        'class_count': len(majors),
        'class_major_min': min(distinct_majors),
        'class_major_max': max(distinct_majors),
        'class_versions': [
            jdk_version_from_class_major(item) for item in distinct_majors
        ],
        'status': 'detected',
    })
    return result


def _build_provenance_candidates(output_path=''):
    candidates = []
    report_dir = str(os.environ.get('UPGRADE_REPORT_DIR') or '').strip()
    if report_dir:
        candidates.append(
            Path(report_dir) / 'evidence' / 'dependencies' / 'build_provenance.json'
        )
    if output_path:
        output = Path(output_path).expanduser().resolve()
        if output.parent.name == 'context' and output.parent.parent.name == 'evidence':
            candidates.append(
                output.parent.parent / 'dependencies' / 'build_provenance.json'
            )
        candidates.append(output.parent / 'build_provenance.json')
    seen = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            yield candidate


def detect_artifact_jdk_evidence(output_path=''):
    """读取 Step1 产物账本，返回 base/current 的实际字节码证据。"""
    provenance_path = next(
        (item for item in _build_provenance_candidates(output_path) if item.is_file()),
        None,
    )
    if provenance_path is None:
        return {}
    try:
        payload = json.loads(provenance_path.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError):
        return {}

    evidence = {}
    for item in payload.get('sides') or []:
        side = str((item or {}).get('side') or '').strip()
        if side not in ('base', 'current'):
            continue
        raw_path = str((item or {}).get('artifact_path') or '').strip()
        if not raw_path:
            continue
        artifact_path = Path(raw_path).expanduser()
        if not artifact_path.is_absolute():
            artifact_path = provenance_path.parent / artifact_path
        detected = detect_jdk_from_artifact(artifact_path)
        detected['build_runtime_jdk_home'] = str((item or {}).get('jdk_home') or '')
        detected['build_tool'] = str((item or {}).get('build_tool') or '')
        detected['revision'] = str((item or {}).get('revision') or '')
        evidence[side] = detected
    return evidence


def select_jdk_evidence(build_versions, artifact_evidence, confirmed_versions=None):
    """
    汇总 JDK 证据。最终制品代表实际结果，优先于构建声明；冲突只记录诊断，
    不把已可由 class 文件回答的问题转成用户 checkpoint。
    """
    confirmed_versions = confirmed_versions or {}
    selected = {}
    for side in ('base', 'current'):
        build_version = normalize_jdk_version((build_versions or {}).get(side))
        artifact = dict((artifact_evidence or {}).get(side) or {})
        artifact_version = normalize_jdk_version(artifact.get('version'))
        confirmed = normalize_jdk_version(confirmed_versions.get(side))
        if confirmed:
            version = confirmed
            source = 'user_confirmed'
            confidence = 'confirmed'
        elif artifact_version:
            version = artifact_version
            source = 'final_artifact_bytecode'
            confidence = 'high'
        elif build_version:
            version = build_version
            source = 'build_model'
            confidence = 'medium'
        else:
            version = None
            source = 'not_found'
            confidence = 'none'
        selected[side] = {
            'version': version,
            'source': source,
            'confidence': confidence,
            'build_model_version': build_version,
            'artifact_bytecode_version': artifact_version,
            'evidence_conflict': bool(
                build_version and artifact_version and build_version != artifact_version
            ),
            'artifact': artifact,
        }
    return selected


def parse_maven_help_evaluate_jdk(output):
    """从 mvn help:evaluate 输出中提取 JDK 版本数字"""
    if not output:
        return None
    candidates = re.findall(r'(?<![\w.])(1\.\d+|\d+)(?=\s|$|%)', output)
    if not candidates:
        return None
    return normalize_jdk_version(candidates[-1])


def resolve_maven_jdk_from_effective_model(
    branch,
    work_dir,
    pom_relpath='pom.xml',
    *,
    strict_git=False,
):
    """
    当 pom.xml 没有显式声明 JDK 版本时，回退到临时 worktree + mvn help:evaluate，
    读取父 POM / pluginManagement 展开后的 maven.compiler.release/source/target。
    """
    git_root = get_git_root(work_dir, strict_git=strict_git) or work_dir
    pom_relpath = (pom_relpath or 'pom.xml').strip() or 'pom.xml'
    try:
        tmp = create_detached_worktree(
            branch,
            git_root,
            label="s2-jdk",
            runner=run_cmd,
            git_command=git_cmd(),
        )
    except RuntimeError as exc:
        if strict_git:
            raise RuntimeError(
                f"STEP2_GIT_WORKTREE_CREATE_FAILED:{branch}:{exc}"
            ) from exc
        print(f"  ⚠️ Step2 无法准备 JDK 探测工作区：{exc}", file=sys.stderr)
        return None

    try:
        root_dir = Path(tmp)
        pom_path = root_dir / pom_relpath
        eval_cwd = str(pom_path.parent if pom_path.exists() else root_dir)
        mvn = mvn_cmd(root_dir)
        for expr in (
            'maven.compiler.release',
            'maven.compiler.target',
            'maven.compiler.source',
            'java.version',
            'jdk.version',
            'kotlin.compiler.jvmTarget',
        ):
            stdout, stderr, rc = run_cmd(
                mvn + ['-q', 'help:evaluate', f'-Dexpression={expr}', '-DforceStdout'],
                cwd=eval_cwd,
                timeout=180,
            )
            if rc != 0:
                continue
            detected = parse_maven_help_evaluate_jdk(stdout)
            if detected:
                return detected
    finally:
        remove_detached_worktree(
            tmp,
            git_root,
            runner=run_cmd,
            git_command=git_cmd(),
        )
    return None


def detect_jdk_versions_from_manifests(
    base_branch,
    cur_branch,
    work_dir,
    build_tool,
    *,
    strict_git=False,
):
    """只读取两个 revision 的构建清单，不启动 Maven/Gradle。"""
    jdk_base, jdk_cur = None, None
    matched_candidate = 'pom.xml'
    if not is_git_repo(work_dir, strict_git=strict_git):
        return jdk_base, jdk_cur, matched_candidate

    if build_tool == 'maven':
        pom_candidates = build_manifest_candidates(
            work_dir, 'pom.xml', strict_git=strict_git,
        )
        base_pom = ''
        cur_pom = ''
        for candidate in pom_candidates:
            if not base_pom:
                base_pom = git_show_file(
                    base_branch, candidate, work_dir, strict_git=strict_git,
                )
            if not cur_pom:
                cur_pom = git_show_file(
                    cur_branch, candidate, work_dir, strict_git=strict_git,
                )
            if base_pom or cur_pom:
                matched_candidate = candidate
                break
        jdk_base = detect_jdk_from_pom(base_pom)
        jdk_cur  = detect_jdk_from_pom(cur_pom)
    else:
        # Gradle
        gradle_candidates = build_manifest_candidates(
            work_dir,
            'build.gradle',
            'build.gradle.kts',
            strict_git=strict_git,
        )
        for gradle_file in gradle_candidates:
            if not jdk_base:
                content = git_show_file(
                    base_branch, gradle_file, work_dir, strict_git=strict_git,
                )
                jdk_base = detect_jdk_from_gradle(content)
            if not jdk_cur:
                content = git_show_file(
                    cur_branch, gradle_file, work_dir, strict_git=strict_git,
                )
                jdk_cur = detect_jdk_from_gradle(content)

    return jdk_base, jdk_cur, matched_candidate


def detect_jdk_versions(
    base_branch,
    cur_branch,
    work_dir,
    build_tool,
    *,
    strict_git=False,
):
    """从两个 revision 推断 JDK；Maven 静态声明不足时再读取有效模型。"""
    # Without git-backed base/current revisions, using the same local manifest
    # for both sides would create a false "base=current" context.
    jdk_base, jdk_cur, matched_candidate = detect_jdk_versions_from_manifests(
        base_branch,
        cur_branch,
        work_dir,
        build_tool,
        strict_git=strict_git,
    )
    if build_tool == 'maven' and is_git_repo(
        work_dir, strict_git=strict_git,
    ):
        if not jdk_base:
            jdk_base = resolve_maven_jdk_from_effective_model(
                base_branch,
                work_dir,
                matched_candidate,
                strict_git=strict_git,
            )
        if not jdk_cur:
            jdk_cur = resolve_maven_jdk_from_effective_model(
                cur_branch,
                work_dir,
                matched_candidate,
                strict_git=strict_git,
            )
    return jdk_base, jdk_cur


def detect_build_tool(cur_branch, work_dir, *, strict_git=False):
    """通过 git 检测构建工具（只读）"""
    # 固定 commit 存在时不能让当前 checkout 覆盖它；分支模式仍优先尊重
    # work_dir 当前目录，以兼容 Git 仓库中的子模块目录。
    fixed_commit = bool(re.fullmatch(
        r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
        str(cur_branch or "").strip(),
    ))
    if not fixed_commit:
        base = Path(work_dir)
        if (base / 'pom.xml').exists():
            return 'maven'
        if (base / 'build.gradle').exists() or (base / 'build.gradle.kts').exists():
            return 'gradle'

    if is_git_repo(work_dir, strict_git=strict_git):
        for candidate in build_manifest_candidates(
            work_dir, 'pom.xml', strict_git=strict_git,
        ):
            stdout, show_stderr, rc = run_cmd(
                git_cmd() + ['show', f'{cur_branch}:{candidate}'],
                cwd=work_dir, timeout=10
            )
            if rc == 0:
                return 'maven'
            if strict_git and not _git_path_is_absent(show_stderr):
                raise RuntimeError(
                    "STEP2_GIT_SHOW_FAILED:"
                    f"{cur_branch}:{candidate}:"
                    f"{str(show_stderr or stdout or f'git exited with {rc}').strip()}"
                )

        stdout, tree_stderr, rc = run_cmd(
            git_cmd() + ['ls-tree', '-r', '--name-only', cur_branch],
            cwd=work_dir, timeout=10
        )
        if rc == 0:
            files = stdout.splitlines()
            candidates = build_manifest_candidates(
                work_dir,
                'build.gradle',
                'build.gradle.kts',
                strict_git=strict_git,
            )
            if any(f in candidates for f in files):
                return 'gradle'
        elif strict_git:
            raise RuntimeError(
                "STEP2_GIT_LS_TREE_FAILED:"
                f"{cur_branch}:{str(tree_stderr or stdout or f'git exited with {rc}').strip()}"
            )

    return 'unknown'


def detect_jvm_param_changes(
    base_branch,
    cur_branch,
    work_dir,
    *,
    strict_git=False,
):
    """从 git diff 提取 JVM 启动参数变更（只读）"""
    if not is_git_repo(work_dir, strict_git=strict_git):
        return []
    stdout, stderr, rc = run_cmd(
        git_cmd() + ['diff', f'{base_branch}..{cur_branch}',
                     '--', '*.sh', 'Dockerfile*', 'docker-compose*.yml', '.env'],
        cwd=work_dir, timeout=30
    )
    if rc != 0:
        if strict_git:
            raise RuntimeError(
                "STEP2_GIT_DIFF_FAILED:"
                f"{base_branch}..{cur_branch}:"
                f"{str(stderr or stdout or f'git exited with {rc}').strip()}"
            )
        return []
    if not stdout:
        return []

    # 提取 -XX: 参数
    params = set()
    for line in stdout.splitlines():
        if line.startswith(('+', '-')) and not line.startswith(('+++', '---')):
            for m in re.finditer(r'-XX:[^\s\'"]+', line):
                params.add(m.group(0))
    return sorted(params)


# ══════════════════════════════════════════════════════════════════
# 主函数
# ══════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description='Step 2：从依赖树推断项目上下文（Windows/Linux/macOS 兼容）'
    )
    ap.add_argument('--dep-changes',     required=True,
                    help='s1_dep_changes.csv 路径')
    ap.add_argument('--base-branch', '--base',
                    dest='base_branch',
                    help='Git 基准分支名（也可用 --base）')
    ap.add_argument('--current-branch', '--current',
                    dest='current_branch',
                    help='Git 当前分支名（也可用 --current）')
    ap.add_argument('--base-revision', default='',
                    help='已固定的 Git 基准 commit；提供时优先于可变分支名执行只读查询')
    ap.add_argument('--current-revision', default='',
                    help='已固定的 Git 当前 commit；提供时优先于可变分支名执行只读查询')
    ap.add_argument('--work-dir',        default='.',
                    help='项目根目录（git 命令的工作目录）')
    ap.add_argument('--source-dirs', nargs='+', default=None,
                    help='显式指定业务源码目录列表；提供后会直接写入 s2_context.json')
    ap.add_argument('--output',          required=True,
                    help='输出 JSON 文件路径（s2_context.json）')
    ap.add_argument('--output-dep-graph', default='',
                    help='可选：同步输出 s2_dep_graph.json，避免重复执行第二个 Step2 子脚本')
    args = ap.parse_args()
    orchestrated_input = load_orchestrated_step2_input(args.output)
    if orchestrated_input:
        args.base_branch = args.base_branch or orchestrated_input.get("base_branch", "")
        args.current_branch = args.current_branch or orchestrated_input.get("current_branch", "")
        args.base_revision = args.base_revision or orchestrated_input.get("base_resolved_commit", "")
        args.current_revision = args.current_revision or orchestrated_input.get("current_resolved_commit", "")
        if not args.source_dirs:
            args.source_dirs = list(orchestrated_input.get("source_dirs") or [])
    if not args.base_branch or not args.current_branch:
        ap.error('the following arguments are required: --base-branch --current-branch')
    base_revision = str(args.base_revision or args.base_branch).strip()
    current_revision = str(args.current_revision or args.current_branch).strip()
    strict_git_snapshot = bool(orchestrated_input)
    git_work_dir = (
        str(_pinned_source_repository(orchestrated_input, args.work_dir))
        if strict_git_snapshot
        else args.work_dir
    )
    if strict_git_snapshot:
        base_revision = require_pinned_git_commit(
            base_revision, git_work_dir, side='base',
        )
        current_revision = require_pinned_git_commit(
            current_revision, git_work_dir, side='current',
        )

    print(f"\nStep 2：推断项目上下文", file=sys.stderr)
    print(f"  基准分支：{args.base_branch}", file=sys.stderr)
    print(f"  当前分支：{args.current_branch}", file=sys.stderr)

    # ── 1. 读取依赖变更 ─────────────────────────────────────────
    deps = load_dep_changes(args.dep_changes)

    # ── 2. 构建工具与业务源码范围 ────────────────────────────────
    # 新编排状态携带 Step1 从 remote current SHA 生成的逻辑快照。
    # 临时 worktree 仅用于验证/发现；context 中继续保存稳定的仓库语义
    # 路径，绝不泄漏生命周期已经结束的临时绝对路径。
    pinned_source_snapshot = {}
    with materialize_pinned_step2_source_workspace(
        orchestrated_input,
        current_revision,
        git_work_dir,
    ) as pinned_workspace:
        if pinned_workspace is not None:
            pinned_source_snapshot = dict(pinned_workspace['snapshot'])
            build_tool = detect_build_tool(
                current_revision,
                pinned_workspace['project_root'],
                strict_git=True,
            )
            declared_tool = str(
                pinned_source_snapshot.get('build_tool') or ''
            ).strip().lower()
            if declared_tool and build_tool != declared_tool:
                raise RuntimeError(
                    'STEP2_PINNED_BUILD_TOOL_MISMATCH:'
                    f"declared={declared_tool}:observed={build_tool}:"
                    f"commit={current_revision}"
                )
            source_dirs = list(pinned_workspace['stable_source_dirs'])
            if not source_dirs:
                detected_in_snapshot = auto_detect_source_dirs(
                    pinned_workspace['project_root'], build_tool,
                )
                for detected in detected_in_snapshot:
                    relative = Path(detected).resolve().relative_to(
                        pinned_workspace['project_root']
                    )
                    source_dirs.append(str(
                        (_pinned_source_repository(
                            orchestrated_input, git_work_dir,
                        ) / relative).resolve()
                    ))
            print(
                "  业务源码目录（current 固定 commit）："
                f"{source_dirs}",
                file=sys.stderr,
            )
        else:
            build_tool = (
                detect_build_tool(
                    current_revision,
                    git_work_dir,
                    strict_git=True,
                )
                if strict_git_snapshot
                else detect_build_tool(current_revision, git_work_dir)
            )
            source_dirs = [
                str(item).strip()
                for item in (args.source_dirs or [])
                if str(item).strip()
            ]
            if source_dirs:
                print(f"  业务源码目录（显式指定）：{source_dirs}", file=sys.stderr)
            else:
                source_dirs = auto_detect_source_dirs(git_work_dir, build_tool)
            if source_dirs and not args.source_dirs:
                print(f"  业务源码目录：{source_dirs}", file=sys.stderr)
        if not source_dirs:
            print(f"  业务源码目录：（未检测到，Step5 需手动指定）", file=sys.stderr)
    print(f"  构建工具：{build_tool}", file=sys.stderr)

    # ── 3. Spring Boot 版本（从依赖树，最可靠）─────────────────
    sb_base, sb_cur, sb_source = detect_spring_boot_version(deps)
    if orchestrated_input.get('springboot_base'):
        sb_base = str(orchestrated_input.get('springboot_base')).strip()
        sb_source = 'user_confirmed'
    if orchestrated_input.get('springboot_current'):
        sb_cur = str(orchestrated_input.get('springboot_current')).strip()
        sb_source = 'user_confirmed'
    print(f"  Spring Boot：{sb_base or '?'} → {sb_cur or '?'} (来源: {sb_source})",
          file=sys.stderr)

    # ── 4. Spring Cloud ──────────────────────────────────────────
    has_sc, sc_ver = detect_spring_cloud(deps)
    if has_sc:
        print(f"  Spring Cloud：{sc_ver or '已检测'}", file=sys.stderr)

    # ── 5. JDK 版本（最终产物字节码优先，构建模型补充）──────────
    artifact_jdk_evidence = detect_artifact_jdk_evidence(args.output)
    artifact_pair_complete = all(
        normalize_jdk_version(
            (artifact_jdk_evidence.get(side) or {}).get('version')
        )
        for side in ('base', 'current')
    )
    confirmed_jdk_pair_complete = all(
        normalize_jdk_version(orchestrated_input.get(f'jdk_{side}'))
        for side in ('base', 'current')
    )
    if artifact_pair_complete or confirmed_jdk_pair_complete:
        # Step1 已给出 base/current 的实际业务字节码，不再为补一个声明值而
        # 启动 Maven/Gradle；同样，Step0 已真实执行并绑定用户确认的两侧 JDK
        # 时也不应在 Step2 再做后置环境探测。只读构建清单仅用于一致性诊断。
        build_jdk_base, build_jdk_cur, _ = detect_jdk_versions_from_manifests(
            base_revision, current_revision,
            git_work_dir, build_tool,
            strict_git=strict_git_snapshot,
        )
    else:
        build_jdk_base, build_jdk_cur = detect_jdk_versions(
            base_revision,
            current_revision,
            git_work_dir,
            build_tool,
            strict_git=strict_git_snapshot,
        )
    selected_jdk = select_jdk_evidence(
        {'base': build_jdk_base, 'current': build_jdk_cur},
        artifact_jdk_evidence,
        {
            'base': orchestrated_input.get('jdk_base'),
            'current': orchestrated_input.get('jdk_current'),
        },
    )
    jdk_base = selected_jdk['base']['version']
    jdk_cur = selected_jdk['current']['version']
    jdk_sources = {
        selected_jdk['base']['source'],
        selected_jdk['current']['source'],
    }
    jdk_source = (
        next(iter(jdk_sources))
        if len(jdk_sources) == 1
        else 'mixed'
    )
    print(f"  JDK：{jdk_base or '❓未知'} → {jdk_cur or '❓未知'}", file=sys.stderr)
    for side, label in (('base', '基准'), ('current', '当前')):
        item = selected_jdk[side]
        if item.get('evidence_conflict'):
            print(
                f"  ⚠️ {label}侧 JDK 声明为 {item.get('build_model_version')}，"
                f"最终产物字节码为 {item.get('artifact_bytecode_version')}；"
                "采用最终产物实际值",
                file=sys.stderr,
            )

    # ── 6. 升级标志位 ────────────────────────────────────────────
    sb_upgraded, sb_major_upgrade, jdk_upgraded = compute_version_flags(
        sb_base, sb_cur, jdk_base, jdk_cur
    )

    # ── 7. 技术栈 ────────────────────────────────────────────────
    tech_flags = detect_tech_flags(deps)
    active_flags = [k for k, v in tech_flags.items() if v]
    if active_flags:
        print(f"  技术栈：{', '.join(active_flags)}", file=sys.stderr)

    # ── 8. 升级依赖清单 ──────────────────────────────────────────
    changed_dependencies = collect_changed_dependencies(deps)
    if changed_dependencies:
        print(f"  升级依赖：{len(changed_dependencies)} 个", file=sys.stderr)

    # ── 9. JVM 参数变更 ──────────────────────────────────────────
    jvm_changes = (
        detect_jvm_param_changes(
            base_revision,
            current_revision,
            git_work_dir,
            strict_git=True,
        )
        if strict_git_snapshot
        else detect_jvm_param_changes(
            base_revision, current_revision, git_work_dir
        )
    )

    # ── 10. 统计变更依赖 ─────────────────────────────────────────
    changed_count = sum(
        1 for row in deps.values()
        if row.get('change_type', '') not in ('未变', '')
    )

    # ── 构建 context.json ────────────────────────────────────────
    ctx = {
        'meta': {
            'what': '项目升级上下文（由真实依赖树、构建模型与最终产物字节码推断）',
            'why': '决定 Step3 扫描项与 Step4/5 的分析策略，解释“为什么会生成/跳过某些产物”',
            'how_to_read': [
                '优先确认 jdk_base/jdk_current 与 springboot_base/springboot_current 是否符合预期',
                'tech_flags 用于解释特定扫描与风险（如 lombok/bytebuddy/mybatis 等）',
                'changed_dependencies 是后续补依赖源码、做源码 diff、做跨依赖调用链的重点依赖集合',
            ],
        },
        'generated_at':    datetime.now().isoformat(),
        'base_branch':     args.base_branch,
        'current_branch':  args.current_branch,
        'base_revision':   base_revision,
        'current_revision': current_revision,
        'revision_source': 'resolved_commit' if args.base_revision and args.current_revision else 'branch_name',
        'build_tool':      build_tool,

        # JDK
        'jdk_base':        jdk_base,
        'jdk_current':     jdk_cur,
        'jdk_upgraded':    jdk_upgraded,
        'jdk_source':      jdk_source,
        'jdk_evidence':    selected_jdk,

        # Spring Boot
        'springboot_base':            sb_base,
        'springboot_current':         sb_cur,
        'springboot_upgraded':        sb_upgraded,
        'springboot_major_upgrade':   sb_major_upgrade,
        'springboot_version_source':  sb_source,

        # Spring Cloud
        'spring_cloud':         has_sc,
        'spring_cloud_version': sc_ver,

        # 升级依赖
        'changed_dependencies':      changed_dependencies,
        'changed_dependency_coords': [item['coord'] for item in changed_dependencies],
        'no_changed_dependencies':   (not changed_dependencies),

        # 技术栈
        'tech_flags': tech_flags,

        # JVM 参数变更
        'jvm_param_changes': jvm_changes,

        # 依赖统计
        'total_deps':   len(deps),
        'changed_deps': changed_count,

        # 业务源码目录（供 Step5 跨依赖检测使用）
        'source_dirs': source_dirs,
        'pinned_source_snapshot': pinned_source_snapshot,
    }

    # ── 写出 ─────────────────────────────────────────────────────
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(ctx, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 输出：{args.output}", file=sys.stderr)

    if args.output_dep_graph:
        dep_graph = build_dep_graph(deps)
        output_dep_graph = Path(args.output_dep_graph)
        output_dep_graph.parent.mkdir(parents=True, exist_ok=True)
        with open(output_dep_graph, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(dep_graph, f, ensure_ascii=False, indent=2)
        print(f"✅ 输出：{args.output_dep_graph}", file=sys.stderr)

    # ── 提示需要补充的字段 ───────────────────────────────────────
    needs_confirm = []
    if not jdk_base:
        needs_confirm.append(
            f"jdk_base（基准分支 JDK 版本）：未能自动推断\n"
            f"    请手动在 {args.output} 中添加：\"jdk_base\": \"8\""
        )
    if not jdk_cur:
        needs_confirm.append(
            f"jdk_current（目标 JDK 版本）：未能自动推断\n"
            f"    请手动在 {args.output} 中添加：\"jdk_current\": \"21\""
        )
    if sb_source == 'not_found':
        needs_confirm.append(
            f"springboot_current（Spring Boot 版本）：未在依赖树中找到\n"
            f"    请手动在 {args.output} 中添加：\"springboot_current\": \"3.2.5\""
        )
    if needs_confirm:
        print(f"\n⚠️  以下信息无法自动推断，需要人工补充：", file=sys.stderr)
        for item in needs_confirm:
            print(f"\n  • {item}", file=sys.stderr)
        print(f"\n补充完成后运行门控检查：", file=sys.stderr)
        print(f"  python scripts/gate.py --step context --report-dir .upgrade-report/",
              file=sys.stderr)
    else:
        print(f"\n运行门控检查：", file=sys.stderr)
        print(f"  python scripts/gate.py --step context --report-dir .upgrade-report/",
              file=sys.stderr)


if __name__ == '__main__':
    main()
