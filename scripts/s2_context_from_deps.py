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

import argparse, csv, json, os, re, sys, tempfile
from collections import defaultdict
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from compat import run_cmd, open_text, git_cmd, mvn_cmd
from csv_io import open_csv_read


MAIN_STATE_FILE_NAME = "main_state.json"


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

def git_show_file(branch, file_path, work_dir='.'):
    """git show branch:file，返回文件内容字符串，失败返回空字符串"""
    stdout, _, rc = run_cmd(
        git_cmd() + ['show', f'{branch}:{file_path}'],
        cwd=work_dir, timeout=30
    )
    return stdout if rc == 0 else ''


def is_git_repo(work_dir='.'):
    """检测当前目录是否为 Git 仓库"""
    _, _, rc = run_cmd(
        git_cmd() + ['rev-parse', '--is-inside-work-tree'],
        cwd=work_dir, timeout=10
    )
    return rc == 0


def get_git_root(work_dir='.'):
    """返回 Git 仓库根目录，失败返回空字符串"""
    stdout, _, rc = run_cmd(
        git_cmd() + ['rev-parse', '--show-toplevel'],
        cwd=work_dir, timeout=10
    )
    return stdout.strip() if rc == 0 else ''


def get_repo_relative_prefix(work_dir='.'):
    """
    返回 work_dir 相对于 Git 仓库根目录的相对路径。
    例：/repo/module-a -> module-a
    """
    git_root = get_git_root(work_dir)
    if not git_root:
        return ''
    try:
        rel = os.path.relpath(
            os.path.realpath(work_dir),
            os.path.realpath(git_root)
        )
    except ValueError:
        return ''
    return '' if rel == '.' else rel.replace('\\', '/')


def build_manifest_candidates(work_dir='.', *filenames):
    """按 work_dir 优先级构造构建文件候选路径"""
    prefix = get_repo_relative_prefix(work_dir)
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
    ver = str(ver).strip()
    if not ver or ver.lower() in ('null', 'none', 'unknown'):
        return None
    if ver.startswith('1.'):
        ver = ver[2:]
    return ver


def detect_jdk_from_pom(pom_content):
    """从 pom.xml 内容提取 JDK 目标版本"""
    if not pom_content:
        return None

    # 按优先级尝试多种配置方式
    patterns = [
        r'<maven\.compiler\.release>(\d+)</maven\.compiler\.release>',
        r'<maven\.compiler\.source>(\d+[\.\d]*)</maven\.compiler\.source>',
        r'<java\.version>(\d+[\.\d]*)</java\.version>',
        r'<jdk\.version>(\d+[\.\d]*)</jdk\.version>',
        # maven-compiler-plugin 的 <release> 配置
        r'maven-compiler-plugin.*?<release>(\d+)</release>',
        # Kotlin/其他插件的 jvmTarget
        r'<jvmTarget>(\d+[\.\d]*)</jvmTarget>',
    ]
    for pattern in patterns:
        m = re.search(pattern, pom_content, re.DOTALL)
        if m:
            return normalize_jdk_version(m.group(1))
    return None


def detect_jdk_from_gradle(gradle_content):
    """从 build.gradle 内容提取 JDK 目标版本"""
    if not gradle_content:
        return None

    patterns = [
        r'sourceCompatibility\s*=\s*JavaVersion\.VERSION_(\d+)',
        r'sourceCompatibility\s*=\s*[\'"](\d+[\.\d]*)[\'"]',
        r'javaVersion\s*=\s*[\'"](\d+[\.\d]*)[\'"]',
        r'targetCompatibility\s*=\s*JavaVersion\.VERSION_(\d+)',
        r'java\s*\{[^}]*release\s*=\s*(\d+)',  # java { release = 17 }
    ]
    for pattern in patterns:
        m = re.search(pattern, gradle_content, re.DOTALL)
        if m:
            return normalize_jdk_version(m.group(1).replace('_', '.'))
    return None


def parse_maven_help_evaluate_jdk(output):
    """从 mvn help:evaluate 输出中提取 JDK 版本数字"""
    if not output:
        return None
    candidates = re.findall(r'(?<![\w.])(1\.\d+|\d+)(?=\s|$|%)', output)
    if not candidates:
        return None
    return normalize_jdk_version(candidates[-1])


def resolve_maven_jdk_from_effective_model(branch, work_dir, pom_relpath='pom.xml'):
    """
    当 pom.xml 没有显式声明 JDK 版本时，回退到临时 worktree + mvn help:evaluate，
    读取父 POM / pluginManagement 展开后的 maven.compiler.release/source/target。
    """
    git_root = get_git_root(work_dir) or work_dir
    pom_relpath = (pom_relpath or 'pom.xml').strip() or 'pom.xml'
    safe_prefix = re.sub(r'[^A-Za-z0-9._-]+', '-', str(branch or 'branch')).strip('-') or 'branch'

    with tempfile.TemporaryDirectory(prefix=f'jua-step2-jdk-{safe_prefix}-') as tmp:
        stdout, stderr, rc = run_cmd(
            git_cmd() + ['worktree', 'add', '--detach', tmp, branch],
            cwd=git_root,
            timeout=180,
        )
        if rc != 0:
            return None

        try:
            root_dir = Path(tmp)
            pom_path = root_dir / pom_relpath
            eval_cwd = str(pom_path.parent if pom_path.exists() else root_dir)
            wrapper = root_dir / 'mvnw'
            mvn = [str(wrapper)] if wrapper.exists() else mvn_cmd()
            for expr in ('maven.compiler.release', 'maven.compiler.target', 'maven.compiler.source'):
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
            run_cmd(
                git_cmd() + ['worktree', 'remove', '--force', tmp],
                cwd=git_root,
                timeout=60,
            )
    return None


def detect_jdk_versions(base_branch, cur_branch, work_dir, build_tool):
    """从两个分支读取 JDK 版本（只读 git，不切换分支）"""
    jdk_base, jdk_cur = None, None
    has_git = is_git_repo(work_dir)

    # Without git-backed base/current revisions, using the same local manifest
    # for both sides would create a false "base=current" context.
    if not has_git:
        return None, None

    if build_tool == 'maven':
        pom_candidates = build_manifest_candidates(work_dir, 'pom.xml')
        base_pom = ''
        cur_pom = ''
        matched_candidate = 'pom.xml'
        for candidate in pom_candidates:
            if not base_pom:
                base_pom = git_show_file(base_branch, candidate, work_dir)
            if not cur_pom:
                cur_pom = git_show_file(cur_branch, candidate, work_dir)
            if base_pom or cur_pom:
                matched_candidate = candidate
                break
        jdk_base = detect_jdk_from_pom(base_pom)
        jdk_cur  = detect_jdk_from_pom(cur_pom)
        if not jdk_base:
            jdk_base = resolve_maven_jdk_from_effective_model(
                base_branch, work_dir, matched_candidate
            )
        if not jdk_cur:
            jdk_cur = resolve_maven_jdk_from_effective_model(
                cur_branch, work_dir, matched_candidate
            )
    else:
        # Gradle
        gradle_candidates = build_manifest_candidates(work_dir, 'build.gradle', 'build.gradle.kts')
        for gradle_file in gradle_candidates:
            if not jdk_base:
                content = git_show_file(base_branch, gradle_file, work_dir)
                jdk_base = detect_jdk_from_gradle(content)
            if not jdk_cur:
                content = git_show_file(cur_branch, gradle_file, work_dir)
                jdk_cur = detect_jdk_from_gradle(content)

    return jdk_base, jdk_cur


def detect_build_tool(cur_branch, work_dir):
    """通过 git 检测构建工具（只读）"""
    # 固定 commit 存在时不能让当前 checkout 覆盖它；分支模式仍优先尊重
    # work_dir 当前目录，以兼容 Git 仓库中的子模块目录。
    fixed_commit = bool(re.fullmatch(r"[0-9a-fA-F]{40}", str(cur_branch or "").strip()))
    if not fixed_commit:
        base = Path(work_dir)
        if (base / 'pom.xml').exists():
            return 'maven'
        if (base / 'build.gradle').exists() or (base / 'build.gradle.kts').exists():
            return 'gradle'

    if is_git_repo(work_dir):
        for candidate in build_manifest_candidates(work_dir, 'pom.xml'):
            stdout, _, rc = run_cmd(
                git_cmd() + ['show', f'{cur_branch}:{candidate}'],
                cwd=work_dir, timeout=10
            )
            if rc == 0:
                return 'maven'

        stdout, _, rc = run_cmd(
            git_cmd() + ['ls-tree', '-r', '--name-only', cur_branch],
            cwd=work_dir, timeout=10
        )
        if rc == 0:
            files = stdout.splitlines()
            candidates = build_manifest_candidates(work_dir, 'build.gradle', 'build.gradle.kts')
            if any(f in candidates for f in files):
                return 'gradle'

    return 'unknown'


def detect_jvm_param_changes(base_branch, cur_branch, work_dir):
    """从 git diff 提取 JVM 启动参数变更（只读）"""
    if not is_git_repo(work_dir):
        return []
    stdout, _, rc = run_cmd(
        git_cmd() + ['diff', f'{base_branch}..{cur_branch}',
                     '--', '*.sh', 'Dockerfile*', 'docker-compose*.yml', '.env'],
        cwd=work_dir, timeout=30
    )
    if rc != 0 or not stdout:
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

    print(f"\nStep 2：推断项目上下文", file=sys.stderr)
    print(f"  基准分支：{args.base_branch}", file=sys.stderr)
    print(f"  当前分支：{args.current_branch}", file=sys.stderr)

    # ── 1. 读取依赖变更 ─────────────────────────────────────────
    deps = load_dep_changes(args.dep_changes)

    # ── 2. 构建工具识别 ─────────────────────────────────────────
    build_tool = detect_build_tool(current_revision, args.work_dir)
    print(f"  构建工具：{build_tool}", file=sys.stderr)

    # ── 2.5. 业务源码目录自动检测 ────────────────────────────────
    # 自动检测常见的业务源码目录，供 Step5 跨依赖检测使用
    source_dirs = [str(item).strip() for item in (args.source_dirs or []) if str(item).strip()]
    if source_dirs:
        print(f"  业务源码目录（显式指定）：{source_dirs}", file=sys.stderr)
    else:
        source_dirs = auto_detect_source_dirs(args.work_dir, build_tool)
    if source_dirs:
        if not args.source_dirs:
            print(f"  业务源码目录：{source_dirs}", file=sys.stderr)
    else:
        print(f"  业务源码目录：（未检测到，Step5 需手动指定）", file=sys.stderr)

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

    # ── 5. JDK 版本（从 git 只读 pom.xml）──────────────────────
    jdk_base, jdk_cur = detect_jdk_versions(
        base_revision, current_revision,
        args.work_dir, build_tool
    )
    if orchestrated_input.get('jdk_base'):
        jdk_base = str(orchestrated_input.get('jdk_base')).strip()
    if orchestrated_input.get('jdk_current'):
        jdk_cur = str(orchestrated_input.get('jdk_current')).strip()
    print(f"  JDK：{jdk_base or '❓未知'} → {jdk_cur or '❓未知'}", file=sys.stderr)

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
    jvm_changes = detect_jvm_param_changes(
        base_revision, current_revision, args.work_dir
    )

    # ── 10. 统计变更依赖 ─────────────────────────────────────────
    changed_count = sum(
        1 for row in deps.values()
        if row.get('change_type', '') not in ('未变', '')
    )

    # ── 构建 context.json ────────────────────────────────────────
    ctx = {
        'meta': {
            'what': '项目升级上下文（由真实依赖树 + 少量 git/pom 只读信息推断）',
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
        'jdk_source':      (
            'user_confirmed'
            if orchestrated_input.get('jdk_base') or orchestrated_input.get('jdk_current')
            else ('pom_xml' if (jdk_base or jdk_cur) else 'not_found')
        ),

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
