#!/usr/bin/env python3
"""
auto_discover_bridge_sources.py

自动发现依赖源码映射，解决用户重复配置问题。

主路径：
  dependency_source_dirs = ["/path/to/dependency-repo-or-module"]

系统自动：
  1. 扫描单模块或多模块源码目录
  2. 推断每个模块的 groupId:artifactId
  3. 为 Step4 派生依赖仓库映射，为 Step5 派生依赖源码映射
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

from compat import (
    _artifact_id_from_gradle_build_file,
    _extract_gradle_group_from_text,
    _iter_gradle_build_files,
    _is_embedded_resource_fixture_dir,
    _parse_gradle_coord,
    _parse_pom_coord,
    resolve_repo_input_path,
)


MAIN_STATE_FILE_NAME = "main_state.json"
STEP_IDS = ("step1", "step2", "step3", "step4", "step5", "step6")


def main_state_path(report_dir, explicit_path=None):
    return Path(explicit_path or (Path(report_dir) / ".runtime" / "state" / MAIN_STATE_FILE_NAME)).resolve()


def load_main_state_payload(report_dir, explicit_path=None):
    path = main_state_path(report_dir, explicit_path=explicit_path)
    if not path.exists():
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        payload = json.load(f)
    return payload if isinstance(payload, dict) else {}


def save_main_state_payload(report_dir, payload, explicit_path=None):
    path = main_state_path(report_dir, explicit_path=explicit_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _candidate_step_inputs(main_state):
    state = dict((main_state or {}).get('state') or {})
    current_step = str(state.get('current_step') or '').strip()
    ordered_steps = []
    if current_step in STEP_IDS:
        ordered_steps.append(current_step)
    ordered_steps.extend([step_id for step_id in ("step5", "step4", "step3", "step2", "step1") if step_id not in ordered_steps])
    for step_id in ordered_steps:
        step_data = dict((main_state or {}).get(step_id) or {})
        for key in ("input", "output"):
            payload = step_data.get(key)
            if isinstance(payload, dict):
                yield step_id, payload


def infer_java_source_dir(root_path):
    """
    从依赖包根目录推断 Java/Kotlin 源码目录（增强版）

    策略：
      1. Maven/Gradle 标准结构: src/main/java, src/main/kotlin
      2. 多模块项目: 递归查找所有模块的源码目录
      3. 非标准结构: 找package声明最多的目录
      4. 跳过无关目录: target, build

    改进：
      - 支持多模块项目（yield多个源码目录）
      - 使用package声明密度而非文件数量判断
      - 验证目录确实包含有效的Java包结构

    Args:
        root_path: 依赖包根目录（包含pom.xml/build.gradle的目录）

    Yields:
        源码目录路径（如 /path/to/lib/src/main/java）
    """
    if not os.path.isdir(root_path):
        return

    seen = set()
    for _coord, source_dir in discover_bridge_source_mappings("", root_path):
        if source_dir in seen:
            continue
        seen.add(source_dir)
        yield source_dir


def _has_child_module_manifests(root_path, max_depth=4):
    skip_dirs = {'.git', 'target', 'build', '.gradle', 'out', 'bin', '.idea', '.upgrade-report'}
    base = Path(root_path).resolve()
    if not base.exists() or not base.is_dir():
        return False
    for current_root, dirs, files in os.walk(str(base)):
        current = Path(current_root).resolve()
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


def _discover_module_source_dirs(module_root, allow_deep_fallback=True):
    standard_candidates = [
        'src/main/java',
        'src/main/kotlin',
        'src/java',
        'java/src',
        'src',
    ]
    source_dirs = []
    for candidate in standard_candidates:
        path = os.path.join(module_root, candidate)
        if os.path.isdir(path) and has_valid_package_structure(path):
            source_dirs.append(os.path.abspath(path))
    if source_dirs:
        return list(dict.fromkeys(source_dirs))
    if not allow_deep_fallback:
        return []
    best_dir = find_directory_with_most_packages(module_root)
    if best_dir:
        return [os.path.abspath(best_dir)]
    return []


def _looks_like_source_module(module_dir):
    base = Path(module_dir).resolve()
    source_markers = (
        'src/main/java',
        'src/main/kotlin',
        'src/java',
        'java/src',
    )
    return any((base / marker).is_dir() for marker in source_markers)


def _extract_gradle_group_from_file(file_path):
    try:
        content = Path(file_path).read_text(encoding='utf-8', errors='replace')
    except Exception:
        return ''
    return _extract_gradle_group_from_text(content)


def _infer_gradle_group_from_ancestors(module_root, repo_root):
    current = Path(module_root).resolve()
    repo_root = Path(repo_root).resolve()
    for candidate in [current, *current.parents]:
        if candidate == repo_root.parent:
            break
        for settings_name in ('gradle.properties', 'build.gradle', 'build.gradle.kts'):
            path = candidate / settings_name
            if not path.exists():
                continue
            group_id = _extract_gradle_group_from_file(path)
            if group_id:
                return group_id
        for build_path in _iter_gradle_build_files(candidate):
            group_id = _extract_gradle_group_from_file(build_path)
            if group_id:
                return group_id
        if candidate == repo_root:
            break
    return ''


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


def _iter_repo_modules(root_path, max_manifests=120):
    skip_dirs = {'.git', 'target', 'build', '.gradle', 'out', 'bin', '.idea', '.upgrade-report'}
    normalized_root = resolve_repo_input_path(root_path)
    normalized_root_path = Path(normalized_root).resolve()
    skip_probe_root_as_module = (
        _has_child_module_manifests(normalized_root_path)
        and not _looks_like_source_module(normalized_root_path)
    )
    count = 0
    for root, dirs, files in os.walk(normalized_root):
        current_root = Path(root).resolve()
        if _is_embedded_resource_fixture_dir(current_root, normalized_root_path):
            dirs[:] = []
            continue
        dirs[:] = [
            d for d in dirs
            if d not in skip_dirs
            and not _is_embedded_resource_fixture_dir(current_root / d, normalized_root_path)
        ]
        dirs.sort()
        if skip_probe_root_as_module and current_root == normalized_root_path:
            files = [name for name in files if name not in ('pom.xml', 'build.gradle', 'build.gradle.kts')]
        coord = None
        if 'pom.xml' in files:
            coord = _parse_pom_coord(os.path.join(root, 'pom.xml'))
        if not coord:
            for build_path in _iter_gradle_build_files(current_root):
                if build_path.name in files:
                    coord = _parse_gradle_coord_with_repo_context(
                        str(build_path),
                        normalized_root,
                    )
                    if coord:
                        break
        if not coord:
            continue
        yield coord, os.path.abspath(root)
        count += 1
        if count >= max_manifests:
            break


def _coord_matches_hint(coord, coord_hint):
    coord_hint = (coord_hint or '').strip()
    coord = (coord or '').strip()
    if not coord_hint:
        return True
    if ':' in coord_hint:
        return coord == coord_hint
    return coord.startswith(coord_hint + ':')


def discover_bridge_source_mappings(coord_hint, root_path):
    """
    从仓库目录发现 dependency_source_mappings 映射。

    返回:
      [(coord, source_dir), ...]
    """
    root_path = resolve_repo_input_path(root_path)
    mappings = []
    seen_pairs = set()

    for coord, module_root in _iter_repo_modules(root_path):
        if not _coord_matches_hint(coord, coord_hint):
            continue
        allow_deep_fallback = not _has_child_module_manifests(module_root)
        for source_dir in _discover_module_source_dirs(module_root, allow_deep_fallback=allow_deep_fallback):
            pair = (coord, source_dir)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            mappings.append(pair)

    if mappings:
        return mappings

    if coord_hint and ':' in coord_hint:
        for source_dir in _discover_module_source_dirs(root_path):
            pair = (coord_hint, source_dir)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            mappings.append(pair)
    return mappings


def _dedupe_preserve_order(items):
    ordered = []
    seen = set()
    for item in items or []:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def load_source_mapping_inputs(report_dir, main_state_file=None):
    """
    统一读取源码映射相关输入。

    返回:
      {
        'dependency_source_dirs': [...],
      }
    """
    dependency_source_dirs = []

    def extend_dirs(values):
        for item in values or []:
            value = str(item or '').strip()
            if not value:
                continue
            if '=' in value:
                _coord, repo_path = value.split('=', 1)
                value = repo_path.strip()
            dependency_source_dirs.append(value)

    main_state = load_main_state_payload(report_dir, explicit_path=main_state_file)
    for _step_id, payload in _candidate_step_inputs(main_state):
        if not dependency_source_dirs:
            extend_dirs(payload.get('dependency_source_dirs', []))
        if not dependency_source_dirs:
            # 对 legacy repo mappings 做兜底：依旧从主状态中恢复仓库根目录。
            extend_dirs(payload.get('dependency_repo_mappings', []))

    normalized_dependency_dirs = []
    for item in dependency_source_dirs:
        value = str(item or '').strip()
        if value:
            normalized_dependency_dirs.append(resolve_repo_input_path(value))

    return {
        'dependency_source_dirs': _dedupe_preserve_order(normalized_dependency_dirs),
    }


def find_maven_modules(root_path):
    """
    从pom.xml提取子模块列表

    返回：
      list: 子模块相对路径列表，如 ['module-a', 'module-b']
    """
    pom_path = os.path.join(root_path, 'pom.xml')
    if not os.path.exists(pom_path):
        return []

    try:
        with open(pom_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        # 提取 <modules><module>xxx</module></modules>
        modules = []
        in_modules = False
        for line in content.splitlines():
            if '<modules>' in line:
                in_modules = True
            elif '</modules>' in line:
                in_modules = False
            elif in_modules:
                match = re.search(r'<module>([^<]+)</module>', line)
                if match:
                    module = match.group(1).strip()
                    if module and not module.startswith('${'):
                        modules.append(module)

        return modules

    except Exception:
        return []


def has_valid_package_structure(directory):
    """
    验证目录是否包含有效的Java包结构

    检查:
      1. 至少有一个.java/.kt文件
      2. 文件中至少有一个package声明
      3. package声明符合Java命名规范（小写+点分隔）

    返回:
      bool: True表示有效的包结构
    """
    package_count = 0
    file_count = 0

    for root, dirs, files in os.walk(directory):
        for fname in files:
            if not (fname.endswith('.java') or fname.endswith('.kt')):
                continue

            file_count += 1
            file_path = os.path.join(root, fname)

            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    # 只读前30行（package通常在开头）
                    for line_num, line in enumerate(f):
                        if line_num > 30:
                            break

                        # 匹配package声明
                        if re.match(r'^\s*package\s+[a-z][a-z0-9_.]*\s*;?', line):
                            package_count += 1
                            break

            except Exception:
                continue

            # 优化：找到10个有效文件就足够判断
            if package_count >= 10:
                return True

    normalized_dir = str(directory or '').replace('\\', '/').rstrip('/')
    standard_source_suffixes = (
        '/src/main/java',
        '/src/main/kotlin',
        '/src/java',
        '/java/src',
        '/src',
    )
    # 对标准源码目录，命中任意一个合法 package 文件即可视为有效，
    # 否则会误伤只有少量源码文件的小模块/最小复现仓库。
    if file_count >= 1 and package_count >= 1 and normalized_dir.endswith(standard_source_suffixes):
        return True
    # 非标准目录保持更严格的启发式，降低误判概率。
    return file_count >= 5 and package_count >= file_count * 0.5


def find_directory_with_most_packages(root_path):
    """
    找到package声明密度最高的目录（非标准结构的fallback）

    返回：
      str: 包含最多package声明的目录路径
    """
    skip_dirs = {
        'target', 'build', '.git', '.idea', '.gradle',
        'bin', 'out', 'node_modules',
        'resources', 'generated', '.svn', 'META-INF'
    }

    dir_scores = {}  # {dir_path: (package_count, file_count)}

    for root, dirs, files in os.walk(root_path):
        # 跳过无关目录
        dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]

        package_count = 0
        source_file_count = 0

        for fname in files:
            if not (fname.endswith('.java') or fname.endswith('.kt')):
                continue

            source_file_count += 1
            file_path = os.path.join(root, fname)

            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    for line_num, line in enumerate(f):
                        if line_num > 30:
                            break
                        if re.match(r'^\s*package\s+[a-z][a-z0-9_.]*\s*;?', line):
                            package_count += 1
                            break
            except Exception:
                continue

        if source_file_count > 0:
            # 计算密度分数：package数量 + 文件数量权重
            score = package_count * 2 + source_file_count
            dir_scores[root] = (package_count, source_file_count, score)

    # 找到分数最高的目录
    if not dir_scores:
        return None

    best_dir = max(dir_scores.items(), key=lambda x: x[1][2])

    # 验证：至少有10个有效package
    if best_dir[1][0] >= 10:
        return best_dir[0]

    return None


def count_source_files(directory):
    """统计目录中的Java/Kotlin源码文件数量"""
    count = 0
    for _root, dirs, files in os.walk(directory):
        count += sum(
            1 for f in files
            if f.endswith('.java') or f.endswith('.kt') or f.endswith('.kts')
        )
    return count


def extract_maven_coords_from_pom(pom_path):
    """从pom.xml提取groupId:artifactId"""
    try:
        with open(pom_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        # 提取groupId
        group_match = re.search(r'<groupId>([^<]+)</groupId>', content)
        artifact_match = re.search(r'<artifactId>([^<]+)</artifactId>', content)

        if not group_match or not artifact_match:
            return None

        groupId = group_match.group(1).strip()
        artifactId = artifact_match.group(1).strip()

        # 处理继承（parent pom）
        if groupId == '${project.groupId}' or not groupId:
            parent_group = re.search(
                r'<parent>.*?<groupId>([^<]+)</groupId>',
                content,
                re.DOTALL
            )
            if parent_group:
                groupId = parent_group.group(1).strip()

        if not groupId or not artifactId:
            return None

        return f"{groupId}:{artifactId}"

    except Exception:
        return None


def extract_maven_coords_from_gradle(gradle_path):
    """从build.gradle提取groupId:artifactId"""
    try:
        with open(gradle_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        # Groovy DSL
        group_match = re.search(r'group\s*=?\s*[\'"]([^\'"]+)[\'"]', content)
        artifact_match = re.search(
            r'(?:archivesBaseName|rootProject\.name|project\.name)\s*=?\s*[\'"]([^\'"]+)[\'"]',
            content
        )

        # Kotlin DSL
        if not group_match:
            group_match = re.search(r'group\s*=\s*[\'"]([^\'"]+)[\'"]', content)
        if not artifact_match:
            artifact_match = re.search(r'name\s*=\s*[\'"]([^\'"]+)[\'"]', content)

        if group_match and artifact_match:
            groupId = group_match.group(1).strip()
            artifactId = artifact_match.group(1).strip()
            return f"{groupId}:{artifactId}"

        return None

    except Exception:
        return None


def auto_discover_bridge_sources(report_dir, main_state_file=None):
    """
    自动发现依赖源码映射

    从 `main_state.json` 读取当前已确认的 dependency_source_dirs /
    dependency_repo_mappings。

    自动推断：
      - 从依赖源码目录或多模块仓库找到 src/main/java / src/main/kotlin
      - 输出 dependency_source_mappings 结果供 Step5 使用

    Args:
        report_dir: .upgrade-report 目录路径
        main_state_file: main_state.json 路径（可选）

    Returns:
        {
            'dependency_source_mappings': ['groupId:artifactId=/path/to/src/main/java'],
            'matched_coords': ['groupId:artifactId'],
            'discovery_log': [...]
        }
    """
    mapping_inputs = load_source_mapping_inputs(report_dir, main_state_file=main_state_file)
    dependency_source_dirs = mapping_inputs['dependency_source_dirs']

    if not dependency_source_dirs:
        return {
            'dependency_source_mappings': [],
            'matched_coords': [],
            'unmatched_coords': [],
            'discovery_log': ['未找到 dependency_source_dirs 配置'],
            'provided_dependency_source_dirs': [],
            'source_dirs_detected_without_coord': [],
            'unresolved_dependency_source_dirs': [],
        }

    print("\n自动发现依赖源码映射", file=sys.stderr)
    print(f"  dependency_source_dirs={len(dependency_source_dirs)}", file=sys.stderr)

    # 自动推断源码目录
    dependency_source_mappings = []
    matched_coords = []
    unmatched_coords = []
    discovery_log = []
    source_dirs_detected_without_coord = []
    unresolved_dependency_source_dirs = []

    for root_path in dependency_source_dirs or []:
        root_path = str(root_path or '').strip()
        if not root_path:
            continue
        discovered_mappings = discover_bridge_source_mappings("", root_path)
        if discovered_mappings:
            discovered_coords = set()
            for matched_coord, source_dir in discovered_mappings:
                dependency_source_mappings.append(f"{matched_coord}={source_dir}")
                discovered_coords.add(matched_coord)
                log_msg = f"✓ {matched_coord} → {source_dir}"
                discovery_log.append(log_msg)
                print(f"  {log_msg}", file=sys.stderr)
            matched_coords.extend(sorted(discovered_coords))
        else:
            direct_source_dirs = _discover_module_source_dirs(root_path)
            if direct_source_dirs:
                source_dirs_detected_without_coord.extend(direct_source_dirs)
                unresolved_dependency_source_dirs.append({
                    'root_path': root_path,
                    'source_dirs': direct_source_dirs,
                    'reason': 'detected_source_dirs_but_no_coord',
                })
                log_msg = (
                    f"⚠️ 已检测到源码目录，但未能从依赖源码目录推断模块坐标"
                    f"（root={root_path}, source_dirs={len(direct_source_dirs)}）"
                )
            else:
                unresolved_dependency_source_dirs.append({
                    'root_path': root_path,
                    'source_dirs': [],
                    'reason': 'no_module_source_discovered',
                })
                log_msg = f"⚠️ 未能从依赖源码目录推断模块源码（root={root_path})"
            discovery_log.append(log_msg)
            print(f"  {log_msg}", file=sys.stderr)

    # 输出结果
    result = {
        'dependency_source_mappings': list(dict.fromkeys(dependency_source_mappings)),
        'matched_coords': list(dict.fromkeys(matched_coords)),
        'unmatched_coords': unmatched_coords,
        'discovery_log': discovery_log,
        'total_input': len(dependency_source_dirs),
        'matched_count': len(list(dict.fromkeys(matched_coords))),
        'unmatched_count': len(unmatched_coords),
        'provided_dependency_source_dirs': dependency_source_dirs,
        'source_dirs_detected_without_coord': list(dict.fromkeys(source_dirs_detected_without_coord)),
        'source_dirs_detected_without_coord_count': len(list(dict.fromkeys(source_dirs_detected_without_coord))),
        'unresolved_dependency_source_dirs': unresolved_dependency_source_dirs,
    }

    print(f"\n发现结果：", file=sys.stderr)
    print(f"  成功：{len(matched_coords)}", file=sys.stderr)
    print(f"  失败：{len(unmatched_coords)}", file=sys.stderr)

    return result


def update_main_state_dependency_source_dirs(report_dir, dependency_source_dirs, main_state_file=None):
    main_state = load_main_state_payload(report_dir, explicit_path=main_state_file)
    if not isinstance(main_state.get('state'), dict):
        main_state['state'] = {}
    current_step = str((main_state.get('state') or {}).get('current_step') or '').strip()
    target_step = current_step if current_step in STEP_IDS else "step5"
    if not isinstance(main_state.get(target_step), dict):
        main_state[target_step] = {}
    if not isinstance(main_state[target_step].get('input'), dict):
        main_state[target_step]['input'] = {}
    main_state[target_step]['input']['dependency_source_dirs'] = list(dependency_source_dirs or [])
    main_state[target_step]['input'].pop('dependency_repo_mappings', None)
    main_state[target_step]['input'].pop('dependency_source_mappings', None)
    save_main_state_payload(report_dir, main_state, explicit_path=main_state_file)


def main():
    ap = argparse.ArgumentParser(
        description='自动发现依赖源码映射，解决用户重复配置问题'
    )
    ap.add_argument(
        '--report-dir',
        required=True,
        help='.upgrade-report 目录路径'
    )
    ap.add_argument(
        '--main-state',
        default='',
        help='main_state.json 路径（可选）'
    )
    ap.add_argument(
        '--dependency-source-dirs',
        nargs='*',
        default=[],
        help='手动指定 dependency_source_dirs（格式：/path/to/repo-root）'
    )
    ap.add_argument(
        '--output',
        default='',
        help='输出JSON文件路径（默认输出到 report-dir/discovered_dependency_sources.json）'
    )
    args = ap.parse_args()

    mapping_inputs = load_source_mapping_inputs(
        args.report_dir,
        args.main_state or None
    )
    all_dependency_source_dirs = _dedupe_preserve_order(
        list(mapping_inputs.get('dependency_source_dirs') or []) + [
            resolve_repo_input_path(item) for item in (args.dependency_source_dirs or []) if str(item or '').strip()
        ]
    )

    if not all_dependency_source_dirs:
        print("❌ 未找到任何 dependency_source_dirs 配置", file=sys.stderr)
        print("   请通过以下方式之一提供配置：", file=sys.stderr)
        print("     1. Step 2/Step 4/Step 5 的主状态输入中配置 dependency_source_dirs", file=sys.stderr)
        print("     2. 命令行参数 --dependency-source-dirs", file=sys.stderr)
        return 1

    if args.dependency_source_dirs:
        update_main_state_dependency_source_dirs(
            args.report_dir,
            all_dependency_source_dirs,
            main_state_file=args.main_state or None,
        )

    # 执行自动发现
    result = auto_discover_bridge_sources(
        args.report_dir,
        args.main_state or None
    )

    # 保存结果
    output_path = args.output or os.path.join(args.report_dir, 'discovered_dependency_sources.json')
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"\n结果已保存：{output_path}", file=sys.stderr)

    # 输出可用的 dependency_source_mappings
    if result['dependency_source_mappings']:
        print("\n可用依赖源码映射（可直接用于 Step 5）：", file=sys.stderr)
        for config in result['dependency_source_mappings']:
            print(f"  {config}", file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
