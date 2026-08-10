#!/usr/bin/env python3
"""
s1_dep_diff.py — Step 1：依赖变更全景扫描

主路径：
  - 自动切换到 base/current 分支
  - 对单个目标模块执行真实 package
  - 只比较最终产物中的打包依赖
  - thin jar / 无嵌套依赖场景直接报错，不再回退到 runtime 依赖

实现原则：
  - 编译产物是版本真相源
  - `mvn dependency:list` 仅用于补充 groupId/artifactId/classifier 等坐标信息
  - runtime 结果中的版本只参与候选匹配与冲突诊断，不能写入或确认最终制品版本

Windows 兼容：通过 compat.py 统一处理编码，不会因 GBK/UTF-8 不匹配崩溃。
"""

import argparse, csv, hashlib, io, json, os, re, shutil, sys, tempfile, time, zipfile
import safe_xml as ET
from collections import defaultdict
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path

# compat 必须第一个 import，它会在 Windows 上修复 stdout/stderr 编码
sys.path.insert(0, str(Path(__file__).parent))
from compat import run_cmd, open_text, mvn_cmd, gradle_cmd, git_cmd, IS_WINDOWS, require_human_confirm
from csv_io import open_csv_write
from analysis_contract import (
    build_project_scope,
    discover_project_modules,
    project_scope_provenance_fields,
    sha256_file,
)
from artifact_safety import (
    _archive_entry_expansion_ratio,
    _unsafe_entry_name,
    is_allowed_duplicate_archive_entry,
    require_safe_archive,
)
from artifact_coordinates import normalize_artifact_coord
from diagnostic_contract import (
    DEPENDENCY_COORDINATES_UNRESOLVED,
    normalize_diagnostic_payload,
)
from pipeline_constants import (
    STEP1_ARTIFACTS_DIRNAME,
    STEP1_DEPENDENCY_JARS_DIRNAME,
    STEP1_DEPENDENCY_JARS_MANIFEST_FILE,
)
from step1_observability import Step1Observer
from step1_ref_resolution import resolve_step1_ref
from reason_guidance import REASON_GUIDANCE_SCHEMA, guidance_for_reason_code
from path_runtime import (
    bounded_filename,
    create_detached_worktree,
    named_temporary_file,
    remove_detached_worktree,
    short_temp_root,
)


EXIT_AWAITING_USER = 4
STEP_INTERACTION_PREFIX = "JUA_STEP_INTERACTION_JSON:"
MAIN_STATE_FILE_NAME = "main_state.json"
NESTED_JAR_SPOOL_MAX_MEMORY_BYTES = 8 * 1024 * 1024
NESTED_JAR_COPY_CHUNK_BYTES = 1024 * 1024
PACKAGED_INVENTORY_CACHE_SCHEMA_VERSION = 3
PACKAGED_INVENTORY_CACHE_DIRNAME = 'step1_packaged_inventory'
STEP1_MAX_DEPENDENCY_JAR_BYTES = 1024 * 1024 * 1024
STEP1_MAX_TOTAL_DEPENDENCY_BYTES = 2 * 1024 * 1024 * 1024
# A cold Maven/Gradle cache can legitimately spend more than 30 minutes
# downloading dependencies and wrapper distributions. Build tools already own
# repository connection/read timeouts, so Step1 must not impose a total
# wall-clock deadline unless an explicit timeout option is added in the future.
STEP1_BUILD_TOOL_TIMEOUT = None
MAVEN_SKIP_TEST_COMPILATION_ARG = '-Dmaven.test.skip=true'
GRADLE_LOCK_RETRY_DELAYS_SECONDS = (1, 3)


def _observed_phase(observer, phase, **kwargs):
    return observer.phase(phase, **kwargs) if observer is not None else nullcontext()


def _side_display(side):
    return {
        "base": "基准侧",
        "current": "当前侧",
    }.get(str(side or "").strip(), str(side or "当前侧").strip())


def retain_artifact_for_analysis(meta, artifact_cache_dir, side):
    """Copy a build artifact out of temporary/user locations and update its provenance metadata."""
    artifact_path = str((meta or {}).get('artifact_path') or '').strip()
    if not artifact_path or not artifact_cache_dir or not Path(artifact_path).is_file():
        return meta
    source_artifact = Path(artifact_path).resolve()
    worktree_dir = str((meta or {}).get('worktree_dir') or '').strip()
    if worktree_dir and not str((meta or {}).get('artifact_relative_path') or '').strip():
        try:
            meta['artifact_relative_path'] = source_artifact.relative_to(
                Path(worktree_dir).resolve()
            ).as_posix()
        except ValueError:
            meta['artifact_relative_path'] = ''
    cache_dir = Path(artifact_cache_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    suffix = ''.join(source_artifact.suffixes) or '.jar'
    retained_artifact = cache_dir / f'{side or "artifact"}{suffix}'
    if source_artifact != retained_artifact:
        shutil.copy2(source_artifact, retained_artifact)
    meta['original_artifact_path'] = artifact_path
    meta['artifact_path'] = str(retained_artifact)
    meta['archives'] = [str(retained_artifact)]
    meta['artifact_retained'] = True
    meta['artifact_sha256'] = sha256_file(retained_artifact)
    return meta


def _write_deterministic_archive(target, source_archive, entries):
    """Write ``(source_name, target_name)`` entries without build-time metadata."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as output:
        for source_name, target_name in entries:
            info = zipfile.ZipInfo(target_name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            output.writestr(info, source_archive.read(source_name))


def _business_content_entries(archive):
    names = sorted(
        info.filename
        for info in archive.infolist()
        if not info.is_dir()
    )
    application_prefixes = ('BOOT-INF/classes/', 'WEB-INF/classes/')
    has_application_layout = any(
        name.startswith(application_prefixes) for name in names
    )
    entries = []
    seen_targets = set()
    for name in names:
        if has_application_layout:
            prefix = next(
                (value for value in application_prefixes if name.startswith(value)),
                '',
            )
            if not prefix:
                continue
            target_name = name[len(prefix):]
        else:
            upper_name = name.upper()
            packaging_only = (
                upper_name == 'META-INF/MANIFEST.MF'
                or upper_name.startswith('META-INF/MAVEN/')
                or bool(re.fullmatch(
                    r'META-INF/[^/]+\.(?:SF|RSA|DSA|EC)', upper_name
                ))
            )
            if packaging_only or name.startswith(('BOOT-INF/', 'WEB-INF/', 'lib/')):
                continue
            target_name = name
        if not target_name:
            continue
        if target_name in seen_targets:
            raise ValueError(f'Step1 业务制品条目重复: {target_name}')
        seen_targets.add(target_name)
        entries.append((name, target_name))
    return entries


def _spring_boot_classpath_order(archive):
    """Return only an explicit, packaged Spring Boot classpath order."""
    try:
        raw = archive.read("BOOT-INF/classpath.idx").decode(
            "utf-8", errors="strict"
        )
    except (KeyError, UnicodeError):
        return {}
    order = {}
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r'-\s+"(BOOT-INF/lib/[^"]+\.jar)"', line)
        if not match:
            return {}
        entry = match.group(1)
        if entry in order:
            return {}
        order[entry] = len(order)
    archive_names = set(archive.namelist())
    if not order or any(entry not in archive_names for entry in order):
        return {}
    return order


def materialize_changed_dependency_jars(
    rows, side_meta, output_dir, base_entries=None, current_entries=None,
):
    """Persist the complete base/current runtime closure used by binary analysis."""
    output_dir = Path(output_dir).resolve()
    jar_dir = output_dir / STEP1_DEPENDENCY_JARS_DIRNAME
    if jar_dir.exists():
        shutil.rmtree(jar_dir)
    jar_dir.mkdir(parents=True, exist_ok=True)

    requests = {}

    def add_request(
        side, lib_entry, coord, version, scope, identity_source, purpose,
        classifier='',
    ):
        normalized_entry = str(lib_entry or '').replace('\\', '/').strip()
        if not normalized_entry:
            raise ValueError(
                f'Step1 {purpose} 依赖缺少最终制品条目: {coord or "<unknown>"}'
            )
        normalized_coord = str(coord or '').strip()
        coord_parts = normalized_coord.split(':', 2)
        coord_classifier = (
            coord_parts[2].strip()
            if len(coord_parts) == 3
            else ''
        )
        normalized_classifier = str(classifier or '').strip()
        if (
            normalized_classifier
            and coord_classifier
            and normalized_classifier != coord_classifier
        ):
            raise ValueError(
                f'Step1 依赖 classifier 冲突: {normalized_entry} '
                f'({coord_classifier} != {normalized_classifier})'
            )
        normalized_classifier = normalized_classifier or coord_classifier
        if normalized_classifier and not coord_classifier and normalized_coord:
            normalized_coord = f'{normalized_coord}:{normalized_classifier}'
        key = (side, normalized_entry)
        request = requests.setdefault(key, {
            'side': side,
            'coord': normalized_coord,
            'classifier': normalized_classifier,
            'version': str(version or '').strip(),
            'scope': str(scope or '').strip(),
            'lib_entry': normalized_entry,
            'identity_source': str(identity_source or '').strip(),
            'purposes': set(),
        })
        request['purposes'].add(purpose)
        for field, value in (
            ('coord', normalized_coord),
            ('classifier', normalized_classifier),
            ('version', version),
            ('scope', scope),
            ('identity_source', identity_source),
        ):
            normalized_value = str(value or '').strip()
            if (
                field == 'coord'
                and request[field]
                and normalized_value
                and request[field] != normalized_value
            ):
                request_parts = request[field].split(':', 2)
                value_parts = normalized_value.split(':', 2)
                request_gav = ':'.join(request_parts[:2])
                value_gav = ':'.join(value_parts[:2])
                request_classifier = (
                    request_parts[2].strip()
                    if len(request_parts) == 3
                    else ''
                )
                value_classifier = (
                    value_parts[2].strip()
                    if len(value_parts) == 3
                    else ''
                )
                if (
                    request_gav == value_gav
                    and not request_classifier
                    and value_classifier
                ):
                    request['coord'] = normalized_value
                    request['classifier'] = value_classifier
                    continue
                if (
                    request_gav == value_gav
                    and request_classifier
                    and not value_classifier
                ):
                    continue
            if (
                field in {'coord', 'classifier', 'version'}
                and request[field]
                and normalized_value
                and request[field] != normalized_value
            ):
                raise ValueError(
                    f'Step1 同一制品条目身份冲突: {normalized_entry} '
                    f'({request[field]} != {normalized_value})'
                )
            if not request[field] and normalized_value:
                request[field] = normalized_value

    for row in rows or []:
        if str(row.get('resolution_status') or '').strip() != 'resolved':
            continue
        if str(row.get('change_type') or '').strip() == '未变':
            continue
        for side, version_field, coord_field, entry_field in (
            ('base', 'old_version', 'base_coord', 'base_lib_entry'),
            ('current', 'new_version', 'current_coord', 'current_lib_entry'),
        ):
            version = str(row.get(version_field) or '').strip()
            if version in ('', '-'):
                continue
            lib_entry = str(row.get(entry_field) or '').replace('\\', '/').strip()
            add_request(
                side,
                lib_entry,
                row.get(coord_field) or row.get('coord'),
                version,
                row.get('scope'),
                row.get(
                    'base_packaged_match_source'
                    if side == 'base'
                    else 'current_packaged_match_source'
                ),
                'step4_change',
                row.get(
                    'base_classifier'
                    if side == 'base'
                    else 'current_classifier'
                ) or row.get('classifier'),
            )

    for side, entries in (
        ('base', base_entries or ()),
        ('current', current_entries or ()),
    ):
        for entry in entries:
            if str(entry.get('resolution_status') or 'resolved').strip() != 'resolved':
                continue
            scope = str(entry.get('scope') or '').strip()
            if scope in {'test', 'provided', 'optional'}:
                continue
            coord = str(entry.get('coord') or '').strip()
            version = str(entry.get('version') or '').strip()
            if not coord or version in ('', '-'):
                continue
            add_request(
                side,
                entry.get('lib_entry'),
                coord,
                version,
                scope,
                entry.get('packaged_match_source'),
                'binary_runtime',
                entry.get('classifier'),
            )

    items = []
    business_artifacts = []
    for side in ('base', 'current'):
        side_requests = [
            request for (request_side, _entry), request in requests.items()
            if request_side == side
        ]
        if not side_requests and side != 'current':
            continue
        meta = dict((side_meta or {}).get(side) or {})
        artifact_path = Path(str(meta.get('artifact_path') or ''))
        if not artifact_path.is_file():
            if side_requests:
                raise ValueError(f"Step1 {side} 最终制品不可用: {artifact_path}")
            continue
        outer_sha256 = str(meta.get('artifact_sha256') or '').strip()
        if not outer_sha256:
            outer_sha256 = sha256_file(artifact_path)
        with zipfile.ZipFile(artifact_path) as outer:
            spring_boot_classpath_order = _spring_boot_classpath_order(outer)
            info_by_name = defaultdict(list)
            archive_entry_order = {}
            for archive_index, info in enumerate(outer.infolist()):
                info_by_name[info.filename].append(info)
                archive_entry_order.setdefault(info.filename, archive_index)
            for request in sorted(side_requests, key=lambda item: item['lib_entry']):
                lib_entry = request['lib_entry']
                matches = [
                    info for info in info_by_name.get(lib_entry, ())
                    if not info.is_dir()
                ]
                if len(matches) != 1:
                    raise ValueError(
                        f"Step1 {side} 最终制品条目数量异常: "
                        f"{lib_entry}（{len(matches)}）"
                    )
                target_name = (
                    hashlib.sha256(lib_entry.encode('utf-8')).hexdigest()[:16]
                    + '-'
                    + bounded_filename(Path(lib_entry).name, max_length=40)
                )
                target = jar_dir / side / target_name
                target.parent.mkdir(parents=True, exist_ok=True)
                with outer.open(matches[0]) as source, open(target, 'wb') as sink:
                    shutil.copyfileobj(source, sink, NESTED_JAR_COPY_CHUNK_BYTES)
                try:
                    require_safe_archive(
                        target,
                        inspect_nested_archives=False,
                        allow_duplicate_maven_metadata=True,
                    )
                except Exception:
                    if target.exists():
                        target.unlink()
                    raise
                retained_item = {
                    'side': side,
                    'coord': request['coord'],
                    'classifier': request['classifier'],
                    'version': request['version'],
                    'scope': request['scope'],
                    'lib_entry': lib_entry,
                    'retained_path': str(target),
                    'nested_jar_sha256': sha256_file(target),
                    'outer_artifact_path': str(artifact_path),
                    'outer_artifact_sha256': outer_sha256,
                    'identity_source': request['identity_source'],
                    'purposes': sorted(request['purposes']),
                }
                if lib_entry in spring_boot_classpath_order:
                    retained_item.update({
                        'runtime_classpath_index': (
                            spring_boot_classpath_order[lib_entry]
                        ),
                        'runtime_classpath_authority': (
                            'spring_boot_classpath_index'
                        ),
                    })
                else:
                    retained_item.update({
                        'runtime_classpath_index': archive_entry_order[lib_entry],
                        'runtime_classpath_authority': 'outer_archive_entry_order',
                    })
                items.append(retained_item)

            business_entries = _business_content_entries(outer)
            if business_entries:
                business_target = jar_dir / side / 'business-classes.jar'
                _write_deterministic_archive(
                    business_target, outer, business_entries
                )
                try:
                    require_safe_archive(
                        business_target,
                        inspect_nested_archives=False,
                        allow_duplicate_maven_metadata=True,
                    )
                except Exception:
                    if business_target.exists():
                        business_target.unlink()
                    raise
                names = set(outer.namelist())
                if any(name.startswith('BOOT-INF/classes/') for name in names):
                    launcher_kind = 'spring-boot-executable-jar'
                elif any(name.startswith('WEB-INF/classes/') for name in names):
                    launcher_kind = 'servlet-war'
                else:
                    launcher_kind = 'java-classpath'
                business_artifacts.append({
                    'side': side,
                    'kind': 'business_content',
                    'retained_path': str(business_target),
                    'sha256': sha256_file(business_target),
                    'entry_count': len(business_entries),
                    'class_count': sum(
                        1 for _source, target in business_entries
                        if target.endswith('.class')
                    ),
                    'outer_artifact_path': str(artifact_path),
                    'outer_artifact_sha256': outer_sha256,
                    'container_and_launcher_kind': launcher_kind,
                })

    gav_artifacts = defaultdict(lambda: {'hashes': set(), 'entries': []})
    for item in items:
        coord = str(item.get('coord') or '').strip()
        coord_parts = coord.split(':', 2)
        classifier = str(item.get('classifier') or '').strip()
        if not classifier and len(coord_parts) == 3:
            classifier = coord_parts[2].strip()
        gav_coord = (
            ':'.join(coord_parts[:2])
            if len(coord_parts) >= 2
            else coord
        )
        key = (
            str(item.get('side') or '').strip(),
            gav_coord,
            str(item.get('version') or '').strip(),
            classifier,
        )
        gav_artifacts[key]['hashes'].add(
            str(item.get('nested_jar_sha256') or '').lower()
        )
        gav_artifacts[key]['entries'].append(str(item.get('lib_entry') or ''))
    identity_conflicts = [
        (key, value)
        for key, value in gav_artifacts.items()
        if len(value['hashes']) > 1
    ]
    if identity_conflicts:
        key, value = identity_conflicts[0]
        classifier_suffix = f':{key[3]}' if key[3] else ''
        raise ValueError(
            'Step1 同一 GAV 对应多个不同字节的最终制品条目: '
            f'{key[0]} {key[1]}:{key[2]}{classifier_suffix} '
            f'({", ".join(sorted(value["entries"]))})'
        )

    runtime_closure = {}
    for side, entries in (
        ('base', base_entries or ()),
        ('current', current_entries or ()),
    ):
        gaps = []
        expected_entries = []
        for entry in entries:
            scope = str(entry.get('scope') or '').strip()
            status = str(entry.get('resolution_status') or 'resolved').strip()
            if scope in {'test', 'optional'}:
                continue
            if scope == 'provided':
                gaps.append(
                    f"external_provided_runtime_not_materialized:{entry.get('coord') or entry.get('lib_entry')}"
                )
                continue
            if status != 'resolved':
                gaps.append(
                    f"runtime_dependency_unresolved:{entry.get('lib_entry') or entry.get('coord')}"
                )
                continue
            expected_entries.append(str(entry.get('lib_entry') or ''))
        retained_entries = sorted({
            str(item.get('lib_entry') or '')
            for item in items
            if item.get('side') == side
            and 'binary_runtime' in set(item.get('purposes') or ())
        })
        missing = sorted(set(expected_entries) - set(retained_entries))
        gaps.extend(f"runtime_dependency_not_retained:{item}" for item in missing)
        business_count = sum(
            1 for item in business_artifacts if item.get('side') == side
        )
        if business_count != 1:
            gaps.append(f"business_artifact_cardinality:{business_count}")
        runtime_closure[side] = {
            'coverage_status': 'complete' if not gaps else 'partial',
            'expected_dependency_count': len(expected_entries),
            'retained_dependency_count': len(retained_entries),
            'business_artifact_count': business_count,
            'coverage_gaps': sorted(set(gaps)),
        }

    manifest_path = output_dir / STEP1_DEPENDENCY_JARS_MANIFEST_FILE
    manifest_path.write_text(
        json.dumps(
            {
                'schema': 'java-upgrade-analyzer.step1-dependency-jars.v3',
                'items': items,
                'business_artifacts': business_artifacts,
                'runtime_closure': runtime_closure,
            },
            ensure_ascii=False,
            indent=2,
        ) + '\n',
        encoding='utf-8',
    )
    return manifest_path, items


class ArtifactCoordinateInputRequiredError(RuntimeError):
    def __init__(self, artifact_path, unresolved_items=None):
        self.artifact_path = str(artifact_path)
        self.unresolved_items = list(unresolved_items or [])
        super().__init__(self.artifact_path)


class SourceRevisionConfirmationRequiredError(RuntimeError):
    def __init__(self, side, source_project_dir, artifact_path="", resolution=None):
        self.side = str(side or "")
        self.source_project_dir = str(source_project_dir or "")
        self.artifact_path = str(artifact_path or "")
        self.resolution = dict(resolution or {})
        super().__init__(
            "只有源码目录不足以确认其对应的制品版本；"
            f"请先为 {self.side or '该侧'} 确认 branch/tag/commit，再执行坐标补全。"
        )


class Step1RefResolutionRequiredError(RuntimeError):
    def __init__(self, side, source_project_dir, artifact_path, resolution):
        self.side = str(side or "")
        self.source_project_dir = str(source_project_dir or "")
        self.artifact_path = str(artifact_path or "")
        self.resolution = dict(resolution or {})
        status = str(self.resolution.get("status") or "not_found")
        super().__init__(
            f"{self.side or '该侧'}源码 ref 无法唯一固定（{status}），"
            "必须人工确认明确的 branch/tag/commit。"
        )


class PinnedCommitMaterializationError(RuntimeError):
    def __init__(self, side, resolution):
        self.side = str(side or "")
        self.resolution = dict(resolution or {})
        expected = str(self.resolution.get("expected_commit") or "").strip()
        super().__init__(
            f"{self.side or '该侧'}已固定 commit {expected or '(unknown)'}，"
            "但 Git 服务无法物化该对象；这是远端对象可达性或权限问题，"
            "不能通过让用户重新选择 ref 解决。"
        )


class Step1RemoteOperationError(RuntimeError):
    def __init__(self, side, source_project_dir, resolution):
        self.side = str(side or "")
        self.source_project_dir = str(source_project_dir or "")
        self.resolution = dict(resolution or {})
        failures = list(
            self.resolution.get("failures")
            or self.resolution.get("remote_failures")
            or []
        )
        last_failure = failures[-1] if failures else {}
        reason = str(
            last_failure.get("reason")
            or self.resolution.get("reason")
            or self.resolution.get("source_status")
            or "未知 Git 远端错误"
        ).strip()
        super().__init__(
            f"STEP1_REMOTE_OPERATION_FAILED: "
            f"{self.side or '该侧'} Git 远端操作在受控重试后仍失败"
            f"（仓库: {self.source_project_dir or '-'}）：{reason}"
        )


def build_step1_ref_resolution_interaction(error):
    side = str(error.side or "").strip() or "current"
    field = f"{side}_branch"
    side_cn = "基准侧" if side == "base" else "当前侧"
    other_side_cn = "当前侧" if side == "base" else "基准侧"
    resolution = dict(getattr(error, "resolution", {}) or {})
    candidates = [dict(item) for item in (resolution.get("candidates") or [])]
    status = str(resolution.get("status") or "not_found")
    source_status = str(resolution.get("source_status") or "")
    query_scope_note = (
        f"本卡片只记录{side_cn}因产物坐标补全而触发的 Git ref 查询；"
        f"它不表示{other_side_cn}执行过远端查询。"
        f"只有{other_side_cn}状态明确为 remote_source_resolved，才能认定其远端解析成功。"
    )
    for candidate in candidates:
        payload = {
            "side": side,
            "ref": str(candidate.get("ref") or ""),
            "commit": str(candidate.get("commit") or ""),
        }
        candidate["selection_key"] = "s1ref:" + hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
    source_only = isinstance(error, SourceRevisionConfirmationRequiredError)
    if source_only:
        reason_code = "step1_source_revision_confirmation_required"
        summary = f"{side_cn}只提供了源码目录，无法证明它对应当前制品的 revision。"
    elif status == "fetch_failed":
        reason_code = "step1_remote_fetch_failed"
        summary = f"{side_cn}远端查询或 fetch 在受控重试后仍失败；无需猜测分支。"
    elif status == "ref_moved":
        reason_code = "step1_remote_ref_moved"
        summary = f"{side_cn}远端 ref 已指向新的 commit，需要基于刷新后的候选重新确认。"
    elif status == "ambiguous":
        reason_code = "ambiguous_step1_source_ref"
        summary = (
            f"{side_cn}未指定 remote 且没有默认 origin，"
            "或同名 branch/tag 指向不同 commit，不能自动选择。"
        )
    elif source_status == "repository_not_git":
        reason_code = "step1_source_directory_not_git"
        summary = f"{side_cn}实际执行解析的源码目录不是 Git 仓库；请修正源码目录。"
    elif source_status == "remote_configuration_missing":
        reason_code = "step1_remote_configuration_missing"
        summary = (
            f"{side_cn}实际执行解析的源码目录没有配置 Git remote；"
            "请修正源码目录或 remote。"
        )
    else:
        reason_code = "step1_source_ref_not_found"
        summary = f"{side_cn}所选 remote 上不存在输入的精确 branch/tag。"
    summary = f"{summary}{query_scope_note}"
    request = {
        "side": side,
        "field": field,
        "requested_ref": str(resolution.get("requested_ref") or ""),
        "status": "confirmation_required" if source_only else status,
        "source_project_dir": str(error.source_project_dir or ""),
        "artifact_path": str(error.artifact_path or ""),
        "candidates": candidates,
        "fingerprint": str(resolution.get("fingerprint") or ""),
        "source_status": source_status,
        "expected_commit": str(resolution.get("expected_commit") or ""),
        "remote_failures": [dict(item) for item in (resolution.get("failures") or [])],
        "local_candidate_commit": str(resolution.get("local_candidate_commit") or ""),
        "dirty": bool(resolution.get("dirty")),
        "repository_path": str(
            resolution.get("repository_path") or error.source_project_dir or ""
        ),
        "configured_remotes": list(resolution.get("configured_remotes") or []),
        "query_mode": str(resolution.get("query_mode") or ""),
        "resolution_trigger": "artifact_coordinate_enrichment",
        "remote_query_scope": side,
        "other_side_remote_status": "not_evaluated_by_this_interaction",
    }
    detected_commit = str(
        resolution.get("resolved_commit") or resolution.get("local_candidate_commit") or ""
    ).strip()
    if source_only and detected_commit:
        request.update({
            "detected_ref": str(resolution.get("resolved_ref") or "HEAD"),
            "detected_commit": detected_commit,
            "candidates": [{
                "ref": detected_commit,
                "display_ref": str(resolution.get("resolved_ref") or "HEAD"),
                "commit": detected_commit,
                "kind": "detected_source_head",
            }],
        })
    for candidate in request.get("candidates") or []:
        if candidate.get("selection_key"):
            continue
        payload = {
            "side": side,
            "ref": str(candidate.get("ref") or candidate.get("display_ref") or ""),
            "commit": str(candidate.get("commit") or ""),
        }
        candidate["selection_key"] = "s1ref:" + hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
    required_fields = [] if status == "fetch_failed" else [field]
    question = (
        f"{side_cn}远端操作失败；请在网络或权限恢复后确认重试。"
        if status == "fetch_failed"
        else f"请为{side_cn}选择或填写明确的 branch、tag 或 commit；确认后才会执行构建工具坐标补全。"
    )
    question = f"{question}{query_scope_note}"
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "input_request",
        "step_id": "step1",
        "reason_code": reason_code,
        "title": "Step1 需要确认源码版本",
        "summary": summary,
        "question": question,
        "required_fields": required_fields,
        "missing_inputs": [{
            "field": field,
            "label": f"{side_cn}源码 ref",
            "side": side,
            "required": status != "fetch_failed",
            "recommended": True,
            "reason": summary,
            "value_type": "branch",
        }],
        "fallback_inputs": [],
        "ref_resolution_scope": {
            "trigger": "artifact_coordinate_enrichment",
            "queried_sides": [side],
            "other_side": "current" if side == "base" else "base",
            "other_side_status": "not_evaluated_by_this_interaction",
            "note": query_scope_note,
        },
        "files_to_review": [str(error.source_project_dir)] if error.source_project_dir else [],
        "ref_resolution_requests": [request],
        "source_ref_decision_items": [{
            "side": side,
            "field": field,
            "status": request.get("status"),
            "source_status": source_status,
            "requested_ref": request.get("requested_ref"),
            "source_project_dir": request.get("source_project_dir"),
            "artifact_path": request.get("artifact_path"),
            "resolution_trigger": request.get("resolution_trigger"),
            "remote_query_scope": request.get("remote_query_scope"),
            "candidates": list(request.get("candidates") or []),
        }],
        "checklist_lines": [
            query_scope_note,
            f"{side_cn}待补全产物: {error.artifact_path}",
            *(
                [f"{side_cn}实际解析目录: {error.source_project_dir}"]
                if error.source_project_dir else []
            ),
            *(
                [f"{side_cn}已配置 remote: {', '.join(request.get('configured_remotes') or [])}"]
                if request.get("configured_remotes") else []
            ),
            *(
                [f"{side_cn}Git 查询模式: {request.get('query_mode')}"]
                if request.get("query_mode") else []
            ),
            *(
                [f"{side_cn}源码目录当前 revision: {request.get('detected_ref')} ({request.get('detected_commit')})"]
                if request.get("detected_commit") else []
            ),
            *[
                f"{side_cn}候选: {item.get('ref')} ({item.get('commit')})"
                for item in candidates
            ],
        ],
        "options": [
            {"id": "continue", "label": "确认 ref 后继续", "description": "固定 commit 后重新执行 Step1。"},
            {"id": "confirm_local_source", "label": "确认使用本地源码兜底", "description": "仅在远端不可用时固定本地 commit。"},
            {"id": "cancel", "label": "取消", "description": "停止本次分析。"},
        ],
        "response_schema": {
            "type": "object",
            "required": ["action"],
            "properties": {
                "action": {"type": "string", "enum": ["continue", "confirm_local_source", "cancel"]},
                field: {"type": "string", "description": f"{side_cn}明确的 branch、tag 或 commit。"},
                f"{side}_source_project_dir": {
                    "type": "string",
                    "description": (
                        f"可选。修正{side_cn}实际执行 Git ref 解析的源码仓库目录；"
                        "当 ref 已确认存在但解析目录不正确时，与原 ref 一起提交。"
                    ),
                },
                f"{side}_expected_commit": {"type": "string", "description": "内部固定值：所选 ref 对应的 commit。"},
                f"{side}_ref_binding": {
                    "type": "object",
                    "description": "内部绑定值：源码仓库、远端 ref 与固定 commit 的一致性快照。",
                },
                "source_ref_selections": {"type": "array", "description": "选择当前卡片中的 ref 方案。"},
                "retry_remote_fetch": {
                    "type": "boolean",
                    "description": "用户已确认远端状态正常后，显式重新查询远端并重试定向 fetch。",
                },
                f"{side}_allow_local_source": {"type": "boolean", "description": "明确允许使用本地 commit 兜底。"},
                f"{side}_allow_dirty_local_source": {"type": "boolean", "description": "明确允许使用含未提交修改的本地源码。"},
                "notes": {"type": "string", "description": "可选。记录 revision 的确认依据。"},
            },
        },
        "action_requirements": {
            "continue": {"required_fields": required_fields},
            "confirm_local_source": {
                "required_fields": [
                    f"{side}_allow_local_source",
                    *([f"{side}_allow_dirty_local_source"] if resolution.get("dirty") else []),
                ],
            },
        },
        "input_normalization": {
            "enabled": True,
            "mode": "llm_assisted_structuring",
            "required_fields": required_fields,
            "rules": [
                "必须提供能够唯一解析到 commit 的明确 ref。",
                "若 ref 已确认存在但实际解析目录不正确，可保留原 ref，并修正对应侧 source_project_dir。",
                "若目录和 ref 都正确，但远端状态已由用户确认恢复，可设置 retry_remote_fetch=true 显式重查。",
            ],
        },
        "runtime_rules": ["确认前不得执行 Maven/Gradle 坐标补全。"],
        "next_action_rule": "只能等待用户补充明确 ref、修正实际解析目录或取消。",
        "must_wait_for_user_reply": True,
    }


def load_orchestrated_step1_input():
    """正式流程下从 main_state 读取 Step1 输入，单脚本 CLI 仅用于调试。"""
    if not os.environ.get("JUA_ORCHESTRATED"):
        return {}
    report_dir = os.environ.get("UPGRADE_REPORT_DIR", "").strip()
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
    return dict((((main_state or {}).get("step1") or {}).get("input")) or {})


def _normalize_unresolved_label(item):
    if isinstance(item, dict):
        artifact_id = str(item.get("artifact_id") or "").strip()
        version = str(item.get("version") or "").strip()
        classifier = str(item.get("classifier") or "").strip()
        source = str(item.get("source") or "").strip()
        label = f"{artifact_id or '<unknown-artifact>'}:{version or '<unknown-version>'}"
        if classifier:
            label = f"{label}:{classifier}"
        if source:
            label = f"{label} [{source}]"
        return label
    return str(item).strip()


def normalize_unresolved_items(unresolved_items):
    normalized = []
    seen = set()
    for item in unresolved_items or []:
        if isinstance(item, dict):
            normalized_item = {
                "artifact_id": str(item.get("artifact_id") or "").strip(),
                "version": str(item.get("version") or "").strip(),
                "classifier": str(item.get("classifier") or "").strip(),
                "entry_id": str(item.get("entry_id") or "").strip(),
                "lib_entry": str(item.get("lib_entry") or "").strip(),
                "lib_name": str(item.get("lib_name") or "").strip(),
                "side": str(item.get("side") or "").strip(),
                "source": str(item.get("source") or "").strip(),
                "reason_code": str(item.get("reason_code") or "").strip(),
            }
            normalized_item["label"] = _normalize_unresolved_label(normalized_item)
        else:
            label = str(item).strip()
            artifact_id, version = "", ""
            if ":" in label:
                artifact_id, version = label.split(":", 1)
            normalized_item = {
                "artifact_id": artifact_id.strip(),
                "version": version.strip(),
                "classifier": "",
                "entry_id": "",
                "lib_entry": "",
                "lib_name": "",
                "side": "",
                "source": "",
                "reason_code": "",
                "label": label,
            }
        dedupe_key = (
            normalized_item.get("artifact_id", ""),
            normalized_item.get("version", ""),
            normalized_item.get("classifier", ""),
            normalized_item.get("entry_id", ""),
            normalized_item.get("lib_entry", ""),
            normalized_item.get("side", ""),
            normalized_item.get("source", ""),
            normalized_item.get("reason_code", ""),
            normalized_item.get("label", ""),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        normalized.append(normalized_item)
    return normalized


class UnresolvedPackagedCoordinatesError(RuntimeError):
    def __init__(self, unresolved_items, resolved_deps=None):
        self.unresolved_items = normalize_unresolved_items(unresolved_items)
        self.resolved_deps = dict(resolved_deps or {})
        unresolved_text = ", ".join(
            item.get("label", "") for item in self.unresolved_items[:10] if item.get("label")
        )
        super().__init__(
            "最终制品中存在无法确认完整身份的依赖，已停止输出以避免错误对比："
            f"{unresolved_text}。请检查嵌套 jar 的 pom.properties；"
            "坐标缺失时可使用 runtime 依赖报告补全，"
            "版本无法从最终制品确认时必须人工确认。"
        )


class Step1CommandExecutionBlockedError(RuntimeError):
    def __init__(
        self,
        *,
        stage,
        command,
        stderr_excerpt,
        side="",
        branch="",
        jdk_field="",
        jdk_home="",
        source_mode="",
        source_project_dir="",
        artifact_path="",
        suspected_causes=None,
    ):
        self.stage = str(stage or "").strip()
        self.command = str(command or "").strip()
        self.stderr_excerpt = str(stderr_excerpt or "").strip()
        self.side = str(side or "").strip()
        self.branch = str(branch or "").strip()
        self.jdk_field = str(jdk_field or "").strip()
        self.jdk_home = str(jdk_home or "").strip()
        self.source_mode = str(source_mode or "").strip()
        self.source_project_dir = str(source_project_dir or "").strip()
        self.artifact_path = str(artifact_path or "").strip()
        self.suspected_causes = list(suspected_causes or [])
        message = (
            f"Step1 在 {self.stage or 'build_command'} 阶段执行失败"
            + (f"（branch={self.branch}）" if self.branch else "")
            + (f": {self.stderr_excerpt}" if self.stderr_excerpt else "")
        )
        super().__init__(message)


class GradleCommandFailure(RuntimeError):
    """Keep the exact failed Gradle stage and command across Step1 layers."""

    def __init__(
        self,
        *,
        stage,
        command,
        stdout,
        stderr,
        return_code,
        attempts=1,
    ):
        self.stage = str(stage or '').strip()
        self.command = str(command or '').strip()
        self.stdout = str(stdout or '')
        self.stderr = str(stderr or '')
        self.return_code = int(return_code)
        self.attempts = max(int(attempts or 1), 1)
        excerpt = (self.stderr or self.stdout).strip()
        super().__init__(
            f"{self.stage} 执行失败（退出码 {self.return_code}，"
            f"尝试 {self.attempts} 次）：{excerpt[:1000]}"
        )


def emit_step_interaction(interaction):
    payload = normalize_diagnostic_payload(interaction, origin_step="step1")
    if payload.get("reason_code"):
        payload.setdefault("diagnostic_guidance_schema", REASON_GUIDANCE_SCHEMA)
        payload.setdefault(
            "diagnostic_guidance",
            guidance_for_reason_code(
                payload["reason_code"], origin_step="step1"
            ),
        )
    sys.stdout.write(STEP_INTERACTION_PREFIX + json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def build_step1_missing_input_interaction(missing_items, unresolved_items=None):
    files_to_review = [item.get("artifact_path") for item in missing_items if item.get("artifact_path")]
    unresolved_items = normalize_unresolved_items(unresolved_items)
    unresolved_labels = [item.get("label", "") for item in unresolved_items if item.get("label")]
    properties = {
        "action": {
            "type": "string",
            "enum": ["continue", "cancel"],
        },
        "notes": {
            "type": "string",
            "description": "记录用户补充说明。",
        },
    }
    question_parts = []
    checklist_lines = [
        "当前默认场景是同一系统、同一仓库、不同分支。",
        "请优先补充对应侧分支信息；只有不是同仓库双分支场景时，才补对应侧源码工程目录。",
    ]
    if unresolved_labels:
        checklist_lines.append("当前仍未识别的嵌套依赖: " + ", ".join(unresolved_labels[:10]))
    missing_inputs = []
    fallback_inputs = []
    for item in missing_items:
        side_cn = item.get("side_cn") or "该侧"
        artifact_path = item.get("artifact_path") or ""
        source_field = item.get("source_field") or ""
        branch_field = item.get("branch_field") or ""
        reason = (
            f"{side_cn}编译包中的部分嵌套依赖缺少 pom.properties，"
            "无法直接识别完整的 Maven 坐标。"
        )
        checklist_lines.append(f"  - {side_cn}产物: {artifact_path}")
        if branch_field:
            field_label = f"{side_cn}分支"
            properties[branch_field] = {
                "type": "string",
                "description": f"{field_label}。",
            }
            missing_inputs.append(
                {
                    "field": branch_field,
                    "label": field_label,
                    "side": item.get("side") or branch_field.replace("_branch", ""),
                    "required": True,
                    "recommended": True,
                    "reason": reason,
                    "artifact_path": artifact_path,
                    "value_type": "branch",
                }
            )
            question_parts.append(f"{reason}请补充 `{branch_field}`。")
            checklist_lines.append(f"  - 缺失字段: {branch_field}（{field_label}）")
            checklist_lines.append(f"  - 缺失原因: {reason}")
            checklist_lines.append(f"  - 优先补充: {branch_field}")
        if source_field:
            field_label = f"{side_cn}源码工程目录"
            properties[source_field] = {
                "type": "string",
                "description": f"{field_label}（仅特殊场景使用）。",
            }
            fallback_inputs.append(
                {
                    "field": source_field,
                    "label": field_label,
                    "side": item.get("side") or source_field.replace("_source_project_dir", ""),
                    "required": False,
                    "recommended": False,
                    "reason": "仅在不是同仓库双分支场景时使用。",
                    "artifact_path": artifact_path,
                    "value_type": "path",
                }
            )
            checklist_lines.append(f"  - 兜底字段: {source_field}（{field_label}）")
            checklist_lines.append(f"  - 兜底说明: 仅在不是同仓库双分支场景时使用")
    question = "；".join(question_parts)
    if fallback_inputs:
        fallback_text = "；".join(
            f"若不是同仓库双分支场景，也可以改补 `{item.get('field')}`"
            for item in fallback_inputs
        )
        question = f"{question}；{fallback_text}。"
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "input_request",
        "step_id": "step1",
        "reason_code": "missing_dependency_coordinates",
        "summary": "最终产物中的部分嵌套依赖缺少 Maven 坐标，需要补充明确的分支或源码工程信息。",
        "title": "step1 需要补充输入",
        "question": question,
        "files_to_review": files_to_review,
        "required_fields": [item.get("field") for item in missing_inputs if item.get("field")],
        "missing_inputs": missing_inputs,
        "fallback_inputs": fallback_inputs,
        "checklist_lines": checklist_lines,
        "unresolved_items": unresolved_items,
        "options": [
            {
                "id": "continue",
                "label": "补充信息后继续",
                "description": "补充对应侧分支信息后继续；若不是同仓库双分支场景，可改补源码工程目录。",
            },
            {
                "id": "cancel",
                "label": "取消",
                "description": "先停止本次执行，稍后再继续。",
            },
        ],
        "response_schema": {
            "type": "object",
            "required": ["action"],
            "properties": properties,
        },
        "input_normalization": {
            "enabled": True,
            "mode": "llm_assisted_structuring",
            "source": "user_free_text",
            "target": "response_json",
            "target_schema_ref": "response_schema",
            "allowed_actions": ["continue", "cancel"],
            "required_fields": [item.get("field") for item in missing_inputs if item.get("field")],
            "rules": [
                "可以将用户自然语言答复整理为符合 response_schema 的 JSON 对象。",
                "必须忠实保留用户意图，不得替用户做决定，不得脑补未提供的事实。",
                "如果用户补充了源码工程目录或分支信息，请写入对应字段后继续。",
                "缺失字段必须按 missing_inputs / fallback_inputs 明确区分，不能笼统写成“缺少信息”。",
            ],
        },
        "resume_hint": "补充缺失业务信息后继续执行 Step1。",
        "runtime_rules": [
            "看到 awaiting_user_input 后，必须先向用户索要缺失业务信息，再决定是否继续。",
            "禁止把内部实现细节直接暴露给用户。",
        ],
        "next_action_rule": "只能向用户补充缺失业务信息并等待回复，不得继续执行后续步骤。",
        "must_wait_for_user_reply": True,
    }


def build_step1_coordinate_followup_interaction(
    *,
    side,
    side_cn,
    artifact_path,
    unresolved_items=None,
    branch_field="",
    branch_value="",
    source_field="",
    source_value="",
    primary_module="",
):
    _ = branch_field
    unresolved_items = normalize_unresolved_items(unresolved_items)
    unresolved_labels = [item.get("label", "") for item in unresolved_items if item.get("label")]
    has_unconfirmed_version = any(
        str(item.get("reason_code") or "").strip()
        == "PACKAGED_VERSION_UNCONFIRMED"
        for item in unresolved_items
    )
    has_unresolved_coordinate = any(
        str(item.get("reason_code") or "").strip()
        != "PACKAGED_VERSION_UNCONFIRMED"
        for item in unresolved_items
    )
    properties = {
        "action": {
            "type": "string",
            "enum": ["continue", "confirm_unresolved", "cancel"],
        },
        "notes": {
            "type": "string",
            "description": "记录用户补充说明，特别是模块范围、源码目录或无法继续的原因。",
        },
        "manual_coord_overrides": {
            "type": "array",
            "description": (
                "可选。补充本轮新增坐标，格式为 artifact:version[:classifier] -> group:artifact；"
                "系统会与前几轮已提交的坐标合并。"
            ),
        },
        "manual_artifact_identities": {
            "type": "array",
            "description": (
                "可选。仅当最终制品无法确认版本或完整身份时，"
                "按 fat JAR 物理条目提交人工确认。"
            ),
            "items": {
                "type": "object",
                "required": [
                    "side", "lib_entry", "group_id", "artifact_id", "version"
                ],
                "properties": {
                    "side": {"type": "string", "enum": ["base", "current"]},
                    "lib_entry": {"type": "string"},
                    "group_id": {"type": "string"},
                    "artifact_id": {"type": "string"},
                    "version": {"type": "string"},
                    "classifier": {"type": "string"},
                },
            },
        },
    }
    missing_inputs = []
    fallback_inputs = []
    required_fields = []
    checklist_lines = [
        f"{side_cn}产物中的部分嵌套依赖即使在已提供补全信息后仍无法安全确认完整身份。",
        f"{side_cn}产物: {artifact_path}",
    ]
    if unresolved_labels:
        checklist_lines.append("未识别的嵌套依赖: " + ", ".join(unresolved_labels[:10]))
        checklist_lines.append("允许人工补充坐标，格式：artifact:version[:classifier] -> group:artifact")
        if any(
            str(item.get("reason_code") or "").strip()
            == "PACKAGED_VERSION_UNCONFIRMED"
            for item in unresolved_items
        ):
            checklist_lines.append(
                "最终制品未能确认版本的条目，必须使用 "
                "manual_artifact_identities 按 side + lib_entry 确认完整身份。"
            )
        checklist_lines.append("未补齐的 unresolved 会保留在 s1_dep_changes.csv，并标记为 unresolved；后续步骤会跳过这些行。")
    if branch_value:
        checklist_lines.append(f"已尝试的 {side_cn}分支: {branch_value}")
    if source_value:
        checklist_lines.append(f"已尝试的 {side_cn}源码目录: {source_value}")
    if primary_module:
        checklist_lines.append(f"当前 primary_module: {primary_module}")

    if has_unconfirmed_version:
        missing_inputs.append(
            {
                "field": "manual_artifact_identities",
                "label": "物理条目完整身份确认",
                "side": side,
                "required": True,
                "recommended": True,
                "reason": (
                    "fat JAR 本身无法唯一确认版本；"
                    "dependency:list 只能补齐坐标，不能作为版本真相源。"
                ),
                "artifact_path": artifact_path,
                "value_type": "artifact_identity_array",
            }
        )
        required_fields.append("manual_artifact_identities")

    if has_unresolved_coordinate and not str(primary_module or "").strip():
        properties["primary_module"] = {
            "type": "string",
            "description": "目标模块名。仅支持单模块；应与用户提供的编译产物所属模块一致。",
        }
        missing_inputs.append(
            {
                "field": "primary_module",
                "label": "目标模块",
                "side": side,
                "required": True,
                "recommended": True,
                "reason": "未指定 primary_module 时，`dependency:list` 在多模块场景下可能返回过宽结果，导致坐标无法唯一补全。",
                "artifact_path": artifact_path,
                "value_type": "string",
            }
        )
        required_fields.append("primary_module")
        checklist_lines.append("优先补充: primary_module（与该产物所属模块保持一致）")

    if (
        has_unresolved_coordinate
        and source_field
        and not str(source_value or "").strip()
    ):
        properties[source_field] = {
            "type": "string",
            "description": f"{side_cn}源码工程目录。用于在当前补全口径仍不足时，直接从该侧源码工程执行 Maven 解析。",
        }
        item = {
            "field": source_field,
            "label": f"{side_cn}源码工程目录",
            "side": side,
            "required": not bool(required_fields),
            "recommended": True,
            "reason": "当前仅靠已提供的 branch 补全仍不足以唯一确认坐标；可改用该侧源码工程目录作为更精确的 Maven 解析入口。",
            "artifact_path": artifact_path,
            "value_type": "path",
        }
        if required_fields:
            fallback_inputs.append(item)
            checklist_lines.append(f"兜底补充: {source_field}")
        else:
            missing_inputs.append(item)
            required_fields.append(source_field)
            checklist_lines.append(f"优先补充: {source_field}")

    kind = "input_request" if missing_inputs or fallback_inputs else "review"
    question = (
        f"{side_cn}产物里仍有嵌套依赖无法安全确认完整 Maven 身份。"
    )
    if unresolved_labels:
        question += f" 未识别项包括：{', '.join(unresolved_labels[:10])}。"
    if "manual_artifact_identities" in required_fields:
        question += (
            " 请按 `side + lib_entry` 补充 "
            "`manual_artifact_identities`。"
        )
    elif "primary_module" in required_fields:
        question += " 请先补充 `primary_module`。"
    elif source_field and source_field in required_fields:
        question += f" 请补充 `{source_field}`。"
    elif source_field and source_field in properties:
        question += f" 若 branch 口径仍不够，请补充 `{source_field}`，也可补充 `manual_coord_overrides`。"
    else:
        question += " 请先人工确认该产物是否包含大量 filename-only 嵌套 jar，以及当前补全来源是否正确；也可补充 `manual_coord_overrides`。"

    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": kind,
        "step_id": "step1",
        "reason_code": DEPENDENCY_COORDINATES_UNRESOLVED,
        "reason_code_aliases": [
            "unresolved_dependency_coordinates_after_enrichment",
        ],
        "origin_step": "step1",
        "diagnostic_guidance_schema": REASON_GUIDANCE_SCHEMA,
        "diagnostic_guidance": guidance_for_reason_code(
            DEPENDENCY_COORDINATES_UNRESOLVED
        ),
        "summary": "Step1 已尝试根据最终制品与已有 branch/source 信息补全身份，但仍有条目无法安全确认坐标或版本。",
        "title": "step1 仍需进一步确认制品身份",
        "question": question,
        "files_to_review": [artifact_path] if artifact_path else [],
        "required_fields": required_fields,
        "missing_inputs": missing_inputs,
        "fallback_inputs": fallback_inputs,
        "checklist_lines": checklist_lines,
        "unresolved_items": unresolved_items,
        "options": [
            {
                "id": "continue",
                "label": "补充信息后继续",
                "description": "补充模块范围、更精确的源码目录或人工补充坐标后，继续重跑 Step1。",
            },
            {
                "id": "confirm_unresolved",
                "label": "人工确认后继续",
                "description": "允许未补齐的 unresolved 保留在 Step1 输出中并标记为 unresolved，后续步骤会跳过这些行。",
            },
            {
                "id": "cancel",
                "label": "取消",
                "description": "先停止本次执行，待确认产物与补全口径后再继续。",
            },
        ],
        "response_schema": {
            "type": "object",
            "required": ["action"],
            "properties": properties,
        },
        "input_normalization": {
            "enabled": True,
            "mode": "llm_assisted_structuring",
            "source": "user_free_text",
            "target": "response_json",
            "target_schema_ref": "response_schema",
            "allowed_actions": ["continue", "confirm_unresolved", "cancel"],
            "required_fields": required_fields,
            "rules": [
                "可以将用户自然语言答复整理为符合 response_schema 的 JSON 对象。",
                "必须忠实保留用户提供的模块名、源码目录，不得脑补。",
                "如果用户补充了 primary_module，应确保它与编译产物所属模块一致。",
                "若用户未提供能改变补全结果的新信息，不要直接继续重试。",
                "如果用户人工补充坐标，统一整理成 artifact:version[:classifier] -> group:artifact。",
                "如果 reason_code 为 PACKAGED_VERSION_UNCONFIRMED，必须按 side + lib_entry 整理为 manual_artifact_identities，不得使用 dependency:list 版本代替人工确认。",
                "如果用户明确接受 unresolved 保留并继续，应使用 action=confirm_unresolved。",
            ],
        },
        "resume_hint": "可补充模块范围、源码目录、人工坐标或物理条目完整身份，也可显式确认 unresolved 后继续执行 Step1。",
        "runtime_rules": [
            f"看到 {DEPENDENCY_COORDINATES_UNRESOLVED} 后，必须先向用户暴露未识别的嵌套依赖和已尝试的补全来源。",
            "禁止把这类失败压成通用 rc=1 或继续盲重试。",
            "只有用户明确选择 confirm_unresolved，才允许保留 unresolved 行并继续。",
        ],
        "next_action_rule": "只能向用户说明哪些嵌套依赖仍无法识别，并等待用户补充新的模块/源码信息或确认 unresolved 处理方式。",
        "must_wait_for_user_reply": True,
    }


def parse_manual_coord_overrides(raw_values):
    overrides = {}
    invalid_entries = []
    for raw in raw_values or []:
        text = str(raw or "").strip()
        if not text:
            continue
        if "->" not in text:
            invalid_entries.append(text)
            continue
        left, right = [part.strip() for part in text.split("->", 1)]
        if ":" not in left or ":" not in right:
            invalid_entries.append(text)
            continue
        left_parts = [part.strip() for part in left.split(":", 2)]
        artifact_id = left_parts[0]
        version = left_parts[1] if len(left_parts) >= 2 else ""
        classifier = left_parts[2] if len(left_parts) >= 3 else ""
        group_id, target_artifact_id = [part.strip() for part in right.split(":", 1)]
        if not artifact_id or not version or not group_id or not target_artifact_id:
            invalid_entries.append(text)
            continue
        key = (
            (artifact_id, version, classifier)
            if classifier
            else (artifact_id, version)
        )
        overrides[key] = {
            "group_id": group_id,
            "artifact_id": target_artifact_id,
            "coord": f"{group_id}:{target_artifact_id}",
            "classifier": classifier,
            "raw": text,
        }
    return overrides, invalid_entries


def parse_manual_artifact_identities(raw_values):
    """Normalize user-confirmed identities keyed by one physical fat-JAR entry."""
    identities = []
    invalid_entries = []
    seen = set()
    for raw in raw_values or []:
        item = raw
        if isinstance(raw, str):
            try:
                item = json.loads(raw)
            except Exception:
                invalid_entries.append(raw)
                continue
        if not isinstance(item, dict):
            invalid_entries.append(str(raw))
            continue
        side = str(item.get('side') or '').strip()
        entry_id = str(item.get('entry_id') or '').strip()
        lib_entry = str(item.get('lib_entry') or '').strip()
        group_id = str(item.get('group_id') or '').strip()
        artifact_id = str(item.get('artifact_id') or '').strip()
        version = str(item.get('version') or '').strip()
        classifier = str(item.get('classifier') or '').strip()
        if (
            side not in {'base', 'current'}
            or not (entry_id or lib_entry)
            or not group_id
            or not artifact_id
            or not version
        ):
            invalid_entries.append(
                json.dumps(item, ensure_ascii=False, sort_keys=True)
            )
            continue
        normalized = {
            'side': side,
            'entry_id': entry_id or lib_entry,
            'lib_entry': lib_entry or entry_id,
            'group_id': group_id,
            'artifact_id': artifact_id,
            'version': version,
            'classifier': classifier,
            'coord': normalize_artifact_coord(
                f'{group_id}:{artifact_id}', classifier
            ),
        }
        key = (
            normalized['side'], normalized['entry_id'], normalized['lib_entry'],
            normalized['coord'], normalized['version'],
        )
        if key in seen:
            continue
        seen.add(key)
        identities.append(normalized)
    return identities, invalid_entries


def _manual_artifact_identity_for_entry(
    packaged_item,
    manual_artifact_identities,
    side="",
):
    packaged_entry_id = str((packaged_item or {}).get('entry_id') or '').strip()
    packaged_lib_entry = str((packaged_item or {}).get('lib_entry') or '').strip()
    packaged_side = str(
        (packaged_item or {}).get('side') or side or ''
    ).strip()
    matches = []
    for identity in manual_artifact_identities or []:
        if identity.get('side') != packaged_side:
            continue
        selectors = {
            str(identity.get('entry_id') or '').strip(),
            str(identity.get('lib_entry') or '').strip(),
        } - {''}
        packaged_selectors = {
            packaged_entry_id, packaged_lib_entry,
        } - {''}
        if selectors.intersection(packaged_selectors):
            matches.append(identity)
    distinct = {
        (item.get('coord'), item.get('version')): item
        for item in matches
    }
    return (
        next(iter(distinct.values())) if len(distinct) == 1 else None,
        list(distinct.values()),
    )


def parse_confirmed_unresolved_items(raw_values):
    parsed_items = []
    invalid_entries = []
    for raw in raw_values or []:
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except Exception:
            invalid_entries.append(text)
            continue
        if not isinstance(item, dict):
            invalid_entries.append(text)
            continue
        parsed_items.append(item)
    return normalize_unresolved_items(parsed_items), invalid_entries


def attach_unresolved_side(unresolved_items, side):
    normalized = []
    for item in normalize_unresolved_items(unresolved_items):
        tagged = dict(item)
        tagged["side"] = str(side or "").strip()
        normalized.append(tagged)
    return normalized


def _infer_maven_failure_causes(stderr_excerpt):
    text = str(stderr_excerpt or "").lower()
    causes = []
    if any(token in text for token in ("invalid target release", "release version", "source option", "target option")):
        causes.append("JDK 版本与目标分支的 Maven/Compiler 配置不兼容。")
    if "unsupported class file major version" in text:
        causes.append("当前 JDK 与依赖或插件产物的 class 版本不兼容。")
    if "java_home" in text and "not defined correctly" in text:
        causes.append("JAVA_HOME 配置无效，Maven 无法启动正确的 JDK。")
    if any(token in text for token in ("could not resolve dependencies", "non-resolvable parent pom", "failure to find")):
        causes.append("依赖仓库或父 POM 不可用，导致 Maven 无法解析依赖。")
    if any(token in text for token in ("the goal you specified requires a project", "could not find the selected project in the reactor")):
        causes.append("执行目录或模块选择不正确，可能没有在根 pom.xml 所在目录执行。")
    if not causes:
        causes.append("Maven 命令执行失败，请检查 JDK、仓库凭据、根目录和模块参数。")
    return causes


def _infer_gradle_failure_causes(stderr_excerpt):
    text = str(stderr_excerpt or "").lower()
    causes = []
    if _is_gradle_lock_contention(text):
        causes.append(
            "Gradle 缓存或 Wrapper 文件锁被其他进程占用；"
            "Step1 已对原命令完成有限退避重试，未删除锁或停止其他构建。"
        )
    if any(token in text for token in ("invalid source release", "unsupported class file major version", "could not target platform")):
        causes.append("JDK 版本与目标分支的 Gradle/Java 配置不兼容。")
    if "java_home" in text or "java installation" in text:
        causes.append("JAVA_HOME 或 Gradle toolchain 配置无效。")
    if any(token in text for token in ("could not resolve all files", "could not resolve all dependencies", "could not find")):
        causes.append("依赖仓库、插件仓库或凭据不可用，导致 Gradle 无法解析依赖。")
    if any(token in text for token in ("task ':", "task with path", "configuration with name 'runtimeclasspath' not found")):
        causes.append("目标模块、构建任务或 runtimeClasspath 配置不存在。")
    if not causes:
        causes.append("Gradle 命令执行失败，请检查 Wrapper、JDK、仓库凭据、根目录和模块参数。")
    return causes


def _infer_step1_blocked_causes(stage, stderr_excerpt):
    if stage in {"mvn_dependency_list", "mvn_package"}:
        return _infer_maven_failure_causes(stderr_excerpt)
    if str(stage or "").startswith("gradle_"):
        return _infer_gradle_failure_causes(stderr_excerpt)
    text = str(stderr_excerpt or "").lower()
    causes = []
    if stage == "prepare_java_env":
        causes.append("提供的 JDK Home 无效，或该目录下缺少可执行的 bin/java。")
    elif stage in {"prepare_branch_worktree", "cleanup_branch_worktree"}:
        if "already registered" in text or "already checked out" in text:
            causes.append("目标分支已存在同名 worktree 或仍被其他 worktree 占用。")
        if "not a git repository" in text:
            causes.append("当前目录不是有效的 Git 仓库，无法创建临时 worktree。")
        if "permission" in text:
            causes.append("当前用户对仓库目录或临时目录权限不足，无法管理 worktree。")
        if any(token in text for token in (
            "filename too long",
            "file name too long",
            "path too long",
            "filename or extension is too long",
        )):
            causes.append("Windows worktree 路径超过工具可处理的长度；Step1 已尝试短路径和 Git 长路径模式。")
        if not causes:
            causes.append("Git worktree 初始化或清理失败，请检查仓库状态与 `.git/worktrees`。")
    if not causes:
        causes.append("Step1 执行准备阶段失败，请检查本地环境与仓库状态。")
    return causes


def build_step1_command_blocked_error(
    *,
    stage,
    command,
    exc,
    side="",
    branch="",
    jdk_field="",
    jdk_home="",
    source_mode="",
    source_project_dir="",
    artifact_path="",
):
    side = str(side or "").strip()
    resolved_jdk_field = str(jdk_field or "").strip()
    if not resolved_jdk_field and side in {"base", "current"}:
        resolved_jdk_field = f"{side}_jdk_home"
    return Step1CommandExecutionBlockedError(
        stage=stage,
        command=command,
        stderr_excerpt=str(exc or "").strip(),
        side=side,
        branch=str(branch or "").strip(),
        jdk_field=resolved_jdk_field,
        jdk_home=resolve_effective_jdk_home(jdk_home),
        source_mode=str(source_mode or "").strip(),
        source_project_dir=str(source_project_dir or "").strip(),
        artifact_path=str(artifact_path or "").strip(),
        suspected_causes=_infer_step1_blocked_causes(stage, str(exc or "")),
    )


def build_step1_command_blocked_from_exception(
    exc,
    *,
    default_stage,
    default_command,
    **context,
):
    if isinstance(exc, GradleCommandFailure):
        stage = exc.stage
        command = exc.command
    else:
        stage = default_stage
        command = default_command
    return build_step1_command_blocked_error(
        stage=stage,
        command=command,
        exc=exc,
        **context,
    )


def append_cleanup_failure_to_blocked_error(blocked_error, cleanup_exc):
    cleanup_message = f"临时 worktree 清理失败：{cleanup_exc}"
    if isinstance(blocked_error, Step1CommandExecutionBlockedError):
        if blocked_error.stderr_excerpt:
            blocked_error.stderr_excerpt = f"{blocked_error.stderr_excerpt}；此外{cleanup_message}"
        else:
            blocked_error.stderr_excerpt = cleanup_message
        extra_cause = "临时 worktree 清理失败，请手工执行 `git worktree prune` 并检查 `.git/worktrees`。"
        if extra_cause not in blocked_error.suspected_causes:
            blocked_error.suspected_causes.append(extra_cause)
        return blocked_error
    return RuntimeError(f"{blocked_error}；此外{cleanup_message}")


def resolve_effective_jdk_home(jdk_home):
    home = str(jdk_home or "").strip()
    if not home:
        home = str(os.environ.get("JAVA_HOME") or "").strip()
    if not home:
        return ""
    return str(Path(home).expanduser().resolve())


def add_branch_hint_to_env(env, branch):
    merged_env = dict(env or {})
    normalized_branch = str(branch or "").strip()
    if normalized_branch:
        merged_env["JUA_GIT_BRANCH_HINT"] = normalized_branch
    return merged_env


def build_step1_command_blocked_interaction(error):
    blocked = error if isinstance(error, Step1CommandExecutionBlockedError) else Step1CommandExecutionBlockedError(
        stage="build_command",
        command="",
        stderr_excerpt=str(error or ""),
    )
    properties = {
        "action": {
            "type": "string",
            "enum": ["continue", "cancel"],
        },
        "notes": {
            "type": "string",
            "description": "记录用户确认的处理动作、环境修复说明或补充备注。",
        },
    }
    missing_inputs = []
    required_fields = []
    is_gradle = blocked.stage.startswith("gradle_") or "gradle" in blocked.command.lower()
    is_git_worktree = blocked.stage in {"prepare_branch_worktree", "cleanup_branch_worktree"}
    execution_tool_name = "Git worktree" if is_git_worktree else ("Gradle" if is_gradle else "Maven")
    checklist_lines = [
        f"这不是缺少业务参数，而是 Step1 已拿到必要输入后执行 {execution_tool_name} 命令时被环境阻塞。",
    ]
    files_to_review = []
    if blocked.artifact_path:
        files_to_review.append(blocked.artifact_path)
        checklist_lines.append(f"相关产物: {blocked.artifact_path}")
    if blocked.branch:
        checklist_lines.append(f"失败分支: {blocked.branch}")
    if blocked.command:
        checklist_lines.append(f"失败命令: {blocked.command}")
    if blocked.source_mode:
        checklist_lines.append(f"补全来源: {blocked.source_mode}")
    if blocked.stderr_excerpt:
        checklist_lines.append(f"错误摘要: {blocked.stderr_excerpt}")
    for cause in blocked.suspected_causes:
        checklist_lines.append(f"可能原因: {cause}")
    if blocked.jdk_field and not is_git_worktree:
        properties[blocked.jdk_field] = {
            "type": "string",
            "description": f"目标分支对应的 JDK Home 目录；若提供后将按该 JDK 重新执行 {execution_tool_name} 命令。",
        }
        missing_inputs.append(
            {
                "field": blocked.jdk_field,
                "label": "JDK Home",
                "side": blocked.side,
                "required": False,
                "recommended": True,
                "reason": f"当前更像是 {execution_tool_name}/JDK 环境阻塞；若该侧需要不同 JDK，请补充对应 JDK Home。",
                "value_type": "path",
            }
        )
        if blocked.jdk_home:
            checklist_lines.append(f"当前该侧 JDK Home: {blocked.jdk_home}")
    question = f"Step1 已显式暴露本次 {execution_tool_name} 命令失败原因，请先处理环境阻塞后再决定是否继续。"
    if blocked.jdk_field and not is_git_worktree:
        question += f" 若需要由 skill 继续重跑，可补充 `{blocked.jdk_field}`。"
    if is_git_worktree:
        reason_code = "step1_git_worktree_command_blocked"
        continue_description = "Step1 已自动尝试短路径和 Git 长路径模式；环境问题修复后继续重跑。"
        resume_hint = "确认错误摘要中的 worktree 路径与环境限制后，再继续执行 Step1。"
    elif is_gradle:
        reason_code = "step1_gradle_command_blocked"
        continue_description = "用户已修复环境问题，或补充了该侧 JDK Home，继续重跑 Step1。"
        resume_hint = "修复环境问题或补充 JDK Home 后，再继续执行 Step1。"
    else:
        reason_code = "step1_maven_command_blocked"
        continue_description = "用户已修复环境问题，或补充了该侧 JDK Home，继续重跑 Step1。"
        resume_hint = "修复环境问题或补充 JDK Home 后，再继续执行 Step1。"
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "execution_blocked",
        "step_id": "step1",
        "reason_code": reason_code,
        "summary": f"Step1 已进入执行阶段，但 {execution_tool_name} 命令被环境问题阻塞；必须先显式暴露原因并等待用户决策。",
        "title": "step1 执行被环境阻塞",
        "question": question,
        "files_to_review": files_to_review,
        "required_fields": required_fields,
        "missing_inputs": missing_inputs,
        "fallback_inputs": [],
        "checklist_lines": checklist_lines,
        "blocked_stage": blocked.stage,
        "blocked_command": blocked.command,
        "blocked_branch": blocked.branch,
        "stderr_excerpt": blocked.stderr_excerpt,
        "suspected_causes": blocked.suspected_causes,
        "options": [
            {
                "id": "continue",
                "label": "修复后继续",
                "description": continue_description,
            },
            {
                "id": "cancel",
                "label": "取消",
                "description": "先停止本次执行，待环境修复后再继续。",
            },
        ],
        "response_schema": {
            "type": "object",
            "required": ["action"],
            "properties": properties,
        },
        "input_normalization": {
            "enabled": True,
            "mode": "llm_assisted_structuring",
            "source": "user_free_text",
            "target": "response_json",
            "target_schema_ref": "response_schema",
            "allowed_actions": ["continue", "cancel"],
            "required_fields": [],
            "rules": [
                "可以将用户自然语言答复整理为符合 response_schema 的 JSON 对象。",
                "必须忠实保留用户意图，不得把环境阻塞误判为缺少业务参数。",
                (
                    "Git worktree 阻塞不需要补充 JDK Home，应按错误摘要处理路径或权限环境。"
                    if is_git_worktree
                    else "若用户补充了对应侧 JDK Home，请写入该字段后再继续。"
                ),
                "若用户只是确认稍后处理，应选择 cancel，不要无条件重试。",
            ],
        },
        "resume_hint": resume_hint,
        "runtime_rules": [
            "看到 execution_blocked 后，必须先向用户暴露失败原因，再等待用户决定是否继续。",
            f"禁止把 {execution_tool_name} 执行失败伪装成“缺少信息”或继续盲重试。",
        ],
        "next_action_rule": f"只能向用户说明 {execution_tool_name} 命令失败原因并等待回复，不得继续执行后续步骤。",
        "must_wait_for_user_reply": True,
    }


def build_java_env(jdk_home):
    home = resolve_effective_jdk_home(jdk_home)
    if not home:
        return {}
    home_path = Path(home)
    java_bin = home_path / "bin" / ("java.exe" if IS_WINDOWS else "java")
    if not home_path.is_dir() or not java_bin.exists():
        raise RuntimeError(f"JDK Home 无效：{home_path}（缺少 bin/java）")
    env = {"JAVA_HOME": str(home_path)}
    current_path = os.environ.get("PATH", "")
    env["PATH"] = str(home_path / "bin") + (os.pathsep + current_path if current_path else "")
    return env


def _strip_info_prefix(line):
    return re.sub(r'^\s*\[INFO\]\s*', '', line.rstrip('\r\n'))


def _normalize_version_text(version):
    value = (version or '').strip()
    if not value:
        return ''
    value = value.lstrip('vV')
    value = value.split('+', 1)[0]
    value = re.sub(r'(?i)[.\-_]?(RELEASE|FINAL|GA|JRE|ANDROID)$', '', value)
    return value.strip('._-')


def parse_version_info(version):
    """
    解析常见 Maven/Gradle 版本号，兼容预发布后缀。

    返回：
      {
        'base': [major, minor, patch, ...],
        'stage_rank': int,
        'stage_num': int,
        'text': str,
      }
    """
    normalized = _normalize_version_text(version)
    if not normalized:
        return None

    stage_rank_map = {
        'snapshot': -5,
        'alpha': -4,
        'a': -4,
        'beta': -3,
        'b': -3,
        'milestone': -2,
        'm': -2,
        'rc': -1,
        'cr': -1,
        'sp': 1,
        'sr': 1,
    }

    tokens = re.findall(r'[A-Za-z]+|\d+', normalized)
    if not tokens:
        return None

    base = []
    idx = 0
    while idx < len(tokens) and tokens[idx].isdigit():
        base.append(int(tokens[idx]))
        idx += 1

    if not base:
        return None

    stage_rank = 0
    stage_num = 0
    qualifier = ''
    if idx < len(tokens):
        qualifier = tokens[idx].lower()
        stage_rank = stage_rank_map.get(qualifier, -6)
        idx += 1
        if idx < len(tokens) and tokens[idx].isdigit():
            stage_num = int(tokens[idx])

    return {
        'base': base,
        'stage_rank': stage_rank,
        'stage_num': stage_num,
        'text': normalized,
        'qualifier': qualifier,
    }


def compare_versions(old_ver, new_ver):
    """
    比较两个版本号。
    返回：
      1  -> old_ver > new_ver
      0  -> 相等
      -1 -> old_ver < new_ver
    """
    left = parse_version_info(old_ver)
    right = parse_version_info(new_ver)
    if not left or not right:
        return 0

    max_len = max(len(left['base']), len(right['base']))
    left_nums = left['base'] + [0] * (max_len - len(left['base']))
    right_nums = right['base'] + [0] * (max_len - len(right['base']))

    if left_nums > right_nums:
        return 1
    if left_nums < right_nums:
        return -1

    left_stage = (left['stage_rank'], left['stage_num'])
    right_stage = (right['stage_rank'], right['stage_num'])
    if left_stage > right_stage:
        return 1
    if left_stage < right_stage:
        return -1

    if left['text'] == right['text']:
        return 0
    return 0


def normalize_primary_module(primary_module):
    item = (primary_module or '').strip()
    if not item:
        return None
    if item.startswith(':'):
        item = item[1:]
    if '/' in item:
        item = item.split('/')[-1]
    if '\\' in item:
        item = item.split('\\')[-1]
    if ':' in item:
        item = item.split(':')[-1]
    return item.strip() or None


def resolve_module_ids(modules, work_dir):
    if modules in (None, ""):
        return []
    if isinstance(modules, str):
        raw_items = [modules]
    elif isinstance(modules, (list, tuple, set)):
        raw_items = list(modules)
    else:
        return []
    resolved = []
    for item in raw_items:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if not value:
            continue
        if value in (".", "./", "__root__", "root"):
            resolved.append("__root__")
            continue
        resolved_id = resolve_primary_module_id(value, work_dir) or normalize_primary_module(value)
        if resolved_id:
            resolved.append(resolved_id)
    return resolved


def _resolve_single_module_selector(primary_module, modules, work_dir):
    raw_modules = []
    if modules in (None, ""):
        raw_modules = []
    elif isinstance(modules, str):
        raw_modules = [modules]
    elif isinstance(modules, (list, tuple, set)):
        raw_modules = list(modules)
    else:
        raise RuntimeError("Step1 的模块参数格式不正确，只支持单模块。")

    normalized = []
    for item in raw_modules:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if not value:
            continue
        normalized_id = resolve_primary_module_id(value, work_dir) or normalize_primary_module(value) or value
        normalized.append((value, normalized_id))

    primary_raw = str(primary_module or '').strip()
    primary_id = resolve_primary_module_id(primary_raw, work_dir) if primary_raw else None
    if primary_raw:
        primary_id = primary_id or normalize_primary_module(primary_raw) or primary_raw

    unique_ids = []
    seen_ids = set()
    for raw_value, normalized_id in normalized:
        if normalized_id in seen_ids:
            continue
        seen_ids.add(normalized_id)
        unique_ids.append((raw_value, normalized_id))

    if len(unique_ids) > 1:
        requested = ", ".join(raw for raw, _ in unique_ids)
        raise RuntimeError(f"Step1 现在只支持单模块，当前收到多个模块：{requested}")

    if primary_raw and unique_ids and primary_id != unique_ids[0][1]:
        raise RuntimeError(
            f"Step1 现在只支持单模块，但 --primary-module={primary_raw} 与 --modules={unique_ids[0][0]} 不一致"
        )

    if primary_raw:
        return primary_raw
    if unique_ids:
        return unique_ids[0][0]
    return '.'


def resolve_primary_module_id(primary_module, work_dir):
    if not primary_module:
        return None

    raw = str(primary_module).strip()
    if not raw:
        return None

    normalized = raw.replace("\\", "/").strip()
    looks_like_pom = normalized.lower().endswith("/pom.xml") or normalized.lower() == "pom.xml"
    if not looks_like_pom:
        return normalize_primary_module(raw)

    pom_path = Path(raw)
    if work_dir and not pom_path.is_absolute():
        pom_path = Path(work_dir) / pom_path
    try:
        if pom_path.exists() and pom_path.is_file():
            with open_text(str(pom_path)) as f:
                text = f.read()
            root = ET.fromstring(text)

            def strip_ns(tag):
                return tag.split("}", 1)[-1] if "}" in tag else tag

            for child in list(root):
                if strip_ns(child.tag) == "artifactId" and (child.text or "").strip():
                    return (child.text or "").strip()
    except (OSError, ET.ParseError, UnicodeError) as exc:
        print(f"⚠️ 无法读取目标模块 POM {pom_path}: {type(exc).__name__}: {exc}", file=sys.stderr)

    try:
        return pom_path.parent.name or None
    except Exception:
        return None


def _strip_xml_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _read_pom_identity(pom_path):
    try:
        with open_text(str(pom_path)) as f:
            text = f.read()
        root = ET.fromstring(text)
    except Exception:
        return '', ''

    group_id = ''
    artifact_id = ''
    parent_group = ''
    for child in list(root):
        tag = _strip_xml_ns(child.tag)
        value = (child.text or '').strip()
        if tag == 'groupId' and value and not group_id:
            group_id = value
        elif tag == 'artifactId' and value and not artifact_id:
            artifact_id = value
        elif tag == 'parent':
            for nested in list(child):
                if _strip_xml_ns(nested.tag) == 'groupId' and (nested.text or '').strip():
                    parent_group = (nested.text or '').strip()
                    break
    return group_id or parent_group, artifact_id


def _looks_like_artifact_candidate(path_obj):
    name = path_obj.name.lower()
    if path_obj.suffix.lower() not in ('.jar', '.war'):
        return False
    excluded_fragments = (
        '-sources.jar',
        '-javadoc.jar',
        '-tests.jar',
        '-test.jar',
        '.original',
        '-plain.jar',
    )
    return not any(fragment in name for fragment in excluded_fragments)


def _resolve_module_dir_for_packaging(selector, work_dir):
    root_dir = Path(work_dir or '.').resolve()
    raw = str(selector or '').strip()
    if not raw or raw in ('.', './', '__root__', 'root'):
        return root_dir

    normalized = raw.replace('\\', '/').strip()
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root_dir / candidate
    if candidate.exists():
        if candidate.is_file() and candidate.name == 'pom.xml':
            return candidate.parent.resolve()
        if candidate.is_dir():
            return candidate.resolve()

    direct_dir = root_dir / normalized
    if direct_dir.is_dir():
        return direct_dir.resolve()

    target_artifact = ''
    target_group = ''
    if ':' in raw:
        target_group, target_artifact = [item.strip() for item in raw.rsplit(':', 1)]
    else:
        target_artifact = normalize_primary_module(raw) or ''

    matches = []
    for pom_path in root_dir.rglob('pom.xml'):
        if any(part in {'target', 'build', '.git', '.idea', '.upgrade-report'} for part in pom_path.parts):
            continue
        group_id, artifact_id = _read_pom_identity(pom_path)
        if target_group and target_artifact:
            if group_id == target_group and artifact_id == target_artifact:
                matches.append(pom_path.parent.resolve())
        elif target_artifact:
            if artifact_id == target_artifact or pom_path.parent.name == target_artifact:
                matches.append(pom_path.parent.resolve())

    if not matches:
        discovery = discover_project_modules(root_dir)
        selector_normalized = raw.replace('\\', '/').rstrip('/')
        for item in discovery.get('modules') or []:
            aliases = {
                str(item.get('module') or ''),
                str(item.get('gradle_path') or ''),
                str(item.get('artifact_id') or ''),
                str(item.get('coord') or ''),
                Path(str(item.get('module_dir') or '')).name,
            }
            if selector_normalized in aliases:
                matches.append(Path(item['module_dir']).resolve())

    if not matches:
        return None
    matches.sort(key=lambda item: (len(item.parts), str(item)))
    return matches[0]


def _discover_packaged_archives(module_dir):
    archives = []
    seen = set()
    for rel_dir in ('target', os.path.join('build', 'libs')):
        candidate_dir = module_dir / rel_dir
        if not candidate_dir.exists() or not candidate_dir.is_dir():
            continue
        for pattern in ('*.jar', '*.war'):
            for artifact_path in candidate_dir.glob(pattern):
                if not artifact_path.is_file() or not _looks_like_artifact_candidate(artifact_path):
                    continue
                resolved = artifact_path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                archives.append(resolved)
    archives.sort(key=lambda item: (-item.stat().st_size, str(item)))
    return archives


def _parse_properties_text(text):
    data = {}
    for line in str(text or '').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or '=' not in stripped:
            continue
        key, value = stripped.split('=', 1)
        data[key.strip()] = value.strip()
    return data


def _parse_artifact_version_from_filename(name):
    stem = Path(name).name
    if stem.lower().endswith('.jar'):
        stem = stem[:-4]
    match = re.match(r'(.+)-(\d[\w.\-+]*)$', stem)
    if not match:
        return '', ''
    return match.group(1), match.group(2)


def _filename_stem(name):
    stem = re.split(r'[\\/]', str(name or ''))[-1]
    if stem.lower().endswith('.jar'):
        stem = stem[:-4]
    return stem


def _classifier_from_filename(name, artifact_id, version):
    stem = _filename_stem(name)
    artifact_id = str(artifact_id or '').strip()
    version = str(version or '').strip()
    if not stem or not artifact_id or not version:
        return ''
    version_first = f'{artifact_id}-{version}'
    if stem == version_first:
        return ''
    if stem.startswith(version_first + '-'):
        return stem[len(version_first) + 1:]
    classifier_first_prefix = f'{artifact_id}-'
    classifier_first_suffix = f'-{version}'
    if stem.startswith(classifier_first_prefix) and stem.endswith(classifier_first_suffix):
        return stem[len(classifier_first_prefix):-len(classifier_first_suffix)]
    return ''


def _physical_version_from_filename_coordinate(
    name,
    artifact_id,
    classifier='',
):
    """Read a version literal from a fat-JAR entry using coordinate fields only."""
    stem = _filename_stem(name)
    artifact_id = str(artifact_id or '').strip()
    classifier = str(classifier or '').strip()
    if not stem or not artifact_id:
        return ''
    prefix = f'{artifact_id}-'
    if not stem.startswith(prefix):
        return ''
    remainder = stem[len(prefix):]
    if not remainder:
        return ''
    if not classifier:
        return remainder if remainder[:1].isdigit() else ''
    classifier_prefix = f'{classifier}-'
    classifier_suffix = f'-{classifier}'
    if remainder.startswith(classifier_prefix):
        version = remainder[len(classifier_prefix):]
        return version if version[:1].isdigit() else ''
    if remainder.endswith(classifier_suffix):
        version = remainder[:-len(classifier_suffix)]
        return version if version[:1].isdigit() else ''
    return ''


def _runtime_candidate_filename_stems(item):
    group_id = str(item.get('group_id') or '').strip()
    artifact_id = str(item.get('artifact_id') or '').strip()
    classifier = str(item.get('classifier') or '').strip()
    versions = _runtime_artifact_versions(item)
    if not artifact_id or not versions:
        return set()
    stems = set()
    for version in versions:
        stems.add(f"{artifact_id}-{version}")
        if group_id:
            stems.add(f"{group_id}-{artifact_id}-{version}")
        if classifier:
            stems.add(f"{artifact_id}-{classifier}-{version}")
            stems.add(f"{artifact_id}-{version}-{classifier}")
    return stems


def _match_runtime_artifact_filename(name, artifact_id, version):
    """Use one runtime version only to test a possible filename interpretation.

    A successful match can identify a coordinate/classifier candidate, but it
    never confirms the packaged version; that must be read independently from
    the physical entry or supplied by a human.
    """
    stem = _filename_stem(name)
    artifact_id = str(artifact_id or '').strip()
    version = str(version or '').strip()
    if not stem or not artifact_id or not version:
        return False, '', ''

    version_first = f'{artifact_id}-{version}'
    if stem == version_first:
        return True, '', 'artifact-version'
    if stem.startswith(version_first + '-'):
        classifier = stem[len(version_first) + 1:]
        if classifier:
            return True, classifier, 'artifact-version-classifier'

    classifier_first_prefix = f'{artifact_id}-'
    classifier_first_suffix = f'-{version}'
    if (
        stem.startswith(classifier_first_prefix)
        and stem.endswith(classifier_first_suffix)
    ):
        classifier = stem[
            len(classifier_first_prefix):-len(classifier_first_suffix)
        ]
        if classifier:
            return True, classifier, 'artifact-classifier-version'
    return False, '', ''


def _runtime_dependency_for_packaged_filename(packaged_item, runtime_deps):
    """Return the strongest unique runtime identity for a physical JAR.

    Exact build-tool artifact inventory matches outrank conventional filename
    inference.  Gradle may still omit the selected artifact classifier, so the
    resolved component version anchors classifier extraction when needed.
    Never choose when two different final identities fit the same filename.
    """
    lib_name = str(
        (packaged_item or {}).get('lib_name')
        or re.split(
            r'[\\/]',
            str((packaged_item or {}).get('lib_entry') or ''),
        )[-1]
        or ''
    ).strip()
    packaged_version = str((packaged_item or {}).get('version') or '').strip()
    inventory_matches = {}
    inferred_matches = {}
    for raw_item in (runtime_deps or {}).values():
        candidate = dict(raw_item or {})
        group_id = str(candidate.get('group_id') or '').strip()
        artifact_id = str(candidate.get('artifact_id') or '').strip()
        versions = _runtime_artifact_versions(candidate)
        if not group_id or not artifact_id or not versions:
            continue
        inventory_filenames = {
            re.split(r'[\\/]', str(value or ''))[-1]
            for value in (
                list(candidate.get('artifact_file_names') or [])
                + [candidate.get('artifact_file_name')]
            )
            if str(value or '').strip()
        }
        exact_inventory_match = lib_name in inventory_filenames
        for version in versions:
            conventional_match, filename_classifier, conventional_layout = (
                _match_runtime_artifact_filename(
                    lib_name,
                    artifact_id,
                    version,
                )
            )
            matched = exact_inventory_match or conventional_match
            layout = (
                conventional_layout
                if conventional_match
                else 'artifact-inventory'
            )
            if not matched:
                continue
            declared_classifier = str(candidate.get('classifier') or '').strip()
            if (
                exact_inventory_match
                and not declared_classifier
                and len(inventory_filenames) > 1
                and not filename_classifier
                and not conventional_match
            ):
                # A component may expose multiple physical artifacts.  When
                # neither the build tool nor the conventional filename
                # identifies their classifiers, mapping all of them to the
                # same GA would silently collapse distinct artifacts.
                continue
            if (
                declared_classifier
                and filename_classifier
                and filename_classifier != declared_classifier
            ):
                continue
            effective_classifier = declared_classifier or filename_classifier
            coord = normalize_artifact_coord(
                candidate.get('coord') or f'{group_id}:{artifact_id}',
                effective_classifier,
            )
            candidate_match = dict(candidate)
            candidate_match.update({
                'coord': coord,
                'classifier': effective_classifier,
                'classifier_source': (
                    'runtime-coordinate'
                    if declared_classifier
                    else (
                        'runtime-version-filename-inference'
                        if filename_classifier
                        else 'none'
                    )
                ),
                # Kept only as matching provenance.  Enrichment must never use
                # this value as the packaged artifact's version truth.
                'matched_runtime_version': version,
                'physical_filename_version_match': conventional_match,
                'packaged_match_source': (
                    'runtime-artifact-inventory'
                    if exact_inventory_match
                    else (
                        'runtime-filename-classifier'
                        if effective_classifier
                        else 'runtime-filename'
                    )
                ),
                'filename_layout': layout,
            })
            target = inventory_matches if exact_inventory_match else inferred_matches
            # Version variants of one coordinate are intentionally one
            # coordinate candidate. dependency:list is not a version source.
            existing_match = target.get(coord)
            if existing_match is None or (
                packaged_version
                and candidate_match.get('matched_runtime_version') == packaged_version
                and existing_match.get('matched_runtime_version') != packaged_version
            ):
                target[coord] = candidate_match

    matches = inventory_matches or inferred_matches
    ordered = [
        matches[key]
        for key in sorted(matches)
    ]
    return (ordered[0] if len(ordered) == 1 else None), ordered


def _build_packaged_entry(entry_name):
    lib_entry = str(entry_name or '').strip()
    lib_name = Path(lib_entry).name if lib_entry else ''
    return {
        'entry_id': lib_entry,
        'lib_entry': lib_entry,
        'lib_name': lib_name,
        'coord': '',
        'group_id': '',
        'artifact_id': '',
        'version': '',
        'classifier': '',
        'filename_stem': _filename_stem(lib_name) if lib_name else '',
        'match_source': '',
        'resolution_status': 'resolved',
        'read_error': '',
        'metadata_anomalies': [],
    }


def _is_ignorable_packaging_support_dep(entry):
    artifact_id = str((entry or {}).get('artifact_id') or '').strip()
    lib_name = str((entry or {}).get('lib_name') or '').strip()
    filename_stem = str((entry or {}).get('filename_stem') or '').strip()
    candidate = artifact_id or filename_stem or _filename_stem(lib_name)
    return candidate.startswith('spring-boot-jarmode-')


def _extract_packaged_dep_from_nested_jar_source(source, entry_name, content_sha256):
    entry = _build_packaged_entry(entry_name)
    entry['content_sha256'] = str(content_sha256 or '')
    candidates = []
    metadata_errors = []
    try:
        with zipfile.ZipFile(source) as nested_zip:
            metadata_identities = defaultdict(set)
            for nested_info in nested_zip.infolist():
                nested_name = nested_info.filename
                if not nested_name.startswith('META-INF/maven/') or not nested_name.endswith('/pom.properties'):
                    continue
                try:
                    props_text = nested_zip.read(nested_info).decode('utf-8', errors='replace')
                except Exception as exc:
                    metadata_errors.append(
                        f"metadata_read_error:{nested_name}:"
                        f"{exc.__class__.__name__}:{exc}"
                    )
                    continue
                props = _parse_properties_text(props_text)
                group_id = (props.get('groupId') or '').strip()
                artifact_id = (props.get('artifactId') or '').strip()
                version = (props.get('version') or '').strip()
                if artifact_id and version:
                    classifier = _classifier_from_filename(entry_name, artifact_id, version)
                    identity = (group_id, artifact_id, version, classifier)
                    metadata_identities[nested_name].add(identity)
                    coord = f"{group_id}:{artifact_id}" if group_id else ''
                    if coord and classifier:
                        coord = f"{coord}:{classifier}"
                    candidates.append({
                        'coord': coord,
                        'group_id': group_id,
                        'artifact_id': artifact_id,
                        'version': version,
                        'classifier': classifier,
                        'match_source': 'embedded-pom',
                    })
            for nested_name, identities in sorted(metadata_identities.items()):
                if len(identities) <= 1:
                    continue
                declarations = '|'.join(
                    ':'.join(identity) for identity in sorted(identities)
                )
                entry['metadata_anomalies'].append(
                    f"maven_metadata_coordinate_conflict:{nested_name}:{declarations}"
                )
    except zipfile.BadZipFile as exc:
        entry['read_error'] = f"bad_nested_zip:{exc}"
    except Exception as exc:
        entry['read_error'] = f"nested_zip_error:{exc}"

    if metadata_errors:
        entry['read_error'] = ';'.join(metadata_errors)

    if entry['read_error']:
        entry.update({
            'match_source': 'embedded-metadata-read-error',
            'resolution_status': 'unresolved',
        })
        return entry

    distinct_candidates = {}
    for candidate in candidates:
        identity = (
            candidate['group_id'], candidate['artifact_id'],
            candidate['version'], candidate['classifier'],
        )
        distinct_candidates.setdefault(identity, candidate)
    candidates = list(distinct_candidates.values())

    if len(candidates) == 1:
        entry.update(candidates[0])
        return entry

    if candidates:
        filename_stem = _filename_stem(entry_name)
        matches = [
            candidate for candidate in candidates
            if filename_stem in _runtime_candidate_filename_stems(candidate)
        ]
        if len(matches) == 1:
            entry.update(matches[0])
            entry['match_source'] = 'embedded-pom-filename-match'
            return entry

        # Shaded/aggregate JARs may contain only dependency POMs. Keep their
        # owner coordinate empty and let the independently resolved Maven
        # runtime inventory perform the unique filename match below.

    stem = _filename_stem(entry_name)
    artifact_id, version = _parse_artifact_version_from_filename(entry_name)
    entry.update({
        'artifact_id': artifact_id or stem,
        'version': version,
        'filename_stem': stem,
        'match_source': 'filename',
    })
    return entry


def _extract_packaged_dep_from_nested_jar(blob, entry_name):
    return _extract_packaged_dep_from_nested_jar_source(
        io.BytesIO(blob), entry_name, hashlib.sha256(blob).hexdigest()
    )


def _stream_nested_jar_to_spool(outer_zip, entry):
    digest = hashlib.sha256()
    spool = tempfile.SpooledTemporaryFile(
        max_size=NESTED_JAR_SPOOL_MAX_MEMORY_BYTES,
        mode='w+b',
        dir=short_temp_root(),
    )
    try:
        with outer_zip.open(entry, 'r') as source:
            while True:
                chunk = source.read(NESTED_JAR_COPY_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                spool.write(chunk)
        spool.seek(0)
        return spool, digest.hexdigest()
    except BaseException:
        spool.close()
        raise


def _canonical_packaged_inventory_bytes(rows):
    return json.dumps(
        rows, ensure_ascii=False, sort_keys=True, separators=(',', ':')
    ).encode('utf-8')


def _packaged_inventory_rows_are_valid(rows):
    if not isinstance(rows, list):
        return False
    required = {
        'entry_id', 'lib_entry', 'lib_name', 'coord', 'group_id',
        'artifact_id', 'version', 'classifier', 'filename_stem',
        'match_source', 'resolution_status', 'read_error', 'content_sha256',
        'metadata_anomalies',
    }
    return all(isinstance(row, dict) and required.issubset(row) for row in rows)


def _packaged_inventory_rows_are_cacheable(rows):
    return (
        _packaged_inventory_rows_are_valid(rows)
        and all(not str(row.get('read_error') or '').strip() for row in rows)
    )


@dataclass(frozen=True)
class _PackagedArchiveScanResult:
    rows: list
    complete: bool
    failures: list
    archive_bytes: int
    nested_entries: int


def _load_packaged_inventory_cache(cache_path, artifact_sha256):
    try:
        payload = json.loads(cache_path.read_text(encoding='utf-8'))
        rows = payload.get('rows')
        if int(payload.get('schema_version') or 0) != PACKAGED_INVENTORY_CACHE_SCHEMA_VERSION:
            return None
        if str(payload.get('artifact_sha256') or '') != artifact_sha256:
            return None
        if not _packaged_inventory_rows_are_cacheable(rows):
            return None
        archive_bytes = int(payload.get('archive_bytes'))
        nested_entries = int(payload.get('nested_entries'))
        if archive_bytes < 0 or nested_entries < 0:
            return None
        rows_sha256 = hashlib.sha256(_canonical_packaged_inventory_bytes(rows)).hexdigest()
        if str(payload.get('rows_sha256') or '') != rows_sha256:
            return None
        return _PackagedArchiveScanResult(
            rows=rows,
            complete=True,
            failures=[],
            archive_bytes=archive_bytes,
            nested_entries=nested_entries,
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _write_packaged_inventory_cache(cache_path, artifact_sha256, scan_result):
    rows = scan_result.rows
    payload = {
        'schema_version': PACKAGED_INVENTORY_CACHE_SCHEMA_VERSION,
        'artifact_sha256': artifact_sha256,
        'archive_bytes': scan_result.archive_bytes,
        'nested_entries': scan_result.nested_entries,
        'rows': rows,
        'rows_sha256': hashlib.sha256(
            _canonical_packaged_inventory_bytes(rows)
        ).hexdigest(),
    }
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with named_temporary_file(
            mode='w', encoding='utf-8', dir=cache_path.parent,
            prefix='.jua-cache-', suffix='.tmp', delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, cache_path)
    except (OSError, TypeError, ValueError):
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def _scan_packaged_archive(artifact_path):
    artifact_path = Path(artifact_path)
    deps = []
    failures = []
    try:
        archive_bytes = artifact_path.stat().st_size
    except OSError as exc:
        return _PackagedArchiveScanResult(
            rows=[],
            complete=False,
            failures=[{
                'stage': 'archive_stat',
                'entry': '',
                'error': f'{exc.__class__.__name__}:{exc}',
            }],
            archive_bytes=0,
            nested_entries=0,
        )
    try:
        outer_zip = zipfile.ZipFile(str(artifact_path))
    except Exception as exc:
        return _PackagedArchiveScanResult(
            rows=[],
            complete=False,
            failures=[{
                'stage': 'archive_open',
                'entry': '',
                'error': f'{exc.__class__.__name__}:{exc}',
            }],
            archive_bytes=archive_bytes,
            nested_entries=0,
        )

    try:
        with outer_zip:
            outer_infos = outer_zip.infolist()
            unsafe_names = sorted({
                info.filename for info in outer_infos
                if _unsafe_entry_name(info.filename)
            })
            if unsafe_names:
                return _PackagedArchiveScanResult(
                    rows=[], complete=False,
                    failures=[{
                        'stage': 'archive_safety',
                        'entry': name,
                        'error': 'ARCHIVE_ENTRY_PATH_UNSAFE',
                    } for name in unsafe_names],
                    archive_bytes=archive_bytes, nested_entries=0,
                )

            infos_by_name = defaultdict(list)
            for info in outer_infos:
                infos_by_name[info.filename].append(info)
            duplicate_names = sorted(
                name for name, infos in infos_by_name.items()
                if (
                    len(infos) > 1
                    and not is_allowed_duplicate_archive_entry(
                        name,
                        allow_duplicate_maven_metadata=True,
                    )
                )
            )
            if duplicate_names:
                dependency_duplicates = {
                    name for name in duplicate_names
                    if name.lower().endswith('.jar') and name.lower().startswith(
                        ('boot-inf/lib/', 'web-inf/lib/', 'lib/')
                    )
                }
                return _PackagedArchiveScanResult(
                    rows=[], complete=False,
                    failures=[{
                        'stage': 'archive_safety',
                        'entry': name,
                        'error': (
                            'ARCHIVE_DUPLICATE_DEPENDENCY_ENTRY'
                            if name in dependency_duplicates
                            else 'ARCHIVE_DUPLICATE_ENTRY'
                        ),
                    } for name in duplicate_names],
                    archive_bytes=archive_bytes,
                    nested_entries=len(dependency_duplicates),
                )

            dependency_infos = []
            for info in outer_infos:
                name = info.filename
                lower_name = name.lower()
                if not lower_name.endswith('.jar'):
                    continue
                if not (
                    lower_name.startswith('boot-inf/lib/')
                    or lower_name.startswith('web-inf/lib/')
                    or lower_name.startswith('lib/')
                ):
                    continue
                dependency_infos.append(info)

            informative_paths = len(dependency_infos)
            total_dependency_bytes = sum(
                max(int(info.file_size), 0) for info in dependency_infos
            )
            if total_dependency_bytes > STEP1_MAX_TOTAL_DEPENDENCY_BYTES:
                return _PackagedArchiveScanResult(
                    rows=[], complete=False,
                    failures=[{
                        'stage': 'archive_safety',
                        'entry': '',
                        'error': 'ARCHIVE_DEPENDENCY_BYTES_EXCEEDED',
                    }],
                    archive_bytes=archive_bytes,
                    nested_entries=informative_paths,
                )

            for info in dependency_infos:
                name = info.filename
                _ratio, size_metadata_error = (
                    _archive_entry_expansion_ratio(info)
                )
                if size_metadata_error:
                    failures.append({
                        'stage': 'archive_safety',
                        'entry': name,
                        'error': size_metadata_error,
                    })
                    continue
                if info.file_size > STEP1_MAX_DEPENDENCY_JAR_BYTES:
                    failures.append({
                        'stage': 'archive_safety',
                        'entry': name,
                        'error': 'ARCHIVE_NESTED_SIZE_EXCEEDED',
                    })
                    continue
                try:
                    nested_source, content_sha256 = _stream_nested_jar_to_spool(
                        outer_zip, info
                    )
                except Exception as exc:
                    dep = _build_packaged_entry(name)
                    dep['match_source'] = 'outer-read-error'
                    dep['resolution_status'] = 'unresolved'
                    dep['read_error'] = f"outer_read_error:{exc}"
                    deps.append(dep)
                    failures.append({
                        'stage': 'nested_entry_read',
                        'entry': name,
                        'error': dep['read_error'],
                    })
                    continue
                try:
                    dep = _extract_packaged_dep_from_nested_jar_source(
                        nested_source, name, content_sha256
                    )
                finally:
                    nested_source.close()
                if not dep:
                    continue
                if str(dep.get('read_error') or '').strip():
                    failures.append({
                        'stage': 'embedded_metadata_read',
                        'entry': name,
                        'error': dep['read_error'],
                    })
                if _is_ignorable_packaging_support_dep(dep):
                    continue
                deps.append(dep)
    except Exception as exc:
        failures.append({
            'stage': 'archive_read',
            'entry': '',
            'error': f'{exc.__class__.__name__}:{exc}',
        })

    return _PackagedArchiveScanResult(
        rows=deps,
        complete=not failures,
        failures=failures,
        archive_bytes=archive_bytes,
        nested_entries=informative_paths,
    )


def _update_packaged_archive_stats(stats, scan_result):
    if stats is None:
        return
    stats['scan_complete'] = bool(scan_result.complete)
    stats['failures'] = [dict(item) for item in scan_result.failures]
    stats['archive_bytes'] = int(scan_result.archive_bytes)
    stats['nested_entries'] = int(scan_result.nested_entries)


def _inspect_packaged_archive(artifact_path, cache_dir=None, cache_stats=None):
    artifact_path = Path(artifact_path)
    stats = cache_stats if isinstance(cache_stats, dict) else None
    try:
        artifact_sha256 = sha256_file(artifact_path)
    except OSError as exc:
        raise RuntimeError(
            f'packaged archive identity unavailable before scan: {artifact_path}: {exc}'
        ) from exc
    if cache_dir is None:
        if stats is not None:
            stats['misses'] = int(stats.get('misses') or 0) + 1
        scan_result = _scan_packaged_archive(artifact_path)
        try:
            artifact_sha256_after_scan = sha256_file(artifact_path)
        except OSError as exc:
            raise RuntimeError(
                f'packaged archive identity unavailable after scan: {artifact_path}: {exc}'
            ) from exc
        if artifact_sha256_after_scan != artifact_sha256:
            raise RuntimeError(
                f'packaged archive changed during packaged archive scan: {artifact_path}'
            )
        _update_packaged_archive_stats(stats, scan_result)
        return scan_result.rows

    cache_path = (
        Path(cache_dir) / f'{artifact_sha256}.json'
    )
    cached_result = _load_packaged_inventory_cache(cache_path, artifact_sha256)
    if cached_result is not None:
        try:
            artifact_sha256_after_load = sha256_file(artifact_path)
        except OSError as exc:
            raise RuntimeError(
                f'packaged archive identity unavailable after cache load: {artifact_path}: {exc}'
            ) from exc
        if artifact_sha256_after_load != artifact_sha256:
            raise RuntimeError(
                f'packaged archive changed during packaged archive cache load: {artifact_path}'
            )
        if stats is not None:
            stats['hits'] = int(stats.get('hits') or 0) + 1
        _update_packaged_archive_stats(stats, cached_result)
        return cached_result.rows

    if stats is not None:
        stats['misses'] = int(stats.get('misses') or 0) + 1
    scan_result = _scan_packaged_archive(artifact_path)
    try:
        artifact_sha256_after_scan = sha256_file(artifact_path)
    except OSError as exc:
        raise RuntimeError(
            f'packaged archive identity unavailable after scan: {artifact_path}: {exc}'
        ) from exc
    if artifact_sha256_after_scan != artifact_sha256:
        raise RuntimeError(
            f'packaged archive changed during packaged archive scan: {artifact_path}'
        )
    _update_packaged_archive_stats(stats, scan_result)
    if (
        scan_result.complete
        and _packaged_inventory_rows_are_cacheable(scan_result.rows)
    ):
        _write_packaged_inventory_cache(cache_path, artifact_sha256, scan_result)
    return scan_result.rows


def _observer_packaged_inventory_cache_dir(observer):
    cache_dir = getattr(observer, 'cache_dir', None) if observer is not None else None
    if cache_dir is None:
        return None
    return Path(cache_dir) / PACKAGED_INVENTORY_CACHE_DIRNAME


def _require_complete_packaged_archive_scan(cache_stats, artifact_path):
    if (cache_stats or {}).get('scan_complete') is not False:
        return
    failures = list((cache_stats or {}).get('failures') or [])
    details = '; '.join(
        ':'.join(filter(None, (
            str(item.get('stage') or ''),
            str(item.get('entry') or ''),
            str(item.get('error') or ''),
        )))
        for item in failures
    ) or 'unknown archive scan failure'
    raise RuntimeError(f"最终制品扫描不完整：{artifact_path}。{details}")


# ══════════════════════════════════════════════════════════════════
# 版本变更分类
# ══════════════════════════════════════════════════════════════════

def classify_change(old_ver, new_ver):
    if old_ver == '-': return '新增', '待分析'
    if new_ver == '-': return '移除', '待分析'
    if old_ver == new_ver: return '未变', '待验证'

    old_info = parse_version_info(old_ver)
    new_info = parse_version_info(new_ver)
    if not old_info or not new_info:
        return '版本格式不规则', '❓需人工确认'

    cmp_result = compare_versions(old_ver, new_ver)
    old_nums = old_info['base']
    new_nums = new_info['base']

    if new_nums[0] > old_nums[0]: return '大版本升级', '高'
    if new_nums[0] < old_nums[0]: return '降级⚠️', '高'

    old_minor = old_nums[1] if len(old_nums) > 1 else 0
    new_minor = new_nums[1] if len(new_nums) > 1 else 0
    if new_minor > old_minor: return '小版本升级', '中'
    if new_minor < old_minor: return '降级⚠️', '高'

    old_patch = old_nums[2] if len(old_nums) > 2 else 0
    new_patch = new_nums[2] if len(new_nums) > 2 else 0
    if new_patch > old_patch: return '补丁升级', '低'
    if new_patch < old_patch: return '降级⚠️', '中'

    if cmp_result < 0:
        return '补丁升级', '低'
    if cmp_result > 0:
        return '降级⚠️', '中'
    return '已变更', '❓需人工确认'


# ══════════════════════════════════════════════════════════════════
# 模块选择与真实构建
# ══════════════════════════════════════════════════════════════════

def _normalize_maven_pl_with_workdir(primary_module, work_dir):
    if not primary_module:
        return None
    item = str(primary_module).strip()
    if not item:
        return None

    is_path_selector = False
    normalized = item.replace("\\", "/").strip()
    looks_like_pom = normalized.lower().endswith("/pom.xml") or normalized.lower() == "pom.xml"
    if looks_like_pom:
        pom_path = Path(item)
        if work_dir and not pom_path.is_absolute():
            pom_path = Path(work_dir) / pom_path
        module_dir = pom_path.parent
        if work_dir:
            try:
                module_dir = module_dir.resolve().relative_to(Path(work_dir).resolve())
            except Exception:
                module_dir = pom_path.parent
        item = module_dir.as_posix()
        is_path_selector = True

    if work_dir and ":" not in item and "/" not in item and "\\" not in item:
        try:
            candidate = (Path(work_dir) / item)
            if candidate.is_dir():
                item = candidate.resolve().relative_to(Path(work_dir).resolve()).as_posix()
                is_path_selector = True
        except (OSError, ValueError) as exc:
            print(f"⚠️ 无法解析 Maven 模块选择器 {item}: {type(exc).__name__}: {exc}", file=sys.stderr)

    item = (item or "").strip()
    if item in (".", "./"):
        return None
    if is_path_selector:
        return item
    if ":" in item or "/" in item or "\\" in item:
        return item
    return f":{item}"


def _detect_archive_packaging_type(artifact_path):
    try:
        with zipfile.ZipFile(str(artifact_path)) as outer_zip:
            names = [name.lower() for name in outer_zip.namelist()]
    except Exception:
        return 'unknown'
    if any(name.startswith('boot-inf/lib/') and name.endswith('.jar') for name in names):
        return 'boot_jar'
    if any(name.startswith('web-inf/lib/') and name.endswith('.jar') for name in names):
        return 'war'
    if any(name.startswith('lib/') and name.endswith('.jar') for name in names):
        return 'packaged_jar'
    return 'thin_jar'


MAVEN_DEPENDENCY_SCOPES = {
    'compile', 'runtime', 'provided', 'test', 'system', 'import',
}
MAVEN_COORD_TOKEN_RE = re.compile(r'^[^\s:\[\]]+$')
GRADLE_ARTIFACT_INVENTORY_PREFIX = 'JUA_ARTIFACT_INVENTORY_JSON:'
GRADLE_ARTIFACT_INVENTORY_TASK = 'juaRuntimeArtifactInventory'


GRADLE_ARTIFACT_INVENTORY_INIT_SCRIPT = r'''
import groovy.json.JsonOutput
import org.gradle.api.GradleException
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.component.ProjectComponentIdentifier

gradle.projectsEvaluated {
    allprojects { ownerProject ->
        if (ownerProject.tasks.findByName("juaRuntimeArtifactInventory") == null) {
            ownerProject.tasks.create(name: "juaRuntimeArtifactInventory") {
                doLast {
                    def configuration = ownerProject.configurations.findByName("runtimeClasspath")
                    if (configuration == null) {
                        throw new GradleException(
                            "runtimeClasspath configuration does not exist for ${ownerProject.path}"
                        )
                    }
                    def artifactCollection = configuration.incoming.artifactView {
                        lenient(true)
                    }.artifacts
                    artifactCollection.artifacts.each { resolvedArtifact ->
                        def component = resolvedArtifact.id.componentIdentifier
                        def row = [
                            file_name: resolvedArtifact.file.name,
                            file_path: resolvedArtifact.file.absolutePath,
                        ]
                        if (component instanceof ModuleComponentIdentifier) {
                            row.group_id = component.group
                            row.artifact_id = component.module
                            row.version = component.version
                        } else if (component instanceof ProjectComponentIdentifier) {
                            row.project_path = component.projectPath
                            def dependencyProject = ownerProject.rootProject.findProject(
                                component.projectPath
                            )
                            if (dependencyProject != null) {
                                row.group_id = dependencyProject.group?.toString()
                                row.artifact_id = dependencyProject.name
                                row.version = dependencyProject.version?.toString()
                            }
                        } else {
                            row.component_display_name = component.displayName
                        }
                        println(
                            "JUA_ARTIFACT_INVENTORY_JSON:"
                            + JsonOutput.toJson(row)
                        )
                    }
                    if (!artifactCollection.failures.empty) {
                        artifactCollection.failures.each { failure ->
                            logger.error(
                                "JUA_ARTIFACT_INVENTORY_FAILURE:"
                                + failure.message
                            )
                        }
                        throw new GradleException(
                            "runtimeClasspath artifact inventory is incomplete"
                        )
                    }
                }
            }
        }
    }
}
'''


def _split_maven_dependency_artifact_path(value):
    text = str(value or '').strip()
    match = re.search(r':((?:[A-Za-z]:[\\/]|/|\\\\).+)$', text)
    if not match:
        return text, ''
    return text[:match.start()].strip(), match.group(1).strip()


def _parse_maven_dependency_list_line(raw_line):
    line = _strip_info_prefix(raw_line).strip()
    if not line:
        return None
    if line.startswith(('The following files have been resolved:', 'The following dependencies have been resolved:')):
        return None

    left = re.sub(r'\s+--\s+.+$', '', line).strip()
    left = re.sub(r'\s+\((?:optional|omitted[^)]*)\)$', '', left, flags=re.IGNORECASE)
    left, artifact_file_path = _split_maven_dependency_artifact_path(left)
    if not left or ':' not in left:
        return None

    parts = [part.strip() for part in left.split(':')]
    if len(parts) < 4:
        return None

    # dependency:list always emits scope as the final coordinate token.  Scope
    # is extensible; using a fixed allow-list silently discarded valid custom
    # scopes.  Structural validation below still rejects Maven log prose.
    if len(parts) < 4:
        return None
    scope_idx = len(parts) - 1
    version_idx = scope_idx - 1
    if version_idx < 2:
        return None

    group_id = (parts[0] or '').strip()
    artifact_id = (parts[1] or '').strip()
    version = (parts[version_idx] or '').strip()
    raw_scope = (parts[scope_idx] or '').strip().lower()
    scope_match = re.match(r'^([^\s]+)(?:\s+\((?:optional|omitted[^)]*)\))?$', raw_scope)
    scope = scope_match.group(1) if scope_match else raw_scope
    middle = parts[2:version_idx]
    dep_type = (middle[0] or '').strip() if middle else ''
    classifier = ':'.join(part for part in middle[1:] if part.strip()) if len(middle) > 1 else ''

    if not dep_type:
        dep_type = 'jar'
    if dep_type.lower() == 'pom':
        return None
    if (
        not group_id or not artifact_id or not version or not scope
        or not all(MAVEN_COORD_TOKEN_RE.match(value) for value in (
            group_id, artifact_id, dep_type, version, scope
        ))
    ):
        return None

    key = f"{group_id}:{artifact_id}" + (f":{classifier}" if classifier else "")
    return {
        'key': key,
        'group_id': group_id,
        'artifact_id': artifact_id,
        'version': version,
        'scope': scope,
        'remark': 'source:dependency:list(runtime)',
        'classifier': classifier,
        'artifact_file_name': (
            re.split(r'[\\/]', artifact_file_path)[-1]
            if artifact_file_path
            else ''
        ),
        'artifact_file_path': artifact_file_path,
        'packaged_present': '',
        'packaged_match_source': '',
    }


def parse_maven_dependency_list(text):
    deps = {}
    for raw_line in text.splitlines():
        parsed = _parse_maven_dependency_list_line(raw_line)
        if not parsed:
            continue
        _merge_runtime_artifact_record(deps, parsed)
    return deps


GRADLE_DEPENDENCY_RE = re.compile(
    r"(?<![\w.-])([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^\s()]+)"
    r"(?:\s+->\s+([^\s()]+))?"
)
GRADLE_PROJECT_DEPENDENCY_RE = re.compile(
    r"\bproject\s+['\"]?((?::)[A-Za-z0-9_.:-]+)['\"]?"
)


def _merge_runtime_artifact_record(deps, item):
    key = str((item or {}).get('key') or '').strip()
    if not key:
        return

    def normalized_values(*groups):
        values = []
        seen = set()
        for group in groups:
            candidates = group if isinstance(group, (list, tuple)) else [group]
            for candidate in candidates:
                value = str(candidate or '').strip()
                if value and value not in seen:
                    seen.add(value)
                    values.append(value)
        return values

    existing = deps.get(key)
    if existing is None:
        record = dict(item)
        record['key'] = key
        observed_versions = normalized_values(
            record.get('observed_versions'),
            record.get('version'),
        )
        record['observed_versions'] = observed_versions
        record['runtime_version_conflict'] = len(observed_versions) > 1
        for singular, plural in (
            ('artifact_file_name', 'artifact_file_names'),
            ('artifact_file_path', 'artifact_file_paths'),
        ):
            values = normalized_values(
                record.get(singular),
                record.get(plural),
            )
            record[plural] = values
            if values:
                record[singular] = values[0]
        deps[key] = record
        return
    # dependency:list/runtime inventory is only a coordinate-enrichment source.
    # Reactor modules can legitimately resolve different versions of the same
    # coordinate, so retain those versions as diagnostics without selecting one
    # or blocking final-artifact analysis.
    observed_versions = normalized_values(
        existing.get('observed_versions'),
        existing.get('version'),
        item.get('observed_versions'),
        item.get('version'),
    )
    existing['observed_versions'] = observed_versions
    existing['runtime_version_conflict'] = len(observed_versions) > 1
    for singular, plural in (
        ('artifact_file_name', 'artifact_file_names'),
        ('artifact_file_path', 'artifact_file_paths'),
    ):
        values = normalized_values(
            existing.get(singular),
            existing.get(plural),
            item.get(singular),
            item.get(plural),
        )
        existing[plural] = values
        if values:
            existing[singular] = values[0]


def _runtime_artifact_versions(item):
    versions = []
    for value in (
        list((item or {}).get('observed_versions') or [])
        + [(item or {}).get('version')]
    ):
        version = str(value or '').strip()
        if version and version not in versions:
            versions.append(version)
    return versions


def parse_gradle_artifact_inventory(text, project_modules=None):
    """Parse exact resolved-artifact records emitted by the generated init task."""
    modules_by_path = {
        str(item.get('gradle_path') or '').strip(): dict(item)
        for item in (project_modules or [])
        if str(item.get('gradle_path') or '').strip()
    }
    deps = {}
    for raw_line in str(text or '').splitlines():
        marker_index = raw_line.find(GRADLE_ARTIFACT_INVENTORY_PREFIX)
        if marker_index < 0:
            continue
        payload = raw_line[
            marker_index + len(GRADLE_ARTIFACT_INVENTORY_PREFIX):
        ].strip()
        try:
            row = json.loads(payload)
        except (TypeError, ValueError):
            continue
        project_path = str(row.get('project_path') or '').strip()
        project_model = modules_by_path.get(project_path) or {}
        group_id = str(
            row.get('group_id') or project_model.get('group_id') or ''
        ).strip()
        artifact_id = str(
            row.get('artifact_id') or project_model.get('artifact_id') or ''
        ).strip()
        version = str(
            row.get('version') or project_model.get('version') or ''
        ).strip()
        file_name = re.split(
            r'[\\/]',
            str(row.get('file_name') or ''),
        )[-1]
        if (
            not group_id
            or not artifact_id
            or not version
            or version == 'unspecified'
            or not file_name
        ):
            continue
        _matched, classifier, _layout = _match_runtime_artifact_filename(
            file_name,
            artifact_id,
            version,
        )
        key = normalize_artifact_coord(
            f'{group_id}:{artifact_id}',
            classifier,
        )
        _merge_runtime_artifact_record(deps, {
            'key': key,
            'coord': key,
            'group_id': group_id,
            'artifact_id': artifact_id,
            'version': version,
            'scope': 'runtime',
            'remark': 'source:gradle_artifact_inventory(runtimeClasspath)',
            'classifier': classifier,
            'artifact_file_name': file_name,
            'artifact_file_path': str(row.get('file_path') or '').strip(),
            'packaged_present': '',
            'packaged_match_source': '',
            'gradle_project_path': project_path,
        })
    return deps


def parse_gradle_dependency_report(text, project_modules=None):
    """Parse resolved external and exact internal-project runtime dependencies."""
    deps = {}
    modules_by_path = {
        str(item.get('gradle_path') or '').strip(): dict(item)
        for item in (project_modules or [])
        if str(item.get('gradle_path') or '').strip()
    }
    for raw_line in str(text or '').splitlines():
        line = raw_line.strip()
        if not line or ' FAILED' in line or line.startswith(('No dependencies', 'A web-based')):
            continue
        match = GRADLE_DEPENDENCY_RE.search(line)
        if not match:
            project_match = GRADLE_PROJECT_DEPENDENCY_RE.search(line)
            project_path = (
                str(project_match.group(1) or '').strip()
                if project_match
                else ''
            )
            project_model = modules_by_path.get(project_path) or {}
            group_id = str(project_model.get('group_id') or '').strip()
            artifact_id = str(project_model.get('artifact_id') or '').strip()
            version = str(project_model.get('version') or '').strip()
            if (
                not project_path
                or not group_id
                or not artifact_id
                or not version
                or version == 'unspecified'
            ):
                continue
            key = f"{group_id}:{artifact_id}"
            deps[key] = {
                'key': key,
                'group_id': group_id,
                'artifact_id': artifact_id,
                'version': version,
                'scope': 'runtime',
                'remark': 'source:gradle_dependencies(runtimeClasspath_project)',
                'classifier': '',
                'packaged_present': '',
                'packaged_match_source': '',
                'gradle_project_path': project_path,
            }
            continue
        group_id, artifact_id, requested_version, selected_version = match.groups()
        selected = (selected_version or '').rstrip(',')
        if selected.count(':') >= 2:
            selected_group, selected_artifact, selected = selected.split(':', 2)
            group_id, artifact_id = selected_group, selected_artifact
        version = (selected or requested_version).rstrip(',')
        if (
            not version
            or version in {'FAILED', '(n)', '(c)'}
            or any(token in version for token in '{}[]')
        ):
            continue
        key = f"{group_id}:{artifact_id}"
        deps[key] = {
            'key': key,
            'group_id': group_id,
            'artifact_id': artifact_id,
            'version': version,
            'scope': 'runtime',
            'remark': 'source:gradle_dependencies(runtimeClasspath)',
            'classifier': '',
            'packaged_present': '',
            'packaged_match_source': '',
        }
    return deps


def _packaged_metadata_anomaly_suffix(item):
    anomalies = sorted({
        str(value).strip()
        for value in ((item or {}).get('metadata_anomalies') or [])
        if str(value).strip()
    })
    return f";metadata_anomalies={'|'.join(anomalies)}" if anomalies else ''


def _enrich_packaged_deps_with_runtime(
    packaged_deps,
    runtime_deps,
    manual_coord_overrides=None,
    manual_artifact_identities=None,
    confirmed_unresolved_items=None,
    side="",
):
    """Use runtime metadata to补齐坐标, while keeping packaged-artifact version facts authoritative."""
    normalized_runtime_deps = {}
    runtime_by_artifact_version = defaultdict(list)
    runtime_by_filename_artifact_version = defaultdict(list)
    runtime_by_filename_stem = defaultdict(list)
    for runtime_coord, raw_item in runtime_deps.items():
        item = dict(raw_item or {})
        coord_parts = str(runtime_coord or '').split(':')
        if len(coord_parts) >= 2:
            item.setdefault('group_id', coord_parts[0])
            item.setdefault('artifact_id', coord_parts[1])
            if len(coord_parts) > 2:
                item.setdefault('classifier', ':'.join(coord_parts[2:]))
            item['coord'] = normalize_artifact_coord(
                item.get('coord') or runtime_coord,
                item.get('classifier'),
            )
        normalized_runtime_deps[item.get('coord') or str(runtime_coord)] = item
        artifact_id = item.get('artifact_id')
        for version in _runtime_artifact_versions(item):
            if artifact_id and version:
                runtime_by_artifact_version[(artifact_id, version)].append(item)
                runtime_by_filename_artifact_version[(artifact_id, version)].append(item)
                classifier = (item.get('classifier') or '').strip()
                if classifier:
                    runtime_by_filename_artifact_version[(f"{artifact_id}-{classifier}", version)].append(item)
        for stem in _runtime_candidate_filename_stems(item):
            runtime_by_filename_stem[stem].append(item)

    runtime_deps = normalized_runtime_deps

    manual_coord_overrides = manual_coord_overrides or {}
    manual_artifact_identities, _invalid_manual_identities = (
        parse_manual_artifact_identities(manual_artifact_identities or [])
    )
    confirmed_unresolved_items = normalize_unresolved_items(
        confirmed_unresolved_items
    )

    def manual_identity_for(packaged_item):
        return _manual_artifact_identity_for_entry(
            packaged_item,
            manual_artifact_identities,
            side,
        )

    def confirmed_unresolved_for(packaged_item):
        artifact_id = str(packaged_item.get('artifact_id') or '').strip()
        version = str(packaged_item.get('version') or '').strip()
        classifier = str(packaged_item.get('classifier') or '').strip()
        entry_id = str(packaged_item.get('entry_id') or '').strip()
        lib_entry = str(packaged_item.get('lib_entry') or '').strip()
        packaged_side = str(
            packaged_item.get('side') or side or ''
        ).strip()
        for confirmed in confirmed_unresolved_items:
            if (
                str(confirmed.get('artifact_id') or '').strip() != artifact_id
                or str(confirmed.get('version') or '').strip() != version
            ):
                continue
            selectors = (
                ('classifier', classifier),
                ('entry_id', entry_id),
                ('lib_entry', lib_entry),
                ('side', packaged_side),
            )
            if any(
                str(confirmed.get(field) or '').strip()
                and str(confirmed.get(field) or '').strip() != value
                for field, value in selectors
            ):
                continue
            return confirmed
        return None

    entries = []
    resolved = {}
    unresolved = []
    for item in packaged_deps:
        enriched = dict(item)
        packaged_version = (item.get('version') or '').strip()
        version_confirmed = str(item.get('match_source') or '').strip() in {
            'embedded-pom',
            'embedded-pom-filename-match',
            'pom.properties',
        }
        runtime_match = None
        manual_override = None
        manual_identity, manual_identity_candidates = manual_identity_for(item)
        filename_runtime_candidates = []
        if manual_identity is not None:
            enriched.update({
                'group_id': manual_identity.get('group_id', ''),
                'artifact_id': manual_identity.get('artifact_id', ''),
                'version': manual_identity.get('version', ''),
                'classifier': manual_identity.get('classifier', ''),
                'coord': manual_identity.get('coord', ''),
                'match_source': 'manual_artifact_identity',
            })
            packaged_version = str(manual_identity.get('version') or '').strip()
            version_confirmed = True
        elif len(manual_identity_candidates) > 1:
            anomaly = 'manual_artifact_identity_ambiguous:' + '|'.join(
                f"{candidate.get('coord')}@{candidate.get('version')}"
                for candidate in manual_identity_candidates
            )
            enriched['metadata_anomalies'] = list(
                enriched.get('metadata_anomalies') or []
            ) + [anomaly]
        coord = (item.get('coord') or '').strip()
        if manual_identity is None and not coord and item.get('match_source') == 'filename':
            runtime_match, filename_runtime_candidates = (
                _runtime_dependency_for_packaged_filename(
                    item,
                    runtime_deps,
                )
            )
        if (
            manual_identity is None
            and
            not coord
            and
            runtime_match is None
            and item.get('artifact_id')
            and item.get('version')
        ):
            item_classifier = str(item.get('classifier') or '').strip()
            candidates = (
                runtime_by_filename_artifact_version.get(
                    (
                        f"{item.get('artifact_id')}-{item_classifier}",
                        item.get('version'),
                    ),
                    [],
                )
                if item_classifier
                else runtime_by_filename_artifact_version.get(
                    (item.get('artifact_id'), item.get('version')),
                    [],
                )
            )
            if not candidates and not item_classifier:
                candidates = runtime_by_artifact_version.get((item.get('artifact_id'), item.get('version')), [])
            if len(candidates) == 1:
                runtime_match = candidates[0]
        if manual_identity is None and not coord and runtime_match is None and item.get('match_source') == 'filename':
            stem_candidates = runtime_by_filename_stem.get((item.get('filename_stem') or '').strip(), [])
            if len(stem_candidates) == 1:
                runtime_match = stem_candidates[0]
        if manual_identity is None and not coord and runtime_match is None and item.get('artifact_id') and item.get('version'):
            item_classifier = str(item.get('classifier') or '').strip()
            manual_override = (
                manual_coord_overrides.get((
                    item.get('artifact_id'),
                    item.get('version'),
                    item_classifier,
                ))
                or manual_coord_overrides.get((
                    item.get('artifact_id'),
                    item.get('version'),
                ))
            )
        if len(filename_runtime_candidates) > 1 and manual_override is None:
            anomaly = 'runtime_filename_coordinate_ambiguous:' + '|'.join(
                f"{candidate.get('coord')}@{candidate.get('version')}"
                for candidate in filename_runtime_candidates
            )
            enriched['metadata_anomalies'] = list(
                enriched.get('metadata_anomalies') or []
            ) + [anomaly]
        if manual_override and runtime_match is None:
            enriched['group_id'] = manual_override.get('group_id') or enriched.get('group_id', '')
            enriched['artifact_id'] = manual_override.get('artifact_id') or enriched.get('artifact_id', '')
            enriched['coord'] = normalize_artifact_coord(
                manual_override.get('coord') or enriched.get('coord', ''),
                enriched.get('classifier'),
            )
            enriched['match_source'] = 'manual_override'
            physical_version = _physical_version_from_filename_coordinate(
                enriched.get('lib_name') or enriched.get('lib_entry'),
                enriched.get('artifact_id'),
                enriched.get('classifier'),
            )
            if physical_version:
                enriched['version'] = physical_version
                packaged_version = physical_version
            version_confirmed = bool(physical_version)
        confirmed_unresolved = confirmed_unresolved_for(item)
        stale_filename_confirmation = bool(
            confirmed_unresolved
            and runtime_match
            and str(confirmed_unresolved.get('source') or '').strip() == 'filename'
            and not str(confirmed_unresolved.get('classifier') or '').strip()
            and (
                runtime_match.get('packaged_match_source') in {
                    'runtime-artifact-inventory',
                    'runtime-filename-classifier',
                }
                or str(runtime_match.get('project_module') or '').strip()
            )
        )
        if (
            confirmed_unresolved
            and manual_override is None
            and manual_identity is None
            and not stale_filename_confirmation
        ):
            unresolved_item = {
                'artifact_id': (item.get('artifact_id') or '').strip() or '<unknown-artifact>',
                'version': (item.get('version') or '').strip() or '<unknown-version>',
                'classifier': (item.get('classifier') or '').strip(),
                'source': confirmed_unresolved.get('source') or enriched.get('match_source', 'archive'),
                'entry_id': enriched.get('entry_id', ''),
                'lib_entry': enriched.get('lib_entry', ''),
                'lib_name': enriched.get('lib_name', ''),
            }
            unresolved.append(unresolved_item)
            display_coord = normalize_artifact_coord(
                enriched.get('coord'),
                unresolved_item.get('classifier'),
            )
            if not display_coord:
                display_coord = (
                    f"{unresolved_item['artifact_id']}:{unresolved_item['version']}"
                    f"{':' + unresolved_item['classifier'] if unresolved_item.get('classifier') else ''}"
                ).strip(':')
            entries.append({
                'entry_id': enriched.get('entry_id', ''),
                'lib_entry': enriched.get('lib_entry', ''),
                'lib_name': enriched.get('lib_name', ''),
                'coord': display_coord,
                'group_id': enriched.get('group_id', ''),
                'artifact_id': enriched.get('artifact_id', ''),
                'version': enriched.get('version', ''),
                'classifier': enriched.get('classifier', ''),
                'scope': 'packaged',
                'remark': (
                    f"source:final_artifact_unresolved({confirmed_unresolved.get('source') or enriched.get('match_source', 'archive')})"
                    f"{_packaged_metadata_anomaly_suffix(enriched)}"
                ),
                'packaged_present': 'true',
                'packaged_match_source': confirmed_unresolved.get('source') or enriched.get('match_source', 'archive'),
                'resolution_status': 'unresolved',
                'match_source': enriched.get('match_source', ''),
                'read_error': enriched.get('read_error', ''),
                'content_sha256': enriched.get('content_sha256', ''),
                'metadata_anomalies': list(enriched.get('metadata_anomalies') or []),
            })
            continue
        if runtime_match:
            enriched['group_id'] = runtime_match.get('group_id') or enriched.get('group_id', '')
            enriched['artifact_id'] = runtime_match.get('artifact_id') or enriched.get('artifact_id', '')
            if runtime_match.get('packaged_match_source'):
                enriched['match_source'] = runtime_match['packaged_match_source']
            classifier = runtime_match.get('classifier') or ''
            enriched['coord'] = normalize_artifact_coord(
                f"{enriched.get('group_id')}:{enriched.get('artifact_id')}",
                classifier,
            )
            enriched['classifier'] = classifier
            # dependency:list contributes only group/artifact/classifier.  The
            # version is re-read from the physical filename under that
            # coordinate interpretation; the runtime version is never copied.
            physical_version = (
                ''
                if runtime_match.get('classifier_source')
                == 'runtime-version-filename-inference'
                else _physical_version_from_filename_coordinate(
                    enriched.get('lib_name') or enriched.get('lib_entry'),
                    enriched.get('artifact_id'),
                    classifier,
                )
            )
            if physical_version:
                enriched['version'] = physical_version
                packaged_version = physical_version
            else:
                enriched['version'] = packaged_version
            version_confirmed = bool(physical_version)

        coord = (enriched.get('coord') or '').strip()
        group_id = (enriched.get('group_id') or '').strip()
        artifact_id = (enriched.get('artifact_id') or '').strip()
        version = (enriched.get('version') or '').strip()
        if not coord or not version or not version_confirmed:
            reason_code = (
                'PACKAGED_VERSION_UNCONFIRMED'
                if not version or not version_confirmed
                else 'DEPENDENCY_COORDINATES_UNRESOLVED'
            )
            unresolved_item = {
                'artifact_id': artifact_id or '<unknown-artifact>',
                'version': version or '<unknown-version>',
                'classifier': (enriched.get('classifier') or '').strip(),
                'source': enriched.get('match_source', 'archive'),
                'entry_id': enriched.get('entry_id', ''),
                'lib_entry': enriched.get('lib_entry', ''),
                'lib_name': enriched.get('lib_name', ''),
                'side': str(side or '').strip(),
                'reason_code': reason_code,
            }
            unresolved.append(unresolved_item)
            display_coord = normalize_artifact_coord(
                coord,
                unresolved_item.get('classifier'),
            ) or (
                f"{unresolved_item['artifact_id']}:{unresolved_item['version']}"
                f"{':' + unresolved_item['classifier'] if unresolved_item.get('classifier') else ''}"
            ).strip(':')
            entries.append({
                'entry_id': enriched.get('entry_id', ''),
                'lib_entry': enriched.get('lib_entry', ''),
                'lib_name': enriched.get('lib_name', ''),
                'coord': display_coord,
                'group_id': group_id,
                'artifact_id': artifact_id,
                'version': version,
                'classifier': enriched.get('classifier', ''),
                'scope': 'packaged',
                'remark': (
                    f"source:final_artifact_unresolved({enriched.get('match_source', 'archive')})"
                    f"{_packaged_metadata_anomaly_suffix(enriched)}"
                ),
                'packaged_present': 'true',
                'packaged_match_source': enriched.get('match_source', 'archive'),
                'resolution_status': 'unresolved',
                'match_source': enriched.get('match_source', ''),
                'read_error': enriched.get('read_error', ''),
                'content_sha256': enriched.get('content_sha256', ''),
                'metadata_anomalies': list(enriched.get('metadata_anomalies') or []),
                'version_confirmation_status': (
                    'confirmed' if version_confirmed else 'unconfirmed'
                ),
            })
            continue
        key = coord or f"{artifact_id}:{version}"
        resolved_row = {
            'key': key,
            'group_id': group_id,
            'artifact_id': artifact_id,
            'version': version,
            'classifier': enriched.get('classifier', ''),
            'scope': 'packaged',
            'remark': (
                f"source:final_artifact({enriched.get('match_source', 'archive')})"
                f"{_packaged_metadata_anomaly_suffix(enriched)}"
            ),
            'packaged_present': 'true',
            'packaged_match_source': enriched.get('match_source', 'archive'),
            'content_sha256': enriched.get('content_sha256', ''),
        }
        resolved[key] = resolved_row
        entries.append({
            'entry_id': enriched.get('entry_id', ''),
            'lib_entry': enriched.get('lib_entry', ''),
            'lib_name': enriched.get('lib_name', ''),
            'coord': key,
            'group_id': group_id,
            'artifact_id': artifact_id,
            'version': version,
            'classifier': enriched.get('classifier', ''),
            **resolved_row,
            'resolution_status': 'resolved',
            'match_source': enriched.get('match_source', ''),
            'read_error': enriched.get('read_error', ''),
            'metadata_anomalies': list(enriched.get('metadata_anomalies') or []),
            'version_confirmation_status': 'confirmed',
        })
    return entries, resolved, unresolved


def _pom_module_values(element):
    for child in list(element):
        if _strip_xml_ns(child.tag) != 'modules':
            continue
        return tuple(
            (module.text or '').strip()
            for module in list(child)
            if _strip_xml_ns(module.tag) == 'module' and (module.text or '').strip()
        )
    return ()


def _module_selector_matches(module_value, target_selector, work_dir):
    module_path = str(module_value or '').replace('\\', '/').strip().strip('/')
    target_raw = str(target_selector or '').replace('\\', '/').strip().strip('/')
    if target_raw.startswith(':'):
        target_raw = target_raw[1:]
    if not module_path or not target_raw:
        return False
    if module_path == target_raw:
        return True
    target_id = normalize_primary_module(target_raw) or target_raw
    if Path(module_path).name == target_id:
        return True
    _group_id, artifact_id = _read_pom_identity(Path(work_dir) / module_path / 'pom.xml')
    return bool(artifact_id and artifact_id == target_id)


def _maven_profile_args_for_module(work_dir, target_selector, active_profiles=None):
    explicit_profiles = list(dict.fromkeys(
        str(profile).strip() for profile in (active_profiles or [])
        if str(profile).strip()
    ))
    if explicit_profiles:
        return [f'-P{",".join(explicit_profiles)}']
    if not target_selector or str(target_selector).strip() in ('.', './'):
        return []
    pom_path = Path(work_dir) / 'pom.xml'
    if not pom_path.is_file():
        return []
    try:
        with open_text(str(pom_path)) as handle:
            root = ET.fromstring(handle.read())
    except (OSError, ET.ParseError, UnicodeError):
        return []

    if any(
        _module_selector_matches(module, target_selector, work_dir)
        for module in _pom_module_values(root)
    ):
        return []

    profile_ids = []
    for child in list(root):
        if _strip_xml_ns(child.tag) != 'profiles':
            continue
        for profile in list(child):
            if _strip_xml_ns(profile.tag) != 'profile':
                continue
            profile_id = ''
            for profile_child in list(profile):
                if _strip_xml_ns(profile_child.tag) == 'id':
                    profile_id = (profile_child.text or '').strip()
                    break
            if profile_id and any(
                _module_selector_matches(module, target_selector, work_dir)
                for module in _pom_module_values(profile)
            ):
                profile_ids.append(profile_id)
    profile_ids = list(dict.fromkeys(profile_ids))
    if len(profile_ids) > 1:
        raise RuntimeError(
            f"目标模块 {target_selector} 同时属于多个 Maven profile："
            + ', '.join(profile_ids)
        )
    return [f'-P{profile_ids[0]}'] if profile_ids else []


def _maven_reactor_has_modules(work_dir):
    pom_path = Path(work_dir) / 'pom.xml'
    if not pom_path.is_file():
        return False
    try:
        with open_text(str(pom_path)) as handle:
            root = ET.fromstring(handle.read())
    except Exception:
        return False
    return any(
        _strip_xml_ns(element.tag) == 'module' and (element.text or '').strip()
        for element in root.iter()
    )


def build_project_module_runtime_catalog(
    work_dir,
    target_selector,
    *,
    build_tool='maven',
    active_maven_profiles=None,
):
    """Return source-backed coordinates for internal modules in the target closure.

    Build-tool runtime output remains authoritative for external dependencies.
    This catalog closes the reactor/project-dependency gap when Maven
    ``dependency:list`` omits a reactor artifact or Gradle exposes only a
    ``ProjectComponentIdentifier``.
    """
    tool = str(build_tool or 'maven').strip().lower()
    active_profiles = (
        set(active_maven_profiles or [])
        if tool == 'maven'
        else None
    )
    scope = build_project_scope(
        work_dir,
        target_selector or '.',
        active_profiles=active_profiles,
        build_tool=tool,
    )
    included_modules = {
        str(item or '').strip()
        for item in scope.get('included_modules') or []
        if str(item or '').strip()
    }
    target_module = str(scope.get('target_module') or '').strip()
    if not included_modules or not target_module:
        return {}

    discovery = discover_project_modules(
        work_dir,
        build_tool=tool,
        active_profiles=active_profiles,
    )
    catalog = {}
    for module in discovery.get('modules') or []:
        module_name = str(module.get('module') or '').strip()
        if module_name not in included_modules or module_name == target_module:
            continue
        group_id = str(module.get('group_id') or '').strip()
        artifact_id = str(module.get('artifact_id') or '').strip()
        version = str(module.get('version') or '').strip()
        if (
            not group_id
            or not artifact_id
            or not version
            or version == 'unspecified'
            or any(token in value for value in (group_id, artifact_id, version)
                   for token in ('${', '}'))
        ):
            continue
        coord = f'{group_id}:{artifact_id}'
        record = {
            'key': coord,
            'coord': coord,
            'group_id': group_id,
            'artifact_id': artifact_id,
            'version': version,
            'scope': 'runtime',
            'remark': 'source:project_module_catalog(target_closure)',
            'classifier': '',
            'packaged_present': '',
            'packaged_match_source': '',
            'project_module': module_name,
        }

        # A unique physical main artifact is stronger than conventional
        # filename matching and also supports a module-specific finalName.
        archives = _discover_packaged_archives(Path(module.get('module_dir') or ''))
        main_archives = []
        for archive in archives:
            matched, classifier, _layout = _match_runtime_artifact_filename(
                archive.name,
                artifact_id,
                version,
            )
            if matched and not classifier:
                main_archives.append(archive)
        physical = (
            main_archives[0]
            if len(main_archives) == 1
            else (archives[0] if len(archives) == 1 else None)
        )
        if physical is not None:
            record['artifact_file_name'] = physical.name
            record['artifact_file_path'] = str(physical)
        catalog[coord] = record
    return catalog


def augment_runtime_deps_with_project_modules(
    runtime_deps,
    work_dir,
    target_selector,
    *,
    build_tool='maven',
    active_maven_profiles=None,
):
    """Merge missing internal-module identities without overriding resolved output."""
    augmented = {
        str(key): dict(value or {})
        for key, value in (runtime_deps or {}).items()
    }
    project_modules = build_project_module_runtime_catalog(
        work_dir,
        target_selector,
        build_tool=build_tool,
        active_maven_profiles=active_maven_profiles,
    )
    for coord, module_record in project_modules.items():
        existing = augmented.get(coord)
        if existing is None:
            _merge_runtime_artifact_record(augmented, dict(module_record))
            continue
        if str(existing.get('version') or '') != str(module_record.get('version') or ''):
            # The executed build model wins over the static source model.
            continue
        existing['project_module'] = module_record.get('project_module', '')
        if not existing.get('artifact_file_name') and module_record.get('artifact_file_name'):
            existing['artifact_file_name'] = module_record['artifact_file_name']
            existing['artifact_file_path'] = module_record.get('artifact_file_path', '')
            existing['artifact_file_names'] = [module_record['artifact_file_name']]
            existing['artifact_file_paths'] = [
                module_record.get('artifact_file_path', '')
            ]
    return augmented


def _collect_maven_runtime_deps_for_workspace(
    work_dir, primary_module=None, modules=None, env=None, observer=None, side="",
    active_maven_profiles=None,
):
    work_dir = str(Path(work_dir).resolve())
    target_selector = _resolve_single_module_selector(primary_module, modules, work_dir)
    pl = _normalize_maven_pl_with_workdir(target_selector, work_dir)
    profile_args = _maven_profile_args_for_module(
        work_dir, target_selector, active_maven_profiles
    )
    reactor_prepare = ['package'] if _maven_reactor_has_modules(work_dir) else []
    list_cmd = mvn_cmd(work_dir) + [
        '--batch-mode',
        *profile_args,
        *(["-pl", pl, "-am"] if pl else []),
        MAVEN_SKIP_TEST_COMPILATION_ARG,
        *reactor_prepare,
        'dependency:list',
        '-DincludeScope=runtime',
        '-DoutputAbsoluteArtifactFilename=true',
    ]
    list_command = ' '.join(list_cmd)
    side_display = _side_display(side)
    with _observed_phase(
        observer,
        "maven_dependency_list",
        side=side,
        item=target_selector or ".",
        command=list_command,
        start_message=f"开始补全{side_display}最终制品依赖坐标",
        complete_message=f"{side_display}依赖坐标补全完成",
    ):
        list_stdout, list_stderr, list_rc = run_cmd(
            list_cmd, cwd=work_dir, timeout=STEP1_BUILD_TOOL_TIMEOUT,
            env=env, stream_output=True,
        )
        if list_rc != 0:
            raise RuntimeError(
                "最终制品中存在无法直接识别坐标的嵌套依赖，且 `mvn dependency:list` 执行失败，"
                f"无法安全补全坐标：{(list_stderr[:300] or list_stdout[:300])}"
            )
    runtime_deps = augment_runtime_deps_with_project_modules(
        parse_maven_dependency_list(list_stdout),
        work_dir,
        target_selector,
        build_tool='maven',
        active_maven_profiles=active_maven_profiles,
    )
    return runtime_deps, list_command


def _gradle_target_model(work_dir, target_selector):
    discovery = discover_project_modules(work_dir, build_tool='gradle')
    selector = str(target_selector or '.').strip().replace('\\', '/').rstrip('/')
    if selector in ('', './', 'root', '__root__'):
        selector = '.'
    matches = []
    for item in discovery.get('modules') or []:
        aliases = {
            str(item.get('module') or ''),
            str(item.get('gradle_path') or ''),
            str(item.get('artifact_id') or ''),
            str(item.get('coord') or ''),
            Path(str(item.get('module_dir') or '')).name,
        }
        if selector in aliases:
            matches.append(item)
    if len(matches) != 1:
        raise RuntimeError(f"无法唯一解析 Gradle 目标模块：{target_selector}")
    return matches[0]


def _gradle_task(target_model, task):
    gradle_path = str((target_model or {}).get('gradle_path') or ':').rstrip(':')
    return f"{gradle_path}:{task}" if gradle_path else task


def _is_gradle_lock_contention(output):
    text = str(output or '').lower()
    return any(token in text for token in (
        'timeout waiting to lock',
        'timed out waiting to lock',
        'could not acquire lock',
        'could not lock',
        'cannot lock',
        'failed to acquire lock',
        'lock timeout',
        'is currently in use by another gradle instance',
        'another gradle instance',
        'reached waiting for exclusive access to file',
    ))


def _run_gradle_command_with_lock_retry(command, **run_kwargs):
    """Retry only the same Gradle command when its completed process reports lock contention."""
    attempts = 0
    stdout = ''
    stderr = ''
    return_code = -1
    for retry_index in range(len(GRADLE_LOCK_RETRY_DELAYS_SECONDS) + 1):
        attempts += 1
        stdout, stderr, return_code = run_cmd(command, **run_kwargs)
        if return_code == 0:
            break
        if not _is_gradle_lock_contention(f'{stdout}\n{stderr}'):
            break
        if retry_index < len(GRADLE_LOCK_RETRY_DELAYS_SECONDS):
            time.sleep(GRADLE_LOCK_RETRY_DELAYS_SECONDS[retry_index])
    return stdout, stderr, return_code, attempts


def _gradle_inventory_fallback_allowed(stdout, stderr):
    """Return whether the generated ArtifactView task is unsupported, not unhealthy."""
    text = f'{stdout}\n{stderr}'.lower()
    task_is_unavailable = any(token in text for token in (
        "task 'juaruntimeartifactinventory' not found",
        "task 'juaruntimeartifactinventory' does not exist",
    ))
    artifact_api_is_unavailable = (
        'artifactview' in text
        and any(token in text for token in (
            'could not find method',
            'no signature of method',
            'nosuchmethoderror',
            'missingmethodexception',
        ))
    )
    component_api_is_unavailable = any(token in text for token in (
        'unable to resolve class org.gradle.api.artifacts.component',
        "could not get unknown property 'incoming'",
    ))
    return (
        task_is_unavailable
        or artifact_api_is_unavailable
        or component_api_is_unavailable
    )


def _raise_gradle_command_failure(
    *,
    stage,
    command,
    stdout,
    stderr,
    return_code,
    attempts,
):
    raise GradleCommandFailure(
        stage=stage,
        command=command,
        stdout=stdout,
        stderr=stderr,
        return_code=return_code,
        attempts=attempts,
    )


def _collect_gradle_runtime_deps_for_workspace(
    work_dir, primary_module=None, modules=None, env=None, observer=None, side="",
):
    work_dir = str(Path(work_dir).resolve())
    target_selector = _resolve_single_module_selector(primary_module, modules, work_dir)
    target_model = _gradle_target_model(work_dir, target_selector)
    discovery = discover_project_modules(work_dir, build_tool='gradle')
    init_script_path = ''
    with named_temporary_file(
        mode='w',
        encoding='utf-8',
        suffix='.gradle',
        prefix='jua-gradle-artifacts-',
        delete=False,
    ) as init_script:
        init_script.write(GRADLE_ARTIFACT_INVENTORY_INIT_SCRIPT)
        init_script_path = init_script.name
    inventory_cmd = gradle_cmd(work_dir) + [
        '--no-daemon', '--console=plain',
        '--init-script', init_script_path,
        _gradle_task(target_model, GRADLE_ARTIFACT_INVENTORY_TASK),
    ]
    inventory_command = ' '.join(
        '<generated-init-script>' if value == init_script_path else value
        for value in inventory_cmd
    )
    fallback_cmd = gradle_cmd(work_dir) + [
        '--no-daemon', '--console=plain',
        _gradle_task(target_model, 'dependencies'),
        '--configuration', 'runtimeClasspath',
    ]
    fallback_command = ' '.join(fallback_cmd)
    side_display = _side_display(side)
    try:
        with _observed_phase(
            observer,
            "gradle_artifact_inventory",
            side=side,
            item=target_selector or ".",
            command=inventory_command,
            start_message=f"开始采集{side_display}运行时物理 artifact 清单",
            complete_message=f"{side_display}运行时物理 artifact 清单采集完成",
        ):
            (
                inventory_stdout,
                inventory_stderr,
                inventory_rc,
                inventory_attempts,
            ) = _run_gradle_command_with_lock_retry(
                inventory_cmd,
                cwd=work_dir,
                timeout=STEP1_BUILD_TOOL_TIMEOUT,
                env=env,
                stream_output=True,
            )
    finally:
        try:
            Path(init_script_path).unlink()
        except OSError:
            pass

    if inventory_rc != 0 and (
        _is_gradle_lock_contention(
            f'{inventory_stdout}\n{inventory_stderr}'
        )
        or not _gradle_inventory_fallback_allowed(
            inventory_stdout,
            inventory_stderr,
        )
    ):
        _raise_gradle_command_failure(
            stage='gradle_artifact_inventory',
            command=inventory_command,
            stdout=inventory_stdout,
            stderr=inventory_stderr,
            return_code=inventory_rc,
            attempts=inventory_attempts,
        )

    runtime_deps = (
        parse_gradle_artifact_inventory(
            inventory_stdout,
            project_modules=discovery.get('modules') or [],
        )
        if inventory_rc == 0
        else {}
    )
    if runtime_deps:
        return augment_runtime_deps_with_project_modules(
            runtime_deps,
            work_dir,
            target_selector,
            build_tool='gradle',
        ), inventory_command

    # Compatibility fallback for Gradle versions/plugins that do not expose
    # ArtifactView.  This preserves existing support, but only the inventory
    # path is considered physical-file evidence.
    with _observed_phase(
        observer,
        "gradle_dependencies_fallback",
        side=side,
        item=target_selector or ".",
        command=fallback_command,
        start_message=f"开始使用 Gradle 组件树补全{side_display}依赖坐标",
        complete_message=f"{side_display}Gradle 组件树坐标补全完成",
    ):
        (
            list_stdout,
            list_stderr,
            list_rc,
            fallback_attempts,
        ) = _run_gradle_command_with_lock_retry(
            fallback_cmd,
            cwd=work_dir,
            timeout=STEP1_BUILD_TOOL_TIMEOUT,
            env=env,
            stream_output=True,
        )
    if list_rc != 0:
        inventory_context = (
            inventory_stderr or inventory_stdout
            if inventory_rc != 0
            else 'artifact inventory returned no usable records'
        )
        _raise_gradle_command_failure(
            stage='gradle_dependencies_fallback',
            command=fallback_command,
            stdout=list_stdout,
            stderr=(
                f"{list_stderr}\n"
                f"artifact inventory context: {inventory_context}"
            ),
            return_code=list_rc,
            attempts=fallback_attempts,
        )
    return augment_runtime_deps_with_project_modules(
        parse_gradle_dependency_report(
            list_stdout,
            project_modules=discovery.get('modules') or [],
        ),
        work_dir,
        target_selector,
        build_tool='gradle',
    ), f'{inventory_command}; fallback={fallback_command}'


def collect_runtime_deps_for_workspace(
    work_dir, primary_module=None, modules=None, env=None, observer=None, side="",
    active_maven_profiles=None, build_tool='maven',
):
    if str(build_tool or 'maven').lower() == 'gradle':
        return _collect_gradle_runtime_deps_for_workspace(
            work_dir,
            primary_module=primary_module,
            modules=modules,
            env=env,
            observer=observer,
            side=side,
        )
    return _collect_maven_runtime_deps_for_workspace(
        work_dir,
        primary_module=primary_module,
        modules=modules,
        env=env,
        observer=observer,
        side=side,
        active_maven_profiles=active_maven_profiles,
    )


def collect_maven_deps_for_workspace(
    work_dir,
    primary_module=None,
    modules=None,
    env=None,
    manual_coord_overrides=None,
    manual_artifact_identities=None,
    allow_unresolved=False,
    confirmed_unresolved_items=None,
    observer=None,
    side="",
    active_maven_profiles=None,
):
    work_dir = str(Path(work_dir).resolve())
    manual_artifact_identities, _ = parse_manual_artifact_identities(
        manual_artifact_identities or []
    )
    target_selector = _resolve_single_module_selector(primary_module, modules, work_dir)
    module_dir = _resolve_module_dir_for_packaging(target_selector, work_dir)
    if not module_dir:
        raise RuntimeError(f"无法解析目标模块目录：{target_selector}")

    pl = _normalize_maven_pl_with_workdir(target_selector, work_dir)
    build_scope = build_project_scope(
        work_dir,
        target_selector or ".",
        active_profiles=set(active_maven_profiles or []),
    )
    profile_args = _maven_profile_args_for_module(
        work_dir, target_selector, active_maven_profiles
    )
    package_cmd = mvn_cmd(work_dir) + [
        '--batch-mode',
        *profile_args,
        *(["-pl", pl, "-am"] if pl else []),
        MAVEN_SKIP_TEST_COMPILATION_ARG,
        'package',
    ]
    package_command = ' '.join(package_cmd)
    side_display = _side_display(side)
    with _observed_phase(
        observer,
        "maven_package",
        side=side,
        item=target_selector or ".",
        command=package_command,
        start_message=f"开始构建{side_display}目标模块",
        complete_message=f"{side_display}目标模块构建完成",
    ):
        stdout, stderr, rc = run_cmd(
            package_cmd, cwd=work_dir, timeout=STEP1_BUILD_TOOL_TIMEOUT,
            env=env, stream_output=True,
        )
        if rc != 0:
            raise RuntimeError(f"mvn package 失败（退出码 {rc}）：\n{stderr[:1000] or stdout[:1000]}")
    with _observed_phase(
        observer,
        "artifact_discovery",
        side=side,
        item=module_dir,
        start_message=f"开始定位{side_display}最终制品",
        complete_message=f"{side_display}最终制品定位完成",
    ):
        archives = _discover_packaged_archives(module_dir)
    if not archives:
        raise RuntimeError(
            f"目标模块未产出可解析的最终制品：{module_dir}。"
            "当前 Step1 只比较最终打包依赖，不再回退到 runtime dependency:list。"
        )

    runtime_deps = {}
    list_cmd_text = ''
    need_runtime_enrichment = False
    for artifact_path in archives:
        with _observed_phase(
            observer,
            "artifact_parse",
            side=side,
            item=str(artifact_path),
            start_message=f"开始解析{side_display}最终制品：{Path(artifact_path).name}",
            complete_message=f"{side_display}最终制品解析完成：{Path(artifact_path).name}",
        ):
            packaging_type = _detect_archive_packaging_type(artifact_path)
            if packaging_type not in ('boot_jar', 'war', 'packaged_jar'):
                continue
            cache_stats = {}
            packaged_raw = _inspect_packaged_archive(
                artifact_path,
                cache_dir=_observer_packaged_inventory_cache_dir(observer),
                cache_stats=cache_stats,
            )
            if observer is not None:
                observer.increment_counter('cache_hits', cache_stats.get('hits', 0))
                observer.increment_counter('cache_misses', cache_stats.get('misses', 0))
                observer.increment_counter('archive_bytes', cache_stats.get('archive_bytes', 0))
                observer.increment_counter('nested_entries', cache_stats.get('nested_entries', 0))
            _require_complete_packaged_archive_scan(cache_stats, artifact_path)
            if not packaged_raw:
                continue
        if any(
            not (item.get('coord') or '').strip()
            and _manual_artifact_identity_for_entry(
                item, manual_artifact_identities, side
            )[0] is None
            for item in packaged_raw
        ):
            need_runtime_enrichment = True
        if need_runtime_enrichment and not runtime_deps:
            runtime_deps, list_command_text = collect_runtime_deps_for_workspace(
                work_dir,
                primary_module=primary_module,
                modules=modules,
                env=env,
                observer=observer,
                side=side,
                active_maven_profiles=active_maven_profiles,
                build_tool='maven',
            )
            list_cmd_text = list_command_text or ''
        with _observed_phase(
            observer,
            "artifact_coordinate_resolution",
            side=side,
            item=str(artifact_path),
            start_message=f"开始解析{side_display}最终制品中的依赖坐标",
            complete_message=f"{side_display}最终制品依赖坐标解析完成",
        ):
            dep_entries, packaged_deps, unresolved_items = _enrich_packaged_deps_with_runtime(
                packaged_raw,
                runtime_deps,
                manual_coord_overrides=manual_coord_overrides,
                manual_artifact_identities=manual_artifact_identities,
                confirmed_unresolved_items=confirmed_unresolved_items,
                side=side,
            )
            if unresolved_items and not allow_unresolved:
                raise UnresolvedPackagedCoordinatesError(unresolved_items, resolved_deps=packaged_deps)
            if dep_entries:
                return packaged_deps, {
                'mode': 'final_artifact',
                'packaging_type': packaging_type,
                'artifact_path': str(artifact_path),
                'module_dir': str(module_dir),
                'build_command': ' '.join(package_cmd),
                'list_command': list_cmd_text,
                'archives': [str(artifact_path)],
                'deps': list(dep_entries),
                'dep_entries': list(dep_entries),
                'matched_count': sum(1 for item in dep_entries if str(item.get('resolution_status') or '').strip() == 'resolved'),
                'unresolved_items': unresolved_items,
                'runtime_only_count': 0,
                'runtime_only_coords': [],
                **project_scope_provenance_fields(build_scope),
            }

    raise RuntimeError(
        f"目标模块的最终制品中未发现可比较的打包依赖：{module_dir}。"
        "当前 Step1 只比较最终打包依赖；thin jar / 无嵌套依赖场景不再作为正式结果输出。"
    )


def collect_gradle_deps_for_workspace(
    work_dir,
    primary_module=None,
    modules=None,
    env=None,
    manual_coord_overrides=None,
    manual_artifact_identities=None,
    allow_unresolved=False,
    confirmed_unresolved_items=None,
    observer=None,
    side="",
):
    work_dir = str(Path(work_dir).resolve())
    manual_artifact_identities, _ = parse_manual_artifact_identities(
        manual_artifact_identities or []
    )
    target_selector = _resolve_single_module_selector(primary_module, modules, work_dir)
    target_model = _gradle_target_model(work_dir, target_selector)
    module_dir = Path(target_model['module_dir'])
    build_scope = build_project_scope(
        work_dir, target_selector or '.', build_tool='gradle'
    )
    package_cmd = gradle_cmd(work_dir) + [
        '--no-daemon', '--console=plain',
        _gradle_task(target_model, 'build'),
        '-x', 'test',
    ]
    package_command = ' '.join(package_cmd)
    side_display = _side_display(side)
    with _observed_phase(
        observer,
        "gradle_build",
        side=side,
        item=target_selector or ".",
        command=package_command,
        start_message=f"开始构建{side_display}目标模块",
        complete_message=f"{side_display}目标模块构建完成",
    ):
        stdout, stderr, rc, build_attempts = (
            _run_gradle_command_with_lock_retry(
                package_cmd,
                cwd=work_dir,
                timeout=STEP1_BUILD_TOOL_TIMEOUT,
                env=env,
                stream_output=True,
            )
        )
        if rc != 0:
            _raise_gradle_command_failure(
                stage='gradle_build',
                command=package_command,
                stdout=stdout,
                stderr=stderr,
                return_code=rc,
                attempts=build_attempts,
            )
    with _observed_phase(
        observer,
        "artifact_discovery",
        side=side,
        item=str(module_dir),
        start_message=f"开始定位{side_display}最终制品",
        complete_message=f"{side_display}最终制品定位完成",
    ):
        archives = _discover_packaged_archives(module_dir)
    if not archives:
        raise RuntimeError(
            f"目标模块未产出可解析的最终制品：{module_dir}。"
            "请确认目标模块存在 jar、bootJar、shadowJar 或 war 构建任务。"
        )

    runtime_deps = {}
    list_cmd_text = ''
    for artifact_path in archives:
        with _observed_phase(
            observer,
            "artifact_parse",
            side=side,
            item=str(artifact_path),
            start_message=f"开始解析{side_display}最终制品：{Path(artifact_path).name}",
            complete_message=f"{side_display}最终制品解析完成：{Path(artifact_path).name}",
        ):
            packaging_type = _detect_archive_packaging_type(artifact_path)
            if packaging_type not in ('boot_jar', 'war', 'packaged_jar'):
                continue
            cache_stats = {}
            packaged_raw = _inspect_packaged_archive(
                artifact_path,
                cache_dir=_observer_packaged_inventory_cache_dir(observer),
                cache_stats=cache_stats,
            )
            if observer is not None:
                observer.increment_counter('cache_hits', cache_stats.get('hits', 0))
                observer.increment_counter('cache_misses', cache_stats.get('misses', 0))
                observer.increment_counter('archive_bytes', cache_stats.get('archive_bytes', 0))
                observer.increment_counter('nested_entries', cache_stats.get('nested_entries', 0))
            _require_complete_packaged_archive_scan(cache_stats, artifact_path)
            if not packaged_raw:
                continue
        if any(
            not (item.get('coord') or '').strip()
            and _manual_artifact_identity_for_entry(
                item, manual_artifact_identities, side
            )[0] is None
            for item in packaged_raw
        ) and not runtime_deps:
            runtime_deps, list_cmd_text = collect_runtime_deps_for_workspace(
                work_dir,
                primary_module=primary_module,
                modules=modules,
                env=env,
                observer=observer,
                side=side,
                build_tool='gradle',
            )
        with _observed_phase(
            observer,
            "artifact_coordinate_resolution",
            side=side,
            item=str(artifact_path),
            start_message=f"开始解析{side_display}最终制品中的依赖坐标",
            complete_message=f"{side_display}最终制品依赖坐标解析完成",
        ):
            dep_entries, packaged_deps, unresolved_items = _enrich_packaged_deps_with_runtime(
                packaged_raw,
                runtime_deps,
                manual_coord_overrides=manual_coord_overrides,
                manual_artifact_identities=manual_artifact_identities,
                confirmed_unresolved_items=confirmed_unresolved_items,
                side=side,
            )
            if unresolved_items and not allow_unresolved:
                raise UnresolvedPackagedCoordinatesError(
                    unresolved_items, resolved_deps=packaged_deps
                )
            if dep_entries:
                return packaged_deps, {
                    'mode': 'final_artifact',
                    'packaging_type': packaging_type,
                    'artifact_path': str(artifact_path),
                    'module_dir': str(module_dir),
                    'build_command': package_command,
                    'list_command': list_cmd_text,
                    'archives': [str(artifact_path)],
                    'deps': list(dep_entries),
                    'dep_entries': list(dep_entries),
                    'matched_count': sum(
                        1 for item in dep_entries
                        if str(item.get('resolution_status') or '').strip() == 'resolved'
                    ),
                    'unresolved_items': unresolved_items,
                    'runtime_only_count': 0,
                    'runtime_only_coords': [],
                    **project_scope_provenance_fields(build_scope),
                }
    raise RuntimeError(
        f"目标模块的最终制品中未发现可比较的打包依赖：{module_dir}。"
        "当前 Step1 只比较最终打包依赖；thin jar / 无嵌套依赖场景不作为正式结果输出。"
    )


def collect_packaged_deps_from_artifact_path(
    artifact_path,
    runtime_deps=None,
    work_dir=None,
    runtime_deps_loader=None,
    manual_coord_overrides=None,
    manual_artifact_identities=None,
    confirmed_unresolved_items=None,
    allow_unresolved=False,
    observer=None,
    side="",
):
    manual_artifact_identities, _ = parse_manual_artifact_identities(
        manual_artifact_identities or []
    )
    artifact_file = Path(artifact_path).expanduser()
    if not artifact_file.is_absolute():
        if work_dir:
            artifact_file = (Path(work_dir).resolve() / artifact_file).resolve()
        else:
            artifact_file = artifact_file.resolve()
    if not artifact_file.exists() or not artifact_file.is_file():
        raise RuntimeError(f"用户提供的编译产物不存在或不是文件：{artifact_file}")

    with _observed_phase(
        observer,
        "artifact_parse",
        side=side,
        item=str(artifact_file),
        start_message=f"开始解析{_side_display(side)}最终制品",
        complete_message=f"{_side_display(side)}最终制品解析完成",
    ):
        packaging_type = _detect_archive_packaging_type(artifact_file)
        if packaging_type not in ('boot_jar', 'war', 'packaged_jar'):
            raise RuntimeError(
                f"用户提供的编译产物未发现可比较的嵌套依赖：{artifact_file}。"
                "当前 Step1 只比较最终打包依赖；thin jar / 无嵌套依赖场景不再作为正式结果输出。"
            )

        cache_stats = {}
        packaged_raw = _inspect_packaged_archive(
            artifact_file,
            cache_dir=_observer_packaged_inventory_cache_dir(observer),
            cache_stats=cache_stats,
        )
        if observer is not None:
            observer.increment_counter('cache_hits', cache_stats.get('hits', 0))
            observer.increment_counter('cache_misses', cache_stats.get('misses', 0))
            observer.increment_counter('archive_bytes', cache_stats.get('archive_bytes', 0))
            observer.increment_counter('nested_entries', cache_stats.get('nested_entries', 0))
        _require_complete_packaged_archive_scan(cache_stats, artifact_file)
        if not packaged_raw:
            raise RuntimeError(
                f"用户提供的编译产物中未发现可比较的打包依赖：{artifact_file}。"
                "当前 Step1 只比较最终打包依赖；thin jar / 无嵌套依赖场景不再作为正式结果输出。"
            )

    resolved_runtime_deps = runtime_deps or {}
    if any(
        not (item.get('coord') or '').strip()
        and _manual_artifact_identity_for_entry(
            item, manual_artifact_identities, side
        )[0] is None
        for item in packaged_raw
    ):
        if not resolved_runtime_deps and runtime_deps_loader is not None:
            resolved_runtime_deps = runtime_deps_loader() or {}
    with _observed_phase(
        observer,
        "artifact_coordinate_resolution",
        side=side,
        item=str(artifact_file),
        start_message=f"开始解析{_side_display(side)}最终制品中的依赖坐标",
        complete_message=f"{_side_display(side)}最终制品依赖坐标解析完成",
    ):
        dep_entries, packaged_deps, unresolved_items = _enrich_packaged_deps_with_runtime(
            packaged_raw,
            resolved_runtime_deps,
            manual_coord_overrides=manual_coord_overrides,
            manual_artifact_identities=manual_artifact_identities,
            confirmed_unresolved_items=confirmed_unresolved_items,
            side=side,
        )
    if unresolved_items and not allow_unresolved:
        raise ArtifactCoordinateInputRequiredError(
            str(artifact_file.resolve()),
            unresolved_items=unresolved_items,
        )

    return packaged_deps, {
        'mode': 'final_artifact',
        'packaging_type': packaging_type,
        'artifact_path': str(artifact_file.resolve()),
        'artifact_input_mode': 'user_provided',
        'module_dir': '',
        'build_command': '',
        'list_command': '',
        'archives': [str(artifact_file.resolve())],
        'deps': list(dep_entries),
        'dep_entries': list(dep_entries),
        'matched_count': sum(1 for item in dep_entries if str(item.get('resolution_status') or '').strip() == 'resolved'),
        'unresolved_items': unresolved_items,
        'runtime_only_count': 0,
        'runtime_only_coords': [],
    }


def _collect_runtime_deps_for_artifact_input(
    source_project_dir,
    branch,
    work_dir,
    primary_module=None,
    modules=None,
    jdk_field="",
    jdk_home="",
    side="",
    artifact_path="",
    observer=None,
    source_resolution=None,
    expected_commit="",
    expected_remote="",
    expected_remote_ref="",
    allow_local_source=False,
    allow_dirty_local_source=False,
    active_maven_profiles=None,
    build_tool='maven',
):
    source_dir = str(source_project_dir or '').strip()
    if branch:
        repo_dir = source_dir or str(Path(work_dir).resolve())
        resolution = dict(source_resolution or {})
        if not (
            resolution.get("status") == "resolved"
            and str(resolution.get("resolved_commit") or "").strip()
            and str(resolution.get("source_status") or "") in {
                "remote_source_resolved",
                "user_confirmed_local_source",
            }
        ):
            resolve_kwargs = {
                "allow_local_source": allow_local_source,
                "allow_dirty_local_source": allow_dirty_local_source,
            }
            if str(expected_commit or "").strip():
                resolve_kwargs["expected_commit"] = str(expected_commit).strip()
            if str(expected_remote or "").strip():
                resolve_kwargs["expected_remote"] = str(expected_remote).strip()
            if str(expected_remote_ref or "").strip():
                resolve_kwargs["expected_remote_ref"] = str(expected_remote_ref).strip()
            resolution = resolve_step1_ref(repo_dir, branch, **resolve_kwargs)
        if resolution.get("status") != "resolved":
            if resolution.get("source_status") in {
                "remote_expected_commit_unmaterializable",
                "remote_ref_moved",
            }:
                raise PinnedCommitMaterializationError(side, resolution)
            if resolution.get("status") == "fetch_failed":
                raise Step1RemoteOperationError(side, repo_dir, resolution)
            raise Step1RefResolutionRequiredError(
                side, repo_dir, artifact_path, resolution,
            )
        resolved_commit = str(resolution.get("resolved_commit") or "").strip()
        if observer is not None:
            observer.event(
                "ref_resolution",
                "completed",
                f"{'基准侧' if side == 'base' else '当前侧'}坐标补全源码版本已固定",
                side=side,
                details={
                    "requested_ref": str(resolution.get("requested_ref") or branch),
                    "resolved_ref": str(resolution.get("resolved_ref") or branch),
                    "resolved_commit": resolved_commit,
                    "resolution_mode": str(resolution.get("resolution_mode") or "exact"),
                    "candidate_count": len(resolution.get("candidates") or []),
                    "source_status": str(resolution.get("source_status") or ""),
                    "remote": str(resolution.get("remote") or ""),
                    "remote_ref": str(resolution.get("remote_ref") or ""),
                },
            )
        runtime_deps, meta = get_runtime_deps_by_switching_branch(
            resolved_commit,
            repo_dir,
            primary_module=primary_module,
            modules=modules,
            jdk_field=jdk_field,
            jdk_home=jdk_home,
            side=side,
            artifact_path=artifact_path,
            observer=observer,
            active_maven_profiles=active_maven_profiles,
            build_tool=build_tool,
        )
        return runtime_deps, {
            **meta,
            'source_mode': 'checkout_branch',
            'requested_ref': str(resolution.get('requested_ref') or branch),
            'resolved_ref': str(resolution.get('resolved_ref') or branch),
            'resolved_commit': resolved_commit,
            'ref_resolution_mode': str(resolution.get('resolution_mode') or 'exact'),
            'ref_source_status': str(resolution.get('source_status') or ''),
            'ref_remote': str(resolution.get('remote') or ''),
            'ref_remote_ref': str(resolution.get('remote_ref') or ''),
            'branch': resolved_commit,
        }
    if source_dir:
        resolution = resolve_step1_ref(source_dir, "HEAD")
        raise SourceRevisionConfirmationRequiredError(
            side, source_dir, artifact_path, resolution,
        )
    return {}, {
        'source_mode': 'none',
        'source_project_dir': '',
        'list_command': '',
    }


def create_branch_worktree(branch, work_dir, side=""):
    side_token = {"base": "b", "current": "c"}.get(str(side or "").strip(), "x")
    return create_detached_worktree(
        branch,
        work_dir,
        label=f"s1-{side_token}",
        runner=run_cmd,
        git_command=git_cmd(),
    )


def remove_branch_worktree(temp_dir, work_dir):
    remove_detached_worktree(
        temp_dir,
        work_dir,
        runner=run_cmd,
        git_command=git_cmd(),
    )


def get_packaged_deps_by_switching_branch(
    branch,
    work_dir,
    primary_module=None,
    modules=None,
    jdk_field="",
    jdk_home="",
    side="",
    manual_coord_overrides=None,
    manual_artifact_identities=None,
    allow_unresolved=False,
    confirmed_unresolved_items=None,
    artifact_cache_dir=None,
    observer=None,
    active_maven_profiles=None,
    build_tool='maven',
):
    blocked_error = None
    env = None
    temp_dir = None
    result = None
    try:
        env = build_java_env(jdk_home)
    except Exception as exc:
        blocked_error = build_step1_command_blocked_error(
            stage="prepare_java_env",
            command="",
            exc=exc,
            side=side,
            branch=branch,
            jdk_field=jdk_field,
            jdk_home=jdk_home,
            source_mode="checkout_build",
        )
    if blocked_error is None:
        try:
            with _observed_phase(
                observer,
                "prepare_worktree",
                side=side,
                item=branch,
                command=f"git worktree add --detach <temp> {branch}",
                start_message=f"开始准备{_side_display(side)}分支工作区",
                complete_message=f"{_side_display(side)}分支工作区准备完成",
            ):
                temp_dir = create_branch_worktree(branch, work_dir, side=side)
        except Exception as exc:
            blocked_error = build_step1_command_blocked_error(
                stage="prepare_branch_worktree",
                command=f"git worktree add --detach <temp> {branch}",
                exc=exc,
                side=side,
                branch=branch,
                jdk_field=jdk_field,
                jdk_home=jdk_home,
                source_mode="checkout_build",
            )
    if blocked_error is None:
        try:
            collector = (
                collect_gradle_deps_for_workspace
                if str(build_tool or 'maven').lower() == 'gradle'
                else collect_maven_deps_for_workspace
            )
            collector_kwargs = {
                'primary_module': primary_module,
                'modules': modules,
                'env': add_branch_hint_to_env(env, branch),
                'manual_coord_overrides': manual_coord_overrides,
                'manual_artifact_identities': manual_artifact_identities,
                'allow_unresolved': allow_unresolved,
                'confirmed_unresolved_items': confirmed_unresolved_items,
                'observer': observer,
                'side': side,
            }
            if str(build_tool or 'maven').lower() == 'maven':
                collector_kwargs['active_maven_profiles'] = active_maven_profiles
            deps, meta = collector(
                str(temp_dir),
                **collector_kwargs,
            )
            meta['branch'] = branch
            meta['jdk_home'] = resolve_effective_jdk_home(jdk_home)
            meta['worktree_dir'] = str(temp_dir)
            artifact_path = str(meta.get('artifact_path') or '').strip()
            revision, _revision_err, revision_rc = run_cmd(git_cmd() + ['rev-parse', 'HEAD'], cwd=str(temp_dir))
            meta['revision'] = revision.strip() if revision_rc == 0 else ''
            if artifact_path and artifact_cache_dir:
                with _observed_phase(
                    observer,
                    "artifact_retention",
                    side=side,
                    item=artifact_path,
                    start_message=f"开始保留{_side_display(side)}最终制品供后续分析",
                    complete_message=f"{_side_display(side)}最终制品保留完成",
                ):
                    retain_artifact_for_analysis(meta, artifact_cache_dir, side)
            else:
                meta['artifact_sha256'] = (
                    sha256_file(artifact_path)
                    if artifact_path and Path(artifact_path).is_file()
                    else ''
                )
            result = (deps, meta)
        except Exception as exc:
            blocked_error = (
                exc
                if isinstance(exc, Step1CommandExecutionBlockedError)
                else build_step1_command_blocked_from_exception(
                    exc,
                    default_stage=(
                        "gradle_build"
                        if str(build_tool).lower() == 'gradle'
                        else "mvn_package"
                    ),
                    default_command=(
                        "gradlew --no-daemon --console=plain build -x test"
                        if str(build_tool).lower() == 'gradle'
                        else f"mvn --batch-mode {MAVEN_SKIP_TEST_COMPILATION_ARG} package"
                    ),
                    side=side,
                    branch=branch,
                    jdk_field=jdk_field,
                    jdk_home=jdk_home,
                    source_mode="checkout_build",
                )
            )
    if temp_dir is not None:
        try:
            with _observed_phase(
                observer,
                "cleanup_worktree",
                side=side,
                item=str(temp_dir),
                command=f"git worktree remove --force {temp_dir}",
                start_message=f"开始清理{_side_display(side)}临时工作区",
                complete_message=f"{_side_display(side)}临时工作区清理完成",
            ):
                remove_branch_worktree(temp_dir, work_dir)
        except Exception as cleanup_exc:
            if blocked_error is not None:
                blocked_error = append_cleanup_failure_to_blocked_error(blocked_error, cleanup_exc)
            else:
                blocked_error = build_step1_command_blocked_error(
                    stage="cleanup_branch_worktree",
                    command=f"git worktree remove --force {temp_dir}",
                    exc=cleanup_exc,
                    side=side,
                    branch=branch,
                    jdk_field=jdk_field,
                    jdk_home=jdk_home,
                    source_mode="checkout_build",
                )
    if blocked_error is not None:
        raise blocked_error
    return result


def get_runtime_deps_by_switching_branch(
    branch, work_dir, primary_module=None, modules=None, jdk_field="", jdk_home="",
    side="", artifact_path="", observer=None, active_maven_profiles=None,
    build_tool='maven',
):
    blocked_error = None
    env = None
    temp_dir = None
    result = None
    try:
        env = build_java_env(jdk_home)
    except Exception as exc:
        blocked_error = build_step1_command_blocked_error(
            stage="prepare_java_env",
            command="",
            exc=exc,
            side=side,
            branch=branch,
            jdk_field=jdk_field,
            jdk_home=jdk_home,
            source_mode="branch_checkout",
            artifact_path=artifact_path,
        )
    if blocked_error is None:
        try:
            with _observed_phase(
                observer,
                "prepare_worktree",
                side=side,
                item=branch,
                command=f"git worktree add --detach <temp> {branch}",
                start_message=f"开始准备{_side_display(side)}分支工作区",
                complete_message=f"{_side_display(side)}分支工作区准备完成",
            ):
                temp_dir = create_branch_worktree(branch, work_dir, side=side)
        except Exception as exc:
            blocked_error = build_step1_command_blocked_error(
                stage="prepare_branch_worktree",
                command=f"git worktree add --detach <temp> {branch}",
                exc=exc,
                side=side,
                branch=branch,
                jdk_field=jdk_field,
                jdk_home=jdk_home,
                source_mode="branch_checkout",
                artifact_path=artifact_path,
            )
    if blocked_error is None:
        try:
            runtime_deps, list_command = collect_runtime_deps_for_workspace(
                str(temp_dir),
                primary_module=primary_module,
                modules=modules,
                env=add_branch_hint_to_env(env, branch),
                observer=observer,
                side=side,
                active_maven_profiles=active_maven_profiles,
                build_tool=build_tool,
            )
            result = (
                runtime_deps,
                {
                    'branch': branch,
                    'list_command': list_command,
                    'jdk_home': resolve_effective_jdk_home(jdk_home),
                    'worktree_dir': str(temp_dir),
                },
            )
        except Exception as exc:
            blocked_error = (
                exc
                if isinstance(exc, Step1CommandExecutionBlockedError)
                else build_step1_command_blocked_from_exception(
                    exc,
                    default_stage=(
                        "gradle_dependencies"
                        if str(build_tool).lower() == 'gradle'
                        else "mvn_dependency_list"
                    ),
                    default_command=(
                        "gradlew --no-daemon --console=plain dependencies "
                        "--configuration runtimeClasspath"
                        if str(build_tool).lower() == 'gradle'
                        else (
                            f"mvn --batch-mode {MAVEN_SKIP_TEST_COMPILATION_ARG} dependency:list "
                            "-DincludeScope=runtime "
                            "-DoutputAbsoluteArtifactFilename=true"
                        )
                    ),
                    side=side,
                    branch=branch,
                    jdk_field=jdk_field,
                    jdk_home=jdk_home,
                    source_mode="branch_checkout",
                    artifact_path=artifact_path,
                )
            )
    if temp_dir is not None:
        try:
            with _observed_phase(
                observer,
                "cleanup_worktree",
                side=side,
                item=str(temp_dir),
                command=f"git worktree remove --force {temp_dir}",
                start_message=f"开始清理{_side_display(side)}临时工作区",
                complete_message=f"{_side_display(side)}临时工作区清理完成",
            ):
                remove_branch_worktree(temp_dir, work_dir)
        except Exception as cleanup_exc:
            if blocked_error is not None:
                blocked_error = append_cleanup_failure_to_blocked_error(blocked_error, cleanup_exc)
            else:
                blocked_error = build_step1_command_blocked_error(
                    stage="cleanup_branch_worktree",
                    command=f"git worktree remove --force {temp_dir}",
                    exc=cleanup_exc,
                    side=side,
                    branch=branch,
                    jdk_field=jdk_field,
                    jdk_home=jdk_home,
                    source_mode="branch_checkout",
                    artifact_path=artifact_path,
                )
    if blocked_error is not None:
        raise blocked_error
    return result


def print_manual_instructions(base_branch, current_branch, primary_module=None, work_dir=None, modules=None):
    """打印用户需要手动执行的命令，确保按最终打包依赖口径获取结果"""
    target_selector = _resolve_single_module_selector(primary_module, modules, work_dir)
    pl = _normalize_maven_pl_with_workdir(target_selector, work_dir)
    package_cmd = (
        f"mvn {'-pl ' + pl + ' -am ' if pl else ''}"
        f"{MAVEN_SKIP_TEST_COMPILATION_ARG} package"
    )

    sep = "=" * 60
    print(f"\n{sep}", file=sys.stderr)
    print("手工执行 Step1（务必在项目根目录执行）：\n", file=sys.stderr)
    print(f"  # 第1步：基准分支", file=sys.stderr)
    print(f"  git checkout {base_branch}", file=sys.stderr)
    print(f"  {package_cmd}", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"  # 第2步：当前分支", file=sys.stderr)
    print(f"  git checkout {current_branch}", file=sys.stderr)
    print(f"  {package_cmd}", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"  # 第3步：运行分析", file=sys.stderr)
    if IS_WINDOWS:
        print(f'  $env:PYTHONUTF8 = "1"', file=sys.stderr)
        print(f"  python scripts\\s1_dep_diff.py `", file=sys.stderr)
        print(f"    --base {base_branch} `", file=sys.stderr)
        print(f"    --current {current_branch} `", file=sys.stderr)
        print(f"    --output .upgrade-report\\evidence\\dependencies\\dep_changes.csv", file=sys.stderr)
    else:
        print(f"  python scripts/s1_dep_diff.py \\", file=sys.stderr)
        print(f"    --base {base_branch} \\", file=sys.stderr)
        print(f"    --current {current_branch} \\", file=sys.stderr)
        print(f"    --output .upgrade-report/evidence/dependencies/dep_changes.csv", file=sys.stderr)
    print(f"\n依赖遗漏常见原因：", file=sys.stderr)
    print(f"  1. 目标模块无法成功 package", file=sys.stderr)
    print(f"  2. 多模块项目在子模块目录执行（应在根 pom.xml 所在目录执行）", file=sys.stderr)
    print(f"  3. 目标模块是 thin jar / 无嵌套依赖，当前 Step1 不支持", file=sys.stderr)
    print(f"  4. 构建插件改写了最终产物，需优先核对实际产物内容", file=sys.stderr)
    print(f"{sep}\n", file=sys.stderr)


# ══════════════════════════════════════════════════════════════════
# 诊断输出
# ══════════════════════════════════════════════════════════════════

def print_parse_report(label, deps, fmt, errors=None):
    print(f"\n{'='*50}", file=sys.stderr)
    print(f"  [{label}] 格式：{fmt}  解析到 {len(deps)} 个依赖", file=sys.stderr)
    if errors:
        print(f"  解析失败：{len(errors)} 行", file=sys.stderr)
    scope_cnt = defaultdict(int)
    for d in deps.values():
        scope_cnt[d['scope']] += 1
    for s, c in sorted(scope_cnt.items()):
        print(f"    {s}: {c}", file=sys.stderr)
    print(f"  前 5 个（请确认是否正确）：", file=sys.stderr)
    for key, dep in list(deps.items())[:5]:
        print(f"    {key}:{dep['version']} ({dep['scope']})", file=sys.stderr)
    print(f"{'='*50}", file=sys.stderr)


def _entry_compare_key(entry):
    if not entry:
        return ''
    artifact_id = str(entry.get('artifact_id') or '').strip()
    classifier = str(entry.get('classifier') or '').strip()
    if artifact_id:
        key = artifact_id
        if classifier:
            key = f"{key}:{classifier}"
        return key
    return str(entry.get('lib_entry') or entry.get('lib_name') or '').strip()


def _entry_sort_key(entry):
    return (
        str(entry.get('coord') or '').strip(),
        str(entry.get('version') or '').strip(),
        str(entry.get('lib_entry') or '').strip(),
    )


def _display_coord(entry):
    if not entry:
        return ''
    coord = normalize_artifact_coord(
        entry.get('coord'),
        entry.get('classifier'),
    )
    if coord:
        return coord
    artifact_id = str(entry.get('artifact_id') or '').strip()
    version = str(entry.get('version') or '').strip()
    if artifact_id or version:
        return f"{artifact_id}:{version}".strip(':')
    return str(entry.get('lib_name') or entry.get('lib_entry') or '').strip()


def _resolved_coord(entry):
    if not entry:
        return ''
    return normalize_artifact_coord(
        entry.get('coord'),
        entry.get('classifier'),
    )


def _entry_full_compare_key(entry):
    return _resolved_coord(entry)


def _entry_content_sha256(entry):
    value = str((entry or {}).get('content_sha256') or '').strip().lower()
    return value if re.fullmatch(r'[0-9a-f]{64}', value) else ''


def _make_step1_change_row(base_entry, current_entry, comparison_key, pairing_status, pairing_reason_code=''):
    old_ver = str((base_entry or {}).get('version') or '-').strip() or '-'
    new_ver = str((current_entry or {}).get('version') or '-').strip() or '-'
    base_status = str((base_entry or {}).get('resolution_status') or '').strip() or 'resolved'
    current_status = str((current_entry or {}).get('resolution_status') or '').strip() or 'resolved'
    forced_unresolved = bool(pairing_reason_code)
    resolution_status = (
        'resolved'
        if not forced_unresolved and base_status == 'resolved' and current_status == 'resolved'
        else 'unresolved'
    )
    if resolution_status == 'resolved':
        change, risk = classify_change(old_ver, new_ver)
        base_content_sha256 = _entry_content_sha256(base_entry)
        current_content_sha256 = _entry_content_sha256(current_entry)
        same_version_content_changed = bool(
            old_ver == new_ver
            and old_ver not in ('', '-')
            and base_content_sha256
            and current_content_sha256
            and base_content_sha256 != current_content_sha256
        )
        if same_version_content_changed:
            # A republished SNAPSHOT/proprietary artifact can change without a
            # version change. The final packaged bytes are authoritative, so
            # retain both sides and let Step4 compare their actual APIs.
            change, risk = '已变更', '❓需人工确认'
    else:
        change, risk = 'unresolved', '需人工确认'
        same_version_content_changed = False
    scope = str(((current_entry or base_entry or {}).get('scope')) or 'packaged').strip() or 'packaged'
    if scope in ('test', 'provided', 'optional') and risk == '高':
        risk = '低(非compile)'
    remark = str(((current_entry or {}).get('remark')) or ((base_entry or {}).get('remark')) or '').strip()
    if same_version_content_changed:
        remark = ';'.join(item for item in (
            remark,
            'same_version_artifact_content_changed',
        ) if item)
    if pairing_reason_code:
        remark = ';'.join(item for item in (remark, f'pairing:{pairing_reason_code}') if item)
    return {
        'coord': _display_coord(current_entry or base_entry),
        'base_coord': _resolved_coord(base_entry),
        'current_coord': _resolved_coord(current_entry),
        'old_version': old_ver,
        'new_version': new_ver,
        'change_type': change,
        'risk': risk,
        'scope': scope,
        'remark': remark,
        'current_packaged': 'true' if current_entry else '',
        'downgrade_confirmed': '',
        'resolution_status': resolution_status,
        'comparison_key': comparison_key,
        'pairing_status': pairing_status,
        'pairing_reason_code': pairing_reason_code,
        'base_lib_entry': str((base_entry or {}).get('lib_entry') or '').strip(),
        'current_lib_entry': str((current_entry or {}).get('lib_entry') or '').strip(),
        'base_packaged_match_source': str((base_entry or {}).get('packaged_match_source') or '').strip(),
        'current_packaged_match_source': str((current_entry or {}).get('packaged_match_source') or '').strip(),
        'base_resolution_status': base_status,
        'current_resolution_status': current_status,
        'base_read_error': str((base_entry or {}).get('read_error') or '').strip(),
        'current_read_error': str((current_entry or {}).get('read_error') or '').strip(),
    }


def _build_step1_change_rows(base_entries, curr_entries):
    base_remaining = [dict(item) for item in (base_entries or [])]
    curr_remaining = [dict(item) for item in (curr_entries or [])]
    rows = []

    # Stage 1: exact groupId:artifactId(+classifier) matches are authoritative.
    base_exact = defaultdict(list)
    curr_exact = defaultdict(list)
    for item in base_remaining:
        if _entry_full_compare_key(item):
            base_exact[_entry_full_compare_key(item)].append(item)
    for item in curr_remaining:
        if _entry_full_compare_key(item):
            curr_exact[_entry_full_compare_key(item)].append(item)
    paired_base_ids = set()
    paired_curr_ids = set()
    for full_key in sorted(set(base_exact) & set(curr_exact)):
        left = sorted(base_exact[full_key], key=_entry_sort_key)
        right = sorted(curr_exact[full_key], key=_entry_sort_key)
        for base_entry, current_entry in zip(left, right):
            paired_base_ids.add(id(base_entry))
            paired_curr_ids.add(id(current_entry))
            rows.append(_make_step1_change_row(
                base_entry, current_entry, full_key, 'exact_coord',
            ))
    base_remaining = [item for item in base_remaining if id(item) not in paired_base_ids]
    curr_remaining = [item for item in curr_remaining if id(item) not in paired_curr_ids]

    # Stage 2: allow group migration only for a unique artifactId(+classifier) pair.
    base_groups = defaultdict(list)
    curr_groups = defaultdict(list)
    for item in base_remaining:
        base_groups[_entry_compare_key(item)].append(item)
    for item in curr_remaining:
        curr_groups[_entry_compare_key(item)].append(item)
    for group_key in sorted(set(base_groups) | set(curr_groups)):
        left = sorted(base_groups.get(group_key, []), key=_entry_sort_key)
        right = sorted(curr_groups.get(group_key, []), key=_entry_sort_key)
        if len(left) == 1 and len(right) == 1:
            rows.append(_make_step1_change_row(
                left[0], right[0], group_key, 'unique_artifact_migration',
            ))
            continue
        ambiguous = bool(left and right)
        reason = 'ambiguous_artifact_migration_candidates' if ambiguous else ''
        for item in left:
            rows.append(_make_step1_change_row(
                item, None, group_key, 'unpaired_ambiguous' if ambiguous else 'base_only', reason,
            ))
        for item in right:
            rows.append(_make_step1_change_row(
                None, item, group_key, 'unpaired_ambiguous' if ambiguous else 'current_only', reason,
            ))
    rows.sort(key=lambda row: (row.get('comparison_key', ''), row.get('base_coord', ''), row.get('current_coord', '')))
    return rows


# ══════════════════════════════════════════════════════════════════
# 主函数
# ══════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description='Step 1：依赖变更全景扫描（Windows/Linux/macOS 兼容）'
    )
    ap.add_argument('--base',           dest='base_branch',    help='基准分支名（自动模式）')
    ap.add_argument('--current',        dest='current_branch', help='当前分支名（自动模式）')
    ap.add_argument('--tool',           choices=['maven', 'gradle'], default=None)
    ap.add_argument('--work-dir',       default='.')
    ap.add_argument('--base-artifact-path',
                    help='基准侧已编译产物路径（直接产物模式）')
    ap.add_argument('--current-artifact-path',
                    help='当前侧已编译产物路径（直接产物模式）')
    ap.add_argument('--base-source-project-dir',
                    help='基准侧源码工程目录（直接产物模式补全坐标）')
    ap.add_argument('--current-source-project-dir',
                    help='当前侧源码工程目录（直接产物模式补全坐标）')
    ap.add_argument('--base-jdk-home',
                    help='基准侧 JDK Home（branch 补全 / checkout build 时使用）')
    ap.add_argument('--current-jdk-home',
                    help='当前侧 JDK Home（当前侧默认 JDK；base 未单独指定时可回落）')
    ap.add_argument('--primary-module',
                    help='仅支持单模块；指定目标模块（如 app / :app / groupId:artifactId / 模块路径）')
    ap.add_argument('--modules', nargs='*', default=None,
                    help='仅支持单模块；可与 --primary-module 等价传单个模块，不允许传多个值。')
    ap.add_argument('--active-maven-profile', action='append', default=[],
                    help='显式激活 Maven profile，可重复传入。正式流程从主状态读取。')
    ap.add_argument('--manual-coord-override', action='append', default=[],
                    help='人工补充坐标，格式 artifact:version[:classifier] -> group:artifact，可重复传入。')
    ap.add_argument('--manual-artifact-identity', action='append', default=[],
                    help=(
                        '人工确认 fat JAR 物理条目的完整身份，值为包含 '
                        'side/lib_entry/group_id/artifact_id/version 的 JSON 对象，可重复传入。'
                    ))
    ap.add_argument('--confirmed-unresolved-item', action='append', default=[],
                    help='已由人工确认保留的 unresolved 项，内部使用，值为 JSON 对象。')
    ap.add_argument('--allow-unresolved', action='store_true',
                    help='允许 unresolved 依赖保留在 Step1 输出中，并标记为 unresolved。')
    ap.add_argument('--output',         help='输出 CSV 文件路径')
    ap.add_argument('--debug-only',     action='store_true',
                    help='只解析并输出诊断，不写 CSV')
    args = ap.parse_args()
    orchestrated_input = load_orchestrated_step1_input()
    if orchestrated_input:
        args.base_branch = (
            args.base_branch
            or orchestrated_input.get("base_resolved_commit", "")
            or orchestrated_input.get("base_resolved_ref", "")
            or orchestrated_input.get("base_branch", "")
        )
        args.current_branch = (
            args.current_branch
            or orchestrated_input.get("current_resolved_commit", "")
            or orchestrated_input.get("current_resolved_ref", "")
            or orchestrated_input.get("current_branch", "")
        )
        args.tool = args.tool or orchestrated_input.get("tool", "maven")
        args.base_artifact_path = args.base_artifact_path or orchestrated_input.get("base_artifact_path", "")
        args.current_artifact_path = args.current_artifact_path or orchestrated_input.get("current_artifact_path", "")
        args.base_source_project_dir = args.base_source_project_dir or orchestrated_input.get("base_source_project_dir", "")
        args.current_source_project_dir = args.current_source_project_dir or orchestrated_input.get("current_source_project_dir", "")
        args.base_jdk_home = args.base_jdk_home or orchestrated_input.get("base_jdk_home", "")
        args.current_jdk_home = args.current_jdk_home or orchestrated_input.get("current_jdk_home", "")
        args.primary_module = args.primary_module or orchestrated_input.get("primary_module", "")
        if args.modules is None:
            args.modules = orchestrated_input.get("modules")
        if not args.active_maven_profile:
            args.active_maven_profile = list(
                orchestrated_input.get("active_maven_profiles") or []
            )
        if not args.manual_coord_override:
            args.manual_coord_override = list(orchestrated_input.get("manual_coord_overrides") or [])
        if not args.manual_artifact_identity:
            args.manual_artifact_identity = [
                json.dumps(item, ensure_ascii=False)
                for item in (
                    orchestrated_input.get("manual_artifact_identities") or []
                )
            ]
        if not args.confirmed_unresolved_item:
            args.confirmed_unresolved_item = [
                json.dumps(item, ensure_ascii=False)
                for item in (orchestrated_input.get("confirmed_unresolved_items") or [])
            ]
        if not args.allow_unresolved and orchestrated_input.get("allow_unresolved"):
            args.allow_unresolved = True
    args.tool = args.tool or 'maven'

    manual_coord_overrides, invalid_manual_overrides = parse_manual_coord_overrides(args.manual_coord_override)
    if invalid_manual_overrides:
        print("❌ 以下人工坐标格式不合法（应为 artifact:version[:classifier] -> group:artifact）：", file=sys.stderr)
        for item in invalid_manual_overrides:
            print(f"  - {item}", file=sys.stderr)
        sys.exit(1)
    manual_artifact_identities, invalid_manual_artifact_identities = (
        parse_manual_artifact_identities(args.manual_artifact_identity)
    )
    if invalid_manual_artifact_identities:
        print(
            "❌ 以下人工制品身份格式不合法（应为包含 "
            "side/lib_entry/group_id/artifact_id/version 的 JSON 对象）：",
            file=sys.stderr,
        )
        for item in invalid_manual_artifact_identities:
            print(f"  - {item}", file=sys.stderr)
        sys.exit(1)
    confirmed_unresolved_items, invalid_confirmed_unresolved_items = parse_confirmed_unresolved_items(
        args.confirmed_unresolved_item
    )
    if invalid_confirmed_unresolved_items:
        print("❌ 以下 confirmed_unresolved_items 格式不合法（应为 JSON 对象）：", file=sys.stderr)
        for item in invalid_confirmed_unresolved_items:
            print(f"  - {item}", file=sys.stderr)
        sys.exit(1)

    observer = Step1Observer(args.output) if args.output else None
    if observer is not None and orchestrated_input:
        for side in ("base", "current"):
            resolved_commit = str(
                orchestrated_input.get(f"{side}_resolved_commit") or ""
            ).strip()
            if not resolved_commit:
                continue
            observer.event(
                "ref_resolution",
                "completed",
                f"{'基准侧' if side == 'base' else '当前侧'}源码版本已固定",
                side=side,
                details={
                    "requested_ref": str(
                        orchestrated_input.get(f"{side}_requested_ref") or ""
                    ),
                    "resolved_ref": str(
                        orchestrated_input.get(f"{side}_resolved_ref") or ""
                    ),
                    "resolved_commit": resolved_commit,
                    "resolution_mode": str(
                        orchestrated_input.get(f"{side}_ref_resolution_mode") or "exact"
                    ),
                    "candidate_count": int(
                        orchestrated_input.get(f"{side}_ref_candidate_count") or 0
                    ),
                },
            )
    total_token = (
        observer.start_phase(
            "step1_total",
            item=args.primary_module or ".",
            message="Step1 开始：准备 base/current 构建产物和依赖范围",
        )
        if observer is not None else None
    )

    packaged_summary = {'mode': 'final_artifact', 'archives': [], 'deps': [], 'matched_count': 0, 'runtime_only_count': 0, 'runtime_only_coords': []}
    base_fmt = ''
    curr_fmt = ''
    base_deps = None
    curr_deps = None
    unresolved_confirmed = bool(args.allow_unresolved)
    unresolved_records = []

    if args.base_artifact_path or args.current_artifact_path:
        if not (args.base_artifact_path and args.current_artifact_path):
            print("❌ 直接产物模式必须同时提供 --base-artifact-path 和 --current-artifact-path。", file=sys.stderr)
            ap.print_help(sys.stderr)
            sys.exit(1)
        print("模式：直接解析用户提供的 base/current 编译产物", file=sys.stderr)
        try:
            base_runtime_deps = {}
            curr_runtime_deps = {}
            base_runtime_meta = {}
            curr_runtime_meta = {}

            def confirmed_source_resolution(side):
                resolved_commit = str(orchestrated_input.get(f"{side}_resolved_commit") or "").strip()
                source_status = str(orchestrated_input.get(f"{side}_ref_source_status") or "").strip()
                if not resolved_commit or source_status not in {
                    "remote_source_resolved",
                    "user_confirmed_local_source",
                }:
                    return {}
                return {
                    "status": "resolved",
                    "source_status": source_status,
                    "requested_ref": str(orchestrated_input.get(f"{side}_requested_ref") or ""),
                    "resolved_ref": str(orchestrated_input.get(f"{side}_resolved_ref") or ""),
                    "resolved_commit": resolved_commit,
                    "resolution_mode": str(orchestrated_input.get(f"{side}_ref_resolution_mode") or ""),
                    "fingerprint": str(orchestrated_input.get(f"{side}_ref_resolution_fingerprint") or ""),
                    "remote": str(orchestrated_input.get(f"{side}_ref_remote") or ""),
                    "remote_ref": str(orchestrated_input.get(f"{side}_ref_remote_ref") or ""),
                    "candidates": [],
                }

            def load_base_runtime_deps():
                nonlocal base_runtime_deps, base_runtime_meta
                if not base_runtime_meta:
                    ref_binding = orchestrated_input.get("base_ref_binding")
                    ref_binding = ref_binding if isinstance(ref_binding, dict) else {}
                    base_runtime_deps, base_runtime_meta = _collect_runtime_deps_for_artifact_input(
                        args.base_source_project_dir,
                        args.base_branch,
                        args.work_dir,
                        primary_module=args.primary_module,
                        modules=args.modules,
                        jdk_field="base_jdk_home",
                        jdk_home=args.base_jdk_home,
                        side="base",
                        artifact_path=args.base_artifact_path,
                        observer=observer,
                        active_maven_profiles=args.active_maven_profile,
                        build_tool=args.tool,
                        source_resolution=confirmed_source_resolution("base"),
                        expected_commit=str(orchestrated_input.get("base_expected_commit") or ""),
                        expected_remote=str(ref_binding.get("remote") or ""),
                        expected_remote_ref=str(ref_binding.get("canonical_ref") or ""),
                        allow_local_source=bool(orchestrated_input.get("base_allow_local_source")),
                        allow_dirty_local_source=bool(orchestrated_input.get("base_allow_dirty_local_source")),
                    )
                return base_runtime_deps

            def load_current_runtime_deps():
                nonlocal curr_runtime_deps, curr_runtime_meta
                if not curr_runtime_meta:
                    ref_binding = orchestrated_input.get("current_ref_binding")
                    ref_binding = ref_binding if isinstance(ref_binding, dict) else {}
                    curr_runtime_deps, curr_runtime_meta = _collect_runtime_deps_for_artifact_input(
                        args.current_source_project_dir,
                        args.current_branch,
                        args.work_dir,
                        primary_module=args.primary_module,
                        modules=args.modules,
                        jdk_field="current_jdk_home",
                        jdk_home=args.current_jdk_home,
                        side="current",
                        artifact_path=args.current_artifact_path,
                        observer=observer,
                        active_maven_profiles=args.active_maven_profile,
                        build_tool=args.tool,
                        source_resolution=confirmed_source_resolution("current"),
                        expected_commit=str(orchestrated_input.get("current_expected_commit") or ""),
                        expected_remote=str(ref_binding.get("remote") or ""),
                        expected_remote_ref=str(ref_binding.get("canonical_ref") or ""),
                        allow_local_source=bool(orchestrated_input.get("current_allow_local_source")),
                        allow_dirty_local_source=bool(orchestrated_input.get("current_allow_dirty_local_source")),
                    )
                return curr_runtime_deps

            base_deps, base_meta = collect_packaged_deps_from_artifact_path(
                args.base_artifact_path,
                runtime_deps=base_runtime_deps,
                work_dir=args.work_dir,
                runtime_deps_loader=load_base_runtime_deps,
                manual_coord_overrides=manual_coord_overrides,
                manual_artifact_identities=manual_artifact_identities,
                confirmed_unresolved_items=confirmed_unresolved_items,
                allow_unresolved=unresolved_confirmed,
                observer=observer,
                side="base",
            )
            curr_deps, curr_meta = collect_packaged_deps_from_artifact_path(
                args.current_artifact_path,
                runtime_deps=curr_runtime_deps,
                work_dir=args.work_dir,
                runtime_deps_loader=load_current_runtime_deps,
                manual_coord_overrides=manual_coord_overrides,
                manual_artifact_identities=manual_artifact_identities,
                confirmed_unresolved_items=confirmed_unresolved_items,
                allow_unresolved=unresolved_confirmed,
                observer=observer,
                side="current",
            )
            if base_runtime_meta.get('list_command'):
                base_meta['list_command'] = base_runtime_meta.get('list_command', '')
                base_meta['runtime_source_mode'] = base_runtime_meta.get('source_mode', '')
                base_meta['requested_ref'] = base_runtime_meta.get('requested_ref', '')
                base_meta['resolved_ref'] = base_runtime_meta.get('resolved_ref', '')
                base_meta['revision'] = base_runtime_meta.get('resolved_commit', '')
                base_meta['ref_resolution_mode'] = base_runtime_meta.get('ref_resolution_mode', '')
                base_meta['ref_source_status'] = base_runtime_meta.get('ref_source_status', '')
                base_meta['ref_remote'] = base_runtime_meta.get('ref_remote', '')
                base_meta['ref_remote_ref'] = base_runtime_meta.get('ref_remote_ref', '')
            if curr_runtime_meta.get('list_command'):
                curr_meta['list_command'] = curr_runtime_meta.get('list_command', '')
                curr_meta['runtime_source_mode'] = curr_runtime_meta.get('source_mode', '')
                curr_meta['requested_ref'] = curr_runtime_meta.get('requested_ref', '')
                curr_meta['resolved_ref'] = curr_runtime_meta.get('resolved_ref', '')
                curr_meta['revision'] = curr_runtime_meta.get('resolved_commit', '')
                curr_meta['ref_resolution_mode'] = curr_runtime_meta.get('ref_resolution_mode', '')
                curr_meta['ref_source_status'] = curr_runtime_meta.get('ref_source_status', '')
                curr_meta['ref_remote'] = curr_runtime_meta.get('ref_remote', '')
                curr_meta['ref_remote_ref'] = curr_runtime_meta.get('ref_remote_ref', '')
        except (Step1RefResolutionRequiredError, SourceRevisionConfirmationRequiredError) as e:
            interaction = build_step1_ref_resolution_interaction(e)
            print(interaction["summary"], file=sys.stderr)
            for line in interaction.get("checklist_lines") or []:
                print(f"  - {line}", file=sys.stderr)
            emit_step_interaction(interaction)
            sys.exit(EXIT_AWAITING_USER)
        except ArtifactCoordinateInputRequiredError as e:
            base_artifact = str(Path(args.base_artifact_path).expanduser().resolve())
            current_artifact = str(Path(args.current_artifact_path).expanduser().resolve())
            unresolved_items = list(e.unresolved_items or [])
            unresolved_records = normalize_unresolved_items(unresolved_items)
            has_unconfirmed_version = any(
                str(item.get("reason_code") or "").strip()
                == "PACKAGED_VERSION_UNCONFIRMED"
                for item in unresolved_records
            )
            missing_items = []
            if e.artifact_path == base_artifact and not (args.base_source_project_dir or args.base_branch):
                missing_items.append(
                    {
                        "side_cn": "基准侧",
                        "artifact_path": e.artifact_path,
                        "source_field": "base_source_project_dir",
                        "branch_field": "base_branch",
                    }
                )
            if e.artifact_path == current_artifact and not (args.current_source_project_dir or args.current_branch):
                missing_items.append(
                    {
                        "side_cn": "当前侧",
                        "artifact_path": e.artifact_path,
                        "source_field": "current_source_project_dir",
                        "branch_field": "current_branch",
                    }
                )
            if missing_items and not has_unconfirmed_version:
                interaction = build_step1_missing_input_interaction(missing_items, unresolved_items=unresolved_items)
                print("当前输入无法补全最终产物中的全部依赖坐标。", file=sys.stderr)
                for item in interaction.get("missing_inputs", []) or []:
                    print(
                        f"  - 缺失字段: {item.get('field')}（{item.get('label')}）",
                        file=sys.stderr,
                    )
                    print(
                        f"    原因: {item.get('reason')}",
                        file=sys.stderr,
                    )
                    print(
                        f"    产物: {item.get('artifact_path')}",
                        file=sys.stderr,
                    )
                for item in interaction.get("fallback_inputs", []) or []:
                    print(
                        f"  - 兜底字段: {item.get('field')}（{item.get('label')}）",
                        file=sys.stderr,
                    )
                    print(
                        f"    说明: {item.get('reason')}",
                        file=sys.stderr,
                    )
                emit_step_interaction(interaction)
                sys.exit(EXIT_AWAITING_USER)
            if e.artifact_path == base_artifact:
                interaction = build_step1_coordinate_followup_interaction(
                    side="base",
                    side_cn="基准侧",
                    artifact_path=e.artifact_path,
                    unresolved_items=unresolved_items,
                    branch_field="base_branch",
                    branch_value=args.base_branch,
                    source_field="base_source_project_dir",
                    source_value=args.base_source_project_dir,
                    primary_module=args.primary_module,
                )
            else:
                interaction = build_step1_coordinate_followup_interaction(
                    side="current",
                    side_cn="当前侧",
                    artifact_path=e.artifact_path,
                    unresolved_items=unresolved_items,
                    branch_field="current_branch",
                    branch_value=args.current_branch,
                    source_field="current_source_project_dir",
                    source_value=args.current_source_project_dir,
                    primary_module=args.primary_module,
                )
            print("当前输入已尝试进行坐标补全，但仍不足以安全输出最终依赖。", file=sys.stderr)
            for line in interaction.get("checklist_lines", []) or []:
                print(f"  - {line}", file=sys.stderr)
            if unresolved_confirmed:
                print("当前已收到人工确认：未补齐的 unresolved 将保留在 Step1 输出中并标记为 unresolved。", file=sys.stderr)
            else:
                emit_step_interaction(interaction)
                sys.exit(EXIT_AWAITING_USER)
        except Step1CommandExecutionBlockedError as e:
            interaction = build_step1_command_blocked_interaction(e)
            print(f"当前输入已进入执行阶段，但 {args.tool} 命令被环境问题阻塞。", file=sys.stderr)
            print(f"  - 阻塞阶段: {e.stage}", file=sys.stderr)
            if e.branch:
                print(f"  - 失败分支: {e.branch}", file=sys.stderr)
            if e.command:
                print(f"  - 失败命令: {e.command}", file=sys.stderr)
            if e.stderr_excerpt:
                print(f"  - 错误摘要: {e.stderr_excerpt}", file=sys.stderr)
            for cause in e.suspected_causes:
                print(f"  - 可能原因: {cause}", file=sys.stderr)
            emit_step_interaction(interaction)
            sys.exit(EXIT_AWAITING_USER)
        except Exception as e:
            print(f"❌ 直接产物模式执行失败：{e}", file=sys.stderr)
            sys.exit(1)
        base_fmt = base_meta.get('mode', 'final_artifact')
        curr_fmt = curr_meta.get('mode', 'final_artifact')
        packaged_summary = dict(curr_meta)
        unresolved_records = (
            attach_unresolved_side(base_meta.get('unresolved_items') or [], 'base')
            + attach_unresolved_side(curr_meta.get('unresolved_items') or [], 'current')
        )
    elif args.base_branch and args.current_branch and args.tool in {'maven', 'gradle'}:
        print(
            f"模式：自动切换分支并使用 {args.tool} 对目标模块执行真实构建",
            file=sys.stderr,
        )
        try:
            base_deps, base_meta = get_packaged_deps_by_switching_branch(
                    args.base_branch, args.work_dir, args.primary_module, args.modules,
                    "base_jdk_home",
                    args.base_jdk_home, "base",
                    manual_coord_overrides=manual_coord_overrides,
                    manual_artifact_identities=manual_artifact_identities,
                    allow_unresolved=unresolved_confirmed,
                    confirmed_unresolved_items=confirmed_unresolved_items,
                    artifact_cache_dir=Path(args.output).parent / STEP1_ARTIFACTS_DIRNAME if args.output else None,
                observer=observer,
                active_maven_profiles=args.active_maven_profile,
                build_tool=args.tool,
            )
            curr_deps, curr_meta = get_packaged_deps_by_switching_branch(
                    args.current_branch, args.work_dir, args.primary_module, args.modules,
                    "current_jdk_home", args.current_jdk_home, "current",
                    manual_coord_overrides=manual_coord_overrides,
                    manual_artifact_identities=manual_artifact_identities,
                    allow_unresolved=unresolved_confirmed,
                    confirmed_unresolved_items=confirmed_unresolved_items,
                    artifact_cache_dir=Path(args.output).parent / STEP1_ARTIFACTS_DIRNAME if args.output else None,
                observer=observer,
                active_maven_profiles=args.active_maven_profile,
                build_tool=args.tool,
            )
        except Step1CommandExecutionBlockedError as e:
            interaction = build_step1_command_blocked_interaction(e)
            print(f"当前输入已进入执行阶段，但 {args.tool} 命令被环境问题阻塞。", file=sys.stderr)
            print(f"  - 阻塞阶段: {e.stage}", file=sys.stderr)
            if e.branch:
                print(f"  - 失败分支: {e.branch}", file=sys.stderr)
            if e.command:
                print(f"  - 失败命令: {e.command}", file=sys.stderr)
            if e.stderr_excerpt:
                print(f"  - 错误摘要: {e.stderr_excerpt}", file=sys.stderr)
            for cause in e.suspected_causes:
                print(f"  - 可能原因: {cause}", file=sys.stderr)
            emit_step_interaction(interaction)
            sys.exit(EXIT_AWAITING_USER)
        except Exception as e:
            print(f"❌ 自动执行失败：{e}", file=sys.stderr)
            print("建议人工执行：", file=sys.stderr)
            target_selector = _resolve_single_module_selector(args.primary_module, args.modules, args.work_dir)
            print(f"  git checkout {args.base_branch}", file=sys.stderr)
            if args.tool == 'gradle':
                target_model = _gradle_target_model(args.work_dir, target_selector)
                command = ' '.join(gradle_cmd(args.work_dir) + [_gradle_task(target_model, 'build'), '-x', 'test'])
            else:
                pl = _normalize_maven_pl_with_workdir(target_selector, args.work_dir)
                command = (
                    f"mvn {'-pl ' + pl + ' -am ' if pl else ''}"
                    f"{MAVEN_SKIP_TEST_COMPILATION_ARG} package"
                )
            print(f"  {command}", file=sys.stderr)
            print(f"  git checkout {args.current_branch}", file=sys.stderr)
            print(f"  {command}", file=sys.stderr)
            sys.exit(1)

        base_fmt = base_meta.get('mode', 'final_artifact')
        curr_fmt = curr_meta.get('mode', 'final_artifact')
        packaged_summary = dict(curr_meta)
        unresolved_records = (
            attach_unresolved_side(base_meta.get('unresolved_items') or [], 'base')
            + attach_unresolved_side(curr_meta.get('unresolved_items') or [], 'current')
        )
    else:
        if args.base_artifact_path or args.current_artifact_path:
            print("❌ 直接产物模式必须同时提供 --base-artifact-path 和 --current-artifact-path。", file=sys.stderr)
        elif not (args.base_branch and args.current_branch):
            print("❌ 必须提供 --base + --current。", file=sys.stderr)
        else:
            print("❌ 隔离分支构建模式需要同时提供 --base + --current。", file=sys.stderr)
            print_manual_instructions(
                args.base_branch,
                args.current_branch,
                args.primary_module,
                args.work_dir,
                args.modules,
            )
        ap.print_help(sys.stderr)
        sys.exit(1)

    print_parse_report('基准分支', base_deps, base_fmt)
    print_parse_report('当前分支', curr_deps, curr_fmt)
    if packaged_summary.get('mode') == 'final_artifact':
        print(
            f"\n[当前打包校准] 从 {len(packaged_summary.get('archives') or [])} 个产物解析到 "
            f"{len(packaged_summary.get('deps') or [])} 个嵌套依赖，"
            f"当前比较口径为最终打包依赖，共 {packaged_summary.get('matched_count', 0)} 个",
            file=sys.stderr,
        )

    base_entries = list(base_meta.get('dep_entries') or base_meta.get('deps') or [])
    curr_entries = list(curr_meta.get('dep_entries') or curr_meta.get('deps') or [])

    if not base_entries and not unresolved_records:
        print("❌ 基准分支解析结果为空", file=sys.stderr)
        sys.exit(1)
    if not curr_entries and not unresolved_records:
        print("❌ 当前分支解析结果为空", file=sys.stderr)
        sys.exit(1)

    if args.debug_only:
        print("\n调试模式完成，未写入文件。", file=sys.stderr)
        if observer is not None and total_token is not None:
            observer.finish_phase(total_token, status="completed", message="Step1 调试模式完成")
        return

    # ── 对比并写 CSV ─────────────────────────────────────────────
    if not args.output:
        print("❌ 请指定 --output 参数", file=sys.stderr)
        sys.exit(1)

    diff_token = (
        observer.start_phase(
            "dependency_diff",
            item=args.primary_module or ".",
            message="开始比较 base/current 最终制品依赖",
        )
        if observer is not None else None
    )
    rows = _build_step1_change_rows(base_entries, curr_entries)
    if observer is not None and diff_token is not None:
        observer.finish_phase(
            diff_token,
            status="completed",
            message=f"依赖比较完成，共生成 {len(rows)} 条依赖记录",
        )

    def _risk_rank(value):
        v = (value or '').strip()
        if '❓' in v:
            return 0
        if v.startswith('高'):
            return 1
        if v.startswith('中'):
            return 2
        return 3

    def _change_rank(value):
        v = (value or '').strip()
        if '降级' in v:
            return 0
        if v == '大版本升级':
            return 1
        if v == '移除':
            return 2
        if v == '小版本升级':
            return 3
        if v == '补丁升级':
            return 4
        if v == '新增':
            return 5
        if v == '版本格式不规则':
            return 6
        if v == '已变更':
            return 7
        if v == '未变':
            return 8
        return 9

    rows.sort(key=lambda r: (_risk_rank(r.get('risk')), _change_rank(r.get('change_type')), r.get('coord', '')))

    out_dir = Path(args.output).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    report_token = (
        observer.start_phase(
            "report_write",
            item=str(out_dir),
            message="开始写入 Step1 正式结果文件",
        )
        if observer is not None else None
    )
    artifact_materialization_token = (
        observer.start_phase(
            "dependency_jar_materialization",
            item=str(out_dir),
            message="开始留存最终制品并提取 Step4/Step5 所需依赖 JAR",
        )
        if observer is not None else None
    )
    if args.base_artifact_path and args.current_artifact_path:
        retain_artifact_for_analysis(base_meta, out_dir / STEP1_ARTIFACTS_DIRNAME, 'base')
        retain_artifact_for_analysis(curr_meta, out_dir / STEP1_ARTIFACTS_DIRNAME, 'current')
    materialize_changed_dependency_jars(
        rows,
        {'base': base_meta, 'current': curr_meta},
        out_dir,
        base_entries=base_entries,
        current_entries=curr_entries,
    )
    if observer is not None and artifact_materialization_token is not None:
        observer.finish_phase(
            artifact_materialization_token,
            status="completed",
            message="最终制品留存和依赖 JAR 提取完成",
        )
    # CSV 统一使用 UTF-8 BOM，可直接用 Excel 打开。
    dependency_csv_token = (
        observer.start_phase(
            "write.dependency_changes",
            item=str(args.output),
            message=f"开始写入 {len(rows)} 条依赖变更记录",
        )
        if observer is not None else None
    )
    with open_csv_write(args.output) as f:
        fields = ['coord', 'base_coord', 'current_coord', 'old_version', 'new_version', 'change_type',
                  'risk', 'scope', 'remark', 'current_packaged', 'downgrade_confirmed', 'resolution_status',
                  'comparison_key', 'pairing_status', 'pairing_reason_code', 'base_lib_entry', 'current_lib_entry',
                  'base_packaged_match_source', 'current_packaged_match_source',
                  'base_resolution_status', 'current_resolution_status',
                  'base_read_error', 'current_read_error']
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    if observer is not None and dependency_csv_token is not None:
        observer.finish_phase(
            dependency_csv_token,
            status="completed",
            message=f"依赖变更记录写入完成，共 {len(rows)} 条",
        )

    current_out = str((out_dir / "deps_current_resolved.csv").resolve())
    current_inventory_token = (
        observer.start_phase(
            "write.current_dependency_inventory",
            item=current_out,
            message=f"开始写入当前制品依赖清单，共 {len(curr_entries)} 项",
        )
        if observer is not None else None
    )
    current_rows = []
    for item in sorted(curr_entries, key=_entry_sort_key):
        current_rows.append({
            'entry_id': item.get('entry_id', ''),
            'lib_entry': item.get('lib_entry', ''),
            'lib_name': item.get('lib_name', ''),
            'coord': item.get('coord', ''),
            'group_id': item.get('group_id', ''),
            'artifact_id': item.get('artifact_id', ''),
            'classifier': item.get('classifier', ''),
            'version': item.get('version', ''),
            'scope': item.get('scope', ''),
            'remark': item.get('remark', ''),
            'packaged_present': item.get('packaged_present', ''),
            'packaged_match_source': item.get('packaged_match_source', ''),
            'read_error': item.get('read_error', ''),
            'resolution_status': 'resolved',
        })
        current_rows[-1]['resolution_status'] = item.get('resolution_status', 'resolved')
    with open_csv_write(current_out) as f:
        fields = ['entry_id', 'lib_entry', 'lib_name', 'coord', 'group_id', 'artifact_id', 'classifier',
                  'version', 'scope', 'remark', 'packaged_present', 'packaged_match_source', 'read_error',
                  'resolution_status']
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(current_rows)
    if observer is not None and current_inventory_token is not None:
        observer.finish_phase(
            current_inventory_token,
            status="completed",
            message=f"当前制品依赖清单写入完成，共 {len(current_rows)} 项",
        )

    provenance_token = (
        observer.start_phase(
            "write.build_provenance",
            item=str(out_dir / 'build_provenance.json'),
            message="开始整理 base/current 构建与制品来源",
        )
        if observer is not None else None
    )
    provenance_sides = []
    provided_artifact_mode = bool(
        args.base_artifact_path and args.current_artifact_path
    )
    for side, meta, branch, configured_jdk in (
        ('base', base_meta, args.base_branch, args.base_jdk_home),
        ('current', curr_meta, args.current_branch, args.current_jdk_home),
    ):
        artifact_path = str((meta or {}).get('artifact_path') or '').strip()
        artifact_hash = str((meta or {}).get('artifact_sha256') or '').strip()
        if not artifact_hash and artifact_path and Path(artifact_path).is_file():
            artifact_hash = sha256_file(artifact_path)
        artifact_available = bool(artifact_path and Path(artifact_path).is_file())
        build_executed_by_system = not provided_artifact_mode
        build_execution_status = (
            "not_executed"
            if provided_artifact_mode
            else ("succeeded" if artifact_available else "failed")
        )
        provenance_sides.append({
            'side': side,
            'source_mode': 'provided_artifact' if provided_artifact_mode else 'checkout_build',
            'input_mode': 'provided_artifact' if provided_artifact_mode else 'checkout_build',
            'ref': str(
                (meta or {}).get('resolved_ref')
                or orchestrated_input.get(f'{side}_resolved_ref')
                or branch
                or ''
            ),
            'requested_ref': str(
                (meta or {}).get('requested_ref')
                or orchestrated_input.get(f'{side}_requested_ref')
                or branch
                or ''
            ),
            'ref_resolution_mode': str(
                (meta or {}).get('ref_resolution_mode')
                or orchestrated_input.get(f'{side}_ref_resolution_mode')
                or ''
            ),
            'ref_source_status': str(
                (meta or {}).get('ref_source_status')
                or orchestrated_input.get(f'{side}_ref_source_status')
                or ''
            ),
            'ref_remote': str(
                (meta or {}).get('ref_remote')
                or orchestrated_input.get(f'{side}_ref_remote')
                or ''
            ),
            'ref_remote_ref': str(
                (meta or {}).get('ref_remote_ref')
                or orchestrated_input.get(f'{side}_ref_remote_ref')
                or ''
            ),
            'revision': str(
                (meta or {}).get('revision')
                or orchestrated_input.get(f'{side}_resolved_commit')
                or ''
            ),
            'target_module': str(args.primary_module or ''),
            'jdk_home': str((meta or {}).get('jdk_home') or resolve_effective_jdk_home(configured_jdk) or ''),
            'build_command': str((meta or {}).get('build_command') or ''),
            'build_tool': str((meta or {}).get('build_tool') or args.tool or 'maven'),
            'artifact_path': artifact_path,
            'original_artifact_path': str((meta or {}).get('original_artifact_path') or artifact_path),
            'artifact_relative_path': str((meta or {}).get('artifact_relative_path') or ''),
            'artifact_sha256': artifact_hash,
            'artifact_available': artifact_available,
            'build_executed_by_system': build_executed_by_system,
            'build_execution_status': build_execution_status,
            # Legacy compatibility only. Consumers must use the three fields
            # above to distinguish artifact receipt from analyzer execution.
            'build_succeeded': artifact_available,
            'project_scope_hash': str((meta or {}).get('project_scope_hash') or ''),
            'source_state_hash': str((meta or {}).get('source_state_hash') or ''),
            'maven_model_hash': str((meta or {}).get('maven_model_hash') or ''),
            'gradle_model_hash': str((meta or {}).get('gradle_model_hash') or ''),
            'build_model_hash': str(
                (meta or {}).get('build_model_hash')
                or (meta or {}).get('maven_model_hash')
                or (meta or {}).get('gradle_model_hash')
                or ''
            ),
            'active_maven_profiles': sorted({
                str(profile).strip()
                for profile in ((meta or {}).get('active_maven_profiles') or [])
                if str(profile).strip()
            }),
        })
    provenance_path = out_dir / 'build_provenance.json'
    provenance_path.write_text(
        json.dumps({
            'schema': 'java-upgrade-analyzer.build-provenance.v2',
            'both_artifacts_available': all(
                item.get('artifact_available') for item in provenance_sides
            ),
            'both_build_executions_succeeded': all(
                item.get('build_executed_by_system')
                and item.get('build_execution_status') == 'succeeded'
                for item in provenance_sides
            ),
            # Legacy compatibility: historically this meant only that both
            # artifact paths existed, including provided-artifact mode.
            'both_builds_succeeded': all(item.get('build_succeeded') for item in provenance_sides),
            'sides': provenance_sides,
        }, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    if observer is not None and provenance_token is not None:
        observer.finish_phase(
            provenance_token,
            status="completed",
            message="base/current 构建与制品来源写入完成",
        )

    # 统计
    counts = defaultdict(int)
    for r in rows: counts[r['change_type']] += 1
    print(f"\n依赖变更统计（共 {len(rows)} 个）：", file=sys.stderr)
    for t, c in sorted(counts.items()):
        print(f"  {t}: {c}", file=sys.stderr)

    alerts = [r for r in rows
              if '降级' in r['change_type'] or '❓' in r['risk']]
    alerts_out = str((out_dir / "dep_alerts.csv").resolve())
    alerts_token = (
        observer.start_phase(
            "write.dependency_alerts",
            item=alerts_out,
            message=f"开始生成依赖告警清单，候选 {len(alerts)} 项",
        )
        if observer is not None else None
    )
    with open_csv_write(alerts_out) as f:
        fields = ['conclusion', 'change_summary', 'review_reason',
                  'coord', 'old_version', 'new_version', 'change_type',
                  'risk', 'scope', 'remark', 'current_packaged', 'downgrade_confirmed', 'resolution_status']
        alert_rows = []
        for item in alerts:
            reasons = []
            if '降级' in str(item.get('change_type') or ''):
                reasons.append('依赖版本发生降级')
            if '❓' in str(item.get('risk') or ''):
                reasons.append('风险状态不明确')
            resolution_status = str(item.get('resolution_status') or '').strip()
            if resolution_status and resolution_status != 'resolved':
                reasons.append(f'依赖坐标解析状态：{resolution_status}')
            row = {field: item.get(field, '') for field in fields}
            row['conclusion'] = '需要人工复核'
            row['change_summary'] = (
                f"{item.get('coord', '-')}: {item.get('old_version', '-')} -> "
                f"{item.get('new_version', '-')}，{item.get('change_type', '-')}"
            )
            row['review_reason'] = '；'.join(reasons) or str(item.get('remark') or '依赖变化需要确认')
            alert_rows.append(row)
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alert_rows)
    if observer is not None and alerts_token is not None:
        observer.finish_phase(
            alerts_token,
            status="completed",
            message=f"依赖告警清单写入完成，共 {len(alerts)} 项",
        )

    summary_out = str((out_dir / "dep_summary.txt").resolve())
    summary_token = (
        observer.start_phase(
            "write.dependency_summary",
            item=summary_out,
            message="开始生成 Step1 可读摘要",
        )
        if observer is not None else None
    )
    summary_lines = []
    summary_lines.append("Step1 依赖变更摘要")
    summary_lines.append("")
    summary_lines.append("一、先看什么")
    if alerts:
        summary_lines.append("- 先看 dep_alerts.csv：这里列出降级、无法确认或解析异常的依赖。")
    else:
        summary_lines.append("- 未生成需要优先复核的依赖；如范围不符合预期，再看 dep_changes.csv。")
    summary_lines.append("- 如怀疑分析范围不对，核对 build_provenance.json 中的 base/current 构建产物来源。")
    summary_lines.append("- Step1 只确认依赖变化范围；是否影响业务，以 Step5 alerts.csv 和 Step6 report.md 为准。")
    summary_lines.append("")
    summary_lines.append("二、本次依赖范围是否可信")
    summary_lines.append(f"- 依赖记录总数：{len(rows)}")
    summary_lines.append(f"- 需要人工确认：{len(alerts)}")
    if curr_entries:
        unresolved_count = sum(1 for item in curr_entries if str(item.get('resolution_status') or '').strip() != 'resolved')
        read_error_count = sum(1 for item in curr_entries if str(item.get('read_error') or '').strip())
        summary_lines.append(f"- 当前打包依赖数：{len(curr_entries)}")
        summary_lines.append(f"- 当前打包依赖坐标未解析：{unresolved_count}")
        summary_lines.append(f"- 当前打包依赖读取失败：{read_error_count}")
    if alerts:
        summary_lines.append("- 结论：存在需要优先复核的依赖变化，请先查看 dep_alerts.csv。")
    else:
        summary_lines.append("- 结论：未发现需要优先复核的依赖变化。")
    summary_lines.append("")
    summary_lines.append("三、分析范围")
    if args.base_artifact_path and args.current_artifact_path:
        summary_lines.append("- 输入模式：用户提供 base/current 编译产物")
        summary_lines.append(f"- base 编译产物：{str(Path(args.base_artifact_path).expanduser().resolve())}")
        summary_lines.append(f"- current 编译产物：{str(Path(args.current_artifact_path).expanduser().resolve())}")
    else:
        summary_lines.append("- 输入模式：自动切换 base/current 分支构建")
        summary_lines.append(f"- base 分支：{args.base_branch}")
        summary_lines.append(f"- current 分支：{args.current_branch}")
    want = resolve_primary_module_id(args.primary_module, args.work_dir)
    summary_lines.append(f"- 目标模块：{want or '未指定'}")
    summary_lines.append(f"- 构建产物类型：{base_fmt}")
    summary_lines.append(f"- current 打包模式：{packaged_summary.get('mode') or '未知'}")
    summary_lines.append(f"- current 可解析打包产物数量：{len(packaged_summary.get('archives') or [])}")
    if packaged_summary.get('archives'):
        summary_lines.append("- current 打包产物样例：")
        for archive_path in (packaged_summary.get('archives') or [])[:5]:
            summary_lines.append(f"  - {archive_path}")
    if base_meta.get('module_dir'):
        summary_lines.append(f"- base 模块目录：{base_meta.get('module_dir')}")
    if curr_meta.get('module_dir'):
        summary_lines.append(f"- current 模块目录：{curr_meta.get('module_dir')}")
    summary_lines.append("")
    summary_lines.append("四、依赖变化统计")
    for t, c in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
        summary_lines.append(f"- {t}: {c}")
    summary_lines.append("")
    summary_lines.append("五、复核入口")
    summary_lines.append("- 完整依赖变化：dep_changes.csv")
    summary_lines.append("- 需要优先复核的依赖：dep_alerts.csv")
    summary_lines.append("- 构建产物来源：build_provenance.json")
    summary_lines.append("")
    section_number = 6
    if unresolved_records:
        summary_lines.append(f"{section_number}、坐标未解析依赖（前 {min(50, len(unresolved_records))} 项）")
        section_number += 1
        for item in unresolved_records[:50]:
            summary_lines.append(f"- {item.get('label')}")
        summary_lines.append("")
    if alerts:
        summary_lines.append(f"{section_number}、优先复核依赖（前 {min(50, len(alerts))} 项）")
        for r in alerts[:50]:
            summary_lines.append(
                f"- {r['coord']}：{r['old_version']} -> {r['new_version']}；变化={r['change_type']}；风险={r['risk']}；范围={r['scope']}；说明={r.get('remark','')}"
            )
        summary_lines.append("")
    summary_lines.append("附：阅读说明")
    summary_lines.append("- Step1 只确定依赖变化范围，不证明业务是否受影响。")
    summary_lines.append("- 是否触达业务代码，以 Step5 的 alerts.csv 和 Step6 的 report.md 为准。")
    with open(summary_out, 'w', encoding='utf-8', newline='\n') as f:
        f.write("\n".join(summary_lines) + "\n")
    if observer is not None and summary_token is not None:
        observer.finish_phase(
            summary_token,
            status="completed",
            message="Step1 可读摘要写入完成",
        )
    if alerts:
        print(f"\n⚠️  需人工确认（{len(alerts)} 项）：", file=sys.stderr)
        for r in alerts:
            print(f"  {r['coord']}: {r['old_version']} → {r['new_version']} [{r['change_type']}]",
                  file=sys.stderr)

    print(f"\n✅ 输出：{args.output}", file=sys.stderr)
    print(f"✅ 输出：{current_out}", file=sys.stderr)
    print(f"✅ 输出：{alerts_out}", file=sys.stderr)
    print(f"✅ 输出：{summary_out}", file=sys.stderr)
    print(f"✅ 输出：{provenance_path.resolve()}", file=sys.stderr)
    print(f"运行门控：python scripts/gate.py --step step1_scope --report-dir .upgrade-report/",
          file=sys.stderr)
    if observer is not None and report_token is not None:
        observer.finish_phase(
            report_token,
            status="completed",
            message="Step1 正式结果文件写入完成",
        )
    if observer is not None and total_token is not None:
        observer.finish_phase(
            total_token,
            status="completed",
            message="Step1 分析完成",
        )
    if not os.environ.get("JUA_ORCHESTRATED"):
        print(
            "\n⚠️  当前为单脚本直跑模式：下面的人工确认只会输出复核清单，"
            "默认不会像 run_step.py 那样进入硬 checkpoint。",
            file=sys.stderr,
        )
        print(
            "    正式流程请优先使用 scripts/run_step.py；"
            "若确需单独执行本脚本，可设置 JUA_CONFIRM_MODE=prompt/block 强化确认语义。",
            file=sys.stderr,
        )
    ok = require_human_confirm(
        "Step1 依赖变更（会影响后续 Step4/Step5 的分析范围）",
        checklist_lines=[
            "需要确认文件：",
            f"  - {str(Path(summary_out).resolve())}",
            f"  - {str(Path(alerts_out).resolve())}",
            "需要确认内容：",
            f"  - primary_module 是否正确：{want or '(空)'}",
            "  - summary 中是否提示“模块不匹配/最终制品不可解析”等阻塞信息",
        ],
    )
    if not ok:
        sys.exit(3)


if __name__ == '__main__':
    main()
