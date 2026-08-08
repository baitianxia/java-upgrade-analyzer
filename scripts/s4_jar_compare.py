#!/usr/bin/env python3
"""
s4_jar_compare.py — Step 4：jar 包变更全量对比

三条并行路径：
  4a. JApiCmp 二进制对比（所有依赖，含传递依赖）
  4b. 依赖源码 git diff API 变更（仅对已提供源码仓库映射的依赖执行）
  4c. changelog 行为变更分析（标注 confirmed=false）

输入：
  s1_dep_changes.csv        — 依赖变更清单
  s2_context.json           — 项目上下文（含升级依赖清单）
  <japicmp-jar>             — JApiCmp 工具 jar

正式证据写入 `.upgrade-report/evidence/api_changes/`，运行耗时写入
`.upgrade-report/.runtime/observability/`：
  [artifact]_[旧版]_vs_[新版]_binary.txt   — JApiCmp 完整原始输出（不裁剪）
  [artifact]_[旧版]_vs_[新版]_behavior.txt — changelog 行为变更记录
  [lib]_gitdiff_api_changes.txt            — 依赖源码 git diff 结果
  all_changed_apis.csv                     — 汇总（Step 5 的核心输入）
  dependency_analysis_status.{csv,json}    — 逐依赖执行状态（区分零变化与无数据）

交互约束：
  脚本只负责产出证据与摘要，不负责等待用户确认
  进入下一步前是否停下、向用户展示哪些文件，由 run_step.py 统一调度
  只有对比成功且 API 数量为 0 的依赖才可标记为“无可见 API 变化”；
  执行失败必须单独标记为“数据不可用”
"""

import argparse, csv, json, os, re, shutil, struct, sys, time, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime
import hashlib, zipfile
import safe_xml as ET

sys.path.insert(0, str(Path(__file__).parent))
from compat import (
    run_cmd, write_text, open_text, mvn_cmd, git_cmd, maven_repo_dir,
    infer_maven_coord_locations,
)
from csv_io import open_csv_append, open_csv_read, open_csv_write

sys.path.insert(0, os.path.dirname(__file__))
from s4_contract import (
    ALL_CHANGED_APIS_FIELDS,
    CHANGED_DEPENDENCIES_CSV,
    CHANGED_DEPENDENCIES_MD,
    DEFAULT_SEVERITY,
    PER_DEPENDENCY_DIRNAME,
    PER_DEPENDENCY_REMOVED_JAR_SYMBOLS_FILE,
    PER_DEPENDENCY_RESOLVED_TARGETS_FILE,
    PER_DEPENDENCY_SUMMARY_FILE,
    get_per_dependency_dir,
    make_per_dependency_dirname,
    validate_row,
)
from progress_logging import PhaseTimer, emit_progress
from pipeline_constants import (
    EVIDENCE_API_CHANGES_DIRNAME,
    EVIDENCE_DEPENDENCIES_DIRNAME,
    EVIDENCE_DIRNAME,
    RUNTIME_CACHE_DIRNAME,
    RUNTIME_DIRNAME,
    RUNTIME_OBSERVABILITY_DIRNAME,
    RUNTIME_STATE_DIRNAME,
    STEP1_DEPENDENCY_JARS_MANIFEST_FILE,
    STEP5_ARTIFACT_BYTECODE_INDEX_FILE,
)
from signature_utils import normalize_signature_for_lookup
from data_contract_analysis import compare_jar_data_contracts
from step1_observability import peak_rss_mb
from analysis_contract import sha256_file
from artifact_coordinates import (
    artifact_classifier,
    artifact_ga,
    split_artifact_coord,
)
from artifact_safety import require_safe_archive
from constant_impact import extract_constant_field_evidence
from diagnostic_contract import (
    DEPENDENCY_SOURCE_REF_UNAVAILABLE,
    JAPICMP_EXECUTION_FAILED,
    JAPICMP_TIMEOUT,
    canonical_reason_code,
    diagnostic_contract_metadata,
    normalize_component_reason_codes,
    normalize_diagnostic_payload,
    reason_code_aliases,
)
from reason_guidance import (
    REASON_GUIDANCE_SCHEMA,
    build_catalog_guidance,
    guidance_for_reason_code,
)
from path_runtime import bounded_path_component
from remote_source_refs import (
    materialize_remote_source_candidate,
    query_live_remote_refs,
    resolve_local_source_ref,
    resolve_remote_source_ref,
)

INTERACTION_PREFIX = "JUA_STEP_INTERACTION_JSON:"
MAIN_STATE_FILE_NAME = "main_state.json"
# Git operations must always be bounded by default.  Callers may raise these
# values for slow remotes/repositories; timeout normalization intentionally has
# no internal upper cap.
DEFAULT_FETCH_TIMEOUT = 60
DEFAULT_JAPICMP_TIMEOUT = None
DEFAULT_GIT_DIFF_TIMEOUT = 300
DEFAULT_JAPICMP_COORD = "com.github.siom79.japicmp:japicmp:0.21.2:jar:jar-with-dependencies"
_WRITE_RESULT_LOCK = threading.RLock()
_JAPICMP_TOOL_DIGEST_LOCK = threading.RLock()
_JAPICMP_TOOL_DIGEST_CACHE = {}
_REMOTE_SOURCE_MATERIALIZATION_LOCK = threading.RLock()
_REMOTE_SOURCE_MATERIALIZATION_CACHE = {}
_REMOTE_SOURCE_MATERIALIZATION_KEY_LOCKS = {}
STEP4_TIMING_FILE = "step4_timing.csv"
DEPENDENCY_ANALYSIS_STATUS_CSV = "dependency_analysis_status.csv"
DEPENDENCY_ANALYSIS_STATUS_JSON = "dependency_analysis_status.json"
DEPENDENCY_ANALYSIS_STATUS_MD = "dependency_analysis_status.md"
JAPICMP_COMPARISON_CACHE_SCHEMA_VERSION = 2
JAPICMP_COMPARISON_CACHE_DIRNAME = "step4_japicmp"
BUSINESS_BYTECODE_CHANGED_API_REFS_CSV = "business_bytecode_changed_api_refs.csv"
BUSINESS_BYTECODE_PRIORITY_EVIDENCE_JSON = "business_bytecode_priority_evidence.json"
STEP4_RECOMMENDED_DEPENDENCY_LIMIT = 10


def _bounded_git_timeout(value, default):
    """Return a positive timeout without truncating an explicit larger value."""
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        timeout = int(default)
    return timeout if timeout > 0 else int(default)


_CHANGE_TYPE_LABELS = {
    "REMOVED": "删除",
    "SIGNATURE_CHANGED": "签名变更",
    "BEHAVIOR_CHANGED": "行为变更",
    "ACCESS_REDUCED": "访问权限降低",
    "SOURCE_INCOMPATIBLE": "源码不兼容",
    "CONSTANT_VALUE_CHANGED": "常量值变更",
    "DATA_FIELD_ADDED": "DTO 字段新增",
    "DATA_FIELD_REMOVED": "DTO 字段删除",
    "DATA_FIELD_TYPE_CHANGED": "DTO 字段类型变化",
}


def require_safe_dependency_jar(path):
    return require_safe_archive(
        path,
        inspect_nested_archives=False,
        allow_duplicate_maven_metadata=True,
    )

_SYMBOL_KIND_LABELS = {
    "method": "方法",
    "field": "字段",
    "class": "类",
    "constructor": "构造方法",
}


def clear_japicmp_tool_digest_cache():
    with _JAPICMP_TOOL_DIGEST_LOCK:
        _JAPICMP_TOOL_DIGEST_CACHE.clear()


def japicmp_tool_sha256(jar_path):
    path = Path(jar_path).resolve()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def effective_java_runtime_identity():
    java_command = shutil.which("java") or "java"
    java_path = Path(java_command).resolve() if Path(java_command).exists() else Path(java_command)
    explicit_java_home = str(os.environ.get("JAVA_HOME") or "").strip()
    identity = {
        "java": str(java_path),
        "java_sha256": "",
        "java_home": explicit_java_home,
        "runtime_java": "",
        "runtime_java_sha256": "",
        "release_sha256": "",
        "complete": True,
        "failures": [],
    }
    try:
        if java_path.is_file():
            identity["java_sha256"] = sha256_file(java_path)
        else:
            identity["failures"].append("java_executable_not_a_file")
    except OSError as exc:
        identity["failures"].append(f"java_executable_hash_failed:{type(exc).__name__}")
    java_home = Path(identity["java_home"]).expanduser() if identity["java_home"] else None
    if java_home is None and java_path.is_absolute():
        java_home = java_path.parent.parent
    # Package managers commonly expose Java through a small shell launcher whose
    # parent is not the effective JDK home.  Resolve only a literal absolute
    # ``exec .../bin/java`` target; never execute or interpolate wrapper text.
    # Hashing both launcher and target keeps the cache identity fail-closed while
    # allowing content-addressed reuse for these deterministic wrappers.
    if not explicit_java_home and java_path.is_file():
        inferred_release = java_home / "release" if java_home is not None else None
        if inferred_release is None or not inferred_release.is_file():
            try:
                if java_path.stat().st_size <= 1024 * 1024:
                    launcher_text = java_path.read_text(encoding="utf-8")
                    match = re.search(
                        r"(?m)^\s*exec\s+(?:\"([^\"]+)\"|'([^']+)'|([^\s]+))",
                        launcher_text,
                    )
                    target_text = next(
                        (item for item in match.groups() if item), ""
                    ) if match else ""
                    target_path = Path(target_text)
                    if (
                        target_path.is_absolute()
                        and target_path.name == "java"
                        and target_path.parent.name == "bin"
                        and target_path.is_file()
                    ):
                        target_path = target_path.resolve()
                        identity["runtime_java"] = str(target_path)
                        identity["runtime_java_sha256"] = sha256_file(target_path)
                        java_home = target_path.parent.parent
            except (OSError, UnicodeError):
                # The normal incomplete-identity path below records the missing
                # release evidence and disables comparison caching.
                pass
    if java_home is not None:
        try:
            identity["java_home"] = str(java_home.resolve())
            release_file = java_home / "release"
            if release_file.is_file():
                identity["release_sha256"] = sha256_file(release_file)
            else:
                identity["failures"].append("java_release_file_missing")
        except OSError as exc:
            identity["java_home"] = str(java_home)
            identity["failures"].append(f"java_release_hash_failed:{type(exc).__name__}")
    identity["complete"] = bool(
        identity["java_sha256"]
        and identity["release_sha256"]
        and (
            not identity["runtime_java"]
            or identity["runtime_java_sha256"]
        )
        and not identity["failures"]
    )
    return identity


def _canonical_json_bytes(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _japicmp_comparison_cache_identity(
    *, coord, old_coord, new_coord, old_version, new_version,
    old_jar_sha256, new_jar_sha256, tool_sha256, target_jdk,
    java_runtime_identity,
):
    return {
        "schema_version": JAPICMP_COMPARISON_CACHE_SCHEMA_VERSION,
        "coord": str(coord or ""),
        "old_coord": str(old_coord or ""),
        "new_coord": str(new_coord or ""),
        "old_version": str(old_version or ""),
        "new_version": str(new_version or ""),
        "old_jar_sha256": str(old_jar_sha256 or ""),
        "new_jar_sha256": str(new_jar_sha256 or ""),
        "tool_sha256": str(tool_sha256 or ""),
        "target_jdk": str(target_jdk or ""),
        "java_runtime_identity": java_runtime_identity or {},
        "options": ["--only-modified", "--ignore-missing-classes", "--xml-file"],
    }


def _japicmp_comparison_cache_path(cache_dir, identity):
    digest = hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()
    return Path(cache_dir) / f"{digest}.json"


def _load_japicmp_comparison_cache(cache_path, identity):
    try:
        payload = json.loads(Path(cache_path).read_text(encoding="utf-8"))
        rows = payload.get("rows")
        raw_output = payload.get("raw_output")
        xml_content = payload.get("xml_content")
        if payload.get("identity") != identity:
            return None
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            return None
        if not isinstance(raw_output, str) or not isinstance(xml_content, str):
            return None
        if payload.get("rows_sha256") != hashlib.sha256(_canonical_json_bytes(rows)).hexdigest():
            return None
        if payload.get("raw_output_sha256") != hashlib.sha256(raw_output.encode("utf-8")).hexdigest():
            return None
        if payload.get("xml_sha256") != hashlib.sha256(xml_content.encode("utf-8")).hexdigest():
            return None
        return {"rows": rows, "raw_output": raw_output, "xml_content": xml_content}
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _write_japicmp_comparison_cache(cache_path, identity, rows, raw_output, xml_content):
    payload = {
        "identity": identity,
        "rows": rows,
        "raw_output": raw_output,
        "xml_content": xml_content,
        "rows_sha256": hashlib.sha256(_canonical_json_bytes(rows)).hexdigest(),
        "raw_output_sha256": hashlib.sha256(raw_output.encode("utf-8")).hexdigest(),
        "xml_sha256": hashlib.sha256(xml_content.encode("utf-8")).hexdigest(),
    }
    cache_path = Path(cache_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = cache_path.with_name(
        f".{cache_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    try:
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temp_path, cache_path)
    except (OSError, TypeError, ValueError):
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def _japicmp_output_header(
    *, display_coord, old_coord, new_coord, old_version, new_version,
    old_jar, new_jar, old_jar_source, new_jar_source,
):
    return (
        f"=== JApiCmp 对比报告 ===\n"
        f"依赖：{display_coord}\n"
        f"旧坐标：{old_coord}\n"
        f"新坐标：{new_coord}\n"
        f"旧版本：{old_version}  ({old_jar})\n"
        f"新版本：{new_version}  ({new_jar})\n"
        f"旧 jar 来源：{old_jar_source or 'unknown'}\n"
        f"新 jar 来源：{new_jar_source or 'unknown'}\n"
        f"执行时间：{datetime.now().isoformat()}\n"
        f"{'='*60}\n\n"
    )


def _api_display_name(row):
    api_name = str((row or {}).get("api_name") or "").strip()
    api_simple = str((row or {}).get("api_simple") or "").strip()
    if api_simple:
        return api_simple
    if not api_name:
        return "-"
    method_match = re.search(r"\.([A-Za-z_$][\w$]*)$", api_name)
    return method_match.group(1) if method_match else api_name.rsplit(".", 1)[-1]


def _signature_display(signature):
    signature = str(signature or "").strip()
    if not signature:
        return "无参数或未知"
    inner = signature
    if inner.startswith("(") and ")" in inner:
        inner = inner[1:inner.index(")")]
    inner = inner.strip()
    if not inner:
        return "无参数"
    return inner


def _changed_api_conclusion(row):
    severity = str((row or {}).get("severity") or "").strip()
    confirmed = str((row or {}).get("confirmed") or "").strip().lower()
    source = str((row or {}).get("source") or "").strip().lower()
    if severity == "P0":
        return "高风险变更"
    if severity == "P1":
        return "需关注变更"
    if confirmed == "false" or source == "changelog":
        return "需要复核"
    return "变更事实"


def _changed_api_summary(row):
    row = row or {}
    change_type = str(row.get("change_type") or "").strip()
    symbol_kind = str(row.get("symbol_kind") or "").strip()
    severity = str(row.get("severity") or "").strip() or "-"
    change_label = _CHANGE_TYPE_LABELS.get(change_type, change_type or "变更")
    kind_label = _SYMBOL_KIND_LABELS.get(symbol_kind, symbol_kind or "API")
    api_name = _api_display_name(row)
    if symbol_kind in {"method", "constructor"}:
        return f"{change_label}{kind_label}，{api_name}，参数：{_signature_display(row.get('api_signature'))}，严重级别：{severity}"
    return f"{change_label}{kind_label}，{api_name}，严重级别：{severity}"


def _changed_api_review_reason(row):
    row = row or {}
    reasons = []
    severity = str(row.get("severity") or "").strip()
    confirmed = str(row.get("confirmed") or "").strip().lower()
    source = str(row.get("source") or "").strip().lower()
    reason_code = str(row.get("reason_code") or "").strip()
    compatibility_flags = str(row.get("compatibility_flags") or "").strip()
    if severity in {"P0", "P1"}:
        reasons.append(f"严重级别 {severity}")
    if confirmed == "false":
        reasons.append("未由二进制对比确认")
    if source == "changelog":
        reasons.append("来源为 changelog")
    if reason_code:
        reasons.append(f"原因码 {reason_code}")
    if compatibility_flags:
        reasons.append(f"兼容性标记 {compatibility_flags}")
    return "；".join(reasons) or "记录 API 变化事实"


def _enrich_changed_api_row(row):
    enriched = dict(row or {})
    enriched["conclusion"] = str(enriched.get("conclusion") or "").strip() or _changed_api_conclusion(enriched)
    enriched["change_summary"] = str(enriched.get("change_summary") or "").strip() or _changed_api_summary(enriched)
    enriched["review_reason"] = str(enriched.get("review_reason") or "").strip() or _changed_api_review_reason(enriched)
    return enriched


def _enrich_changed_api_rows(rows):
    return [_enrich_changed_api_row(row) for row in (rows or [])]


# ══════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════


def load_orchestrated_step4_input(output_dir):
    """正式流程下从 main_state 读取 Step4 输入，CLI 仅保留调试模式。"""
    if not os.environ.get("JUA_ORCHESTRATED"):
        return {}
    report_dir = os.environ.get("UPGRADE_REPORT_DIR", "").strip()
    if not report_dir and output_dir:
        report_dir = str(infer_report_dir_from_output_dir(output_dir))
    if not report_dir:
        return {}
    state_path = Path(report_dir) / RUNTIME_DIRNAME / RUNTIME_STATE_DIRNAME / MAIN_STATE_FILE_NAME
    if not state_path.exists():
        return {}
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            main_state = json.load(f)
    except Exception:
        return {}
    return dict((((main_state or {}).get("step4") or {}).get("input")) or {})


def infer_report_dir_from_output_dir(output_dir):
    output_path = Path(output_dir).resolve()
    if output_path.name == EVIDENCE_API_CHANGES_DIRNAME and output_path.parent.name == EVIDENCE_DIRNAME:
        return output_path.parent.parent
    return output_path.parent


def default_coverage_output_path(output_dir):
    report_dir = infer_report_dir_from_output_dir(output_dir)
    return report_dir / RUNTIME_DIRNAME / "coverage" / "s4_coverage.json"

def load_json(path):
    if not os.path.exists(path): return {}
    with open_text(path) as f:
        return json.load(f)

def load_csv(path):
    if not os.path.exists(path): return []
    rows = []
    with open_csv_read(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            first_value = next(iter(row.values()), "") if row else ""
            if row and not str(first_value).startswith('#'):
                normalized = {k: (v or '').strip() for k, v in row.items()}
                if normalized.get("resolution_status") == "unresolved":
                    continue
                rows.append(normalized)
    return rows

def write_result(path, content):
    """写文件，使用 compat.write_text 确保跨平台 UTF-8 和目录创建"""
    with _WRITE_RESULT_LOCK:
        write_text(path, content)


class Step4TimingRecorder:
    """Append Step4 work-in-progress and completed timing events immediately."""

    FIELDS = [
        "phase",
        "coord",
        "old_version",
        "new_version",
        "status",
        "started_at",
        "ended_at",
        "elapsed_sec",
        "peak_rss_mb",
        "external_process_count",
        "api_count",
        "message",
        "details",
    ]

    def __init__(self, report_dir):
        self.output_dir = (
            Path(report_dir) / RUNTIME_DIRNAME / RUNTIME_OBSERVABILITY_DIRNAME
        )
        self.path = self.output_dir / STEP4_TIMING_FILE
        self._lock = threading.RLock()
        self._rows = []
        self.flush()

    def record(
        self,
        phase,
        *,
        coord="",
        old_version="",
        new_version="",
        status="",
        elapsed=None,
        external_process_count=0,
        api_count="",
        message="",
        details=None,
    ):
        try:
            elapsed_value = "" if elapsed is None else f"{max(0.0, float(elapsed)):.6f}"
        except (TypeError, ValueError):
            elapsed_value = ""
        if isinstance(details, (dict, list, tuple)):
            details_value = json.dumps(details, ensure_ascii=False, sort_keys=True)
        else:
            details_value = "" if details is None else str(details)
        now = datetime.now().astimezone().isoformat(timespec="milliseconds")
        row = {
            "phase": str(phase or ""),
            "coord": str(coord or ""),
            "old_version": str(old_version or ""),
            "new_version": str(new_version or ""),
            "status": str(status or ""),
            "started_at": now if status == "running" else "",
            "ended_at": "" if status == "running" else now,
            "elapsed_sec": elapsed_value,
            "peak_rss_mb": f"{peak_rss_mb():.3f}",
            "external_process_count": str(max(0, int(external_process_count or 0))),
            "api_count": "" if api_count is None else str(api_count),
            "message": str(message or ""),
            "details": details_value,
        }
        with self._lock:
            self._rows.append(row)
            with open_csv_append(self.path) as f:
                csv.DictWriter(f, fieldnames=self.FIELDS).writerow(row)

    def flush(self):
        with self._lock:
            self._flush_locked()
        return str(self.path)

    def _flush_locked(self):
        rows = list(self._rows)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open_csv_write(self.path) as f:
            writer = csv.DictWriter(f, fieldnames=self.FIELDS)
            writer.writeheader()
            writer.writerows(rows)


def cleanup_step4_generated_outputs(output_dir):
    """清理当前 output_dir 下旧的 Step4 产物，避免重跑时混入陈旧证据。"""
    output_path = Path(output_dir)
    if not output_path.exists():
        return
    removable_patterns = (
        "*_binary.txt",
        "*_behavior.txt",
        "*_gitdiff_api_changes.txt",
        "all_changed_apis.csv",
        "all_changed_apis_raw.csv",
        "all_changed_apis_alerts.csv",
        CHANGED_DEPENDENCIES_CSV,
        CHANGED_DEPENDENCIES_MD,
        BUSINESS_BYTECODE_CHANGED_API_REFS_CSV,
        BUSINESS_BYTECODE_PRIORITY_EVIDENCE_JSON,
        "changed_classes.json",
        "timeouts.json",
        "git_ref_pending.json",
        "git_ref_matches.txt",
        "git_ref_matches.json",
        DEPENDENCY_ANALYSIS_STATUS_CSV,
        DEPENDENCY_ANALYSIS_STATUS_JSON,
        DEPENDENCY_ANALYSIS_STATUS_MD,
        STEP4_TIMING_FILE,
        "summary.txt",
    )
    for pattern in removable_patterns:
        for path in output_path.glob(pattern):
            if path.is_file():
                path.unlink()
    per_dependency_dir = output_path.resolve().parent / PER_DEPENDENCY_DIRNAME
    if per_dependency_dir.exists():
        shutil.rmtree(per_dependency_dir, ignore_errors=True)
    artifact_cache_dir = output_path / "step4_artifact_jars"
    if artifact_cache_dir.exists():
        shutil.rmtree(artifact_cache_dir, ignore_errors=True)


def infer_package_from_source_path(source_path):
    normalized = (source_path or '').replace('\\', '/').strip('/')
    if not normalized.endswith('.java'):
        return ''
    parts = normalized.split('/')
    for marker in ('src/main/java', 'src/test/java'):
        marker_parts = marker.split('/')
        for idx in range(len(parts) - len(marker_parts)):
            if parts[idx:idx + len(marker_parts)] == marker_parts:
                package_parts = parts[idx + len(marker_parts):-1]
                return '.'.join(p for p in package_parts if p)
    if len(parts) > 1:
        return '.'.join(parts[:-1])
    return ''


def _split_coord(coord: str):
    group_id, artifact_id, classifier = split_artifact_coord(coord)
    if not group_id or not artifact_id:
        return None, None, None
    return group_id, artifact_id, classifier or None


def _artifact_output_stem(coord):
    _group_id, artifact_id, classifier = _split_coord(coord)
    artifact_id = artifact_id or "dependency"
    return (
        f"{artifact_id}_{classifier}"
        if classifier
        else artifact_id
    )


def _resolve_step4_side_coord(row, side, fallback_coord=""):
    row = row or {}
    if side == "base":
        side_coord = str(row.get("base_coord") or "").strip()
    elif side == "current":
        side_coord = str(row.get("current_coord") or "").strip()
    else:
        side_coord = ""
    return side_coord or str(fallback_coord or row.get("coord") or "").strip()


class Step1ArtifactJarResolver:
    """Resolve dependency jars exclusively from the JARs materialized by Step1."""

    def __init__(self, report_dir, output_dir):
        self.report_dir = Path(report_dir or ".").resolve()
        self.output_dir = Path(output_dir or ".").resolve()
        self._load_failure = None
        self._entry_failures = {}
        self._manifest_loaded = False
        self._manifest_index = {}
        self._load_manifest()
        self._entry_cache = {}

    def _load_manifest(self):
        manifest_path = (
            self.report_dir / "dependencies"
            / STEP1_DEPENDENCY_JARS_MANIFEST_FILE
        )
        if not manifest_path.is_file():
            self._load_failure = {
                "reason_code": "STEP1_DEPENDENCY_JARS_MANIFEST_MISSING",
                "message": "Step1 变化依赖 JAR 清单不存在",
                "manifest_path": str(manifest_path),
            }
            return
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self._load_failure = {
                "reason_code": "STEP1_DEPENDENCY_JARS_MANIFEST_UNREADABLE",
                "message": "Step1 变化依赖 JAR 清单无法读取",
                "manifest_path": str(manifest_path),
                "error_type": type(exc).__name__,
                "error": str(exc)[:300],
            }
            return
        self._manifest_loaded = True
        for item in data.get("items") or []:
            if not isinstance(item, dict):
                continue
            side = str(item.get("side") or "").strip()
            lib_entry = str(item.get("lib_entry") or "").replace("\\", "/").strip()
            if side and lib_entry:
                self._manifest_index[(side, lib_entry)] = dict(item)

    def resolve_for_row(self, row, side):
        row = row or {}
        entry_field = "base_lib_entry" if side == "base" else "current_lib_entry"
        lib_entry = str(row.get(entry_field) or "").replace("\\", "/").strip()
        if not lib_entry:
            return None
        return self.resolve_entry(side, lib_entry)

    def failure_for_row(self, row, side):
        """Return user-reviewable evidence explaining why a final-artifact jar was unavailable."""
        row = row or {}
        entry_field = "base_lib_entry" if side == "base" else "current_lib_entry"
        lib_entry = str(row.get(entry_field) or "").replace("\\", "/").strip()
        if not lib_entry:
            return {
                "source": "step1_final_artifact",
                "side": side,
                "reason_code": "FINAL_ARTIFACT_LIB_ENTRY_MISSING",
                "message": f"Step1 未记录 {side} 最终制品内的依赖 JAR 条目",
            }
        if self._load_failure:
            return {
                "source": "step1_final_artifact",
                "side": side,
                "lib_entry": lib_entry,
                **self._load_failure,
            }
        if self._manifest_loaded:
            return dict(self._entry_failures.get((side, lib_entry)) or {
                "source": "step1_retained_dependency_jar",
                "side": side,
                "lib_entry": lib_entry,
                "reason_code": "STEP1_DEPENDENCY_JAR_NOT_RETAINED",
                "message": "Step1 未留存该变化依赖 JAR",
            })
        return {
            "source": "step1_retained_dependency_jar",
            "side": side,
            "lib_entry": lib_entry,
            "reason_code": "STEP1_DEPENDENCY_JARS_MANIFEST_MISSING",
            "message": "Step1 变化依赖 JAR 清单不存在",
        }

    def resolve_entry(self, side, lib_entry):
        if self._manifest_loaded:
            key = (side, lib_entry)
            if key in self._entry_cache:
                cached = self._entry_cache[key]
                return dict(cached) if cached else None
            item = dict(self._manifest_index.get(key) or {})
            if not item:
                self._entry_failures[key] = {
                    "source": "step1_retained_dependency_jar",
                    "side": side,
                    "lib_entry": lib_entry,
                    "reason_code": "STEP1_DEPENDENCY_JAR_NOT_RETAINED",
                    "message": "Step1 未留存该变化依赖 JAR",
                }
                self._entry_cache[key] = None
                return None
            retained_path = Path(str(item.get("retained_path") or ""))
            expected_sha = str(item.get("nested_jar_sha256") or "").strip()
            if not retained_path.is_file():
                self._entry_failures[key] = {
                    **item,
                    "source": "step1_retained_dependency_jar",
                    "reason_code": "STEP1_DEPENDENCY_JAR_MISSING",
                    "message": "Step1 留存的变化依赖 JAR 不存在",
                }
                self._entry_cache[key] = None
                return None
            if not expected_sha or sha256_file(retained_path) != expected_sha:
                self._entry_failures[key] = {
                    **item,
                    "source": "step1_retained_dependency_jar",
                    "reason_code": "STEP1_DEPENDENCY_JAR_SHA_MISMATCH",
                    "message": "Step1 留存的变化依赖 JAR SHA-256 不一致",
                }
                self._entry_cache[key] = None
                return None
            try:
                require_safe_dependency_jar(retained_path)
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                self._entry_failures[key] = {
                    **item,
                    "source": "step1_retained_dependency_jar",
                    "reason_code": "STEP1_DEPENDENCY_JAR_UNSAFE",
                    "message": "Step1 留存的变化依赖 JAR 无法安全读取",
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:300],
                }
                self._entry_cache[key] = None
                return None
            evidence = {
                **item,
                "path": str(retained_path),
                "source": "step1_retained_dependency_jar",
                "artifact_path": str(item.get("outer_artifact_path") or ""),
                "artifact_sha256": str(item.get("outer_artifact_sha256") or ""),
            }
            self._entry_cache[key] = dict(evidence)
            return evidence
        return None


def collapse_same_gav_artifact_rows(rows):
    """Analyze one logical GAV change once when its retained bytes are identical."""
    collapsed = []
    seen = {}
    conflicts = []
    for row in rows or ():
        key = (
            str(row.get('base_coord') or row.get('coord') or '').strip(),
            str(row.get('current_coord') or row.get('coord') or '').strip(),
            str(row.get('old_version') or '').strip(),
            str(row.get('new_version') or '').strip(),
            str(row.get('change_type') or '').strip(),
        )
        identity = (
            str(
                (row.get('_step4_base_jar_evidence') or {}).get(
                    'nested_jar_sha256'
                ) or ''
            ).lower(),
            str(
                (row.get('_step4_current_jar_evidence') or {}).get(
                    'nested_jar_sha256'
                ) or ''
            ).lower(),
        )
        previous = seen.get(key)
        if previous is None:
            seen[key] = (identity, row)
            collapsed.append(row)
            continue
        previous_identity, previous_row = previous
        if identity == previous_identity:
            continue
        conflicts.append({
            'coord': str(row.get('coord') or '').strip(),
            'old_version': key[2],
            'new_version': key[3],
            'base_entries': sorted({
                str(previous_row.get('base_lib_entry') or '').strip(),
                str(row.get('base_lib_entry') or '').strip(),
            } - {''}),
            'current_entries': sorted({
                str(previous_row.get('current_lib_entry') or '').strip(),
                str(row.get('current_lib_entry') or '').strip(),
            } - {''}),
            'reason_code': 'SAME_GAV_DIFFERENT_RETAINED_BYTES',
        })
    return collapsed, conflicts


_REPO_REFS_CACHE = {}
_CORE_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
_NON_CORE_TOKEN_RE = re.compile(r"[A-Za-z]+[A-Za-z0-9]*|\d+")


def _normalize_version_text(version: str):
    v = (version or "").strip()
    if not v or v == "-":
        return None
    return re.sub(r'(?i)-SNAPSHOT$', '', v).strip() or None


def _remote_branch_name(ref_name: str):
    ref_name = (ref_name or "").strip()
    if not ref_name:
        return ""
    if "/" not in ref_name:
        return ref_name
    return ref_name.split("/", 1)[1].strip()


def _remote_name(ref_name: str):
    ref_name = (ref_name or "").strip()
    if not ref_name or "/" not in ref_name:
        return ""
    return ref_name.split("/", 1)[0].strip()


def _extract_core_version_span(text: str):
    text = (_normalize_version_text(text) or (text or "").strip())
    if not text:
        return None
    match = _CORE_VERSION_RE.search(text)
    if not match:
        return None
    return match.start(), match.end()


def _extract_non_core_tokens(text: str):
    text = (_normalize_version_text(text) or (text or "").strip())
    if not text:
        return []
    span = _extract_core_version_span(text)
    if not span:
        return [token.lower() for token in _NON_CORE_TOKEN_RE.findall(text)]
    start, end = span
    tokens = []
    for part in (text[:start], text[end:]):
        tokens.extend(token.lower() for token in _NON_CORE_TOKEN_RE.findall(part))
    return tokens


def _counter_includes(container, required):
    container = container or Counter()
    required = required or Counter()
    for token, count in required.items():
        if container.get(token, 0) < count:
            return False
    return True


def _build_token_delta(old_tokens, new_tokens):
    old_counter = Counter(old_tokens or [])
    new_counter = Counter(new_tokens or [])
    return new_counter - old_counter, old_counter - new_counter


def _sum_counter(counter):
    return sum((counter or Counter()).values())


def _score_token_delta_alignment(expected_added, expected_removed, actual_added, actual_removed):
    expected_total = _sum_counter(expected_added) + _sum_counter(expected_removed)
    actual_total = _sum_counter(actual_added) + _sum_counter(actual_removed)
    if expected_total == 0 and actual_total == 0:
        return 40, "exact"

    matched = _sum_counter((expected_added or Counter()) & (actual_added or Counter()))
    matched += _sum_counter((expected_removed or Counter()) & (actual_removed or Counter()))
    missing = _sum_counter((expected_added or Counter()) - (actual_added or Counter()))
    missing += _sum_counter((expected_removed or Counter()) - (actual_removed or Counter()))
    extra = _sum_counter((actual_added or Counter()) - (expected_added or Counter()))
    extra += _sum_counter((actual_removed or Counter()) - (expected_removed or Counter()))

    score = matched * 35 - missing * 45 - extra * 30
    if missing == 0 and extra == 0 and expected_total > 0:
        score += 70
        match_kind = "exact"
    elif matched > 0 and missing == 0:
        score += 15
        match_kind = "partial"
    else:
        match_kind = "mismatch"
    return score, match_kind


def rank_repo_ref_pair_candidates(old_candidates, new_candidates, old_version: str, new_version: str):
    """Rank old/new remote-ref pairs with one deterministic scoring contract."""
    old_version_norm = _normalize_version_text(old_version)
    new_version_norm = _normalize_version_text(new_version)
    expected_added_tokens, expected_removed_tokens = _build_token_delta(
        _extract_non_core_tokens(old_version_norm),
        _extract_non_core_tokens(new_version_norm),
    )
    version_delta_present = bool(_sum_counter(expected_added_tokens) or _sum_counter(expected_removed_tokens))

    pair_candidates = []
    for old_item in old_candidates or []:
        for new_item in new_candidates or []:
            same_prefix = bool(old_item.get("prefix")) and old_item.get("prefix") == new_item.get("prefix")
            same_remote = bool(old_item.get("remote_name")) and old_item.get("remote_name") == new_item.get("remote_name")
            actual_added_tokens, actual_removed_tokens = _build_token_delta(
                _extract_non_core_tokens(old_item.get("branch_name")),
                _extract_non_core_tokens(new_item.get("branch_name")),
            )
            delta_score, delta_match_kind = _score_token_delta_alignment(
                expected_added_tokens,
                expected_removed_tokens,
                actual_added_tokens,
                actual_removed_tokens,
            )
            pair_bonus = (30 if same_prefix else 0) + (10 if same_remote else 0)
            if version_delta_present and old_item.get("ref") == new_item.get("ref"):
                pair_bonus -= 40
            pair_candidates.append(
                {
                    "old": old_item,
                    "new": new_item,
                    "pair_score": old_item.get("score", 0) + new_item.get("score", 0) + pair_bonus + delta_score,
                    "same_prefix": same_prefix,
                    "same_remote": same_remote,
                    "delta_match_kind": delta_match_kind,
                }
            )

    pair_candidates.sort(
        key=lambda item: (
            -item["pair_score"],
            -int(item["delta_match_kind"] == "exact"),
            -int(item["delta_match_kind"] == "partial"),
            -int(item["same_prefix"]),
            -int(item["same_remote"]),
            _ref_kind_priority(item["old"].get("kind")),
            _ref_kind_priority(item["new"].get("kind")),
            -int(item["old"].get("score", 0)),
            -int(item["new"].get("score", 0)),
            len(item["old"].get("ref", "")),
            len(item["new"].get("ref", "")),
            item["old"].get("ref", ""),
            item["new"].get("ref", ""),
        )
    )
    return pair_candidates


def _ref_kind_priority(kind: str):
    return {
        "remote": 0,
        "tag": 1,
    }.get((kind or "").strip(), 9)


def _is_dev_branch_name(branch_name: str):
    # Only demote an actual DEV path/token.  A substring check also demoted
    # unrelated names such as ``device-fix`` and ``developer-tools``, making
    # otherwise identical inventories rank differently from user intent.
    return bool(re.search(r"(?i)(?:^|[-_/.:])dev(?:$|[-_/.:])", (branch_name or "").strip()))


def is_ephemeral_dependency_source_mapping(source_mapping):
    """
    Skip git-diff for temporary extracted source bundles under
    `.tmp-validation/dependency-sources`.

    These directories are useful for source-level fallback analysis, but they do
    not represent the dependency's real git repository. If we climb to an
    enclosing workspace git root here, Step4 will produce a fake
    `git refs 待确认` checkpoint on the wrong repository.
    """
    source_mapping = source_mapping or {}
    repo_path = str(source_mapping.get("repo_path") or "").strip()
    module_path = str(source_mapping.get("module_path") or "").strip()
    if not repo_path or not module_path:
        return False

    try:
        repo_root = Path(repo_path).resolve()
        module_root = Path(module_path).resolve()
    except Exception:
        return False

    parts = module_root.parts
    try:
        tmp_idx = parts.index(".tmp-validation")
        dep_idx = parts.index("dependency-sources", tmp_idx + 1)
    except ValueError:
        return False

    if dep_idx + 1 >= len(parts):
        return False

    extracted_root = Path(*parts[: dep_idx + 2])
    if repo_root == extracted_root:
        return False

    return repo_root in extracted_root.parents


def _filter_inferred_coords_by_prefix(inferred_coords, coord_prefix):
    coord_prefix = (coord_prefix or "").strip()
    if not coord_prefix:
        return list(inferred_coords or [])
    if ":" in coord_prefix:
        coord_ga = artifact_ga(coord_prefix)
        return [
            item for item in (inferred_coords or [])
            if artifact_ga(item) == coord_ga
        ]
    return [item for item in (inferred_coords or []) if item.startswith(coord_prefix + ":")]


def _cached_maven_coord_locations(repo_path, cache):
    """Infer repository coordinates once per lexical absolute repository path."""
    cache_key = os.path.normcase(os.path.abspath(str(repo_path or "")))
    if cache_key not in cache:
        cache[cache_key] = infer_maven_coord_locations(
            cache_key,
            max_poms=120,
            max_depth=4,
        )
    return cache[cache_key]


def _list_repo_refs(repo_dir: str, timeout=DEFAULT_FETCH_TIMEOUT):
    repo_dir = os.path.abspath(repo_dir)
    cached = _REPO_REFS_CACHE.get(repo_dir)
    if cached is not None:
        return cached

    inventory = query_live_remote_refs(
        repo_dir,
        timeout=_bounded_git_timeout(timeout, DEFAULT_FETCH_TIMEOUT),
    )
    remote_records = [
        dict(item) for item in (inventory.get("refs") or [])
        if item.get("kind") in {"branch", "tag"}
    ]
    result = {
        "tags": [
            item.get("ref") for item in remote_records
            if item.get("kind") == "tag" and item.get("ref")
        ],
        "heads": [],
        "remotes": [
            item.get("ref") for item in remote_records
            if item.get("kind") == "branch" and item.get("ref")
        ],
        "remote_records": remote_records,
        "remote_failures": list(inventory.get("failures") or []),
        # Preserve the configured inventory separately from the refs that
        # happened to match.  Callers need this to apply deterministic remote
        # priority without treating a failed peer as an absent remote.
        "configured_remotes": [
            str(item).strip() for item in (inventory.get("remotes") or [])
            if str(item or "").strip()
        ],
        "queried_at": str(inventory.get("queried_at") or ""),
    }
    _REPO_REFS_CACHE[repo_dir] = result
    return result


def _git_ref_exists(repo_dir: str, ref: str):
    ref = (ref or "").strip()
    if not ref:
        return False
    _out, _err, rc = run_cmd(git_cmd() + ["rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo_dir, timeout=10)
    return rc == 0


def source_refs_have_different_commits(source_branches, repo_dir):
    """Return whether two source refs can represent different source content.

    Different branch names may point at the same commit (notably artifact-only
    comparisons).  In that case scanning every unchanged dependency is both
    wasteful and misleading.  If either ref cannot be resolved, stay
    conservative and treat them as different.
    """
    refs = [str(item or '').strip() for item in (source_branches or [])[:2]]
    if len(refs) < 2 or not all(refs):
        return False
    if refs[0] == refs[1]:
        return False
    commits = []
    for ref in refs:
        stdout, _stderr, rc = run_cmd(
            git_cmd() + ["rev-parse", "--verify", f"{ref}^{{commit}}"],
            cwd=repo_dir,
            timeout=10,
        )
        if rc != 0 or not str(stdout or '').strip():
            return True
        commits.append(str(stdout).strip().splitlines()[-1])
    return commits[0] != commits[1]


def _extract_branch_prefix(branch_name: str, match_start: int):
    branch_name = (branch_name or "").strip()
    if match_start <= 0:
        return ""
    return branch_name[:match_start].rstrip("-_/.:").strip().lower()


def _classify_version_match(branch_name: str, version_norm: str):
    branch_name = (branch_name or "").strip()
    version_norm = (version_norm or "").strip()
    if not branch_name or not version_norm:
        return None

    branch_lower = branch_name.lower()
    version_lower = version_norm.lower()
    version_non_core_tokens = Counter(_extract_non_core_tokens(version_norm))
    best = None
    search_start = 0

    while True:
        match_start = branch_lower.find(version_lower, search_start)
        if match_start < 0:
            break
        match_end = match_start + len(version_lower)
        prev_char = branch_lower[match_start - 1] if match_start > 0 else ""
        next_char = branch_lower[match_end] if match_end < len(branch_lower) else ""
        search_start = match_start + 1

        # Avoid matching inside a larger numeric dotted version token.
        if prev_char and (prev_char.isdigit() or prev_char == "."):
            continue

        if not next_char or next_char in "-_/":
            match_kind = "exact_boundary"
            score = 140
        else:
            continue

        prefix = _extract_branch_prefix(branch_name, match_start)
        candidate = {
            "match_kind": match_kind,
            "score": score,
            "prefix": prefix,
            "match_start": match_start,
            "match_end": match_end,
        }
        if (
            best is None
            or candidate["score"] > best["score"]
            or (
                candidate["score"] == best["score"]
                and len(candidate["prefix"]) > len(best["prefix"])
            )
            or (
                candidate["score"] == best["score"]
                and len(candidate["prefix"]) == len(best["prefix"])
                and candidate["match_start"] < best["match_start"]
            )
        ):
            best = candidate

    if best is not None or not version_non_core_tokens:
        return best

    core_span = _extract_core_version_span(version_norm)
    if not core_span:
        return best
    core_version = version_norm[core_span[0]:core_span[1]]
    core_lower = core_version.lower()
    branch_non_core_tokens = Counter(_extract_non_core_tokens(branch_name))
    if not _counter_includes(branch_non_core_tokens, version_non_core_tokens):
        return best

    search_start = 0
    while True:
        match_start = branch_lower.find(core_lower, search_start)
        if match_start < 0:
            break
        match_end = match_start + len(core_lower)
        prev_char = branch_lower[match_start - 1] if match_start > 0 else ""
        next_char = branch_lower[match_end] if match_end < len(branch_lower) else ""
        search_start = match_start + 1

        if prev_char and (prev_char.isdigit() or prev_char == "."):
            continue
        if next_char and next_char not in "-_/":
            continue

        prefix = _extract_branch_prefix(branch_name, match_start)
        candidate = {
            "match_kind": "core_with_tokens",
            "score": 138,
            "prefix": prefix,
            "match_start": match_start,
            "match_end": match_end,
        }
        if (
            best is None
            or candidate["score"] > best["score"]
            or (
                candidate["score"] == best["score"]
                and len(candidate["prefix"]) > len(best["prefix"])
            )
            or (
                candidate["score"] == best["score"]
                and len(candidate["prefix"]) == len(best["prefix"])
                and candidate["match_start"] < best["match_start"]
            )
        ):
            best = candidate
    return best


def _score_ref_match(ref_name: str, version_norm: str):
    branch_name = _remote_branch_name(ref_name)
    v = (version_norm or "").strip()
    if not branch_name or not v:
        return None
    match_info = _classify_version_match(branch_name, v)
    if not match_info:
        return None
    score = match_info["score"] - (10 if _is_dev_branch_name(branch_name) else 0)
    return {
        "score": score,
        "match_kind": match_info["match_kind"],
        "prefix": match_info["prefix"],
        "branch_name": branch_name,
        "remote_name": _remote_name(ref_name),
    }


def _top_ref_candidates_have_one_healthy_commit(candidates):
    candidates = list(candidates or [])
    if not candidates:
        return False, set()
    best = candidates[0]
    tied = [
        item for item in candidates
        if item.get("score") == best.get("score")
        and _ref_kind_priority(item.get("kind")) == _ref_kind_priority(best.get("kind"))
    ]
    commits = {
        str(item.get("commit") or "").strip().lower()
        for item in tied
        if str(item.get("commit") or "").strip()
    }
    is_healthy = bool(tied) and len(commits) == 1 and all(
        str(item.get("commit") or "").strip() for item in tied
    )
    remotes = {
        str(item.get("remote") or item.get("remote_name") or "").strip()
        for item in tied
        if str(item.get("remote") or item.get("remote_name") or "").strip()
    }
    return is_healthy, remotes


def _remote_failure_reason(failures):
    reasons = "; ".join(
        str(item.get("reason") or item.get("stage") or "remote query failed")
        for item in (failures or [])
    )
    return f"remote_query_failed={reasons or 'remote query failed'}"


def _select_live_remote_tier(candidates, configured_remotes, failures):
    """Select one deterministic remote tier and fail closed within that tier.

    ``origin`` is the conventional primary when configured.  Every other
    configured remote is a peer: a failed peer cannot be silently discarded
    in favour of another peer, because doing so makes the answer depend on
    transient transport timing.  Failures in a lower tier are irrelevant once
    a healthy origin supplied matching candidates.
    """
    configured = []
    for remote in configured_remotes or []:
        name = str(remote or "").strip()
        if name and name not in configured:
            configured.append(name)
    known = set(configured)
    failures = [dict(item) for item in (failures or [])]
    origin_candidates = [
        item for item in candidates
        if str(item.get("remote") or item.get("remote_name") or "").strip() == "origin"
    ]
    unscoped_or_unknown = [
        item for item in failures
        if not str(item.get("remote") or "").strip()
        or str(item.get("remote") or "").strip() not in known
    ]

    if "origin" in known:
        origin_failures = [
            item for item in failures
            if str(item.get("remote") or "").strip() == "origin"
        ]
        if origin_failures or unscoped_or_unknown:
            blocking = origin_failures + [
                item for item in unscoped_or_unknown if item not in origin_failures
            ]
            return origin_candidates or list(candidates), blocking
        if origin_candidates:
            return origin_candidates, []

        # Origin was queried successfully but has no matching ref.  All other
        # remotes now form one peer tier, so every peer must be healthy.
        peer_candidates = [
            item for item in candidates
            if str(item.get("remote") or item.get("remote_name") or "").strip() != "origin"
        ]
        peer_failures = [
            item for item in failures
            if str(item.get("remote") or "").strip() != "origin"
        ]
        return peer_candidates, peer_failures

    # Without origin there is no implicit ordering among configured remotes.
    return list(candidates), failures


def list_repo_ref_candidates_for_version(
    repo_dir: str,
    version: str,
    *,
    remote_timeout=DEFAULT_FETCH_TIMEOUT,
):
    version_norm = _normalize_version_text(version)
    if not version_norm:
        return [], version_norm, "version_empty"
    refs = _list_repo_refs(
        repo_dir,
        timeout=_bounded_git_timeout(remote_timeout, DEFAULT_FETCH_TIMEOUT),
    )
    remote_records = [
        dict(item) for item in (refs.get("remote_records") or [])
        if str(item.get("ref") or "")
    ]
    if not remote_records:
        # Compatibility for older cached/test inventories.  Live inventories
        # always provide records (including tag commit/canonical-ref metadata).
        remote_records = [
            {
                "ref": str(ref_name),
                "kind": "branch",
                "remote": _remote_name(ref_name),
            }
            for ref_name in (refs.get("remotes") or [])
            if str(ref_name or "").strip()
        ]
    candidates = []
    for record in remote_records:
        ref_name = str(record.get("ref") or "").strip()
        match_info = _score_ref_match(ref_name, version_norm)
        if not match_info:
            continue
        ref_kind = "tag" if str(record.get("kind") or "").strip() == "tag" else "remote"
        candidates.append({
            "ref": ref_name,
            "kind": ref_kind,
            "score": match_info["score"],
            "version": version_norm,
            "match_kind": match_info["match_kind"],
            "prefix": match_info["prefix"],
            "branch_name": match_info["branch_name"],
            "remote_name": str(record.get("remote") or match_info["remote_name"]),
            "commit": str(record.get("commit") or ""),
            "canonical_ref": str(record.get("canonical_ref") or ""),
            "remote": str(record.get("remote") or match_info["remote_name"]),
        })
    candidates.sort(key=lambda item: (
        -item["score"],
        _ref_kind_priority(item["kind"]),
        0 if item["match_kind"] == "exact_boundary" else 1,
        -len(item["prefix"]),
        len(item["ref"]),
        item["ref"],
        item["canonical_ref"],
    ))
    result = candidates
    configured_remotes = refs.get("configured_remotes")
    if configured_remotes is not None:
        result, blocking_failures = _select_live_remote_tier(
            candidates,
            configured_remotes,
            refs.get("remote_failures") or [],
        )
        if blocking_failures:
            return result, version_norm, _remote_failure_reason(blocking_failures)
    elif refs.get("remote_failures"):
        # Compatibility for older cached/test inventories which did not
        # preserve configured remotes.  New live inventories always use the
        # deterministic tier rules above.
        unique_commit, healthy_remotes = _top_ref_candidates_have_one_healthy_commit(result)
        relevant_failures = [
            item for item in (refs.get("remote_failures") or [])
            if not str(item.get("remote") or "").strip()
            or str(item.get("remote") or "").strip() in healthy_remotes
        ]
        # A failure from another configured remote must not invalidate a
        # unique, commit-pinned result obtained successfully from a healthy
        # remote.  The failed remote remains in the inventory diagnostics.
        if not unique_commit or relevant_failures:
            failures = relevant_failures or list(refs.get("remote_failures") or [])
            return result, version_norm, _remote_failure_reason(failures)
    if not result:
        return result, version_norm, f"no_ref_match_for_version={version_norm}"
    return result, version_norm, None


def resolve_repo_ref_pair_for_versions(
    repo_dir: str,
    old_version: str,
    new_version: str,
    *,
    remote_timeout=DEFAULT_FETCH_TIMEOUT,
):
    old_candidates, old_version_norm, old_error = list_repo_ref_candidates_for_version(
        repo_dir, old_version, remote_timeout=remote_timeout,
    )
    new_candidates, new_version_norm, new_error = list_repo_ref_candidates_for_version(
        repo_dir, new_version, remote_timeout=remote_timeout,
    )
    if old_error or new_error:
        return None, None, old_error, new_error, old_candidates, new_candidates

    pair_candidates = rank_repo_ref_pair_candidates(
        old_candidates,
        new_candidates,
        old_version_norm,
        new_version_norm,
    )
    if not pair_candidates:
        return None, None, old_error, new_error, old_candidates, new_candidates

    best = pair_candidates[0]
    tied_pairs = [
        item for item in pair_candidates
        if item["pair_score"] == best["pair_score"]
        and item["delta_match_kind"] == best["delta_match_kind"]
        and item["same_prefix"] == best["same_prefix"]
        and item["same_remote"] == best["same_remote"]
        and _ref_kind_priority(item["old"].get("kind"))
        == _ref_kind_priority(best["old"].get("kind"))
        and _ref_kind_priority(item["new"].get("kind"))
        == _ref_kind_priority(best["new"].get("kind"))
    ]
    if len(tied_pairs) > 1:
        fixed_commit_pairs = {
            (item["old"].get("commit"), item["new"].get("commit"))
            for item in tied_pairs
        }
        if len(fixed_commit_pairs) != 1 or not all(next(iter(fixed_commit_pairs), (None, None))):
            return (
                None,
                None,
                f"ambiguous_ref_matches_for_version={old_version_norm}",
                f"ambiguous_ref_matches_for_version={new_version_norm}",
                old_candidates,
                new_candidates,
            )

    old_reason = (
        "matched_by_version_pair("
        f"kind={best['old'].get('kind')},score={best['old'].get('score')},"
        f"version={old_version_norm},match_kind={best['old'].get('match_kind')},"
        f"same_prefix={str(best['same_prefix']).lower()},same_remote={str(best['same_remote']).lower()},"
        f"delta_match={best['delta_match_kind']})"
    )
    new_reason = (
        "matched_by_version_pair("
        f"kind={best['new'].get('kind')},score={best['new'].get('score')},"
        f"version={new_version_norm},match_kind={best['new'].get('match_kind')},"
        f"same_prefix={str(best['same_prefix']).lower()},same_remote={str(best['same_remote']).lower()},"
        f"delta_match={best['delta_match_kind']})"
    )
    return (
        best["old"]["ref"],
        best["new"]["ref"],
        old_reason,
        new_reason,
        old_candidates,
        new_candidates,
    )


def _commit_prefix_matches(candidate_commit, requested_commit):
    candidate = str(candidate_commit or "").strip().lower()
    requested = str(requested_commit or "").strip().lower()
    return bool(
        candidate
        and requested
        and re.fullmatch(r"[0-9a-f]{7,64}", requested)
        and candidate.startswith(requested)
    )


def _with_local_fallback_details(remote_reason, local_result):
    reason = str(remote_reason or "remote_source_unavailable")
    local_result = local_result or {}
    commit = str(
        local_result.get("resolved_commit")
        or local_result.get("local_candidate_commit")
        or ""
    ).strip()
    if not commit:
        return reason
    details = [f"local_fallback_available={commit}"]
    if local_result.get("dirty") is True:
        details.append("local_fallback_dirty=true")
    return ";".join([reason, *details])


def _resolve_local_fallback_after_remote_failure(
    repo_dir,
    selected_ref,
    remote_reason,
    *,
    version_norm="",
    allow_local_source=False,
    allow_dirty_local_source=False,
):
    """Keep the remote failure primary unless local use was explicitly allowed."""
    local = resolve_local_source_ref(
        repo_dir,
        selected_ref,
        allow_local_source=allow_local_source,
        allow_dirty_local_source=allow_dirty_local_source,
    )
    if local.get("status") == "user_confirmed_local_source":
        return str(local.get("resolved_commit") or selected_ref), (
            "selected_by_user("
            f"kind=user_confirmed_local_source,score=-1,version={version_norm})"
        )
    if local.get("status") == "awaiting_dirty_local_source_confirmation":
        return None, _with_local_fallback_details(remote_reason, local)
    return None, _with_local_fallback_details(remote_reason, local)


def _local_fallback_from_reason(reason):
    match = re.search(
        r"(?:^|;)local_fallback_available=([0-9a-fA-F]{7,64})(?:;|$)",
        str(reason or ""),
    )
    if not match:
        return {}
    return {
        "available": True,
        "commit": match.group(1),
        "dirty": "local_fallback_dirty=true" in str(reason or ""),
    }


def resolve_repo_ref_for_version(
    repo_dir: str,
    version: str,
    selected_ref: str = "",
    *,
    expected_commit="",
    remote_timeout=DEFAULT_FETCH_TIMEOUT,
    allow_local_source=False,
    allow_dirty_local_source=False,
):
    selected_ref = (selected_ref or "").strip()
    expected_commit = str(expected_commit or "").strip()
    version_norm = _normalize_version_text(version)
    if selected_ref:
        selected_is_commit = bool(
            re.fullmatch(r"[0-9a-fA-F]{7,64}", selected_ref)
        )
        # An explicit selection is an exact remote lookup, not a version-name
        # heuristic.  The shared resolver applies explicit -> origin -> peer
        # tiers and keeps one total deadline, so an unrelated slow remote
        # cannot consume the selection budget first.
        remote_result = resolve_remote_source_ref(
            repo_dir,
            selected_ref,
            query_timeout=remote_timeout,
            fetch_timeout=remote_timeout,
            expected_commit=expected_commit,
        )
        remote_candidates = [
            dict(item) for item in remote_result.get("candidates") or []
        ]
        if remote_result.get("status") == "remote_source_resolved":
            resolved_ref = str(
                remote_result.get("resolved_ref") or selected_ref
            ).strip()
            resolved_commit = str(
                remote_result.get("resolved_commit") or expected_commit
            ).strip()
            canonical_ref = str(remote_result.get("remote_ref") or "").strip()
            remote = str(remote_result.get("remote") or "").strip()
            selected_kind = (
                "tag" if canonical_ref.startswith("refs/tags/") else "remote"
            )
            selected_candidate = {
                "ref": resolved_ref,
                "kind": selected_kind,
                "score": -1,
                "version": version_norm,
                "match_kind": "explicit_user_selection",
                "prefix": "",
                "branch_name": str(
                    canonical_ref.removeprefix("refs/heads/")
                    or _remote_branch_name(resolved_ref)
                ),
                "remote_name": remote,
                "commit": resolved_commit,
                "canonical_ref": canonical_ref,
                "remote": remote,
            }
            merged_candidates = [selected_candidate]
            merged_candidates.extend(
                candidate for candidate in remote_candidates
                if candidate.get("ref") != selected_candidate["ref"]
            )
            return resolved_ref, (
                "selected_by_user("
                f"kind={'remote_commit' if selected_is_commit else selected_kind},"
                f"score=-1,version={version_norm})"
            ), merged_candidates

        failures = list(remote_result.get("failures") or [])
        reasons = "; ".join(
            str(item.get("reason") or "").strip()
            for item in failures
            if str(item.get("reason") or "").strip()
        )
        remote_status = str(
            remote_result.get("status") or "remote_source_unavailable"
        ).strip()
        if remote_status == "remote_source_ambiguous":
            ambiguity = (
                "ambiguous_explicit_remote_commit"
                if selected_is_commit
                else "ambiguous_explicit_remote_ref"
            )
            # Ambiguity is a valid remote observation, not a transport failure.
            # A local checkout must not silently break the tie between different
            # remote commits, even when local fallback was authorized elsewhere.
            return None, f"{ambiguity}={selected_ref}", remote_candidates
        if remote_status in {
            "remote_query_failed",
            "remote_fetch_failed",
            "remote_expected_commit_unmaterializable",
            "repository_not_git",
        }:
            remote_reason = f"{remote_status}={reasons or selected_ref}"
        else:
            remote_reason = f"remote_source_unavailable={selected_ref}"
        resolved_local, local_reason = _resolve_local_fallback_after_remote_failure(
            repo_dir,
            selected_ref,
            remote_reason,
            version_norm=version_norm,
            allow_local_source=allow_local_source,
            allow_dirty_local_source=allow_dirty_local_source,
        )
        return resolved_local, local_reason, remote_candidates

    candidates, version_norm, error = list_repo_ref_candidates_for_version(
        repo_dir, version, remote_timeout=remote_timeout,
    )
    if error:
        return None, error, candidates
    best = candidates[0]
    tied_candidates = [
        item for item in candidates
        if item.get("score") == best.get("score")
        and _ref_kind_priority(item.get("kind")) == _ref_kind_priority(best.get("kind"))
    ]
    if len(tied_candidates) > 1:
        fixed_commits = {item.get("commit") for item in tied_candidates}
        if len(fixed_commits) != 1 or not next(iter(fixed_commits), ""):
            return None, f"ambiguous_ref_matches_for_version={version_norm}", candidates
    return best["ref"], f"matched_by_version(kind={best['kind']},score={best['score']},version={version_norm})", candidates


def parse_dependency_git_ref_overrides(raw_text):
    text = (raw_text or '').strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except Exception as exc:
        raise ValueError(f"dependency_git_ref_overrides_json 不是合法 JSON：{exc}") from exc
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        raise ValueError("dependency_git_ref_overrides_json 必须是对象或对象数组")
    mapping = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("dependency_git_ref_overrides_json 的每项都必须是对象")
        coord = str(item.get("coord") or "").strip()
        old_ref = str(item.get("old_ref") or item.get("base_ref") or "").strip()
        new_ref = str(item.get("new_ref") or item.get("current_ref") or "").strip()
        expected_old_commit = str(item.get("expected_old_commit") or item.get("old_commit") or "").strip()
        expected_new_commit = str(item.get("expected_new_commit") or item.get("new_commit") or "").strip()
        selection_key = str(item.get("selection_key") or "").strip()
        allow_local_source = item.get("allow_local_source") is True
        allow_dirty_local_source = item.get("allow_dirty_local_source") is True
        if not (coord and old_ref and new_ref):
            raise ValueError("dependency_git_ref_overrides_json 的每项都必须包含 coord/old_ref/new_ref")
        if allow_dirty_local_source and not allow_local_source:
            raise ValueError("allow_dirty_local_source=true 时必须同时设置 allow_local_source=true")
        mapping[coord] = {
            "old_ref": old_ref,
            "new_ref": new_ref,
            "allow_local_source": allow_local_source,
            "allow_dirty_local_source": allow_dirty_local_source,
            "expected_old_commit": expected_old_commit,
            "expected_new_commit": expected_new_commit,
            "selection_key": selection_key,
        }
    return mapping


def build_git_ref_pair_options(pending_item, limit=6):
    """Build stable, commit-deduplicated choices for one checkpoint item."""
    item = dict(pending_item or {})
    old_candidates = list(item.get("old_candidates") or [])
    new_candidates = list(item.get("new_candidates") or [])
    ranked_pairs = rank_repo_ref_pair_candidates(
        old_candidates,
        new_candidates,
        str(item.get("old_version") or ""),
        str(item.get("new_version") or ""),
    )
    options = []
    seen_identities = set()
    for pair in ranked_pairs:
        old_item = dict(pair.get("old") or {})
        new_item = dict(pair.get("new") or {})
        old_commit = str(old_item.get("commit") or "")
        new_commit = str(new_item.get("commit") or "")
        identity = (
            old_commit or str(old_item.get("ref") or ""),
            new_commit or str(new_item.get("ref") or ""),
        )
        if identity in seen_identities:
            continue
        seen_identities.add(identity)
        key_payload = {
            "coord": str(item.get("coord") or ""),
            "repo_path": str(item.get("repo_path") or ""),
            "old": identity[0],
            "new": identity[1],
        }
        selection_key = "refpair:" + hashlib.sha256(
            json.dumps(key_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
        old_aliases = sorted({
            str(candidate.get("ref") or "")
            for candidate in old_candidates
            if str(candidate.get("ref") or "")
            and old_commit
            and str(candidate.get("commit") or "") == old_commit
        })
        new_aliases = sorted({
            str(candidate.get("ref") or "")
            for candidate in new_candidates
            if str(candidate.get("ref") or "")
            and new_commit
            and str(candidate.get("commit") or "") == new_commit
        })
        options.append({
            "selection_key": selection_key,
            "rank": len(options) + 1,
            "old_ref": str(old_item.get("ref") or ""),
            "new_ref": str(new_item.get("ref") or ""),
            "old_commit": old_commit,
            "new_commit": new_commit,
            "old_aliases": old_aliases,
            "new_aliases": new_aliases,
            "same_remote": bool(pair.get("same_remote")),
            "same_prefix": bool(pair.get("same_prefix")),
            "version_delta_match": str(pair.get("delta_match_kind") or ""),
            "pair_score": int(pair.get("pair_score") or 0),
        })
        if limit not in (None, 0) and len(options) >= max(1, int(limit)):
            break
    return options


def describe_git_ref_pending_item(pending_item):
    item = dict(pending_item or {})
    pending_kind = str(item.get("pending_kind") or "").strip()
    if pending_kind == "fetch_failed":
        failed_sides = "/".join(item.get("failed_sides") or []) or "old/new"
        fallback = dict(item.get("local_fallback_available") or {})
        available_sides = [
            side for side in ("old", "new")
            if (fallback.get(side) or {}).get("available")
        ]
        suffix = (
            f" 本地存在可选兜底（{'/'.join(available_sides)}），需显式授权后才能使用。"
            if available_sides else ""
        )
        return (
            f"{failed_sides} 远端 ref 已唯一定位，但按错误类型完成自动尝试后仍无法 fetch；"
            f"无需重新选择分支。{suffix}"
        )
    if pending_kind == "remote_query_failed":
        return "远端 ref 清单查询在受控重试后仍失败，当前无法证明候选唯一；无需猜测分支。"
    if pending_kind == "remote_ref_moved":
        return "确认卡生成后远端 ref 指向了新的 commit，必须基于刷新后的候选重新确认。"
    if pending_kind == "remote_unavailable":
        fallback = dict(item.get("local_fallback_available") or {})
        available_sides = [
            side for side in ("old", "new")
            if (fallback.get(side) or {}).get("available")
        ]
        suffix = (
            f"；本地存在可选兜底（{'/'.join(available_sides)}），但尚未授权使用"
            if available_sides else ""
        )
        return f"远端来源不可用；请检查远端 ref、网络、权限或配置{suffix}。"
    if pending_kind == "not_found":
        return "远端没有找到可唯一匹配版本的 ref；请提供明确的 remote/ref。"
    reason = str(item.get("reason") or "").strip()
    old_reason = str(item.get("old_reason") or "").strip()
    new_reason = str(item.get("new_reason") or "").strip()
    old_ref = str(item.get("resolved_old_ref") or "").strip()
    new_ref = str(item.get("resolved_new_ref") or "").strip()
    if reason in {"远程旧版本源码无法固定", "远程新版本源码无法固定"}:
        return reason + "；可能是远端变化、网络或权限问题。"
    ambiguous_old = "ambiguous_ref_matches" in old_reason
    ambiguous_new = "ambiguous_ref_matches" in new_reason
    if ambiguous_old and ambiguous_new:
        return "升级前后版本都匹配到多个不同 commit。"
    if ambiguous_old:
        return "升级前版本匹配到多个不同 commit。"
    if ambiguous_new:
        return "升级后版本匹配到多个不同 commit。"
    if not old_ref and not new_ref:
        return "升级前后版本都未能唯一匹配远端 ref。"
    if not old_ref:
        return "升级前版本未能唯一匹配远端 ref；升级后版本已自动识别。"
    if not new_ref:
        return "升级后版本未能唯一匹配远端 ref；升级前版本已自动识别。"
    return reason or "远端 ref 无法固定为可复现的 commit。"


def build_git_ref_confirmation_interaction(output_dir, pending_items):
    files_to_review = []
    for name in ("git_ref_pending.json", "git_ref_matches.txt", "git_ref_matches.json", "summary.txt"):
        path = os.path.join(output_dir, name)
        if os.path.exists(path):
            files_to_review.append(os.path.abspath(path))
    decision_items = []
    for pending_item in pending_items or []:
        item = dict(pending_item or {})
        all_pair_options = build_git_ref_pair_options(item, limit=0)
        pair_options = all_pair_options[:6]
        pending_kind = str(item.get("pending_kind") or "") or classify_git_ref_pending_kind(
            item.get("reason"), item.get("old_reason"), item.get("new_reason")
        )
        selectable_pair_options = (
            pair_options if pending_kind in {"ambiguous", "remote_ref_moved", "not_found"} else []
        )
        decision_items.append({
            "coord": str(item.get("coord") or ""),
            "old_version": str(item.get("old_version") or ""),
            "new_version": str(item.get("new_version") or ""),
            "reason": describe_git_ref_pending_item(item),
            "old_reason": str(item.get("old_reason") or ""),
            "new_reason": str(item.get("new_reason") or ""),
            "pending_kind": pending_kind,
            "pair_options": selectable_pair_options,
            "pair_option_count": len(all_pair_options),
            "displayed_pair_option_count": len(selectable_pair_options),
            "pair_options_truncated": bool(selectable_pair_options) and len(all_pair_options) > len(pair_options),
            "requires_choice": pending_kind in {"ambiguous", "remote_ref_moved"} and bool(selectable_pair_options),
            "local_fallback_available": dict(item.get("local_fallback_available") or {}),
        })
    pending_kinds = {item.get("pending_kind") for item in decision_items}
    has_local_fallback = any(
        (side_info or {}).get("available")
        for item in decision_items
        for side_info in (item.get("local_fallback_available") or {}).values()
    )
    if pending_kinds == {"ambiguous"}:
        question = (
            "以下依赖的升级前、升级后源码存在多组不同提交范围，选择不同方案会改变源码差异结果。"
            "请按依赖一次性选择对应方案。"
        )
        recommended_action = "核对版本对应的源码分支和提交摘要，并一次性提交每个依赖的方案编号。"
    elif pending_kinds and pending_kinds <= {"fetch_failed", "remote_query_failed"}:
        question = (
            "以下依赖的远端查询或 fetch 在受控重试后仍失败。"
            "请在网络或权限恢复后确认重试；无需猜测或重新选择已经唯一确定的分支。"
            + (
                "如需改用卡片中展示的本地兜底，必须在对应 override 中显式设置 allow_local_source=true。"
                if has_local_fallback else ""
            )
        )
        recommended_action = (
            "确认网络/权限已恢复后一次性重试全部失败项；"
            "或对需要本地兜底的依赖显式授权。"
            if has_local_fallback
            else "确认网络/权限已恢复后一次性重试全部失败项。"
        )
    else:
        question = (
            "以下依赖仍无法固定 old/new 远端 commit。请一次性处理全部条目："
            "歧义或分支漂移项选择方案，未找到项填写明确 remote/ref，fetch 失败项只需确认重试。"
        )
        recommended_action = "按每项原因选择方案、补充明确 ref 或确认重试，并在一条回复中提交。"
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "review",
        "step_id": "step4",
        "title": "确认依赖源码版本",
        "question": question,
        "summary": (
            f"共有 {len(pending_items)} 个依赖存在会改变源码对比范围的版本歧义。"
            if pending_kinds == {"ambiguous"}
            else f"共有 {len(pending_items)} 个依赖源码版本待处理。"
        ),
        "user_reason": (
            "候选源码分支指向不同提交，选择不同方案会改变源码差异范围。"
            if pending_kinds == {"ambiguous"}
            else "依赖源码版本当前无法可靠固定。"
        ),
        "recommended_action": recommended_action,
        "reason_code": "step4_git_refs_need_confirmation",
        "files_to_review": files_to_review,
        "required_fields": ["action"],
        "options": [
            {
                "id": "rerun_current_step",
                "label": "确认源码版本后重跑",
                "description": "提供 dependency_git_ref_overrides 并重跑 Step4。",
            },
            {
                "id": "restart_from_step",
                "label": "从更早步骤重跑",
                "description": "如源码映射本身有误，可回到 step2 或 step4 重新处理。",
            },
            {
                "id": "cancel",
                "label": "取消",
                "description": "先人工复核依赖源码仓库与版本映射，再继续。",
            },
        ],
        "response_schema": {
            "type": "object",
            "required": ["action"],
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["rerun_current_step", "restart_from_step", "cancel"],
                },
                "dependency_git_ref_overrides": {
                    "type": "array",
                    "description": (
                        "按依赖显式指定远程 old_ref/new_ref，例如 origin/release-1；"
                        "远程不可用且用户明确同意本地兜底时，额外设置 allow_local_source=true。"
                    ),
                },
                "dependency_git_ref_selections": {
                    "type": "array",
                    "description": "按依赖选择下方稳定方案，例如 {coord, selection_key}；也可用 1 开始的 option 编号。",
                },
                "dependency_source_dirs": {
                    "type": "array",
                    "description": "若源码仓库映射有误，也可同时修正依赖源码目录。",
                },
                "retry_remote_fetch": {
                    "type": "boolean",
                    "description": "重试已按错误类型完成自动尝试、但仍失败的远端查询或 fetch 条目。",
                },
                "step4_fetch_timeout": {
                    "type": "integer",
                    "description": "可选。调整单次远端 Git fetch 的超时时间（秒）。",
                },
                "restart_step_id": {
                    "type": "string",
                    "enum": ["step2", "step4"],
                },
                "notes": {
                    "type": "string",
                },
            },
        },
        "input_normalization": {
            "enabled": True,
            "allowed_actions": ["rerun_current_step", "restart_from_step", "cancel"],
            "required_fields": ["action"],
        },
        "action_requirements": {
            "rerun_current_step": {
                "at_least_one_of": [
                    "dependency_git_ref_selections",
                    "dependency_git_ref_overrides",
                    "dependency_source_dirs",
                    "retry_remote_fetch",
                    "step4_fetch_timeout",
                ],
                "description": "重跑 Step4 时，至少要确认新旧源码版本、重试远端操作，或修正依赖源码目录。",
            },
            "restart_from_step": {
                "required_fields": ["restart_step_id"],
                "description": "从更早步骤重跑时，必须明确 restart_step_id。",
            },
        },
        "pending_git_ref_items": pending_items,
        "git_ref_decision_items": decision_items,
        "resume_hint": (
            "用户确认新旧源码版本（old_ref/new_ref）后，可使用 --response-json 传回 "
            "action=rerun_current_step 与 dependency_git_ref_overrides 重跑 Step4；"
            "若问题源于依赖源码目录指向错误，也可同时修正依赖源码目录后重跑。"
        ),
        "next_action_rule": "只能向用户确认新旧源码版本并等待回复，不得直接继续执行后续步骤。",
        "must_wait_for_user_reply": True,
    }


def build_timeout_resolution_interaction(output_dir, timeout_items):
    files_to_review = []
    for name in ("timeouts.json", "summary.txt", "git_ref_matches.txt", "git_ref_matches.json"):
        path = os.path.join(output_dir, name)
        if os.path.exists(path):
            files_to_review.append(os.path.abspath(path))
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "review",
        "step_id": "step4",
        "title": "step4 存在超时证据缺口",
        "question": (
            "Step4 出现了超时，当前证据池不完整。"
            "请先确认是 git diff、JApiCmp 对比还是 JApiCmp 工具自动安装超时，并在必要时放宽 Step4 超时参数后重跑；"
            "在超时问题解决前不要继续进入 Step5。"
        ),
        "summary": f"共有 {len(timeout_items)} 个超时项需要先处理。",
        "reason_code": "step4_timeouts_need_resolution",
        "files_to_review": files_to_review,
        "required_fields": ["action"],
        "options": [
            {
                "id": "rerun_current_step",
                "label": "调整超时后重跑",
                "description": "补充 Step4 超时参数后重跑当前步骤。",
            },
            {
                "id": "restart_from_step",
                "label": "从更早步骤重跑",
                "description": "如依赖源码映射或输入本身有误，可回到 step2 或 step4 重新处理。",
            },
            {
                "id": "cancel",
                "label": "取消",
                "description": "先人工复核证据缺口与超时原因，再继续。",
            },
        ],
        "response_schema": {
            "type": "object",
            "required": ["action"],
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["rerun_current_step", "restart_from_step", "cancel"],
                },
                "step4_git_diff_timeout": {
                    "type": "integer",
                    "description": "可选。放宽单个依赖执行 git diff 的超时时间（秒）。",
                },
                "step4_japicmp_timeout": {
                    "type": "integer",
                    "description": "可选。放宽单个依赖执行 JApiCmp 的超时时间（秒）。",
                },
                "step4_fetch_timeout": {
                    "type": "integer",
                    "description": "可选。放宽单次远端 Git fetch 的超时时间（秒）。",
                },
                "step4_tool_install_timeout": {
                    "type": "integer",
                    "description": "可选。放宽 JApiCmp 工具自动安装的超时时间（秒）。",
                },
                "dependency_source_dirs": {
                    "type": "array",
                    "description": "可选。若超时与源码映射范围过大有关，也可同时修正依赖源码目录。",
                },
                "restart_step_id": {
                    "type": "string",
                    "enum": ["step2", "step4"],
                },
                "notes": {
                    "type": "string",
                },
            },
        },
        "action_requirements": {
            "rerun_current_step": {
                "at_least_one_of": [
                    "step4_git_diff_timeout",
                    "step4_japicmp_timeout",
                    "step4_fetch_timeout",
                    "step4_tool_install_timeout",
                    "dependency_source_dirs"
                ],
                "description": "重跑 Step4 时，至少要调整一个超时参数，或修正依赖源码目录。",
            },
            "restart_from_step": {
                "required_fields": ["restart_step_id"],
                "description": "从更早步骤重跑时，必须明确 restart_step_id。",
            },
        },
        "input_normalization": {
            "enabled": True,
            "allowed_actions": ["rerun_current_step", "restart_from_step", "cancel"],
            "required_fields": ["action"],
        },
        "timeout_items": timeout_items,
        "resume_hint": (
            "若用户调整了 Step4 超时参数，请使用 --response-json 传回 "
            "action=rerun_current_step 与对应的 git diff/JApiCmp/Git fetch/工具安装超时参数重跑 Step4；"
            "若根因是依赖源码目录范围过大或映射错误，也可同时修正依赖源码目录后重跑。"
        ),
        "next_action_rule": "只能先处理超时导致的证据缺口并等待用户回复，不得直接继续执行后续步骤。",
        "must_wait_for_user_reply": True,
    }


def emit_interaction(interaction):
    payload = normalize_diagnostic_payload(interaction, origin_step="step4")
    if payload.get("reason_code"):
        payload.setdefault("diagnostic_guidance_schema", REASON_GUIDANCE_SCHEMA)
        payload.setdefault(
            "diagnostic_guidance",
            guidance_for_reason_code(
                payload["reason_code"], origin_step="step4"
            ),
        )
    print(f"{INTERACTION_PREFIX}{json.dumps(payload, ensure_ascii=False)}")


def _env_flag_disabled(name):
    return str(os.environ.get(name, "") or "").strip().lower() in {"0", "false", "no", "off"}


def japicmp_default_jar_path():
    return str(
        maven_repo_dir()
        / 'com' / 'github' / 'siom79' / 'japicmp' / 'japicmp' / '0.21.2'
        / 'japicmp-0.21.2-jar-with-dependencies.jar'
    )


def should_auto_install_japicmp():
    return not _env_flag_disabled("JUA_JAPICMP_AUTO_INSTALL")


def auto_install_japicmp(japicmp_jar, timeout=DEFAULT_FETCH_TIMEOUT):
    """Try to install JApiCmp once into the current Maven local repository."""
    target = str(japicmp_jar or "").strip() or japicmp_default_jar_path()
    if os.path.exists(target):
        return True, target, ""
    if not should_auto_install_japicmp():
        return False, target, "auto_install_disabled"
    cmd = mvn_cmd() + [
        "dependency:get",
        f"-Dartifact={DEFAULT_JAPICMP_COORD}",
        "-q",
    ]
    print(
        "⚙️  JApiCmp 未安装，正在尝试自动安装："
        + " ".join(cmd),
        file=sys.stderr,
    )
    _stdout, stderr, rc = run_cmd(cmd, timeout=timeout)
    if rc == 0 and os.path.exists(target):
        print(f"✅ JApiCmp 自动安装成功：{target}", file=sys.stderr)
        return True, target, ""
    reason = (stderr or f"mvn dependency:get failed rc={rc}").strip()
    if rc == -1 and "超时" in reason:
        timeout_label = f"{timeout}s" if timeout not in (None, "") else "unbounded"
        reason = f"timeout({timeout_label})"
    return False, target, reason[:500]


def dependency_needs_japicmp(row):
    change = str((row or {}).get("change_type") or "").strip()
    old_ver = str((row or {}).get("old_version") or "").strip()
    new_ver = str((row or {}).get("new_version") or "").strip()
    if not (row or {}).get("coord"):
        return False
    if change == "未变":
        return False
    is_removed_dependency = (change == '移除') or (new_ver == '-' and old_ver != '-')
    is_added_dependency = (change == '新增') or (old_ver == '-' and new_ver != '-')
    return (not is_removed_dependency) and (not is_added_dependency) and old_ver not in ("", "-") and new_ver not in ("", "-")


def write_japicmp_preflight_details(output_dir, japicmp_jar, install_error, planned_dependencies):
    preflight_path = os.path.join(output_dir, "japicmp_preflight.json")
    payload = normalize_diagnostic_payload({
        "status": "blocked_by_system",
        "reason_code": "step4_japicmp_missing_need_resolution",
        "generated_at": datetime.now().isoformat(),
        "japicmp_jar": str(japicmp_jar or ""),
        "install_error": str(install_error or ""),
        "planned_dependencies": planned_dependencies,
        "impact": [
            "依赖 API 对比工具（JApiCmp）不可用，Step4 无法形成 API 变化数据。",
            "当前无法判断删除、签名变化、字段变化和重新编译不兼容等 API 变化。",
            "修复或提供 API 对比工具后重跑；在此之前不能按“没有 API 变化”处理。",
        ],
        "manual_install": [
            f"mvn dependency:get -Dartifact={DEFAULT_JAPICMP_COORD}",
            "或提供 japicmp_jar 的绝对路径。",
        ],
    }, origin_step="step4")
    Path(preflight_path).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return preflight_path

def _jar_class_hash_map(jar_path: str) -> dict:
    m = {}
    require_safe_dependency_jar(jar_path)
    with zipfile.ZipFile(jar_path) as zf:
        for entry in zf.namelist():
            if not entry.endswith(".class"):
                continue
            if entry.startswith("META-INF/") and not entry.startswith("META-INF/versions/"):
                continue
            if entry.endswith("module-info.class"):
                continue
            data = zf.read(entry)
            digest = hashlib.sha1(data).hexdigest()
            class_fqn = entry[:-6].replace("/", ".")
            if class_fqn:
                m[class_fqn] = digest
    return m


def compute_changed_classes(old_jar: str, new_jar: str) -> dict:
    old_map = _jar_class_hash_map(old_jar)
    new_map = _jar_class_hash_map(new_jar)
    old_classes = set(old_map.keys())
    new_classes = set(new_map.keys())

    added = sorted(new_classes - old_classes)
    removed = sorted(old_classes - new_classes)
    modified = sorted(c for c in (old_classes & new_classes) if old_map.get(c) != new_map.get(c))

    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "counts": {
            "old_total": len(old_classes),
            "new_total": len(new_classes),
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
        },
    }


def _jar_class_variant_hash_map(jar_path):
    """Return one aggregate hash per logical class, including MR-JAR variants."""
    variants = defaultdict(list)
    multi_release_enabled = False
    require_safe_dependency_jar(jar_path)
    with zipfile.ZipFile(jar_path) as archive:
        try:
            manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
        except KeyError:
            manifest = ""
        multi_release_enabled = bool(
            re.search(r"(?im)^Multi-Release\s*:\s*true\s*$", manifest)
        )
        for entry in sorted(archive.namelist()):
            if not entry.endswith(".class"):
                continue
            versioned = re.match(r"^META-INF/versions/(\d+)/(.*\.class)$", entry)
            if entry.startswith("META-INF/") and not versioned:
                continue
            logical_entry = versioned.group(2) if versioned else entry
            if logical_entry.endswith(("module-info.class", "package-info.class")):
                continue
            class_name = logical_entry[:-6].replace("/", ".")
            variants[class_name].append(
                (entry, hashlib.sha256(archive.read(entry)).hexdigest())
            )
    result = {
        class_name: hashlib.sha256(
            json.dumps(entries, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        for class_name, entries in variants.items()
    }
    return result, multi_release_enabled


def _run_javap_behavior_dumps(
    jar_path,
    class_binary_names,
    batch_size=32,
    multi_release_version=None,
):
    names = [str(item) for item in class_binary_names]
    dumps = {}
    errors = []
    invocations = 0
    size = max(1, int(batch_size))

    def command_for(batch):
        command = ["javap"]
        if multi_release_version is not None:
            command.extend(["--multi-release", str(multi_release_version)])
        command.extend(["-classpath", str(jar_path), "-c", "-s", "-p", *batch])
        return command

    for offset in range(0, len(names), size):
        batch = names[offset:offset + size]
        if not batch:
            continue
        invocations += 1
        stdout, stderr, rc = run_cmd(
            command_for(batch),
            timeout=max(60, min(300, len(batch) * 8)),
        )
        if rc != 0:
            # A single unreadable class makes javap return a non-zero status for
            # the whole batch. Retry only this failed batch one class at a time
            # so healthy classes still produce evidence.
            for class_binary_name in batch:
                invocations += 1
                item_stdout, item_stderr, item_rc = run_cmd(
                    command_for([class_binary_name]),
                    timeout=60,
                )
                if item_rc != 0:
                    errors.append(
                        f"{class_binary_name}:"
                        f"{(item_stderr or item_stdout or 'javap failed').strip()[:300]}"
                    )
                    continue
                sections = _split_javap_public_api_dump(
                    item_stdout,
                    [class_binary_name],
                )
                section = sections.get(class_binary_name)
                if section is None:
                    errors.append(f"{class_binary_name}:javap_class_section_missing")
                else:
                    dumps[class_binary_name] = section
            continue
        sections = _split_javap_public_api_dump(stdout, batch)
        for class_binary_name in batch:
            section = sections.get(class_binary_name)
            if section is None:
                errors.append(f"{class_binary_name}:javap_class_section_missing")
            else:
                dumps[class_binary_name] = section
    return dumps, errors, invocations


def _normalize_javap_behavior_line(line):
    text = " ".join(str(line or "").strip().split())
    if not text:
        return ""
    # Constant-pool positions are packaging details. javap's symbolic comment
    # remains, so replacing the numeric slot removes harmless pool reordering
    # without hiding the referenced owner/member/value.
    return re.sub(r"#\d+", "#", text)


def _parse_javap_method_bodies(text, class_binary_name):
    """Parse executable method fingerprints from `javap -c -s -p` output."""
    class_fqcn = str(class_binary_name or "").replace("$", ".")
    class_simple = class_fqcn.rsplit(".", 1)[-1]
    methods = {}
    current = None
    collecting_code = False

    def finalize():
        nonlocal current, collecting_code
        if current and current.get("descriptor") and current.get("code_lines"):
            body = "\n".join(current["code_lines"])
            identity = (
                current["api_name"],
                current["symbol_kind"],
                current["descriptor"],
            )
            methods[identity] = {
                **current,
                "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            }
        current = None
        collecting_code = False

    for raw_line in str(text or "").splitlines():
        stripped = raw_line.strip()
        is_static_initializer = stripped == "static {};"
        is_method_declaration = is_static_initializer or (
            stripped.endswith(";")
            and "(" in stripped
            and ")" in stripped
            and not stripped.startswith(("descriptor:", "Signature:"))
        )
        if is_method_declaration:
            finalize()
            declaration = stripped[:-1].split(" throws ", 1)[0].strip()
            if is_static_initializer:
                api_simple = class_simple
                api_name = class_fqcn
                symbol_kind = "class"
                api_signature = ""
            else:
                name_token = declaration.split("(", 1)[0].strip().split()[-1]
                displayed_simple = name_token.rsplit(".", 1)[-1].replace("$", ".").rsplit(".", 1)[-1]
                is_constructor = displayed_simple == class_simple
                api_simple = class_simple if is_constructor else displayed_simple
                api_name = f"{class_fqcn}.{api_simple}"
                symbol_kind = "constructor" if is_constructor else "method"
                api_signature = extract_api_signature_from_declaration(declaration)
            current = {
                "api_name": api_name,
                "api_simple": api_simple,
                "symbol_kind": symbol_kind,
                "api_signature": api_signature,
                "descriptor": "",
                "declaration": declaration,
                "code_lines": [],
            }
            continue
        if current is None:
            continue
        if stripped.startswith("descriptor:"):
            current["descriptor"] = stripped.split(":", 1)[1].strip()
            continue
        if stripped == "Code:":
            collecting_code = True
            continue
        if not collecting_code:
            continue
        if re.match(r"^\d+:\s", stripped):
            normalized = _normalize_javap_behavior_line(stripped)
            if normalized:
                current["code_lines"].append(normalized)
            continue
        if stripped == "Exception table:":
            current["code_lines"].append("Exception table:")
            continue
        if current["code_lines"] and current["code_lines"][-1] == "Exception table:":
            # The header itself is followed by column labels; keep only rows.
            if stripped.startswith("from"):
                continue
        if re.match(r"^(?:default|-?\d+):\s+-?\d+", stripped):
            current["code_lines"].append(_normalize_javap_behavior_line(stripped))
            continue
        if re.match(r"^\d+\s+\d+\s+\d+\s+", stripped):
            current["code_lines"].append(_normalize_javap_behavior_line(stripped))
            continue
    finalize()
    return methods


def compare_jar_method_bodies(
    old_jar,
    new_jar,
    *,
    coord,
    old_version,
    new_version,
    output_dir,
    target_jdk=None,
):
    """Find same-signature executable changes using immutable final JARs."""
    safe_coord = str(coord or "").strip()
    artifact = _artifact_output_stem(safe_coord).replace(".", "-")
    evidence_stem = bounded_path_component(
        f"{artifact}_{old_version}_vs_{new_version}",
        max_length=72,
        default="dependency-comparison",
    )
    evidence_path = Path(output_dir) / f"{evidence_stem}_bytecode_behavior.json"
    try:
        old_hashes, old_multi_release = _jar_class_variant_hash_map(old_jar)
        new_hashes, new_multi_release = _jar_class_variant_hash_map(new_jar)
    except (OSError, zipfile.BadZipFile, ValueError) as exc:
        result = {
            "status": "insufficient",
            "reason_code": "FINAL_JAR_BEHAVIOR_DIFF_UNAVAILABLE",
            "errors": [f"{type(exc).__name__}:{str(exc)[:200]}"],
            "rows": [],
        }
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {**result, "evidence_path": str(evidence_path.resolve())}

    modified_classes = sorted(
        class_name
        for class_name in (set(old_hashes) & set(new_hashes))
        if old_hashes[class_name] != new_hashes[class_name]
    )
    target_jdk_major = _java_major_version(target_jdk)
    old_dumps, old_errors, old_invocations = _run_javap_behavior_dumps(
        old_jar,
        modified_classes,
        multi_release_version=target_jdk_major if old_multi_release else None,
    )
    new_dumps, new_errors, new_invocations = _run_javap_behavior_dumps(
        new_jar,
        modified_classes,
        multi_release_version=target_jdk_major if new_multi_release else None,
    )
    errors = [f"old:{item}" for item in old_errors] + [f"new:{item}" for item in new_errors]
    if (old_multi_release or new_multi_release) and target_jdk_major is None:
        errors.append("target_jdk_required_for_multi_release_jar")
    rows = []
    changed_methods = []
    scanned_classes = []
    for class_name in modified_classes:
        if class_name not in old_dumps or class_name not in new_dumps:
            continue
        scanned_classes.append(class_name)
        old_methods = _parse_javap_method_bodies(old_dumps[class_name], class_name)
        new_methods = _parse_javap_method_bodies(new_dumps[class_name], class_name)
        for identity in sorted(set(old_methods) & set(new_methods)):
            old_method = old_methods[identity]
            new_method = new_methods[identity]
            if old_method["body_sha256"] == new_method["body_sha256"]:
                continue
            api_name, symbol_kind, descriptor = identity
            changed_methods.append({
                "api_name": api_name,
                "symbol_kind": symbol_kind,
                "descriptor": descriptor,
                "old_body_sha256": old_method["body_sha256"],
                "new_body_sha256": new_method["body_sha256"],
            })
            row = {
                "coord": safe_coord,
                "old_version": str(old_version or ""),
                "new_version": str(new_version or ""),
                "change_type": "BEHAVIOR_CHANGED",
                "api_name": api_name,
                "api_simple": new_method["api_simple"],
                "symbol_kind": symbol_kind,
                "api_signature": new_method.get("api_signature") or "",
                "confirmed": "true",
                "severity": DEFAULT_SEVERITY["BEHAVIOR_CHANGED"],
                "source": "jar_bytecode",
                "binary_compatible": "true",
                "source_compatible": "true",
                "reason_code": "FINAL_JAR_METHOD_BODY_CHANGED",
                "evidence_path": str(evidence_path.resolve()),
            }
            if not validate_row(row):
                rows.append(row)

    status = "complete" if not errors and len(scanned_classes) == len(modified_classes) else "insufficient"
    payload = {
        "schema": "java-upgrade-analyzer.jar-bytecode-behavior.v1",
        "status": status,
        "reason_code": "" if status == "complete" else "FINAL_JAR_BEHAVIOR_DIFF_UNAVAILABLE",
        "coord": safe_coord,
        "old_version": str(old_version or ""),
        "new_version": str(new_version or ""),
        "old_jar_sha256": sha256_file(old_jar),
        "new_jar_sha256": sha256_file(new_jar),
        "target_jdk": target_jdk_major,
        "multi_release": bool(old_multi_release or new_multi_release),
        "modified_classes": len(modified_classes),
        "scanned_classes": len(scanned_classes),
        "changed_methods": changed_methods,
        "javap_invocations": old_invocations + new_invocations,
        "errors": errors,
        "rows": rows,
    }
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {**payload, "evidence_path": str(evidence_path.resolve())}


def _java_major_version(value):
    text = str(value or "").strip()
    if not text:
        return None
    legacy = re.search(r"(?:^|[^0-9])1\.(\d+)(?:[^0-9]|$)", text)
    if legacy:
        return int(legacy.group(1))
    match = re.search(r"(?:^|[^0-9])(\d+)(?:[^0-9]|$)", text)
    return int(match.group(1)) if match else None


def collect_data_contract_changes(
    old_jar,
    new_jar,
    *,
    coord,
    old_version,
    new_version,
    jdk_current=None,
):
    """Build Step4 rows for instance-field contract changes from final JARs."""
    return compare_jar_data_contracts(
        old_jar,
        new_jar,
        coord=coord,
        old_version=old_version,
        new_version=new_version,
        target_java_version=_java_major_version(jdk_current),
    )


def _iter_jar_class_entries(jar_path):
    require_safe_dependency_jar(jar_path)
    with zipfile.ZipFile(jar_path) as zf:
        for entry in sorted(zf.namelist()):
            if not entry.endswith('.class') or entry.startswith('META-INF/'):
                continue
            if entry.endswith('module-info.class') or entry.endswith('package-info.class'):
                continue
            yield entry[:-6].replace('/', '.')


def _jar_binary_class_set(jar_path):
    try:
        return set(_iter_jar_class_entries(str(jar_path or '')))
    except (OSError, zipfile.BadZipFile):
        return set()


def _coord_group(coord):
    return str(coord or '').split(':', 1)[0].strip()


def _write_runtime_provider_set_jar(paths):
    normalized = tuple(dict.fromkeys(
        str(Path(path).resolve()) for path in paths if path
    ))
    digest = hashlib.sha256('\n'.join(normalized).encode('utf-8')).hexdigest()[:16]
    output = Path(normalized[0]).parent / f'.jua-runtime-provider-set-{digest}.jar'
    seen = set()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as target:
        for path in normalized:
            require_safe_dependency_jar(path)
            with zipfile.ZipFile(path) as source:
                for name in sorted(source.namelist()):
                    if not name.endswith('.class') or name.startswith('META-INF/') or name in seen:
                        continue
                    seen.add(name)
                    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    entry.create_system = 3
                    entry.external_attr = 0o100644 << 16
                    target.writestr(entry, source.read(name))
    return str(output)


def pair_artifact_replacement_rows(rows):
    """Build logical runtime providers from class-continuity evidence."""
    prepared = [dict(row or {}) for row in (rows or [])]
    removed = []
    added = []
    upgraded = []
    class_sets = {}
    for index, row in enumerate(prepared):
        old_version = str(row.get('old_version') or '-').strip() or '-'
        new_version = str(row.get('new_version') or '-').strip() or '-'
        change_type = str(row.get('change_type') or '').strip()
        if row.get('_step4_base_jar_path'):
            class_sets[(index, 'base')] = _jar_binary_class_set(row.get('_step4_base_jar_path'))
        if row.get('_step4_current_jar_path'):
            class_sets[(index, 'current')] = _jar_binary_class_set(row.get('_step4_current_jar_path'))
        if (change_type == '移除' or (new_version == '-' and old_version != '-')) and row.get('_step4_base_jar_path'):
            removed.append(index)
        elif (change_type == '新增' or (old_version == '-' and new_version != '-')) and row.get('_step4_current_jar_path'):
            added.append(index)
        elif row.get('_step4_base_jar_path') and row.get('_step4_current_jar_path'):
            upgraded.append(index)

    provider_replacements = {}
    provider_consumed_added = set()
    provider_evidence = []
    candidate_owners = defaultdict(list)
    for added_index in added:
        added_classes = class_sets.get((added_index, 'current')) or set()
        added_group = _coord_group(
            prepared[added_index].get('current_coord') or prepared[added_index].get('coord')
        )
        for upgraded_index in upgraded:
            old_classes = class_sets.get((upgraded_index, 'base')) or set()
            upgraded_group = _coord_group(
                prepared[upgraded_index].get('base_coord') or prepared[upgraded_index].get('coord')
            )
            if added_group and added_group == upgraded_group and len(old_classes & added_classes) >= 2:
                candidate_owners[added_index].append(upgraded_index)
    companions = defaultdict(list)
    for added_index, owners in candidate_owners.items():
        if len(owners) == 1:
            companions[owners[0]].append(added_index)
    for upgraded_index, companion_indexes in companions.items():
        row = dict(prepared[upgraded_index])
        provider_indexes = [upgraded_index, *companion_indexes]
        provider_paths = [
            prepared[index].get('_step4_current_jar_path') for index in provider_indexes
        ]
        old_classes = class_sets.get((upgraded_index, 'base')) or set()
        new_classes = set().union(*(
            class_sets.get((index, 'current')) or set() for index in provider_indexes
        ))
        row['_step4_current_jar_path'] = _write_runtime_provider_set_jar(provider_paths)
        row['pairing_status'] = 'artifact_provider_set_replacement'
        row['pairing_reason_code'] = ''
        provider_replacements[upgraded_index] = row
        provider_consumed_added.update(companion_indexes)
        provider_evidence.append({
            'base_coord': str(row.get('base_coord') or row.get('coord') or '').strip(),
            'current_coord': str(row.get('current_coord') or row.get('coord') or '').strip(),
            'old_version': str(row.get('old_version') or '-').strip() or '-',
            'new_version': str(row.get('new_version') or '-').strip() or '-',
            'old_classes': len(old_classes),
            'new_classes': len(new_classes),
            'shared_classes': len(old_classes & new_classes),
            'old_class_coverage': round(len(old_classes & new_classes) / len(old_classes), 6) if old_classes else 0.0,
            'new_class_coverage': round(len(old_classes & new_classes) / len(new_classes), 6) if new_classes else 0.0,
            'current_provider_count': len(provider_indexes),
            'current_provider_coords': [
                str(prepared[index].get('current_coord') or prepared[index].get('coord') or '').strip()
                for index in provider_indexes
            ],
            'evidence_type': 'final_artifact_binary_provider_set',
        })

    candidates = {}
    reverse_candidates = defaultdict(list)
    for old_index in removed:
        old_classes = class_sets.get((old_index, 'base')) or set()
        if len(old_classes) < 2:
            continue
        matches = []
        for new_index in added:
            if new_index in provider_consumed_added:
                continue
            old_group = _coord_group(
                prepared[old_index].get('base_coord') or prepared[old_index].get('coord')
            )
            new_group = _coord_group(
                prepared[new_index].get('current_coord') or prepared[new_index].get('coord')
            )
            if not old_group or old_group != new_group:
                continue
            new_classes = class_sets.get((new_index, 'current')) or set()
            if old_classes and old_classes.issubset(new_classes):
                matches.append(new_index)
                reverse_candidates[new_index].append(old_index)
        candidates[old_index] = matches

    replacements = {}
    evidence = list(provider_evidence)
    for old_index, matches in candidates.items():
        if len(matches) != 1:
            continue
        new_index = matches[0]
        if len(reverse_candidates.get(new_index) or []) != 1:
            continue
        old_row = prepared[old_index]
        new_row = prepared[new_index]
        old_classes = class_sets[(old_index, 'base')]
        new_classes = class_sets[(new_index, 'current')]
        base_coord = str(old_row.get('base_coord') or old_row.get('coord') or '').strip()
        current_coord = str(new_row.get('current_coord') or new_row.get('coord') or '').strip()
        merged = dict(new_row)
        merged.update({
            'coord': current_coord or base_coord,
            'base_coord': base_coord,
            'current_coord': current_coord,
            'old_version': str(old_row.get('old_version') or '-').strip() or '-',
            'new_version': str(new_row.get('new_version') or '-').strip() or '-',
            'change_type': '坐标替代升级',
            'base_lib_entry': str(old_row.get('base_lib_entry') or '').strip(),
            'pairing_status': 'artifact_class_set_replacement',
            'pairing_reason_code': '',
            '_step4_base_jar_path': old_row.get('_step4_base_jar_path') or '',
            '_step4_base_jar_evidence': old_row.get('_step4_base_jar_evidence') or {},
        })
        replacements[old_index] = (new_index, merged)
        evidence.append({
            'base_coord': base_coord,
            'current_coord': current_coord,
            'old_version': merged['old_version'],
            'new_version': merged['new_version'],
            'old_classes': len(old_classes),
            'new_classes': len(new_classes),
            'shared_classes': len(old_classes & new_classes),
            'old_class_coverage': round(len(old_classes & new_classes) / len(old_classes), 6),
            'new_class_coverage': round(len(old_classes & new_classes) / len(new_classes), 6),
            'base_lib_entry': merged.get('base_lib_entry') or '',
            'current_lib_entry': merged.get('current_lib_entry') or '',
            'evidence_type': 'final_artifact_binary_class_containment',
        })

    consumed_added = {new_index for new_index, _merged in replacements.values()}
    result = []
    for index, row in enumerate(prepared):
        if index in provider_replacements:
            result.append(provider_replacements[index])
        elif index in provider_consumed_added:
            continue
        elif index in replacements:
            result.append(replacements[index][1])
        elif index not in consumed_added:
            result.append(row)
    return result, evidence


def _run_javap_public_api_dump(jar_path, class_binary_name):
    stdout, stderr, rc = run_cmd(
        ['javap', '-classpath', jar_path, '-public', '-s', class_binary_name],
        timeout=60,
    )
    if rc != 0:
        raise RuntimeError((stderr or stdout or 'javap failed').strip()[:300] or 'javap failed')
    return stdout


def _split_javap_public_api_dump(text, class_binary_names):
    sections = {}
    starts = []
    output = str(text or '')
    for class_binary_name in class_binary_names:
        names = {
            str(class_binary_name), str(class_binary_name).replace('$', '.'),
        }
        matches = []
        for name in names:
            pattern = re.compile(
                rf'(?m)^[^\n]*\b(?:class|interface|enum|record)\s+'
                rf'{re.escape(name)}(?:[\s<{{]|$)[^\n]*$'
            )
            matches.extend(pattern.finditer(output))
        unique_starts = {match.start() for match in matches}
        if len(unique_starts) != 1:
            continue
        starts.append((next(iter(unique_starts)), str(class_binary_name)))
    starts.sort()
    for index, (start, class_binary_name) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(output)
        sections[class_binary_name] = output[start:end]
    return sections


def _run_javap_public_api_dumps(jar_path, class_binary_names, batch_size=64):
    names = [str(item) for item in class_binary_names]
    dumps = {}
    errors = []
    invocations = 0
    size = max(1, int(batch_size))
    for offset in range(0, len(names), size):
        batch = names[offset:offset + size]
        invocations += 1
        if len(batch) == 1:
            try:
                dumps[batch[0]] = _run_javap_public_api_dump(jar_path, batch[0])
            except Exception as exc:
                errors.append(f'{batch[0]}:{str(exc)[:120]}')
            continue
        stdout, stderr, rc = run_cmd(
            ['javap', '-classpath', jar_path, '-public', '-s', *batch],
            timeout=max(60, min(300, len(batch) * 5)),
        )
        if rc != 0:
            errors.append(
                f'batch[{batch[0]}..{batch[-1]}]:'
                f'{(stderr or stdout or "javap failed").strip()[:300]}'
            )
            continue
        sections = _split_javap_public_api_dump(stdout, batch)
        for class_binary_name in batch:
            if class_binary_name not in sections:
                errors.append(f'{class_binary_name}:javap_class_section_missing')
                continue
            dumps[class_binary_name] = sections[class_binary_name]
    return dumps, errors, invocations


def _build_removed_api_row(coord, old_ver, api_name, api_simple, symbol_kind, api_signature=''):
    return {
        'coord': coord,
        'old_version': old_ver,
        'new_version': '-',
        'change_type': 'REMOVED',
        'api_name': api_name,
        'api_simple': api_simple,
        'symbol_kind': symbol_kind,
        'api_signature': api_signature or '',
        'confirmed': 'true',
        'severity': DEFAULT_SEVERITY['REMOVED'],
        'source': 'old_jar',
    }


def _parse_removed_jar_javap_output(text, coord, old_ver, class_binary_name):
    class_fqcn = class_binary_name.replace('$', '.')
    class_simple = class_fqcn.rsplit('.', 1)[-1]
    lines = [line.strip() for line in str(text or '').splitlines() if line.strip()]
    header_line = ''
    for line in lines:
        if class_binary_name in line or class_fqcn in line:
            header_line = line
            break
    if header_line and not re.search(r'\b(public|protected)\b', header_line):
        return []

    rows = [
        _build_removed_api_row(
            coord=coord,
            old_ver=old_ver,
            api_name=class_fqcn,
            api_simple=class_simple,
            symbol_kind='class',
            api_signature='',
        )
    ]
    seen = {(class_fqcn, 'class', '')}
    for line in lines:
        if not line.endswith(';'):
            continue
        declaration = line[:-1].split(' throws ', 1)[0].strip()
        if '(' not in declaration or ')' not in declaration:
            continue
        if not declaration.startswith(('public ', 'protected ')):
            continue
        signature_start = declaration.index('(')
        signature_end = declaration.rindex(')')
        params = declaration[signature_start + 1:signature_end].strip()
        name = declaration[:signature_start].strip().split()[-1]
        is_constructor = name in {class_simple, class_fqcn, class_binary_name}
        api_name = f"{class_fqcn}.{class_simple if is_constructor else name}"
        api_simple = class_simple if is_constructor else name
        api_signature = f"({params})" if params else "()"
        symbol_kind = 'constructor' if is_constructor else 'method'
        dedupe_key = (api_name, symbol_kind, api_signature)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        rows.append(
            _build_removed_api_row(
                coord=coord,
                old_ver=old_ver,
                api_name=api_name,
                api_simple=api_simple,
                symbol_kind=symbol_kind,
                api_signature=api_signature,
            )
        )
    return rows


def _api_owner_class(api_name):
    text = str(api_name or '').strip()
    if '.' not in text:
        return ''
    return text.rsplit('.', 1)[0]


def _jar_public_api_index(jar_path, coord='', version='', target_classes=None):
    """Return public/protected API membership from a jar.

    Step4 treats the dependency jar as the primary truth. Source git diff is
    only auxiliary, so source-derived API rows must be checked against the
    compiled artifact before they are allowed into Step5 input.
    """
    jar_path = str(jar_path or '').strip()
    index = {
        'classes': set(),
        'members': set(),
        'errors': [],
    }
    if not jar_path or not os.path.exists(jar_path):
        index['errors'].append('jar_missing')
        return index
    wanted_classes = {
        str(item or '').replace('$', '.').strip()
        for item in (target_classes or [])
        if str(item or '').strip()
    }
    try:
        class_entries = list(_iter_jar_class_entries(jar_path))
    except Exception as exc:
        index['errors'].append(f'jar_read_failed:{str(exc)[:120]}')
        return index

    selected_class_entries = []
    for class_binary_name in class_entries:
        class_fqcn = class_binary_name.replace('$', '.')
        if wanted_classes and class_fqcn not in wanted_classes:
            continue
        index['classes'].add(class_fqcn)
        selected_class_entries.append(class_binary_name)
    javap_dumps, javap_errors, _invocations = _run_javap_public_api_dumps(
        jar_path, selected_class_entries
    )
    index['errors'].extend(javap_errors)
    for class_binary_name in selected_class_entries:
        try:
            javap_text = javap_dumps[class_binary_name]
            rows = _parse_removed_jar_javap_output(
                javap_text,
                coord or 'unknown:unknown',
                version or '',
                class_binary_name,
            )
        except Exception as exc:
            index['errors'].append(f'{class_fqcn}:{str(exc)[:120]}')
            continue
        for row in rows:
            if row.get('symbol_kind') in {'method', 'constructor'}:
                signature = str(row.get('api_signature') or '').strip()
                normalized = normalize_signature_for_lookup(signature) or signature
                index['members'].add((
                    str(row.get('api_name') or '').strip(),
                    str(row.get('symbol_kind') or '').strip(),
                    normalized,
                ))
            elif row.get('symbol_kind') == 'class':
                index['classes'].add(str(row.get('api_name') or '').strip())
    return index


def _jar_index_has_api(index, row):
    row = row or {}
    symbol_kind = str(row.get('symbol_kind') or '').strip()
    api_name = str(row.get('api_name') or '').strip()
    if not api_name:
        return False
    if symbol_kind == 'class':
        return api_name in (index or {}).get('classes', set())
    if symbol_kind in {'method', 'constructor'}:
        signature = str(row.get('api_signature') or '').strip()
        normalized = normalize_signature_for_lookup(signature) or signature
        return (api_name, symbol_kind, normalized) in (index or {}).get('members', set())
    if symbol_kind == 'field':
        # Source git diff does not currently produce field rows. If it does in
        # the future, require an explicit field index instead of assuming true.
        return False
    return False


def filter_gitdiff_rows_with_jar_truth(gitdiff_rows, old_jar='', new_jar='', coord='', old_ver='', new_ver=''):
    """Promote only jar-confirmed source rows to Step5 input.

    Structural API changes from source diff are intentionally *not* promoted:
    JApiCmp/removed-jar export is the primary source for binary API changes.
    Source diff remains useful for BEHAVIOR_CHANGED, but only when the changed
    member exists in both compiled jars.
    """
    rows = list(gitdiff_rows or [])
    if not rows:
        return [], []

    target_classes = sorted({
        _api_owner_class(row.get('api_name'))
        for row in rows
        if _api_owner_class(row.get('api_name'))
    })
    old_index = _jar_public_api_index(old_jar, coord, old_ver, target_classes=target_classes)
    new_index = _jar_public_api_index(new_jar, coord, new_ver, target_classes=target_classes)
    old_errors = old_index.get('errors') or []
    new_errors = new_index.get('errors') or []
    accepted = []
    rejected = []

    for row in rows:
        item = dict(row)
        change_type = str(item.get('change_type') or '').strip()
        if change_type != 'BEHAVIOR_CHANGED':
            item['filter_reason'] = 'source_structural_change_not_promoted_japicmp_is_primary'
            rejected.append(item)
            continue
        old_has = _jar_index_has_api(old_index, item)
        new_has = _jar_index_has_api(new_index, item)
        if old_has and new_has:
            item['confirmed'] = 'true'
            item['source'] = 'gitdiff'
            accepted.append(item)
        else:
            reasons = []
            if not old_has:
                reasons.append('old_jar_member_missing')
            if not new_has:
                reasons.append('new_jar_member_missing')
            if old_errors:
                reasons.append('old_jar_index_errors')
            if new_errors:
                reasons.append('new_jar_index_errors')
            item['filter_reason'] = '|'.join(reasons) or 'jar_member_not_confirmed'
            rejected.append(item)
    return accepted, rejected


def write_gitdiff_auxiliary_rows(output_dir, coord, rows):
    rows = _enrich_changed_api_rows(rows or [])
    if not rows:
        return ''
    artifact = _artifact_output_stem(coord).replace('.', '-')
    path = os.path.join(output_dir, f"{artifact}_gitdiff_auxiliary_only.csv")
    fields = list(ALL_CHANGED_APIS_FIELDS)
    for extra in ('filter_reason', 'jar_truth'):
        if extra not in fields:
            fields.append(extra)
    with open_csv_write(path) as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    return path


def export_removed_jar_apis(
    coord,
    old_ver,
    output_dir,
    old_coord=None,
    fetch_timeout=DEFAULT_FETCH_TIMEOUT,
    old_jar_path=None,
    old_jar_evidence=None,
):
    resolved_old_coord = str(old_coord or coord or '').strip()
    group_id, artifact_id, classifier = _split_coord(resolved_old_coord)
    safe_name = (artifact_id or 'unknown').replace('.', '-') + (f"_{classifier}" if classifier else "")
    out_file = os.path.join(output_dir, f"{safe_name}_{old_ver}_removed_symbols.txt")
    if not group_id or not artifact_id or not old_ver or old_ver == '-':
        msg = f"=== 无法导出 removed jar 符号：非法坐标或版本 ===\ncoord={resolved_old_coord}\nold_version={old_ver}\n"
        write_result(out_file, msg)
        return out_file, [], {"old_jar": None}, "非法坐标"

    old_jar = str(old_jar_path or "").strip() or None
    old_jar_source = (old_jar_evidence or {}).get("source") if old_jar else ""
    if old_jar and not os.path.exists(old_jar):
        old_jar = None
        old_jar_source = ""
    if not old_jar:
        msg = (
            f"=== 无法导出 removed jar 符号：base 最终制品证据缺失 ===\n"
            f"coord={resolved_old_coord}\nold_version={old_ver}\n"
            "Step4 只允许分析 Step1 留存的 base 最终制品内 JAR，"
            "不会读取本地 Maven 仓库或下载替代 JAR。\n"
        )
        write_result(out_file, msg)
        return out_file, [], {
            "old_jar": None,
            "old_jar_source": "",
            "old_jar_evidence": old_jar_evidence or {},
            "reason_code": "BASE_FINAL_ARTIFACT_JAR_EVIDENCE_MISSING",
        }, "base 最终制品内未找到待分析依赖 JAR"

    apis = []
    errors = []
    class_count = 0
    class_entries = list(_iter_jar_class_entries(old_jar))
    class_count = len(class_entries)
    javap_dumps, javap_errors, javap_invocations = _run_javap_public_api_dumps(
        old_jar, class_entries
    )
    errors.extend(javap_errors[:20])
    for class_binary_name in class_entries:
        try:
            javap_text = javap_dumps[class_binary_name]
            apis.extend(_parse_removed_jar_javap_output(javap_text, coord, old_ver, class_binary_name))
        except Exception as exc:
            if len(errors) < 20:
                errors.append(f"{class_binary_name}: {str(exc)[:200]}")
    lines = [
        f"coord={resolved_old_coord}",
        f"old_version={old_ver}",
        f"old_jar={old_jar}",
        f"old_jar_source={old_jar_source or 'unknown'}",
        f"class_count={class_count}",
        f"exported_api_count={len(apis)}",
        f"api_surface_empty={str(not apis and not errors).lower()}",
    ]
    if errors:
        lines.append("errors:")
        lines.extend(f"  - {item}" for item in errors)
    write_result(out_file, "\n".join(lines) + "\n")
    return out_file, apis, {
        "old_jar": old_jar,
        "old_jar_source": old_jar_source,
        "javap_invocations": javap_invocations,
        "class_count": class_count,
        "exported_api_count": len(apis),
        "api_surface_empty": not apis and not errors,
        "old_jar_evidence": old_jar_evidence or {},
        "errors": errors,
    }, ("removed JAR javap 导出不完整" if errors else None)


# ══════════════════════════════════════════════════════════════════
# 4a. JApiCmp 二进制对比
# ══════════════════════════════════════════════════════════════════


def attach_constant_field_evidence(rows, old_jar_path):
    """Attach old-artifact ConstantValue evidence without inferring absence."""
    enriched = []
    for original in rows or ():
        row = dict(original)
        flags = str(row.get("compatibility_flags") or "").upper()
        is_candidate = bool(
            str(row.get("symbol_kind") or "").lower() == "field"
            and (
                str(row.get("change_type") or "").upper()
                in {"CONSTANT_VALUE_CHANGED", "REMOVED", "FIELD_REMOVED"}
                or "FIELD_REMOVED" in flags
                or "CONSTANT" in flags
            )
        )
        if not is_candidate:
            enriched.append(row)
            continue
        api_name = str(row.get("api_name") or "")
        owner, separator, field_name = api_name.rpartition(".")
        if not separator or not owner or not field_name:
            evidence = {
                "owner": owner,
                "field_name": field_name,
                "descriptor": str(row.get("field_descriptor") or ""),
                "has_constant_value": False,
                "constant_value": None,
                "artifact_sha256": "",
                "artifact_entry": "",
                "status": "incomplete",
                "failures": ["invalid_field_identity"],
            }
        else:
            evidence = extract_constant_field_evidence(
                old_jar_path,
                owner,
                field_name,
                str(row.get("field_descriptor") or ""),
            ).to_dict()
        row["field_descriptor"] = str(evidence.get("descriptor") or "")
        row["constant_field_evidence_json"] = json.dumps(
            evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        if evidence.get("status") == "complete":
            row["old_field_has_constant_value"] = (
                "true" if evidence.get("has_constant_value") is True else "false"
            )
            if (
                evidence.get("has_constant_value") is True
                and str(row.get("change_type") or "").upper()
                in {"REMOVED", "FIELD_REMOVED"}
            ):
                compatibility_flags = [
                    item for item in str(
                        row.get("compatibility_flags") or ""
                    ).split("|") if item
                ]
                if "CONSTANT_REMOVED" not in compatibility_flags:
                    compatibility_flags.append("CONSTANT_REMOVED")
                row["compatibility_flags"] = "|".join(compatibility_flags)
        enriched.append(row)
    return enriched

def run_japicmp(
    coord,
    old_ver,
    new_ver,
    output_dir,
    japicmp_jar,
    japicmp_timeout=DEFAULT_JAPICMP_TIMEOUT,
    fetch_timeout=DEFAULT_FETCH_TIMEOUT,
    old_coord=None,
    new_coord=None,
    old_jar_path=None,
    new_jar_path=None,
    old_jar_evidence=None,
    new_jar_evidence=None,
    cache_dir=None,
    jdk_current=None,
):
    """
    对单个依赖运行 JApiCmp，返回
    (output_file, changed_apis, artifact_metadata, error_msg)。
    保留完整原始输出，不裁剪任何内容。
    """
    display_coord = str(coord or "").strip()
    resolved_old_coord = str(old_coord or coord or "").strip()
    resolved_new_coord = str(new_coord or coord or "").strip()
    old_group_id, old_artifact_id, old_classifier = _split_coord(resolved_old_coord)
    new_group_id, new_artifact_id, new_classifier = _split_coord(resolved_new_coord)
    safe_artifact_id = new_artifact_id or old_artifact_id
    safe_classifier = new_classifier or old_classifier
    if not display_coord:
        display_coord = resolved_new_coord or resolved_old_coord
    if not old_group_id or not old_artifact_id or not new_group_id or not new_artifact_id:
        invalid_stem = bounded_path_component(
            f"invalid_coord_{old_ver}_vs_{new_ver}",
            max_length=72,
            default="invalid_coord",
        )
        out_file = os.path.join(output_dir, f"{invalid_stem}_binary.txt")
        msg = (
            f"=== 非法 Maven 坐标：{display_coord or coord} ===\n"
            f"old_coord={resolved_old_coord or '(空)'}\n"
            f"new_coord={resolved_new_coord or '(空)'}\n"
            "期望格式：groupId:artifactId 或 groupId:artifactId:classifier\n"
        )
        write_result(out_file, msg)
        return out_file, [], {
            "old_jar": None, "new_jar": None, "external_process_count": 0,
            "reason_code": "DEPENDENCY_COORDINATES_INVALID",
        }, "非法坐标"
    safe_name = safe_artifact_id.replace('.', '-') + (f"_{safe_classifier}" if safe_classifier else "")
    comparison_stem = bounded_path_component(
        f"{safe_name}_{old_ver}_vs_{new_ver}",
        max_length=72,
        default="dependency-comparison",
    )
    out_file = os.path.join(output_dir, f"{comparison_stem}_binary.txt")
    xml_file = os.path.join(output_dir, f"{comparison_stem}_binary.xml")

    old_jar = str(old_jar_path or "").strip() or None
    new_jar = str(new_jar_path or "").strip() or None
    old_jar_source = (old_jar_evidence or {}).get("source") if old_jar else ""
    new_jar_source = (new_jar_evidence or {}).get("source") if new_jar else ""
    if old_jar and not os.path.exists(old_jar):
        old_jar = None
        old_jar_source = ""
    if new_jar and not os.path.exists(new_jar):
        new_jar = None
        new_jar_source = ""
    # 最终制品证据不完整时失败封闭，不使用本地仓库或下载 JAR 替代。
    if not old_jar or not new_jar:
        missing_sides = []
        if not old_jar:
            missing_sides.append('base')
        if not new_jar:
            missing_sides.append('current')
        msg = (
            f"=== 无法完成对比：最终制品证据缺失 ===\n"
            f"依赖：{display_coord}\n"
            f"旧坐标：{resolved_old_coord}\n"
            f"新坐标：{resolved_new_coord}\n"
            f"缺少制品侧：{', '.join(missing_sides)}\n"
            "Step4 只允许分析 Step1 留存的 base/current 最终制品内 JAR，"
            "不会读取本地 Maven 仓库或下载替代 JAR。请先修复 Step1 制品条目证据后重跑。\n"
        )
        write_result(out_file, msg)
        return out_file, [], {
            "old_jar": old_jar,
            "new_jar": new_jar,
            "old_jar_source": old_jar_source,
            "new_jar_source": new_jar_source,
            "old_jar_evidence": old_jar_evidence or {},
            "new_jar_evidence": new_jar_evidence or {},
            "missing_sides": missing_sides,
            "reason_code": "FINAL_ARTIFACT_JAR_EVIDENCE_MISSING",
            "external_process_count": 0,
        }, f"最终制品 JAR 证据缺失：{display_coord}（{', '.join(missing_sides)}）"

    if not os.path.exists(japicmp_jar):
        msg = (
            f"=== JApiCmp 未安装 ===\n"
            f"请下载：mvn dependency:get \\\n"
            f"  -Dartifact=com.github.siom79.japicmp:japicmp:0.21.2:jar:jar-with-dependencies\n"
            f"下载后重新运行。\n"
        )
        write_result(out_file, msg)
        return out_file, [], {
            "old_jar": old_jar,
            "new_jar": new_jar,
            "old_jar_source": old_jar_source,
            "new_jar_source": new_jar_source,
            "old_jar_evidence": old_jar_evidence or {},
            "new_jar_evidence": new_jar_evidence or {},
            "reason_code": "JAPICMP_TOOL_UNAVAILABLE",
            "external_process_count": 0,
        }, "JApiCmp 未安装"

    tool_sha256 = ''
    old_jar_sha256 = ''
    new_jar_sha256 = ''
    comparison_identity = None
    comparison_cache_path = None
    java_runtime_identity = effective_java_runtime_identity()
    try:
        tool_sha256 = japicmp_tool_sha256(japicmp_jar)
        old_jar_sha256 = sha256_file(old_jar)
        new_jar_sha256 = sha256_file(new_jar)
        if cache_dir is not None and java_runtime_identity.get("complete") is True:
            comparison_identity = _japicmp_comparison_cache_identity(
                coord=display_coord,
                old_coord=resolved_old_coord,
                new_coord=resolved_new_coord,
                old_version=old_ver,
                new_version=new_ver,
                old_jar_sha256=old_jar_sha256,
                new_jar_sha256=new_jar_sha256,
                tool_sha256=tool_sha256,
                target_jdk=jdk_current,
                java_runtime_identity=java_runtime_identity,
            )
            comparison_cache_path = _japicmp_comparison_cache_path(
                cache_dir, comparison_identity
            )
            cached = _load_japicmp_comparison_cache(
                comparison_cache_path, comparison_identity
            )
            if cached is not None:
                Path(xml_file).write_text(cached["xml_content"], encoding="utf-8")
                try:
                    parsed_cached_rows = parse_japicmp_xml(
                        xml_file, coord, old_ver, new_ver
                    )
                    parsed_cached_rows = attach_constant_field_evidence(
                        parsed_cached_rows, old_jar
                    )
                except (ET.ParseError, OSError, ValueError):
                    cached = None
                else:
                    if _canonical_json_bytes(parsed_cached_rows) != _canonical_json_bytes(cached["rows"]):
                        cached = None
            if cached is not None:
                cache_load_changes = []
                try:
                    if sha256_file(old_jar) != old_jar_sha256:
                        cache_load_changes.append('old_jar')
                    if sha256_file(new_jar) != new_jar_sha256:
                        cache_load_changes.append('new_jar')
                    if japicmp_tool_sha256(japicmp_jar) != tool_sha256:
                        cache_load_changes.append('japicmp_tool')
                    if effective_java_runtime_identity() != java_runtime_identity:
                        cache_load_changes.append('java_runtime')
                except OSError as exc:
                    cache_load_changes.append(
                        f'identity_unavailable:{type(exc).__name__}'
                    )
                if cache_load_changes:
                    return out_file, [], {
                        "old_jar": old_jar,
                        "new_jar": new_jar,
                        "old_jar_source": old_jar_source,
                        "new_jar_source": new_jar_source,
                        "old_jar_evidence": old_jar_evidence or {},
                        "new_jar_evidence": new_jar_evidence or {},
                        "reason_code": "JAPICMP_INPUT_CHANGED_DURING_CACHE_LOAD",
                        "input_change_failures": cache_load_changes,
                        "comparison_cache_hit": False,
                        "java_runtime_identity": java_runtime_identity,
                        "target_jdk": str(jdk_current or ""),
                        "external_process_count": 0,
                    }, "JApiCmp 缓存读取期间输入身份发生变化，缓存结果已拒绝"
                header = _japicmp_output_header(
                    display_coord=display_coord,
                    old_coord=resolved_old_coord,
                    new_coord=resolved_new_coord,
                    old_version=old_ver,
                    new_version=new_ver,
                    old_jar=old_jar,
                    new_jar=new_jar,
                    old_jar_source=old_jar_source,
                    new_jar_source=new_jar_source,
                )
                write_result(out_file, header + cached["raw_output"])
                return out_file, cached["rows"], {
                    "old_jar": old_jar,
                    "new_jar": new_jar,
                    "old_jar_source": old_jar_source,
                    "new_jar_source": new_jar_source,
                    "old_jar_evidence": old_jar_evidence or {},
                    "new_jar_evidence": new_jar_evidence or {},
                    "xml_file": xml_file,
                    "parser_mode": "xml",
                    "xml_error": "",
                    "missing_class_policy": "ignored",
                    "japicmp_version": "0.21.2",
                    "japicmp_sha256": tool_sha256,
                    "comparison_cache_hit": True,
                    "java_runtime_identity": java_runtime_identity,
                    "target_jdk": str(jdk_current or ""),
                    "external_process_count": 0,
                }, None
    except OSError:
        comparison_identity = None
        comparison_cache_path = None

    try:
        Path(xml_file).unlink(missing_ok=True)
    except OSError as exc:
        return out_file, [], {
            "old_jar": old_jar,
            "new_jar": new_jar,
            "old_jar_source": old_jar_source,
            "new_jar_source": new_jar_source,
            "old_jar_evidence": old_jar_evidence or {},
            "new_jar_evidence": new_jar_evidence or {},
            "reason_code": "JAPICMP_XML_CLEANUP_FAILED",
            "external_process_count": 0,
        }, f"无法清理旧 JApiCmp XML：{exc}"

    # 执行 JApiCmp
    stdout, stderr, rc = run_cmd(
        ['java', '-jar', japicmp_jar,
         '--old', old_jar,
         '--new', new_jar,
         '--only-modified',
         '--ignore-missing-classes',
         '--xml-file', xml_file],
        timeout=japicmp_timeout
    )
    if rc == -1 and '超时' in stderr:
        timeout_label = f"{japicmp_timeout}秒" if japicmp_timeout not in (None, "") else "未设置超时"
        write_result(out_file, f"❌ JApiCmp 执行超时（{timeout_label}）\n{stderr}")
        return out_file, [], {
            "old_jar": old_jar,
            "new_jar": new_jar,
            "old_jar_source": old_jar_source,
            "new_jar_source": new_jar_source,
            "old_jar_evidence": old_jar_evidence or {},
            "new_jar_evidence": new_jar_evidence or {},
            "reason_code": JAPICMP_TIMEOUT,
            "external_process_count": 1,
        }, "超时"
    if rc != 0:
        error_lines = [f"❌ JApiCmp 执行失败（退出码 {rc}）"]
        if stderr:
            error_lines.append(f"stderr:\n{stderr}")
        if stdout:
            error_lines.append(f"stdout:\n{stdout}")
        write_result(out_file, "\n".join(error_lines) + "\n")
        failure_msg = (stderr or stdout or f"JApiCmp 失败，退出码 {rc}").strip()
        return out_file, [], {
            "old_jar": old_jar,
            "new_jar": new_jar,
            "old_jar_source": old_jar_source,
            "new_jar_source": new_jar_source,
            "old_jar_evidence": old_jar_evidence or {},
            "new_jar_evidence": new_jar_evidence or {},
            "reason_code": JAPICMP_EXECUTION_FAILED,
            "external_process_count": 1,
        }, failure_msg[:100]
    raw_output = stdout or stderr or "(无输出)"

    # 完整保留原始输出
    header = _japicmp_output_header(
        display_coord=display_coord,
        old_coord=resolved_old_coord,
        new_coord=resolved_new_coord,
        old_version=old_ver,
        new_version=new_ver,
        old_jar=old_jar,
        new_jar=new_jar,
        old_jar_source=old_jar_source,
        new_jar_source=new_jar_source,
    )
    write_result(out_file, header + raw_output)

    # XML 是机器解析主证据；仅在工具未生成或 XML 不可解析时回退文本。
    parser_mode = 'xml'
    xml_error = ''
    try:
        changed_apis = parse_japicmp_xml(xml_file, coord, old_ver, new_ver)
        changed_apis = attach_constant_field_evidence(changed_apis, old_jar)
    except (ET.ParseError, OSError, ValueError) as exc:
        parser_mode = 'text_fallback'
        xml_error = f"{type(exc).__name__}:{exc}"
        fallback_rows = parse_japicmp_output(raw_output, coord, old_ver, new_ver)
        for row in fallback_rows:
            row['reason_code'] = 'JAPICMP_TEXT_FALLBACK_USED'
            row['evidence_path'] = str(out_file)
            row['binary_compatible'] = row.get('binary_compatible') or 'unknown'
            row['source_compatible'] = row.get('source_compatible') or 'unknown'
        reason_code = (
            'JAPICMP_FRESH_XML_MISSING'
            if not Path(xml_file).is_file()
            else 'JAPICMP_FRESH_XML_INVALID'
        )
        return out_file, [], {
            "old_jar": old_jar,
            "new_jar": new_jar,
            "old_jar_source": old_jar_source,
            "new_jar_source": new_jar_source,
            "old_jar_evidence": old_jar_evidence or {},
            "new_jar_evidence": new_jar_evidence or {},
            "xml_file": xml_file if Path(xml_file).is_file() else '',
            "parser_mode": parser_mode,
            "xml_error": xml_error,
            "text_fallback_row_count": len(fallback_rows),
            "reason_code": reason_code,
            "missing_class_policy": "ignored",
            "japicmp_version": "0.21.2",
            "japicmp_sha256": tool_sha256,
            "comparison_cache_hit": False,
            "java_runtime_identity": java_runtime_identity,
            "target_jdk": str(jdk_current or ""),
            "external_process_count": 1,
        }, f"JApiCmp 未产生可验证的新鲜 XML：{xml_error}"

    input_change_failures = []
    try:
        if not old_jar_sha256 or sha256_file(old_jar) != old_jar_sha256:
            input_change_failures.append('old_jar')
        if not new_jar_sha256 or sha256_file(new_jar) != new_jar_sha256:
            input_change_failures.append('new_jar')
        if not tool_sha256 or japicmp_tool_sha256(japicmp_jar) != tool_sha256:
            input_change_failures.append('japicmp_tool')
        if effective_java_runtime_identity() != java_runtime_identity:
            input_change_failures.append('java_runtime')
    except OSError as exc:
        input_change_failures.append(f'identity_unavailable:{type(exc).__name__}')
    if input_change_failures:
        return out_file, [], {
            "old_jar": old_jar,
            "new_jar": new_jar,
            "old_jar_source": old_jar_source,
            "new_jar_source": new_jar_source,
            "old_jar_evidence": old_jar_evidence or {},
            "new_jar_evidence": new_jar_evidence or {},
            "xml_file": xml_file,
            "parser_mode": parser_mode,
            "xml_error": xml_error,
            "reason_code": "JAPICMP_INPUT_CHANGED_DURING_COMPARISON",
            "input_change_failures": input_change_failures,
            "japicmp_sha256": tool_sha256,
            "comparison_cache_hit": False,
            "java_runtime_identity": java_runtime_identity,
            "target_jdk": str(jdk_current or ""),
            "external_process_count": 1,
        }, "JApiCmp 对比期间输入身份发生变化，结果已拒绝"
    if (
        parser_mode == 'xml'
        and comparison_cache_path is not None
        and comparison_identity is not None
        and Path(xml_file).is_file()
    ):
        try:
            _write_japicmp_comparison_cache(
                comparison_cache_path,
                comparison_identity,
                changed_apis,
                raw_output,
                Path(xml_file).read_text(encoding='utf-8'),
            )
        except OSError:
            pass
    return out_file, changed_apis, {
        "old_jar": old_jar,
        "new_jar": new_jar,
        "old_jar_source": old_jar_source,
        "new_jar_source": new_jar_source,
        "old_jar_evidence": old_jar_evidence or {},
        "new_jar_evidence": new_jar_evidence or {},
        "xml_file": xml_file if os.path.exists(xml_file) else '',
        "parser_mode": parser_mode,
        "xml_error": xml_error,
        "missing_class_policy": "ignored",
        "japicmp_version": "0.21.2",
        "japicmp_sha256": tool_sha256,
        "comparison_cache_hit": False,
        "java_runtime_identity": java_runtime_identity,
        "comparison_cache_disabled_reason": (
            "JAVA_RUNTIME_IDENTITY_INCOMPLETE"
            if java_runtime_identity.get("complete") is not True else ""
        ),
        "target_jdk": str(jdk_current or ""),
        "external_process_count": 1,
    }, None


def _xml_local_name(element):
    return str(element.tag).rsplit('}', 1)[-1].lower()


def _xml_attr(element, *names):
    lowered = {str(key).lower(): str(value) for key, value in element.attrib.items()}
    for name in names:
        value = lowered.get(str(name).lower())
        if value is not None:
            return value.strip()
    return ''


def _compat_value(element, *names):
    value = _xml_attr(element, *names).lower()
    return value if value in ('true', 'false') else 'unknown'


def parse_japicmp_xml(xml_file, coord, old_ver, new_ver):
    """Parse JApiCmp XML while preserving binary and source compatibility separately."""
    path = Path(xml_file)
    if not path.is_file() or path.stat().st_size == 0:
        raise OSError(f"JApiCmp XML 未生成：{path}")
    root = ET.parse(str(path)).getroot()
    if _xml_local_name(root) != 'japicmp':
        raise ValueError(
            f"JApiCmp XML structure invalid: unexpected root {_xml_local_name(root)!r}"
        )
    if not any(
        _xml_local_name(element) in {'classes', 'class-list', 'classlist'}
        for element in root.iter()
    ):
        raise ValueError("JApiCmp XML structure invalid: classes container missing")
    apis = []

    def is_jdk_standard_owner(owner):
        owner = str(owner or '').strip()
        return owner.startswith(('java.', 'jdk.', 'sun.', 'com.sun.'))

    def iter_top_level_class_elements():
        class_tags = {'class', 'interface', 'enum', 'annotation', 'record'}
        if _xml_local_name(root) in class_tags:
            yield root
            return
        class_containers = [
            element for element in root.iter()
            if _xml_local_name(element) in {'classes', 'class-list', 'classlist'}
        ]
        if not class_containers:
            class_containers = [root]
        for container in class_containers:
            for descendant in container.iter():
                if _xml_local_name(descendant) not in class_tags:
                    continue
                if not _xml_attr(
                    descendant, 'fullyQualifiedName', 'fully_qualified_name', 'name'
                ):
                    raise ValueError(
                        "JApiCmp XML structure invalid: class identity missing"
                    )
        seen = set()
        for container in class_containers:
            for child in list(container):
                if _xml_local_name(child) not in class_tags:
                    continue
                identity = id(child)
                if identity in seen:
                    continue
                seen.add(identity)
                yield child
                for descendant in child.iter():
                    if descendant is child or _xml_local_name(descendant) != 'class':
                        continue
                    identity = id(descendant)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    yield descendant

    def add_row(owner, element, symbol_kind):
        if is_jdk_standard_owner(owner):
            return
        status = _xml_attr(element, 'changeStatus', 'change_status', 'status').upper()
        binary = _compat_value(element, 'binaryCompatible', 'binary_compatible')
        source = _compat_value(element, 'sourceCompatible', 'source_compatible')
        old_value = _xml_attr(element, 'oldValue', 'old_value')
        new_value = _xml_attr(element, 'newValue', 'new_value')
        for child in element:
            local_name = _xml_local_name(child)
            if local_name in {'oldvalue', 'old-value'} and not old_value:
                old_value = (child.text or '').strip() or _xml_attr(child, 'value')
            elif local_name in {'newvalue', 'new-value'} and not new_value:
                new_value = (child.text or '').strip() or _xml_attr(child, 'value')
        flags = []
        for child in element.iter():
            if _xml_local_name(child) not in ('compatibilitychange', 'compatibility-change'):
                continue
            flag = _xml_attr(child, 'type', 'name') or (child.text or '').strip()
            if flag and flag not in flags:
                flags.append(flag)
        if (
            symbol_kind == 'field'
            and status == 'REMOVED'
            and old_value
            and 'CONSTANT_REMOVED' not in flags
        ):
            flags.append('CONSTANT_REMOVED')
        if status in ('NEW', 'UNCHANGED'):
            return
        if symbol_kind == 'class' and status == 'MODIFIED':
            # JApiCmp marks the containing class MODIFIED whenever a member is
            # changed.  Emitting a second class-level API row in that case is a
            # false structural change.  Keep a class row only when JApiCmp
            # provides an explicit class/supertype contract flag.
            class_level_prefixes = (
                'CLASS_', 'SUPERCLASS_', 'INTERFACE_', 'GENERIC_TEMPLATE_',
                'TYPE_', 'ANNOTATION_', 'ENUM_', 'RECORD_',
            )
            explicit_class_flag = any(
                str(flag).upper().startswith(class_level_prefixes) for flag in flags
            )
            changed_type_relation = any(
                _xml_local_name(descendant) in {'interface', 'superclass'}
                and _xml_attr(descendant, 'changeStatus', 'change_status', 'status').upper()
                not in {'', 'NEW', 'UNCHANGED'}
                and not is_jdk_standard_owner(
                    _xml_attr(descendant, 'fullyQualifiedName', 'fully_qualified_name', 'name')
                )
                for descendant in element.iter()
                if descendant is not element
            )
            if not explicit_class_flag and not changed_type_relation:
                return
        if symbol_kind == 'field' and old_value and new_value and old_value != new_value:
            change_type = 'CONSTANT_VALUE_CHANGED'
            reason_code = 'field_constant_value_changed'
        elif status == 'REMOVED':
            change_type = 'REMOVED'
            reason_code = 'japicmp_removed'
        elif binary == 'true' and source == 'false':
            change_type = 'SOURCE_INCOMPATIBLE'
            reason_code = 'binary_compatible_source_incompatible'
        elif binary == 'false' or source == 'false' or (
            status == 'MODIFIED' and binary == 'unknown' and source == 'unknown'
        ):
            change_type = 'SIGNATURE_CHANGED'
            reason_code = 'binary_or_source_incompatible'
        else:
            return

        raw_name = _xml_attr(element, 'name')
        if symbol_kind == 'class':
            api_name = owner
            signature = ''
        elif symbol_kind == 'constructor':
            simple_owner = owner.rsplit('.', 1)[-1]
            api_name = f"{owner}.{simple_owner}"
            signature = _xml_member_signature(element)
        else:
            if not raw_name:
                return
            api_name = f"{owner}.{raw_name}"
            signature = _xml_member_signature(element) if symbol_kind == 'method' else ''
        row = {
            'coord': coord,
            'old_version': old_ver,
            'new_version': new_ver,
            'change_type': change_type,
            'api_name': api_name,
            'api_simple': api_name.rsplit('.', 1)[-1],
            'symbol_kind': symbol_kind,
            'api_signature': signature,
            'confirmed': 'true',
            'severity': DEFAULT_SEVERITY[change_type],
            'source': 'japicmp',
            'binary_compatible': binary,
            'source_compatible': source,
            'compatibility_flags': '|'.join(flags),
            'reason_code': reason_code,
            'evidence_path': str(path),
            'old_value': old_value,
            'new_value': new_value,
        }
        if not validate_row(row):
            apis.append(row)

    for class_element in iter_top_level_class_elements():
        owner = _xml_attr(class_element, 'fullyQualifiedName', 'fully_qualified_name', 'name')
        if not owner:
            raise ValueError("JApiCmp XML structure invalid: class identity missing")
        if is_jdk_standard_owner(owner):
            continue
        add_row(owner, class_element, 'class')
        def iter_owned_members(element):
            for member in list(element):
                tag = _xml_local_name(member)
                if tag in {'class', 'interface', 'enum', 'annotation', 'record'}:
                    continue
                if tag in {'method', 'constructor', 'field'}:
                    yield member
                yield from iter_owned_members(member)

        for member in iter_owned_members(class_element):
            tag = _xml_local_name(member)
            if tag == 'method':
                add_row(owner, member, 'method')
            elif tag == 'constructor':
                add_row(owner, member, 'constructor')
            elif tag == 'field':
                add_row(owner, member, 'field')
    return apis


def _xml_member_signature(element):
    params = []
    for child in element.iter():
        if _xml_local_name(child) != 'parameter':
            continue
        value = _xml_attr(child, 'type', 'newType', 'oldType', 'name')
        if value:
            params.append(value)
    return build_api_signature_from_types(params, erase_generics=True)


def parse_japicmp_output(output, coord, old_ver, new_ver):
    """
    解析 JApiCmp 输出，提取结构化的变更 API。
    只提取能静态确认的变更（confirmed=true）。
    """
    apis = []
    current_declaring_type = None

    method_call_pattern = re.compile(
        r'([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*\(([^()]*)\)'
    )

    def extract_package_prefix(api_name):
        if not api_name or '.' not in api_name:
            return ''
        owner = api_name.rsplit('.', 1)[0]
        parts = [part for part in owner.split('.') if part]
        package_parts = []
        for part in parts:
            if part[:1].islower():
                package_parts.append(part)
                continue
            break
        return '.'.join(package_parts)

    def qualify_api_name_with_package(api_name, package_prefix):
        if not api_name or not package_prefix or '.' not in api_name:
            return api_name
        owner, member = api_name.rsplit('.', 1)
        owner_parts = [part for part in owner.split('.') if part]
        if not owner_parts:
            return api_name
        if owner_parts[0][:1].islower():
            return api_name
        return f"{package_prefix}.{owner}.{member}"

    def looks_like_member_fqn(candidate):
        candidate = (candidate or '').strip()
        if '.' not in candidate:
            return False
        owner = candidate.rsplit('.', 1)[0]
        owner_simple = owner.rsplit('.', 1)[-1]
        return bool(owner_simple[:1].isupper())

    def extract_member_name_before_parenthesis(payload):
        payload = payload or ''
        params_raw = extract_parenthesized_segment(payload)
        if params_raw is None:
            return None, None
        marker = '(' + params_raw + ')'
        marker_index = payload.rfind(marker)
        if marker_index < 0:
            marker_index = payload.rfind('(')
        if marker_index < 0:
            return None, params_raw
        left = marker_index - 1
        while left >= 0 and payload[left].isspace():
            left -= 1
        token_end = left + 1
        while left >= 0 and (payload[left].isalnum() or payload[left] in '$_'):
            left -= 1
        member_name = payload[left + 1:token_end].strip() or None
        return member_name, params_raw

    def extract_method_name_and_signature(payload, current_owner=''):
        """
        Extract method FQN and parameter signature from JApiCmp output（增强版）

        改进：
          1. 保留完整类型信息（含泛型）
          2. 处理数组类型 String[] -> String[]
          3. 处理varargs ...
          4. 保留包结构用于精确匹配
          5. 链式表达式中优先选择最后一个合法成员，避免前半段调用抢占命中
        """
        member_name, params_raw = extract_member_name_before_parenthesis(payload)
        if current_owner and member_name:
            return (
                f"{current_owner}.{member_name}",
                build_api_signature_from_types(
                    split_parameters_preserving_generics(params_raw or '')
                ),
            )

        candidates = []
        package_hints = []
        for match in method_call_pattern.finditer(payload or ''):
            api_name = match.group(1).strip()
            params_raw = match.group(2).strip()
            package_prefix = extract_package_prefix(api_name)
            if package_prefix:
                package_hints.append(package_prefix)
            api_signature = build_api_signature_from_types(
                split_parameters_preserving_generics(params_raw)
            )
            candidates.append((api_name, api_signature))
        if candidates:
            api_name, api_signature = candidates[-1]
            if package_hints:
                api_name = qualify_api_name_with_package(api_name, package_hints[0])
            return api_name, api_signature

        # Fallback: method without parentheses
        matches = re.findall(r'([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)', payload or '')
        if matches:
            member_matches = [item for item in matches if looks_like_member_fqn(item)]
            selected = (member_matches or matches)[-1]
            package_prefixes = [extract_package_prefix(item) for item in matches]
            package_prefixes = [item for item in package_prefixes if item]
            if package_prefixes:
                selected = qualify_api_name_with_package(selected, package_prefixes[0])
            return selected, ''
        return None, ''

    def extract_constructor_name_and_signature(payload, current_owner=''):
        member_name, params_raw = extract_member_name_before_parenthesis(payload)
        if current_owner:
            owner_simple = current_owner.rsplit('.', 1)[-1]
            constructor_name = member_name or owner_simple
            return (
                f"{current_owner}.{constructor_name}",
                build_api_signature_from_types(
                    split_parameters_preserving_generics(params_raw or '')
                ),
            )
        if member_name and params_raw is not None:
            return member_name, build_api_signature_from_types(
                split_parameters_preserving_generics(params_raw or '')
            )
        return None, ''

    def extract_field_name(payload, current_owner=''):
        if current_owner:
            trailing = re.search(r'([A-Za-z_$][\w$]*)\s*$', payload or '')
            if trailing:
                return f"{current_owner}.{trailing.group(1)}"
        matches = re.findall(
            r'([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)',
            payload or ''
        )
        if matches:
            return matches[-1]
        trailing = re.search(r'([A-Za-z_$][\w$]*)\s*$', payload or '')
        return trailing.group(1) if trailing else None

    def extract_class_name(payload):
        matches = re.findall(
            r'([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)',
            payload or ''
        )
        return matches[-1] if matches else None

    def infer_method_symbol_kind(api_name):
        if not api_name or '.' not in api_name:
            return 'method'
        owner = api_name.rsplit('.', 1)[0]
        member = api_name.rsplit('.', 1)[-1]
        owner_simple = owner.rsplit('.', 1)[-1]
        return 'constructor' if member == owner_simple else 'method'

    def add_row(change_type, api_name, api_signature='', symbol_kind='method'):
        if not api_name:
            return
        api_simple = api_name.rsplit('.', 1)[-1]
        row = {
            'coord':       coord,
            'old_version': old_ver,
            'new_version': new_ver,
            'change_type': change_type,
            'api_name':    api_name,
            'api_simple':  api_simple,
            'symbol_kind': symbol_kind,
            'api_signature': api_signature,
            'confirmed':   'true',
            'severity':    DEFAULT_SEVERITY[change_type],
            'source':      'japicmp',
        }
        errors = validate_row(row)
        if not errors:
            apis.append(row)

    legacy_patterns = [
        (r'METHOD_REMOVED.*?(\w[\w.]+)\s*\(', 'REMOVED', 'method'),
        (r'CLASS_REMOVED.*?([\w.]+)$', 'REMOVED', 'class'),
        (r'METHOD_RETURN_TYPE_CHANGED.*?(\w[\w.]+)\s*\(', 'SIGNATURE_CHANGED', 'method'),
        (r'PARAMETER.*CHANGED.*?(\w[\w.]+)\s*\(', 'SIGNATURE_CHANGED', 'method'),
        (r'METHOD_.*LESS_ACCESSIBLE.*?(\w[\w.]+)\s*\(', 'ACCESS_REDUCED', 'method'),
        (r'FIELD_REMOVED.*?(\w[\w.]+)$', 'REMOVED', 'field'),
    ]

    text_change_map = {
        ('REMOVED', 'METHOD'): 'REMOVED',
        ('REMOVED', 'CONSTRUCTOR'): 'REMOVED',
        ('REMOVED', 'CLASS'): 'REMOVED',
        ('REMOVED', 'INTERFACE'): 'REMOVED',
        ('REMOVED', 'ENUM'): 'REMOVED',
        ('REMOVED', 'ANNOTATION'): 'REMOVED',
        ('REMOVED', 'RECORD'): 'REMOVED',
        ('REMOVED', 'FIELD'): 'REMOVED',
        ('MODIFIED', 'METHOD'): 'SIGNATURE_CHANGED',
        ('MODIFIED', 'CONSTRUCTOR'): 'SIGNATURE_CHANGED',
        ('MODIFIED', 'FIELD'): 'SIGNATURE_CHANGED',
        ('MODIFIED', 'CLASS'): 'SIGNATURE_CHANGED',
        ('MODIFIED', 'INTERFACE'): 'SIGNATURE_CHANGED',
        ('MODIFIED', 'ENUM'): 'SIGNATURE_CHANGED',
        ('MODIFIED', 'ANNOTATION'): 'SIGNATURE_CHANGED',
        ('MODIFIED', 'RECORD'): 'SIGNATURE_CHANGED',
    }

    line_pattern = re.compile(
        r'^[*+\-]+\!?'
        r'\s+'
        r'(REMOVED|MODIFIED|NEW)'
        r'\s+'
        r'(METHOD|CLASS|FIELD|CONSTRUCTOR|INTERFACE|ENUM|ANNOTATION|RECORD)'
        r':\s+'
        r'(.+?)\s*$'
    )

    for raw_line in output.splitlines():
        indent = len(raw_line) - len(raw_line.lstrip())
        line = raw_line.strip()
        if not line:
            continue

        matched = False
        line_match = line_pattern.match(line)
        if line_match:
            action, target_type, payload = line_match.groups()
            change_type = text_change_map.get((action, target_type))
            if target_type in {'CLASS', 'INTERFACE', 'ENUM', 'ANNOTATION', 'RECORD'}:
                if indent == 0:
                    current_declaring_type = extract_class_name(payload)
                matched = True
            if change_type:
                if target_type == 'METHOD':
                    api_name, api_signature = extract_method_name_and_signature(
                        payload,
                        current_owner=current_declaring_type or '',
                    )
                    add_row(change_type, api_name, api_signature, infer_method_symbol_kind(api_name))
                elif target_type == 'CONSTRUCTOR':
                    api_name, api_signature = extract_constructor_name_and_signature(
                        payload,
                        current_owner=current_declaring_type or '',
                    )
                    add_row(change_type, api_name, api_signature, 'constructor')
                elif target_type == 'FIELD':
                    add_row(
                        change_type,
                        extract_field_name(payload, current_owner=current_declaring_type or ''),
                        '',
                        'field',
                    )
                elif indent == 0:
                    add_row(change_type, extract_class_name(payload), '', 'class')
                matched = True

        if matched:
            continue

        for pattern, change_type, symbol_kind in legacy_patterns:
            m = re.search(pattern, line)
            if m:
                payload = m.group(1).strip()
                if symbol_kind == 'method':
                    api_name, api_signature = extract_method_name_and_signature(payload)
                    add_row(change_type, api_name, api_signature, infer_method_symbol_kind(api_name))
                elif symbol_kind == 'field':
                    add_row(change_type, extract_field_name(payload), '', 'field')
                else:
                    add_row(change_type, extract_class_name(payload), '', 'class')
                break

    return apis or []


def split_parameters_preserving_generics(params_str):
    """
    分割参数列表，正确处理泛型中的逗号

    示例：
      "String, List<Map<String, Integer>>, int[]"
      -> ["String", "List<Map<String, Integer>>", "int[]"]

    Args:
        params_str: 参数字符串

    Returns:
        list: 参数类型列表
    """
    params = []
    current = []
    generic_depth = 0
    paren_depth = 0
    bracket_depth = 0

    for char in params_str:
        if char == '<':
            generic_depth += 1
            current.append(char)
        elif char == '>':
            generic_depth = max(0, generic_depth - 1)
            current.append(char)
        elif char == '(':
            paren_depth += 1
            current.append(char)
        elif char == ')':
            paren_depth = max(0, paren_depth - 1)
            current.append(char)
        elif char == '[':
            bracket_depth += 1
            current.append(char)
        elif char == ']':
            bracket_depth = max(0, bracket_depth - 1)
            current.append(char)
        elif char == ',' and generic_depth == 0 and paren_depth == 0 and bracket_depth == 0:
            # 顶层逗号，分割参数
            param = ''.join(current).strip()
            if param:
                params.append(param)
            current = []
        else:
            current.append(char)

    # 最后一个参数
    param = ''.join(current).strip()
    if param:
        params.append(param)

    return params


def normalize_type_expression(type_expr):
    """
    统一规范化类型表达式，供 japicmp / git diff / 后续签名比对共用。
    """
    type_expr = (type_expr or '').strip()
    if not type_expr:
        return ''

    type_expr = re.sub(r'@[\w$.]+(?:\([^)]*\))?\s*', '', type_expr)
    type_expr = re.sub(r'\b(?:final|volatile|transient|vararg|crossinline|noinline)\b\s*', '', type_expr)
    type_expr = re.sub(r'\s+', ' ', type_expr).strip()

    if type_expr.endswith('...'):
        type_expr = type_expr[:-3].strip() + '[]'

    type_expr = re.sub(r'\s*\[\s*\]\s*', '[]', type_expr)
    type_expr = re.sub(r'\s*<\s*', '<', type_expr)
    type_expr = re.sub(r'\s*>\s*', '>', type_expr)
    type_expr = re.sub(r'\s*,\s*', ', ', type_expr)
    return type_expr.strip()


def strip_parameter_name(param_decl):
    """
    从参数声明中剥离参数名，只保留类型表达式。
    """
    param_decl = (param_decl or '').strip()
    if not param_decl:
        return ''

    depth_angle = 0
    depth_paren = 0
    depth_bracket = 0
    top_level_equal = -1
    for idx, ch in enumerate(param_decl):
        if ch == '<':
            depth_angle += 1
        elif ch == '>':
            depth_angle = max(0, depth_angle - 1)
        elif ch == '(':
            depth_paren += 1
        elif ch == ')':
            depth_paren = max(0, depth_paren - 1)
        elif ch == '[':
            depth_bracket += 1
        elif ch == ']':
            depth_bracket = max(0, depth_bracket - 1)
        elif ch == '=' and depth_angle == 0 and depth_paren == 0 and depth_bracket == 0:
            top_level_equal = idx
            break
    if top_level_equal >= 0:
        param_decl = param_decl[:top_level_equal].strip()

    # Kotlin 形参形如 "name: Type"；只保留冒号右侧类型表达式。
    depth_angle = 0
    depth_paren = 0
    depth_bracket = 0
    for idx, ch in enumerate(param_decl):
        if ch == '<':
            depth_angle += 1
        elif ch == '>':
            depth_angle = max(0, depth_angle - 1)
        elif ch == '(':
            depth_paren += 1
        elif ch == ')':
            depth_paren = max(0, depth_paren - 1)
        elif ch == '[':
            depth_bracket += 1
        elif ch == ']':
            depth_bracket = max(0, depth_bracket - 1)
        elif ch == ':' and depth_angle == 0 and depth_paren == 0 and depth_bracket == 0:
            left = param_decl[:idx].strip()
            right = param_decl[idx + 1:].strip()
            if re.fullmatch(r'[A-Za-z_$][\w$]*', left):
                return right

    depth = 0
    for idx in range(len(param_decl) - 1, -1, -1):
        ch = param_decl[idx]
        if ch == '>':
            depth += 1
        elif ch == '<':
            depth = max(0, depth - 1)
        elif ch.isspace() and depth == 0:
            candidate = param_decl[idx + 1:].strip()
            if re.fullmatch(r'[A-Za-z_$][\w$]*', candidate):
                return param_decl[:idx].strip()
            break
    return param_decl


def _erase_generic_arguments(type_expr):
    erased = []
    depth = 0
    for char in str(type_expr or ''):
        if char == '<':
            depth += 1
        elif char == '>' and depth:
            depth -= 1
        elif depth == 0:
            erased.append(char)
    return ''.join(erased).strip()


def build_api_signature_from_types(type_exprs, erase_generics=False):
    normalized_params = []
    for type_expr in type_exprs or []:
        normalized = normalize_type_expression(type_expr)
        if erase_generics:
            normalized = _erase_generic_arguments(normalized)
        if normalized:
            normalized_params.append(normalized)
    return '(' + ', '.join(normalized_params) + ')' if normalized_params else '()'


def extract_parenthesized_segment(text):
    text = text or ''
    candidate_start = -1
    for idx, ch in enumerate(text):
        if ch != '(':
            continue
        left = idx - 1
        while left >= 0 and text[left].isspace():
            left -= 1
        token_end = left + 1
        while left >= 0 and (text[left].isalnum() or text[left] in '$_'):
            left -= 1
        token = text[left + 1:token_end]
        if not token:
            continue
        if left >= 0 and text[left] == '@':
            continue
        candidate_start = idx
    if candidate_start < 0:
        return None
    depth = 0
    current = []
    for ch in text[candidate_start + 1:]:
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            if depth == 0:
                return ''.join(current)
            depth -= 1
            current.append(ch)
        else:
            current.append(ch)
    return None


def extract_api_signature_from_declaration(signature_line):
    """
    从方法声明中提取参数签名，保留完整类型信息，用于区分重载方法。
    """
    params_raw = extract_parenthesized_segment(signature_line or '')
    if params_raw is None:
        return ''

    params_raw = params_raw.strip()
    if not params_raw:
        return '()'

    params_list = split_parameters_preserving_generics(params_raw)
    type_params = [strip_parameter_name(param) for param in params_list]
    return build_api_signature_from_types(type_params)


def is_test_source_path(source_path):
    normalized = '/' + (source_path or '').replace('\\', '/').strip('/').lower() + '/'
    test_markers = (
        '/src/test/',
        '/src/testfixtures/',
        '/src/androidtest/',
        '/src/integrationtest/',
    )
    return any(marker in normalized for marker in test_markers)


def is_non_runtime_support_path(source_path):
    normalized = '/' + (source_path or '').replace('\\', '/').strip('/').lower() + '/'
    support_markers = (
        '/.mvn/',
        '/buildsrc/',
    )
    return any(marker in normalized for marker in support_markers)


def should_skip_gitdiff_path(source_path):
    return is_test_source_path(source_path) or is_non_runtime_support_path(source_path)


def infer_method_symbol_kind_from_api_name(api_name):
    if not api_name or '.' not in api_name:
        return 'method'
    owner = api_name.rsplit('.', 1)[0]
    member = api_name.rsplit('.', 1)[-1]
    owner_simple = owner.rsplit('.', 1)[-1]
    return 'constructor' if member == owner_simple else 'method'


def dependency_is_removed_or_added(row):
    row = row or {}
    change = str(row.get('change_type') or '').strip()
    old_ver = str(row.get('old_version') or '-').strip()
    new_ver = str(row.get('new_version') or '-').strip()
    is_removed_dependency = (change == '移除') or (new_ver == '-' and old_ver != '-')
    is_added_dependency = (change == '新增') or (old_ver == '-' and new_ver != '-')
    return is_removed_dependency or is_added_dependency


def dependency_needs_gitdiff_preflight(row, source_mapping):
    row = row or {}
    if not str(row.get('coord') or '').strip():
        return False
    if dependency_is_removed_or_added(row):
        return False
    if not (source_mapping or {}).get("repo_path"):
        return False
    if is_ephemeral_dependency_source_mapping(source_mapping):
        return False
    return True


def classify_git_ref_pending_kind(reason, old_reason="", new_reason=""):
    text = " ".join(str(value or "") for value in (reason, old_reason, new_reason)).lower()
    if "remote_ref_moved" in text:
        return "remote_ref_moved"
    if "remote_query_failed" in text:
        return "remote_query_failed"
    if "ambiguous_" in text:
        return "ambiguous"
    if "remote_source_unavailable" in text:
        return "remote_unavailable"
    if "selected_ref_not_found" in text or "no_ref_match" in text:
        return "not_found"
    if "local_source_confirmation_required" in text:
        return "local_confirmation_required"
    return "not_found"


def _is_git_worktree(repo_path, *, timeout=DEFAULT_FETCH_TIMEOUT):
    """Recognize normal and linked worktrees through Git itself."""
    stdout, _stderr, rc = run_cmd(
        git_cmd() + ["rev-parse", "--is-inside-work-tree"],
        cwd=repo_path,
        timeout=_bounded_git_timeout(timeout, DEFAULT_FETCH_TIMEOUT),
    )
    return rc == 0 and str(stdout or "").strip().lower() == "true"


def _with_remote_snapshot_candidate_metadata(materialized, candidate):
    result = dict(materialized or {})
    result.update({
        "resolved_ref": str(candidate.get("ref") or ""),
        "remote": str(candidate.get("remote") or candidate.get("remote_name") or ""),
        "remote_ref": str(candidate.get("canonical_ref") or ""),
    })
    if result.get("status") == "remote_source_resolved":
        used_fetch = any(
            str(item.get("stage") or "").startswith("fetch")
            for item in result.get("attempts") or []
        )
        # Selection authority remains the immutable remote snapshot.  A local
        # rev-parse here only proves that the selected object is materialized;
        # it does not select or validate the user's checkout HEAD.
        result["resolution_mode"] = "live_remote"
        result["materialization_mode"] = (
            "live_remote_snapshot_fetch"
            if used_fetch
            else "live_remote_snapshot_local"
        )
    return result


def _materialize_resolved_remote_ref(
    repo_path,
    resolved_ref,
    candidates,
    *,
    expected_commit="",
    fetch_timeout=DEFAULT_FETCH_TIMEOUT,
):
    candidate = next(
        (
            item for item in (candidates or [])
            if item.get("ref") == resolved_ref
            and item.get("commit")
            and (item.get("remote") or item.get("remote_name"))
        ),
        None,
    )
    if not candidate:
        return None, "remote_candidate_metadata_missing"
    snapshot_commit = str(candidate.get("commit") or "").strip()
    expected_commit = str(expected_commit or "").strip()
    materialization_commit = (
        snapshot_commit
        if not expected_commit
        or _commit_prefix_matches(snapshot_commit, expected_commit)
        else expected_commit
    )
    materialization_candidate = dict(candidate)
    materialization_candidate["commit"] = materialization_commit
    timeout = _bounded_git_timeout(fetch_timeout, DEFAULT_FETCH_TIMEOUT)
    cache_key = (
        os.path.normcase(os.path.realpath(os.path.abspath(str(repo_path or "")))),
        materialization_commit.lower(),
    )
    with _REMOTE_SOURCE_MATERIALIZATION_LOCK:
        key_lock = _REMOTE_SOURCE_MATERIALIZATION_KEY_LOCKS.setdefault(
            cache_key,
            threading.Lock(),
        )
    with key_lock:
        with _REMOTE_SOURCE_MATERIALIZATION_LOCK:
            cached = _REMOTE_SOURCE_MATERIALIZATION_CACHE.get(cache_key)
        if cached:
            return _with_remote_snapshot_candidate_metadata(cached, candidate), ""

        materialized = materialize_remote_source_candidate(
            repo_path,
            materialization_candidate,
            timeout=timeout,
            expected_commit=materialization_commit,
        )
        materialized = _with_remote_snapshot_candidate_metadata(
            materialized,
            candidate,
        )
        if snapshot_commit.lower() != materialization_commit.lower():
            materialized["observed_commit"] = snapshot_commit
        if materialized.get("status") != "remote_source_resolved":
            failure = materialized.get("failure") or {}
            return materialized, str(failure.get("reason") or "remote fetch failed")
        with _REMOTE_SOURCE_MATERIALIZATION_LOCK:
            _REMOTE_SOURCE_MATERIALIZATION_CACHE[cache_key] = dict(materialized)
        return materialized, ""


def resolve_gitdiff_ref_plan_for_row(
    row,
    source_mapping,
    source_meta,
    dependency_git_ref_overrides,
    *,
    fetch_timeout=DEFAULT_FETCH_TIMEOUT,
):
    row = row or {}
    source_mapping = source_mapping or {}
    source_meta = source_meta or {}
    fetch_timeout = _bounded_git_timeout(fetch_timeout, DEFAULT_FETCH_TIMEOUT)
    coord = str(row.get('coord') or '').strip()
    old_ver = str(row.get('old_version') or '').strip()
    new_ver = str(row.get('new_version') or '').strip()
    repo_path = source_mapping.get("repo_path") or ""
    module_path = source_mapping.get("module_path") or repo_path
    overrides = dependency_git_ref_overrides.get(coord) or {}
    override_old_ref = str(overrides.get("old_ref") or "").strip()
    override_new_ref = str(overrides.get("new_ref") or "").strip()
    expected_old_commit = str(overrides.get("expected_old_commit") or "").strip()
    expected_new_commit = str(overrides.get("expected_new_commit") or "").strip()
    allow_local_source = bool(overrides.get("allow_local_source"))
    allow_dirty_local_source = bool(overrides.get("allow_dirty_local_source"))

    resolved_old_ref = resolved_new_ref = None
    old_reason = new_reason = ""
    old_candidates = []
    new_candidates = []
    reason = ""
    if not repo_path or not os.path.isdir(repo_path):
        reason = "源码路径未提供或不存在"
    elif not _is_git_worktree(repo_path, timeout=fetch_timeout):
        reason = "非 git 仓库"
    elif override_old_ref or override_new_ref:
        resolved_old_ref, old_reason, old_candidates = resolve_repo_ref_for_version(
            repo_path,
            old_ver,
            selected_ref=override_old_ref,
            expected_commit=expected_old_commit,
            remote_timeout=fetch_timeout,
            allow_local_source=allow_local_source,
            allow_dirty_local_source=allow_dirty_local_source,
        )
        resolved_new_ref, new_reason, new_candidates = resolve_repo_ref_for_version(
            repo_path,
            new_ver,
            selected_ref=override_new_ref,
            expected_commit=expected_new_commit,
            remote_timeout=fetch_timeout,
            allow_local_source=allow_local_source,
            allow_dirty_local_source=allow_dirty_local_source,
        )
    else:
        (
            resolved_old_ref,
            resolved_new_ref,
            old_reason,
            new_reason,
            old_candidates,
            new_candidates,
        ) = resolve_repo_ref_pair_for_versions(
            repo_path,
            old_ver,
            new_ver,
            remote_timeout=fetch_timeout,
        )

    module_rel_path = ""
    if module_path and repo_path:
        try:
            module_rel_path = Path(module_path).resolve().relative_to(Path(repo_path).resolve()).as_posix()
        except Exception:
            module_rel_path = ""

    common = {
        "coord": coord,
        "old_version": old_ver,
        "new_version": new_ver,
        "repo_path": os.path.abspath(repo_path) if repo_path else "",
        "module_path": os.path.abspath(module_path) if module_path else "",
        "module_rel_path": module_rel_path,
        "old_candidates": old_candidates,
        "new_candidates": new_candidates,
        "old_ref_override": override_old_ref,
        "new_ref_override": override_new_ref,
        "selected_old_ref": resolved_old_ref,
        "selected_new_ref": resolved_new_ref,
        "expected_old_commit": expected_old_commit,
        "expected_new_commit": expected_new_commit,
        "mapping_mode": source_meta.get("mapping_mode"),
        "local_fallback_available": {
            "old": _local_fallback_from_reason(old_reason),
            "new": _local_fallback_from_reason(new_reason),
        },
    }
    if reason or (not resolved_old_ref) or (not resolved_new_ref):
        return {
            **common,
            "status": "pending",
            "pending_kind": classify_git_ref_pending_kind(reason, old_reason, new_reason),
            "reason": reason or "无法定位对比 ref",
            "resolved_old_ref": resolved_old_ref,
            "resolved_new_ref": resolved_new_ref,
            "old_reason": old_reason,
            "new_reason": new_reason,
        }
    old_source = new_source = None
    old_materialize_error = new_materialize_error = ""
    if "user_confirmed_local_source" in str(old_reason):
        old_source = {
            "status": "user_confirmed_local_source",
            "resolved_ref": override_old_ref,
            "resolved_commit": resolved_old_ref,
        }
    else:
        old_source, old_materialize_error = _materialize_resolved_remote_ref(
            repo_path,
            resolved_old_ref,
            old_candidates,
            expected_commit=expected_old_commit,
            fetch_timeout=fetch_timeout,
        )
    if "user_confirmed_local_source" in str(new_reason):
        new_source = {
            "status": "user_confirmed_local_source",
            "resolved_ref": override_new_ref,
            "resolved_commit": resolved_new_ref,
        }
    else:
        new_source, new_materialize_error = _materialize_resolved_remote_ref(
            repo_path,
            resolved_new_ref,
            new_candidates,
            expected_commit=expected_new_commit,
            fetch_timeout=fetch_timeout,
        )

    # Fetching a remotely selected ref and using a local object are separate
    # phases.  A local object is only adopted after explicit authorization;
    # otherwise it is attached as informational fallback evidence while the
    # remote failure remains the primary status.
    local_fallback_available = dict(common["local_fallback_available"])
    for side in ("old", "new"):
        source = old_source if side == "old" else new_source
        materialize_error = old_materialize_error if side == "old" else new_materialize_error
        if not materialize_error or str((source or {}).get("status") or "") == "remote_ref_moved":
            continue
        selected = (
            (override_old_ref or resolved_old_ref)
            if side == "old"
            else (override_new_ref or resolved_new_ref)
        )
        local = resolve_local_source_ref(
            repo_path,
            selected,
            allow_local_source=allow_local_source,
            allow_dirty_local_source=allow_dirty_local_source,
        )
        fallback_info = _local_fallback_from_reason(
            _with_local_fallback_details("fetch_failed", local)
        )
        if fallback_info:
            local_fallback_available[side] = fallback_info
        if local.get("status") != "user_confirmed_local_source":
            continue
        local_reason = (
            "selected_by_user("
            f"kind=user_confirmed_local_source,score=-1,version="
            f"{old_ver if side == 'old' else new_ver})"
        )
        if side == "old":
            old_source = local
            old_materialize_error = ""
            old_reason = local_reason
        else:
            new_source = local
            new_materialize_error = ""
            new_reason = local_reason

    if old_materialize_error or new_materialize_error:
        def refresh_moved_candidates(candidates, selected_ref, source):
            observed = str((source or {}).get("observed_commit") or "")
            if str((source or {}).get("status") or "") != "remote_ref_moved":
                return list(candidates or [])
            return [
                ({**candidate, "commit": observed} if observed else None)
                if str(candidate.get("ref") or "") == str(selected_ref or "")
                else candidate
                for candidate in (candidates or [])
                if str(candidate.get("ref") or "") != str(selected_ref or "") or observed
            ]

        displayed_old_candidates = refresh_moved_candidates(old_candidates, resolved_old_ref, old_source)
        displayed_new_candidates = refresh_moved_candidates(new_candidates, resolved_new_ref, new_source)
        failure_sources = [
            source for source, error in (
                (old_source, old_materialize_error),
                (new_source, new_materialize_error),
            )
            if error and isinstance(source, dict)
        ]
        failure_statuses = {str(source.get("status") or "") for source in failure_sources}
        if "remote_ref_moved" in failure_statuses:
            pending_kind = "remote_ref_moved"
        else:
            pending_kind = "fetch_failed"
        failed_sides = []
        if old_materialize_error:
            failed_sides.append("old")
        if new_materialize_error:
            failed_sides.append("new")
        return {
            **common,
            "local_fallback_available": local_fallback_available,
            "status": "pending",
            "pending_kind": pending_kind,
            "reason": "远程源码无法固定",
            "failed_sides": failed_sides,
            "resolved_old_ref": None if old_materialize_error else (old_source or {}).get("resolved_commit"),
            "resolved_new_ref": None if new_materialize_error else (new_source or {}).get("resolved_commit"),
            "old_reason": old_materialize_error or old_reason,
            "new_reason": new_materialize_error or new_reason,
            "old_source": old_source or {},
            "new_source": new_source or {},
            "old_candidates": displayed_old_candidates,
            "new_candidates": displayed_new_candidates,
        }
    return {
        **common,
        "local_fallback_available": local_fallback_available,
        "status": "matched",
        "api_changes": 0,
        "behavior_changed": 0,
        "structural_source_changes": 0,
        "out_file": "",
        "base_ref": old_source.get("resolved_commit"),
        "cur_ref": new_source.get("resolved_commit"),
        "ref_source": "preflight",
        "old_source": old_source,
        "new_source": new_source,
        "old_match_reason": old_reason,
        "new_match_reason": new_reason,
    }


def preflight_gitdiff_refs(
    dep_rows,
    dependency_paths,
    dependency_path_meta,
    dependency_git_ref_overrides,
    *,
    fetch_timeout=DEFAULT_FETCH_TIMEOUT,
):
    matched = []
    pending = []
    for row in dep_rows:
        coord = str((row or {}).get("coord") or "").strip()
        source_mapping = dependency_paths.get(coord) or {}
        if not dependency_needs_gitdiff_preflight(row, source_mapping):
            continue
        plan = resolve_gitdiff_ref_plan_for_row(
            row,
            source_mapping,
            dependency_path_meta.get(coord) or {},
            dependency_git_ref_overrides,
            fetch_timeout=fetch_timeout,
        )
        if plan.get("status") == "matched":
            matched.append(plan)
        else:
            pending.append(plan)
    return matched, pending


def partition_git_ref_pending_items(pending_items):
    """Keep only result-changing source ambiguities as user checkpoints.

    Source git diff is auxiliary to the final-artifact JAR comparison.  Remote
    query/fetch failures, moved refs after controlled retries, missing matches,
    and unusable local fallbacks are operational failures; asking the user to
    repair them would leak internal implementation work into the interaction.
    Those cases are therefore recorded as an explicit source-evidence gap while
    binary analysis continues.  A user checkpoint is reserved for two or more
    concrete commit pairs, where choosing a pair changes the source diff range.
    """
    user_confirmation = []
    internally_skipped = []
    for pending_item in pending_items or []:
        item = dict(pending_item or {})
        pending_kind = str(item.get("pending_kind") or "").strip() or classify_git_ref_pending_kind(
            item.get("reason"), item.get("old_reason"), item.get("new_reason")
        )
        pair_options = build_git_ref_pair_options(item, limit=0)
        is_result_changing_ambiguity = pending_kind == "ambiguous" and len(pair_options) > 1
        if is_result_changing_ambiguity:
            item["pending_kind"] = pending_kind
            user_confirmation.append(item)
            continue

        internal_reason_by_kind = {
            "fetch_failed": "远端源码拉取在受控重试后仍不可用",
            "remote_query_failed": "远端源码版本查询在受控重试后仍不可用",
            "remote_ref_moved": "远端源码分支在校验期间发生变化，无法固定为可复现提交",
            "remote_unavailable": "远端源码仓库当前不可用",
            "not_found": "未能稳定定位与依赖版本对应的远端源码提交",
            "local_confirmation_required": "本地源码不能在未授权的情况下作为远端源码替代",
            "ambiguous": "未形成两个以上可供可靠选择的完整源码提交范围",
        }
        internally_skipped.append({
            **item,
            "status": "skipped",
            "pending_kind": pending_kind,
            "origin_step": "step4",
            "reason_code": DEPENDENCY_SOURCE_REF_UNAVAILABLE,
            "reason_code_aliases": [],
            "diagnostic_guidance_schema": REASON_GUIDANCE_SCHEMA,
            "diagnostic_guidance": guidance_for_reason_code(
                DEPENDENCY_SOURCE_REF_UNAVAILABLE
            ),
            "reason": (
                f"{internal_reason_by_kind.get(pending_kind, '依赖源码版本无法可靠固定')}；"
                "已跳过源码行为差异辅助分析，将使用最终制品 JAR 完成二进制与方法字节码分析"
            ),
            "resolution": "continue_with_final_artifact_analysis",
            "user_attention_required": False,
            "evidence_impact": "源码证据暂缺；等待最终 JAR 方法字节码兜底结果",
            "ref_pair_options": pair_options,
        })
    return user_confirmation, internally_skipped


def write_git_ref_pending_file(output_dir, pending_items):
    pending_refs_path = os.path.join(output_dir, "git_ref_pending.json")
    serialized_items = []
    for pending_item in pending_items or []:
        item = dict(pending_item or {})
        item["user_reason"] = describe_git_ref_pending_item(item)
        item["ref_pair_options"] = build_git_ref_pair_options(item, limit=0)
        serialized_items.append(item)
    with open(pending_refs_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "schema": "java-upgrade-analyzer.step4-git-ref-pending.v2",
                "generated_at": datetime.now().isoformat(),
                "items": serialized_items,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )
    return pending_refs_path


def write_git_ref_preflight_summary(output_dir, pending_items, matched_items):
    summary_path = os.path.join(output_dir, "summary.txt")
    lines = [
        "Step4 依赖的新旧源码版本检查摘要",
        "",
        "一、结论总览",
        f"- 待确认的新旧源码版本：{len(pending_items or [])}",
        f"- 已自动匹配的新旧源码版本：{len(matched_items or [])}",
        "",
        "二、判断口径",
        "- Step4 会在正式分析前检查依赖的新旧版本能否唯一匹配到对应源码版本。",
        "- 待确认表示系统找到了多个或没有找到对应源码版本，不能自行决定对比范围。",
    ]
    if pending_items:
        lines += ["", f"三、待确认的新旧源码版本（前 {min(20, len(pending_items or []))} 项）"]
    for item in (pending_items or [])[:20]:
        lines.append("")
        lines.append(f"- {item.get('coord')}：{item.get('old_version')} -> {item.get('new_version')}")
        lines.append(f"  - 原因：{describe_git_ref_pending_item(item)}")
        lines.append(f"  - 仓库路径：{item.get('repo_path') or '-'}")
        old_candidates = item.get("old_candidates") or []
        new_candidates = item.get("new_candidates") or []
        lines.append(f"  - 旧版源码候选：{', '.join(c.get('ref', '') for c in old_candidates[:10]) or '无'}")
        lines.append(f"  - 新版源码候选：{', '.join(c.get('ref', '') for c in new_candidates[:10]) or '无'}")
        for option in build_git_ref_pair_options(item, limit=3):
            lines.append(
                f"  - 方案 {option.get('rank')}：{option.get('old_ref') or '-'} -> "
                f"{option.get('new_ref') or '-'}"
            )
    if len(pending_items or []) > 20:
        lines.append(f"\n...（仅展示前 20，共 {len(pending_items)}）")
    Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
    Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary_path


# ══════════════════════════════════════════════════════════════════
# 4b. 依赖源码 git diff
# ══════════════════════════════════════════════════════════════════

def run_gitdiff(lib_info, output_dir, git_diff_timeout=DEFAULT_GIT_DIFF_TIMEOUT):
    """
    对已提供源码仓库映射的依赖做 git diff，提取 public/protected API 变更。
    lib_info: {coord, repo_path, module_path, old_version, new_version}
    """
    coord      = lib_info['coord']
    repo_path  = lib_info.get('repo_path') or lib_info.get('lib_path', '')
    module_path = lib_info.get('module_path') or repo_path
    old_ver    = lib_info.get('old_version', '')
    new_ver    = lib_info.get('new_version', '')
    fetch_timeout = _bounded_git_timeout(
        lib_info.get("fetch_timeout", DEFAULT_FETCH_TIMEOUT),
        DEFAULT_FETCH_TIMEOUT,
    )
    git_diff_timeout = _bounded_git_timeout(
        git_diff_timeout,
        DEFAULT_GIT_DIFF_TIMEOUT,
    )
    artifact = _artifact_output_stem(coord)
    artifact_stem = bounded_path_component(
        artifact,
        max_length=64,
        default="dependency",
    )

    out_file = os.path.join(output_dir, f"{artifact_stem}_gitdiff_api_changes.txt")

    if not repo_path or not os.path.isdir(repo_path):
        msg = (
            f"=== 依赖源码路径未提供或不存在：{coord} ===\n"
            f"路径：{repo_path or '未提供'}\n\n"
            f"需要用户协助：\n"
            f"  请提供该依赖的本地源码路径，以便做 git diff 分析。\n"
            f"  如果没有本地源码，该依赖将只做 JApiCmp 字节码对比（4a 路径）。\n"
        )
        write_result(out_file, msg)
        return {
            "status": "error",
            "out_file": out_file,
            "apis": [],
            "error": "源码路径未提供",
            "meta": {},
        }

    if not _is_git_worktree(repo_path, timeout=fetch_timeout):
        msg = (
            f"=== 依赖源码目录不是 git 仓库：{coord} ===\n"
            f"路径：{os.path.abspath(repo_path)}\n\n"
            f"需要用户协助：\n"
            f"  1. 提供该依赖的 git 工作树根目录\n"
            f"  2. 或者仅使用 JApiCmp（二进制对比）路径\n"
        )
        write_result(out_file, msg)
        return {
            "status": "error",
            "out_file": out_file,
            "apis": [],
            "error": "非 git 仓库",
            "meta": {},
        }

    override_old_ref = str(lib_info.get("old_ref_override") or "").strip()
    override_new_ref = str(lib_info.get("new_ref_override") or "").strip()
    expected_old_commit = str(lib_info.get("expected_old_commit") or "").strip()
    expected_new_commit = str(lib_info.get("expected_new_commit") or "").strip()
    fixed_base_ref = str(lib_info.get("base_ref") or "").strip()
    fixed_cur_ref = str(lib_info.get("cur_ref") or "").strip()
    if fixed_base_ref and fixed_cur_ref:
        resolved_old_ref = fixed_base_ref
        resolved_new_ref = fixed_cur_ref
        old_reason = str(lib_info.get("old_match_reason") or "preflight_remote_commit")
        new_reason = str(lib_info.get("new_match_reason") or "preflight_remote_commit")
        old_candidates = []
        new_candidates = []
    elif override_old_ref or override_new_ref:
        resolved_old_ref, old_reason, old_candidates = resolve_repo_ref_for_version(
            repo_path,
            old_ver,
            selected_ref=override_old_ref,
            expected_commit=expected_old_commit,
            remote_timeout=fetch_timeout,
            allow_local_source=bool(lib_info.get("allow_local_source")),
            allow_dirty_local_source=bool(lib_info.get("allow_dirty_local_source")),
        )
        resolved_new_ref, new_reason, new_candidates = resolve_repo_ref_for_version(
            repo_path,
            new_ver,
            selected_ref=override_new_ref,
            expected_commit=expected_new_commit,
            remote_timeout=fetch_timeout,
            allow_local_source=bool(lib_info.get("allow_local_source")),
            allow_dirty_local_source=bool(lib_info.get("allow_dirty_local_source")),
        )
    else:
        (
            resolved_old_ref,
            resolved_new_ref,
            old_reason,
            new_reason,
            old_candidates,
            new_candidates,
        ) = resolve_repo_ref_pair_for_versions(
            repo_path,
            old_ver,
            new_ver,
            remote_timeout=fetch_timeout,
        )
    if (not resolved_old_ref) or (not resolved_new_ref):
        refs = _list_repo_refs(repo_path, timeout=fetch_timeout)
        sample_remotes = ", ".join(refs.get("remotes", [])[:15])
        msg = (
            f"=== 无法定位 git 对比 ref：{coord} ===\n"
            f"版本：{old_ver} → {new_ver}\n"
            f"分支匹配版本：old={_normalize_version_text(old_ver) or '-'} new={_normalize_version_text(new_ver) or '-'}\n"
            f"version 匹配结果：old={resolved_old_ref or '(未命中)'} ({old_reason or '-'}) "
            f"new={resolved_new_ref or '(未命中)'} ({new_reason or '-'})\n\n"
            f"已发现远端分支（仅展示前 15 个）：\n"
            f"  remotes: {sample_remotes or '(无)'}\n\n"
            f"说明：当前按远端分支或 tag 匹配；只去掉版本号末尾的 -SNAPSHOT 后，"
            f"按“ref 名包含版本号”筛选候选，且分支优先于 tag、非 DEV ref 优先于 DEV ref。\n"
            f"请修复：在该依赖仓库中提供名称包含版本号的远端分支或 tag"
            f"（常见：origin/release-{_normalize_version_text(old_ver) or old_ver}）。\n"
        )
        write_result(out_file, msg)
        return {
            "status": "needs_user_confirmation",
            "out_file": out_file,
            "apis": [],
            "error": "无法定位对比 ref",
            "meta": {
                "coord": coord,
                "repo_path": os.path.abspath(repo_path),
                "module_path": os.path.abspath(module_path) if module_path else os.path.abspath(repo_path),
                "resolved_old_ref": resolved_old_ref,
                "resolved_new_ref": resolved_new_ref,
                "old_reason": old_reason,
                "new_reason": new_reason,
                "old_candidates": old_candidates,
                "new_candidates": new_candidates,
                "old_version": old_ver,
                "new_version": new_ver,
                "old_ref_override": override_old_ref,
                "new_ref_override": override_new_ref,
                "reason": "无法定位对比 ref",
            },
        }

    if not (fixed_base_ref and fixed_cur_ref):
        if "user_confirmed_local_source" not in str(old_reason):
            old_source, error = _materialize_resolved_remote_ref(
                repo_path,
                resolved_old_ref,
                old_candidates,
                expected_commit=expected_old_commit,
                fetch_timeout=fetch_timeout,
            )
            if error:
                return {
                    "status": "needs_user_confirmation",
                    "out_file": out_file,
                    "apis": [],
                    "error": "远程旧版本源码无法固定",
                    "meta": {"coord": coord, "reason": error, "old_candidates": old_candidates, "new_candidates": new_candidates},
                }
            resolved_old_ref = old_source.get("resolved_commit")
        if "user_confirmed_local_source" not in str(new_reason):
            new_source, error = _materialize_resolved_remote_ref(
                repo_path,
                resolved_new_ref,
                new_candidates,
                expected_commit=expected_new_commit,
                fetch_timeout=fetch_timeout,
            )
            if error:
                return {
                    "status": "needs_user_confirmation",
                    "out_file": out_file,
                    "apis": [],
                    "error": "远程新版本源码无法固定",
                    "meta": {"coord": coord, "reason": error, "old_candidates": old_candidates, "new_candidates": new_candidates},
                }
            resolved_new_ref = new_source.get("resolved_commit")
    base_ref = resolved_old_ref
    cur_ref = resolved_new_ref
    ref_source = "preflight_fixed_commit" if fixed_base_ref and fixed_cur_ref else "version_fixed_commit"
    module_rel_path = ""
    if module_path:
        try:
            module_rel_path = Path(module_path).resolve().relative_to(Path(repo_path).resolve()).as_posix()
        except Exception:
            module_rel_path = ""

    diff_cmd_primary = git_cmd() + [
        'diff', '--no-ext-diff', '--no-textconv', '--no-color',
        '--function-context', '-U0', f'{base_ref}..{cur_ref}', '--',
    ]
    if module_rel_path and module_rel_path != '.':
        diff_cmd_primary.append(module_rel_path)
    else:
        diff_cmd_primary.extend(['*.java', '*.kt'])
    stdout, _stderr, rc = run_cmd(diff_cmd_primary, cwd=repo_path, timeout=git_diff_timeout)
    diff_cmd_used = diff_cmd_primary
    if rc != 0:
        diff_cmd_fallback = git_cmd() + [
            'diff', '--no-ext-diff', '--no-textconv', '--no-color',
            '-U20', f'{base_ref}..{cur_ref}', '--',
        ]
        if module_rel_path and module_rel_path != '.':
            diff_cmd_fallback.append(module_rel_path)
        else:
            diff_cmd_fallback.extend(['*.java', '*.kt'])
        stdout2, stderr2, rc2 = run_cmd(diff_cmd_fallback, cwd=repo_path, timeout=git_diff_timeout)
        if rc2 != 0:
            write_result(out_file, f"git diff 执行失败（退出码 {rc2}）：{stderr2}")
            error_text = stderr2[:100]
            if rc2 == -1 and '超时' in (stderr2 or ''):
                error_text = f"git diff 超时({git_diff_timeout}s)"
            return {
                "status": "error",
                "out_file": out_file,
                "apis": [],
                "error": error_text,
                "meta": {
                    "coord": coord,
                    "base_ref": base_ref,
                    "cur_ref": cur_ref,
                    "ref_source": ref_source,
                    "resolved_old_ref": resolved_old_ref,
                    "resolved_new_ref": resolved_new_ref,
                    "old_reason": old_reason,
                    "new_reason": new_reason,
                    "old_candidates": old_candidates,
                    "new_candidates": new_candidates,
                    "old_version": old_ver,
                    "new_version": new_ver,
                    "repo_path": os.path.abspath(repo_path),
                    "module_path": os.path.abspath(module_path) if module_path else os.path.abspath(repo_path),
                    "module_rel_path": module_rel_path or ".",
                    "timed_out": rc2 == -1 and '超时' in (stderr2 or ''),
                    "reason": error_text,
                },
            }
        stdout, _stderr, rc = stdout2, stderr2, rc2
        diff_cmd_used = diff_cmd_fallback
    diff_output = stdout or ""

    if not diff_output:
        write_result(out_file, f"=== {coord} ===\n两分支间无 Java/Kotlin 文件差异。\n")
        return {
            "status": "success",
            "out_file": out_file,
            "apis": [],
            "error": None,
            "meta": {
                "coord": coord,
                "base_ref": base_ref,
                "cur_ref": cur_ref,
                "ref_source": ref_source,
                "resolved_old_ref": resolved_old_ref,
                "resolved_new_ref": resolved_new_ref,
                "old_reason": old_reason,
                "new_reason": new_reason,
                "old_candidates": old_candidates,
                "new_candidates": new_candidates,
                "old_version": old_ver,
                "new_version": new_ver,
                "repo_path": os.path.abspath(repo_path),
                "module_path": os.path.abspath(module_path) if module_path else os.path.abspath(repo_path),
                "module_rel_path": module_rel_path or ".",
            },
        }

    # 完整保留 diff 输出
    header = (
        f"=== 依赖源码 git diff：{coord} ===\n"
        f"对比 ref：{base_ref} .. {cur_ref}  ref_source={ref_source}\n"
        f"版本：{old_ver} → {new_ver}\n"
        f"版本匹配：old={old_reason or '-'} new={new_reason or '-'}\n"
        f"命令：{' '.join(diff_cmd_used)}\n"
        f"仓库目录：{os.path.abspath(repo_path)}\n"
        f"模块目录：{os.path.abspath(module_path) if module_path else os.path.abspath(repo_path)}\n"
        f"模块相对路径：{module_rel_path or '.'}\n"
        f"执行时间：{datetime.now().isoformat()}\n"
        f"{'='*60}\n\n"
    )
    write_result(out_file, header + diff_output)

    # 提取 API 变更（签名变化 + public/protected 方法体变化）
    apis = parse_gitdiff_apis(diff_output, coord, old_ver, new_ver)
    return {
        "status": "success",
        "out_file": out_file,
        "apis": apis,
        "error": None,
        "meta": {
            "coord": coord,
            "base_ref": base_ref,
            "cur_ref": cur_ref,
            "ref_source": ref_source,
            "repo_path": os.path.abspath(repo_path),
            "module_path": os.path.abspath(module_path) if module_path else os.path.abspath(repo_path),
            "module_rel_path": module_rel_path or ".",
            "resolved_old_ref": resolved_old_ref,
            "resolved_new_ref": resolved_new_ref,
            "old_reason": old_reason,
            "new_reason": new_reason,
            "old_candidates": old_candidates,
            "new_candidates": new_candidates,
            "old_version": old_ver,
            "new_version": new_ver,
        },
    }


def write_git_ref_match_outputs(
    output_dir,
    gitdiff_runs=None,
    gitdiff_skipped=None,
    gitdiff_pending=None,
    source_repo_mappings=None,
):
    gitdiff_runs = gitdiff_runs or []
    gitdiff_skipped = gitdiff_skipped or []
    gitdiff_pending = gitdiff_pending or []
    source_repo_mappings = source_repo_mappings or []

    json_path = os.path.join(output_dir, "git_ref_matches.json")
    txt_path = os.path.join(output_dir, "git_ref_matches.txt")

    needs_user_confirmation = bool(gitdiff_pending)
    payload = {
        "generated_at": datetime.now().isoformat(),
        "need_user_confirmation": needs_user_confirmation,
        "summary": {
            "matched": len(gitdiff_runs),
            "skipped": len(gitdiff_skipped),
            "pending": len(gitdiff_pending),
            "source_repo_mappings": len(source_repo_mappings),
        },
        "source_repo_mappings": source_repo_mappings,
        "matched_items": gitdiff_runs,
        "skipped_items": gitdiff_skipped,
        "pending_items": gitdiff_pending,
    }
    write_result(json_path, json.dumps(payload, ensure_ascii=False, indent=2))

    lines = []
    if needs_user_confirmation:
        lines.append("Step4 依赖的新旧源码版本匹配结果（需要确认）")
    else:
        lines.append("Step4 依赖源码版本解析结果（无需用户确认）")
    lines.append("")
    lines.append("一、结论总览")
    lines.append(f"- 已匹配：{len(gitdiff_runs)}")
    lines.append(f"- 待确认：{len(gitdiff_pending)}")
    lines.append(f"- 未匹配/跳过：{len(gitdiff_skipped)}")
    lines.append(f"- 源码仓库映射：{len(source_repo_mappings)}")
    lines.append(f"- 生成时间：{payload['generated_at']}")
    lines.append("")
    lines.append("二、判断口径")
    lines.append("- 依赖的新旧版本与源码版本的匹配结果会直接决定源码实现对比范围。")
    lines.append(
        "- 当前自动匹配策略：仅扫描远端分支 remotes；"
        "只去掉版本号末尾的 -SNAPSHOT 后，按分支名包含版本号命中；非 DEV 分支优先于 DEV 分支。"
    )
    if needs_user_confirmation:
        lines.append("- 当前存在待确认项；这些依赖的源码实现对比范围尚未确定。")
    elif gitdiff_skipped:
        lines.append(
            "- 当前没有需要用户处理的歧义；内部源码解析故障已自动降级并记录，"
            "最终制品 JAR 二进制分析继续执行。"
        )
    else:
        lines.append("- 当前没有待确认项；可按需抽查依赖、源码仓库和新旧源码版本是否符合预期。")
    lines.append("")
    lines.append("三、源码仓库映射")
    for item in source_repo_mappings:
        lines.append(
            f"- {item.get('coord')}：仓库={item.get('repo_path')}；输入={item.get('input_spec') or '自动发现'}；映射方式={item.get('mapping_mode') or '-'}"
        )
        if item.get("module_path"):
            lines.append(f"  - 模块路径：{item.get('module_path')}")
        repo_coords = item.get("repo_inferred_coords") or []
        lines.append(f"  - 仓库内识别到的坐标：{', '.join(repo_coords[:10]) or '无'}")
    if not source_repo_mappings:
        lines.append("- (无)")
    lines.append("")
    lines.append("四、已匹配 ref")
    for item in gitdiff_runs:
        lines.append(
            f"- {item.get('coord')}：版本={item.get('old_version')} -> {item.get('new_version')}；"
            f"ref={item.get('base_ref')}..{item.get('cur_ref')}；"
            f"匹配原因=old[{item.get('old_match_reason') or '-'}]，new[{item.get('new_match_reason') or '-'}]"
        )
        if item.get("repo_path"):
            lines.append(f"  - 仓库路径：{item.get('repo_path')}")
        if item.get("module_path"):
            lines.append(f"  - 模块路径：{item.get('module_path')}")
        if item.get("module_rel_path"):
            lines.append(f"  - 模块相对路径：{item.get('module_rel_path')}")
        old_candidates = item.get("old_candidates") or []
        new_candidates = item.get("new_candidates") or []
        lines.append(f"  - old 候选 refs：{', '.join(c.get('ref', '') for c in old_candidates[:10]) or '无'}")
        lines.append(f"  - new 候选 refs：{', '.join(c.get('ref', '') for c in new_candidates[:10]) or '无'}")
    if not gitdiff_runs:
        lines.append("- (无)")
    lines.append("")
    lines.append("五、待确认 ref")
    for item in gitdiff_pending:
        lines.append(
            f"- {item.get('coord')}：版本={item.get('old_version')} -> {item.get('new_version')}；原因={item.get('reason') or '-'}"
        )
        old_candidates = item.get("old_candidates") or []
        new_candidates = item.get("new_candidates") or []
        lines.append(f"  - old 候选 refs：{', '.join(c.get('ref', '') for c in old_candidates[:10]) or '无'}")
        lines.append(f"  - new 候选 refs：{', '.join(c.get('ref', '') for c in new_candidates[:10]) or '无'}")
    if not gitdiff_pending:
        lines.append("- (无)")
    lines.append("")
    lines.append("六、未匹配/跳过")
    for item in gitdiff_skipped:
        lines.append(
            f"- {item.get('coord')}：版本={item.get('old_version')} -> {item.get('new_version')}；原因={item.get('reason') or '-'}"
        )
        if item.get("behavior_fallback_status") == "complete":
            lines.append(
                "  - 恢复结果：最终 JAR 方法字节码对比已完成，源码行为证据缺口已补齐；"
                f"证据={item.get('behavior_fallback_evidence') or '-'}"
            )
        old_candidates = item.get("old_candidates") or []
        new_candidates = item.get("new_candidates") or []
        if old_candidates:
            lines.append(f"  - old 候选 refs：{', '.join(c.get('ref', '') for c in old_candidates[:10])}")
        if new_candidates:
            lines.append(f"  - new 候选 refs：{', '.join(c.get('ref', '') for c in new_candidates[:10])}")
    if not gitdiff_skipped:
        lines.append("- (无)")
    write_result(txt_path, "\n".join(lines) + "\n")
    return json_path, txt_path


def parse_gitdiff_apis(diff_output, coord, old_ver='', new_ver=''):
    """从 git diff 提取 public/protected API 变更和行为变更（支持 Java 和 Kotlin）"""
    apis = []
    removed_methods = []
    added_methods = []
    seen_methods_by_id = {}
    body_changed_minus = set()
    body_changed_plus = set()
    current_package = ''
    class_scope_stack = []
    brace_depth = 0

    # Java 方法签名模式
    # 分组: 1=前缀(+/-), 2=方法名
    sig_pattern_java = re.compile(
        r'^([ +\-])\s*(?:public|protected|private)\s+'
        r'(?:static\s+|final\s+|abstract\s+|synchronized\s+|default\s+)*'
        r'(?:<[^>]+>\s+)?'
        r'(?:[\w<>\[\],.?@]+\s+)?'    # 返回类型
        r'(\w+)\s*\('             # 方法名
    )

    # Kotlin 方法签名模式（支持 fun 关键字）
    # 分组: 1=前缀(+/-), 2=方法名（与Java正则保持一致）
    sig_pattern_kotlin = re.compile(
        r'^([ +\-])\s*'
        r'(?:(?:public|protected|private|internal)\s+)?'
        r'(?:(?:open|abstract|override|final|suspend|inline|operator|infix|tailrec|external)\s+)*'
        r'fun\s+'
        r'(?:<[^>]+>\s+)?'
        r'(\w+)\s*\('
    )

    class_decl_pattern = re.compile(
        r'^[ +\-]\s*'
        r'(?:(?:public|protected|private|internal)\s+)?'
        r'(?:(?:abstract|final|sealed|non-sealed|static|strictfp|open|data|inner|value)\s+)*'
        r'(?:class|interface|enum|object|record|@interface)\s+'
        r'([A-Za-z_$][\w$]*)\b'
    )

    current_file = ''
    current_class = ''
    current_method = None
    is_kotlin_file = False
    skip_current_file = False

    def normalize_signature_for_compare(signature_line):
        declaration = re.split(r'\{', signature_line, maxsplit=1)[0]
        declaration = re.split(r'=', declaration, maxsplit=1)[0]
        declaration = re.sub(r'\s+', ' ', declaration).strip()
        return declaration

    def collect_declaration_block(diff_lines, start_index):
        current_line = diff_lines[start_index]
        block_parts = [current_line[1:].strip()]
        balance = current_line.count('(') - current_line.count(')')
        if balance <= 0:
            return ' '.join(part for part in block_parts if part).strip()
        for look_ahead in range(start_index + 1, len(diff_lines)):
            next_line = diff_lines[look_ahead]
            if next_line.startswith(('diff --git ', '@@', 'index ', '---', '+++')):
                break
            if next_line[:1] not in {' ', '+', '-'}:
                break
            stripped_next = strip_diff_prefix(next_line).strip()
            block_parts.append(stripped_next)
            balance += next_line.count('(') - next_line.count(')')
            if balance <= 0:
                break
        return ' '.join(part for part in block_parts if part).strip()

    def build_class_fqcn():
        if not class_scope_stack:
            if not current_class:
                return ''
            nested = current_class
        else:
            nested = '.'.join(item['name'] for item in class_scope_stack)
        return f"{current_package}.{nested}" if current_package else nested

    def strip_diff_prefix(raw_line):
        if raw_line.startswith(('+++', '---')):
            return ''
        if raw_line[:1] in {'+', '-', ' '}:
            return raw_line[1:]
        return raw_line

    def sanitize_for_brace_count(text):
        if not text:
            return ''
        text = re.sub(r'//.*', '', text)
        text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
        text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
        return text

    def update_class_scope_depth(brace_text):
        nonlocal brace_depth, current_class
        brace_depth += brace_text.count('{') - brace_text.count('}')
        while class_scope_stack and brace_depth < class_scope_stack[-1]['depth']:
            class_scope_stack.pop()
        if class_scope_stack:
            current_class = class_scope_stack[-1]['name']

    diff_lines = diff_output.splitlines()
    for idx, line in enumerate(diff_lines):
        if line.startswith('diff --git '):
            m = re.search(r'^diff --git a/(.+?) b/(.+)$', line)
            if m:
                current_file = (m.group(2) or '').strip()
                base = os.path.basename(current_file)
                skip_current_file = should_skip_gitdiff_path(current_file)
                if base.endswith('.java'):
                    current_class = base[:-5]
                    class_scope_stack = []
                    current_package = infer_package_from_source_path(current_file)
                    is_kotlin_file = False
                elif base.endswith('.kt'):
                    current_class = base[:-3]
                    class_scope_stack = []
                    current_package = infer_package_from_source_path(current_file)
                    is_kotlin_file = True
                else:
                    current_class = ''
                    class_scope_stack = []
                    current_package = ''
                    is_kotlin_file = False
                current_method = None
                brace_depth = 0
            continue
        if skip_current_file:
            continue
        if line.startswith(('index ', '---', '+++')):
            continue
        if line.startswith('@@'):
            current_method = None
            continue

        package_m = re.search(r'^[ +\-]\s*package\s+([\w.]+)\s*;', line)
        if package_m and not line.startswith('---') and not line.startswith('+++'):
            current_package = package_m.group(1)
            continue

        # Kotlin package 格式: package com.example.foo
        if is_kotlin_file:
            kotlin_package_m = re.search(r'^[ +\-]\s*package\s+([\w.]+)\s*$', line)
            if kotlin_package_m and not line.startswith('---') and not line.startswith('+++'):
                current_package = kotlin_package_m.group(1)
                continue

        stripped_line = strip_diff_prefix(line)
        brace_probe = sanitize_for_brace_count(stripped_line)

        # 追踪当前类名（Java 和 Kotlin 都支持）
        class_m = class_decl_pattern.search(line)
        if class_m and not line.startswith('---') and not line.startswith('+++'):
            current_class = class_m.group(1)
            if not class_scope_stack or class_scope_stack[-1]['name'] != current_class:
                class_scope_stack.append({
                    'name': current_class,
                    'depth': brace_depth + max(brace_probe.count('{') - brace_probe.count('}'), 1),
                })

        # 尝试匹配 Java 或 Kotlin 方法签名
        if is_kotlin_file:
            m = sig_pattern_kotlin.match(line)
        else:
            m = sig_pattern_java.match(line)

        if not m:
            if (
                line.startswith(('+', '-'))
                and not line.startswith(('+++', '---'))
                and current_class
                and current_method
            ):
                stripped = line[1:].strip()
                if stripped and not stripped.startswith(('//', '*', '/*', '@')):
                    if line.startswith('-'):
                        body_changed_minus.add(current_method['method_id'])
                    elif line.startswith('+'):
                        body_changed_plus.add(current_method['method_id'])
            update_class_scope_depth(brace_probe)
            continue

        # 【关键修复】统一使用 group(1) 和 group(2)
        # Java/Kotlin 正则现在都有2个分组：1=前缀(+/-), 2=方法名
        prefix = m.group(1)
        method_name = m.group(2)
        full_sig = collect_declaration_block(diff_lines, idx)
        class_fqcn = build_class_fqcn()
        key = f"{class_fqcn}.{method_name}" if class_fqcn else (
            f"{current_class}.{method_name}" if current_class else method_name
        )
        api_signature = extract_api_signature_from_declaration(full_sig)
        method_id = f"{key}{api_signature}" if api_signature else key
        current_method = {
            'api_name': key,
            'symbol_kind': infer_method_symbol_kind_from_api_name(key),
            'api_signature': api_signature,
            'method_id': method_id,
        }
        seen_methods_by_id[method_id] = dict(current_method)

        if prefix == '-':
            removed_methods.append({
                'api_name': key,
                'api_signature': api_signature,
                'full_sig': full_sig,
                'compare_sig': normalize_signature_for_compare(full_sig),
                'method_id': method_id,
            })
        elif prefix == '+':
            added_methods.append({
                'api_name': key,
                'api_signature': api_signature,
                'full_sig': full_sig,
                'compare_sig': normalize_signature_for_compare(full_sig),
                'method_id': method_id,
            })

        update_class_scope_depth(brace_probe)

    # 只在 - 出现但 + 未出现的方法 = 真正被删除
    added_methods_by_name = {}
    for item in added_methods:
        added_methods_by_name.setdefault(item['api_name'], []).append(item)
    removed_method_ids = {item['method_id'] for item in removed_methods}
    added_method_ids = {item['method_id'] for item in added_methods}

    for removed in removed_methods:
        key = removed['api_name']
        api_signature = removed['api_signature']
        compare_sig = removed['compare_sig']

        # 检查该方法是否在 added 中也有
        same_name_added = added_methods_by_name.get(key, [])
        if same_name_added:
            same_signature_added = [item for item in same_name_added if item.get('api_signature') == api_signature]
            if same_signature_added and any(item['compare_sig'] == compare_sig for item in same_signature_added):
                change_type = 'BEHAVIOR_CHANGED'
            else:
                change_type = 'SIGNATURE_CHANGED'
        else:
            change_type = 'REMOVED'

        method_name = key.split('.')[-1]

        row = {
            'coord':       coord,
            'old_version': old_ver,
            'new_version': new_ver,
            'change_type': change_type,
            'api_name':    key,
            'api_simple':  method_name,
            'symbol_kind': removed.get('symbol_kind', infer_method_symbol_kind_from_api_name(key)),
            'api_signature': api_signature,
            'confirmed':   'true',   # git diff 确认，可靠
            'severity':    DEFAULT_SEVERITY.get(change_type, 'P1'),
            'source':      'gitdiff',
        }
        errors = validate_row(row)
        if not errors:
            apis.append(row)

    # public/protected 方法体变化（签名未变）
    behavior_changed = sorted(
        (body_changed_minus & body_changed_plus) - removed_method_ids - added_method_ids
    )
    for method_id in behavior_changed:
        method_info = seen_methods_by_id.get(method_id)
        if not method_info:
            continue
        key = method_info['api_name']
        method_name = key.split('.')[-1]
        row = {
            'coord':       coord,
            'old_version': old_ver,
            'new_version': new_ver,
            'change_type': 'BEHAVIOR_CHANGED',
            'api_name':    key,
            'api_simple':  method_name,
            'symbol_kind': method_info.get('symbol_kind', infer_method_symbol_kind_from_api_name(key)),
            'api_signature': method_info.get('api_signature', ''),
            'confirmed':   'true',   # 源码 diff 直接确认方法体有变化
            'severity':    DEFAULT_SEVERITY['BEHAVIOR_CHANGED'],
            'source':      'gitdiff',
        }
        errors = validate_row(row)
        if not errors:
            apis.append(row)

    return apis


# ══════════════════════════════════════════════════════════════════
# 4c. changelog 行为变更（需人工后续验证）
# ══════════════════════════════════════════════════════════════════

def analyze_changelog(coord, old_ver, new_ver, output_dir):
    """
    记录需要做 changelog 分析的条目。
    实际的联网查询由 AI（thirdparty agent）完成，这里只生成任务文件。
    AI 完成后将结果追加写入 behavior.txt 并更新 all_changed_apis.csv。
    """
    artifact = _artifact_output_stem(coord)
    safe = artifact.replace('.', '-')
    behavior_stem = bounded_path_component(
        f"{safe}_{old_ver}_vs_{new_ver}",
        max_length=72,
        default="dependency-behavior",
    )
    out_file = os.path.join(output_dir, f"{behavior_stem}_behavior.txt")

    content = (
        f"=== changelog 行为变更分析任务：{coord} ===\n"
        f"旧版本：{old_ver}  新版本：{new_ver}\n"
        f"状态：待分析\n\n"
        f"分析要点（AI 执行时需要回答）：\n"
        f"  1. 官方 changelog/release notes URL：\n"
        f"  2. 大版本升级时，至少查阅 2 个独立来源\n"
        f"  3. 重点关注以下类型的行为变更关键词：\n"
        f"     - default behavior changed\n"
        f"     - null handling\n"
        f"     - encoding / charset\n"
        f"     - exception type changed\n"
        f"     - sort order / precision\n\n"
        f"分析结果（AI 填写后追加到此处）：\n"
        f"  [待填写]\n\n"
        f"注意：changelog 来源的变更 confirmed=false，\n"
        f"      在报告中标注「需人工运行时验证」。\n"
    )
    write_result(out_file, content)
    return out_file


# ══════════════════════════════════════════════════════════════════
# 汇总写入 all_changed_apis.csv
# ══════════════════════════════════════════════════════════════════

def write_all_changed_apis(all_apis, output_dir):
    """
    写入 all_changed_apis.csv，验证每行数据合法性。
    这是 Step 5 的核心输入，格式必须严格正确。
    """
    raw_out_file = os.path.join(output_dir, 'all_changed_apis_raw.csv')
    out_file = os.path.join(output_dir, 'all_changed_apis.csv')
    invalid_rows = []
    valid_rows = []

    for row in all_apis:
        errors = validate_row(row)
        if errors:
            invalid_rows.append({'row': row, 'errors': errors})
        else:
            valid_rows.append(_enrich_changed_api_row(row))

    if invalid_rows:
        print(f"\n⚠️  {len(invalid_rows)} 行数据未通过契约验证，已跳过：",
              file=sys.stderr)
        for item in invalid_rows[:5]:
            print(f"  {item['row'].get('api_name', '?')}: "
                  f"{'; '.join(item['errors'])}", file=sys.stderr)

    with open_csv_write(raw_out_file) as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS)
        writer.writeheader()
        writer.writerows(valid_rows)

    normalized_rows = _enrich_changed_api_rows(normalize_step5_input_rows(valid_rows))
    with open_csv_write(out_file) as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS)
        writer.writeheader()
        writer.writerows(normalized_rows)

    return out_file, len(normalized_rows), len(invalid_rows)


def _dependency_name_from_coord(coord):
    parts = [part.strip() for part in str(coord or "").split(":")]
    return parts[1] if len(parts) >= 2 else ""


def _is_high_risk_api_row(row):
    severity = str((row or {}).get("severity") or "").strip().upper()
    change_type = str((row or {}).get("change_type") or "").strip().lower()
    if severity:
        return severity in {"P0", "P1", "HIGH", "CRITICAL"}
    return change_type in {
        "removed",
        "signature_changed",
        "method_removed",
        "field_removed",
        "class_removed",
    }


def _normalized_bytecode_owner(value):
    return str(value or "").strip().replace("/", ".").replace("$", ".")


def _changed_api_reference_target(row, row_index):
    row = row or {}
    api_name = str(row.get("api_name") or "").strip()
    symbol_kind = str(row.get("symbol_kind") or "").strip().lower()
    if not api_name or symbol_kind not in {"method", "constructor", "field", "class"}:
        return None
    if symbol_kind == "class":
        owner = _normalized_bytecode_owner(api_name)
        member = ""
    elif "." in api_name:
        owner, member = api_name.rsplit(".", 1)
        owner = _normalized_bytecode_owner(owner)
        if symbol_kind == "constructor":
            member = "<init>"
        elif row.get("api_simple"):
            member = str(row.get("api_simple") or "").strip()
    else:
        return None
    signature = str(row.get("api_signature") or "").strip()
    normalized_signature = normalize_signature_for_lookup(signature) or signature
    return {
        "row_index": row_index,
        "coord": str(row.get("coord") or "").strip(),
        "api_name": api_name,
        "api_signature": signature,
        "symbol_kind": symbol_kind,
        "change_type": str(row.get("change_type") or "").strip(),
        "owner": owner,
        "member": member,
        "normalized_signature": normalized_signature,
    }


def _business_bytecode_edge_target(edge):
    edge = edge or {}
    evidence_type = str(edge.get("evidence_type") or "").strip()
    # Constant-pool/signature-only class entries have no owning executable
    # instruction.  They are useful telemetry but are not direct usage evidence.
    if evidence_type == "bytecode_class_reference":
        return None
    callee_key = str(edge.get("callee_key") or "").strip()
    if not callee_key or callee_key.startswith("invokedynamic:"):
        return None
    if callee_key.startswith("class:"):
        return {
            "kind": "class",
            "owner": _normalized_bytecode_owner(callee_key[6:]),
            "member": "",
            "normalized_signature": "",
        }
    if "field" in evidence_type:
        owner, separator, member = callee_key.rpartition(".")
        if not separator:
            return None
        return {
            "kind": "field",
            "owner": _normalized_bytecode_owner(owner),
            "member": member,
            "normalized_signature": "",
        }
    signature_offset = callee_key.find("(")
    if signature_offset >= 0:
        qualified_member = callee_key[:signature_offset]
        signature = callee_key[signature_offset:]
        owner, separator, member = qualified_member.rpartition(".")
        if not separator:
            return None
        owner = _normalized_bytecode_owner(owner)
        if "constructor" in evidence_type:
            member = "<init>"
        return {
            "kind": "method",
            "owner": owner,
            "member": member,
            "normalized_signature": (
                normalize_signature_for_lookup(signature) or signature
            ),
        }
    return {
        "kind": "class",
        "owner": _normalized_bytecode_owner(callee_key),
        "member": "",
        "normalized_signature": "",
    }


def summarize_business_bytecode_changed_api_references(api_rows, evidence):
    """Match direct executable business-bytecode edges to changed APIs.

    Exact method matches require a recorded API signature.  A method change
    without a signature is retained as a candidate reference instead of being
    promoted to exact evidence.  This summary is only a Step4 ordering signal;
    it is not a replacement for Step5 reachability analysis.
    """
    targets = {}
    class_targets = defaultdict(list)
    field_targets = defaultdict(list)
    exact_method_targets = defaultdict(list)
    candidate_method_targets = defaultdict(list)
    for row_index, row in enumerate(api_rows or []):
        target = _changed_api_reference_target(row, row_index)
        if not target or not target["coord"]:
            continue
        targets[row_index] = target
        owner = target["owner"]
        if target["symbol_kind"] == "class":
            class_targets[owner].append(row_index)
        elif target["symbol_kind"] == "field":
            field_targets[(owner, target["member"])].append(row_index)
        elif target["normalized_signature"]:
            exact_method_targets[(
                owner,
                target["member"],
                target["normalized_signature"],
            )].append(row_index)
        else:
            candidate_method_targets[(owner, target["member"])].append(row_index)

    by_coord = defaultdict(lambda: {
        "exact_api_indexes": set(),
        "candidate_api_indexes": set(),
        "exact_reference_occurrence_count": 0,
        "candidate_reference_occurrence_count": 0,
    })
    evidence_rows = []
    for edge in evidence or []:
        edge_target = _business_bytecode_edge_target(edge)
        if not edge_target or not edge_target["owner"]:
            continue
        exact_indexes = set(class_targets.get(edge_target["owner"], ()))
        candidate_indexes = set()
        if edge_target["kind"] == "field":
            exact_indexes.update(field_targets.get((
                edge_target["owner"], edge_target["member"],
            ), ()))
        elif edge_target["kind"] == "method":
            exact_indexes.update(exact_method_targets.get((
                edge_target["owner"],
                edge_target["member"],
                edge_target["normalized_signature"],
            ), ()))
            candidate_indexes.update(candidate_method_targets.get((
                edge_target["owner"], edge_target["member"],
            ), ()))

        for match_quality, indexes in (
            ("exact", sorted(exact_indexes)),
            ("signature_incomplete_candidate", sorted(candidate_indexes - exact_indexes)),
        ):
            for row_index in indexes:
                target = targets[row_index]
                aggregate = by_coord[target["coord"]]
                if match_quality == "exact":
                    aggregate["exact_api_indexes"].add(row_index)
                    aggregate["exact_reference_occurrence_count"] += 1
                else:
                    aggregate["candidate_api_indexes"].add(row_index)
                    aggregate["candidate_reference_occurrence_count"] += 1
                evidence_rows.append({
                    "coord": target["coord"],
                    "api_name": target["api_name"],
                    "api_signature": target["api_signature"],
                    "symbol_kind": target["symbol_kind"],
                    "change_type": target["change_type"],
                    "match_quality": match_quality,
                    "caller_class": str(edge.get("caller_owner") or ""),
                    "caller_method": str(edge.get("caller_name") or ""),
                    "caller_signature": str(edge.get("caller_signature") or ""),
                    "instruction_offset": edge.get("instruction_offset", edge.get("line", "")),
                    "callee_key": str(edge.get("callee_key") or ""),
                    "evidence_type": str(edge.get("evidence_type") or ""),
                    "artifact_entry": str(edge.get("class_file") or ""),
                })

    public_by_coord = {}
    for coord, item in by_coord.items():
        public_by_coord[coord] = {
            "business_exact_referenced_api_count": len(item["exact_api_indexes"]),
            "business_candidate_referenced_api_count": len(
                item["candidate_api_indexes"] - item["exact_api_indexes"]
            ),
            "business_exact_reference_occurrence_count": int(
                item["exact_reference_occurrence_count"]
            ),
            "business_candidate_reference_occurrence_count": int(
                item["candidate_reference_occurrence_count"]
            ),
        }
    evidence_rows.sort(key=lambda row: (
        row["coord"],
        row["api_name"],
        row["api_signature"],
        row["match_quality"],
        row["caller_class"],
        row["caller_method"],
        int(row["instruction_offset"] or 0),
    ))
    return {
        "by_coord": public_by_coord,
        "evidence_rows": evidence_rows,
    }


def _step4_business_artifact(report_dir):
    manifest_path = (
        Path(report_dir)
        / EVIDENCE_DIRNAME
        / EVIDENCE_DEPENDENCIES_DIRNAME
        / STEP1_DEPENDENCY_JARS_MANIFEST_FILE
    )
    if not manifest_path.is_file():
        return {}, "step1_dependency_jar_manifest_missing", manifest_path
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, "step1_dependency_jar_manifest_unreadable", manifest_path
    candidates = [
        dict(item)
        for item in (payload.get("business_artifacts") or [])
        if str((item or {}).get("side") or "").strip() == "current"
        and str((item or {}).get("kind") or "").strip() == "business_content"
    ]
    identities = {
        (
            str(item.get("retained_path") or "").strip(),
            str(item.get("sha256") or "").strip().lower(),
        )
        for item in candidates
    }
    identities.discard(("", ""))
    if not identities:
        return {}, "current_business_artifact_missing", manifest_path
    if len(identities) != 1:
        return {}, "current_business_artifact_ambiguous", manifest_path
    retained_path, artifact_sha256 = next(iter(identities))
    artifact_path = Path(retained_path)
    if not artifact_path.is_absolute():
        artifact_path = (manifest_path.parent / artifact_path).resolve()
    return {
        "coord": "__business__",
        "jar_path": str(artifact_path),
        "sha256": artifact_sha256,
    }, "", manifest_path


def collect_business_bytecode_priority_evidence(api_rows, output_dir):
    output_path = Path(output_dir)
    report_dir = infer_report_dir_from_output_dir(output_path)
    evidence_csv = output_path / BUSINESS_BYTECODE_CHANGED_API_REFS_CSV
    summary_json = output_path / BUSINESS_BYTECODE_PRIORITY_EVIDENCE_JSON
    evidence_fields = [
        "coord", "api_name", "api_signature", "symbol_kind", "change_type",
        "match_quality", "caller_class", "caller_method", "caller_signature",
        "instruction_offset", "callee_key", "evidence_type", "artifact_entry",
    ]
    business_artifact, artifact_error, manifest_path = _step4_business_artifact(report_dir)
    evidence = []
    metrics = {}
    reason_codes = []
    if artifact_error:
        reason_codes.append(artifact_error)
        scan_status = "unavailable"
    else:
        try:
            # Lazy import keeps standalone Step4 utilities light while sharing
            # the exact cache consumed by Step5, so the bytecode scan is not paid twice.
            from business_bytecode_graph import collect_business_bytecode_edges
            catalog = {
                "entries": [business_artifact],
                "by_coord": {"__business__": business_artifact},
                "jar_paths": {"__business__": business_artifact["jar_path"]},
            }
            evidence, metrics = collect_business_bytecode_edges(
                [],
                artifact_catalog=catalog,
                cache_path=(
                    Path(report_dir)
                    / RUNTIME_DIRNAME
                    / RUNTIME_CACHE_DIRNAME
                    / STEP5_ARTIFACT_BYTECODE_INDEX_FILE
                ),
            )
            reason_codes.extend(str(item) for item in (metrics.get("failures") or []))
            scan_status = "complete" if not reason_codes else "incomplete"
        except Exception as exc:
            scan_status = "unavailable"
            reason_codes.append(
                f"business_bytecode_priority_scan_failed:{type(exc).__name__}:{exc}"
            )

    matched = summarize_business_bytecode_changed_api_references(api_rows, evidence)
    with open_csv_write(evidence_csv) as fh:
        writer = csv.DictWriter(fh, fieldnames=evidence_fields)
        writer.writeheader()
        writer.writerows(matched["evidence_rows"])
    payload = {
        "schema": "java-upgrade-analyzer.step4-business-priority-evidence.v1",
        "scan_status": scan_status,
        "reason_codes": reason_codes,
        "business_artifact": business_artifact,
        "manifest_file": str(manifest_path),
        "evidence_file": str(evidence_csv),
        "metrics": metrics,
        "matched_dependency_count": len(matched["by_coord"]),
        "exact_referenced_api_count": sum(
            int(item.get("business_exact_referenced_api_count") or 0)
            for item in matched["by_coord"].values()
        ),
        "candidate_referenced_api_count": sum(
            int(item.get("business_candidate_referenced_api_count") or 0)
            for item in matched["by_coord"].values()
        ),
    }
    summary_json.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        **matched,
        "scan_status": scan_status,
        "reason_codes": reason_codes,
        "evidence_file": str(evidence_csv),
        "summary_file": str(summary_json),
        "metrics": metrics,
    }


def build_changed_dependency_rows(api_rows):
    grouped = {}
    for row in api_rows or []:
        coord = str((row or {}).get("coord") or "").strip()
        if not coord:
            continue
        item = grouped.setdefault(
            coord,
            {
                "selection_key": f"coord:{coord}",
                "coord": coord,
                "dependency_name": _dependency_name_from_coord(coord),
                "changed_api_count": 0,
                "high_risk_api_count": 0,
                "change_type_set": set(),
                "symbol_kind_set": set(),
            },
        )
        item["changed_api_count"] += 1
        if _is_high_risk_api_row(row):
            item["high_risk_api_count"] += 1
        change_type = str((row or {}).get("change_type") or "").strip()
        symbol_kind = str((row or {}).get("symbol_kind") or "").strip()
        if change_type:
            item["change_type_set"].add(change_type)
        if symbol_kind:
            item["symbol_kind_set"].add(symbol_kind)

    result = []
    for item in grouped.values():
        result.append(
            {
                "selection_key": item["selection_key"],
                "coord": item["coord"],
                "dependency_name": item["dependency_name"],
                "changed_api_count": item["changed_api_count"],
                "high_risk_api_count": item["high_risk_api_count"],
                "change_types": ", ".join(sorted(item["change_type_set"])),
                "symbol_kinds": ", ".join(sorted(item["symbol_kind_set"])),
                "detail": f"{PER_DEPENDENCY_DIRNAME}/{make_per_dependency_dirname(item['coord'])}/{PER_DEPENDENCY_SUMMARY_FILE}",
            }
        )
    # This helper only groups change facts. Impact ordering is applied later,
    # after business-bytecode evidence has been joined. Keeping change type or
    # severity out of this provisional order prevents callers from accidentally
    # treating removals as inherently more important than other API changes.
    return sorted(
        result,
        key=lambda row: (-int(row["changed_api_count"]), row["coord"]),
    )


DEPENDENCY_ANALYSIS_STATUS_FIELDS = [
    "coord",
    "old_version",
    "new_version",
    "dependency_change_type",
    "api_comparison_result_text",
    "implementation_check_result_text",
    "final_result_text",
    "analysis_complete",
    "can_treat_as_no_change",
    "requires_action_before_conclusion",
    "next_action",
    "api_comparison_method",
    "api_comparison_status",
    "api_comparison_data_available",
    "api_change_count",
    "api_comparison_reason_code",
    "api_comparison_reason_code_aliases",
    "api_comparison_failure_reason",
    "api_comparison_evidence_path",
    "implementation_check_status",
    "implementation_data_available",
    "implementation_change_count",
    "implementation_reason_code",
    "implementation_failure_reason",
    "implementation_evidence_path",
    "origin_step",
]


def dependency_analysis_status_public_row(row):
    """Expose field names that identify both the subject and the meaning."""
    row = row or {}
    return {
        "coord": row.get("coord", ""),
        "old_version": row.get("old_version", ""),
        "new_version": row.get("new_version", ""),
        "dependency_change_type": row.get("change_type", ""),
        "api_comparison_result_text": row.get("binary_api_result_text", ""),
        "implementation_check_result_text": row.get(
            "implementation_check_result_text", ""
        ),
        "final_result_text": row.get("final_result_text", ""),
        "analysis_complete": row.get("analysis_complete", False),
        "can_treat_as_no_change": row.get("can_treat_as_no_change", False),
        "requires_action_before_conclusion": row.get(
            "requires_action_before_conclusion", False
        ),
        "next_action": row.get("next_action", ""),
        "api_comparison_method": row.get("comparison_mode", ""),
        "api_comparison_status": row.get("comparison_status", ""),
        "api_comparison_data_available": row.get("api_data_available", False),
        "api_change_count": row.get("changed_api_count"),
        "api_comparison_reason_code": row.get("reason_code", ""),
        "api_comparison_reason_code_aliases": row.get(
            "reason_code_aliases", []
        ),
        "api_comparison_failure_reason": row.get("failure_message", ""),
        "api_comparison_evidence_path": row.get("evidence_path", ""),
        "implementation_check_status": row.get(
            "implementation_check_status", ""
        ),
        "implementation_data_available": row.get(
            "implementation_data_available", False
        ),
        "implementation_change_count": row.get("implementation_change_count"),
        "implementation_reason_code": row.get("implementation_reason_code", ""),
        "implementation_failure_reason": row.get(
            "implementation_failure_reason", ""
        ),
        "implementation_evidence_path": row.get(
            "implementation_evidence_path", ""
        ),
        "origin_step": row.get("origin_step", "step4"),
    }


def build_dependency_analysis_status_rows(
    dep_rows,
    binary_runs,
    *,
    gitdiff_runs=None,
    gitdiff_skipped=None,
    gitdiff_pending=None,
    bytecode_behavior_runs=None,
    changed_deps_missing_source=None,
):
    """Build one unambiguous binary-comparison outcome for every dependency."""
    primary_modes = {"japicmp", "old_jar_export", "dependency_worker"}
    runs_by_coord = {}
    for run in binary_runs or []:
        coord = str((run or {}).get("coord") or "").strip()
        mode = str((run or {}).get("mode") or "").strip()
        if coord and mode in primary_modes:
            runs_by_coord[coord] = dict(run)

    rows = []
    for dep in dep_rows or []:
        coord = str((dep or {}).get("coord") or "").strip()
        if not coord:
            continue
        old_version = str((dep or {}).get("old_version") or "").strip()
        new_version = str((dep or {}).get("new_version") or "").strip()
        change_type = str((dep or {}).get("change_type") or "").strip()
        run = runs_by_coord.get(coord)

        if run:
            mode = str(run.get("mode") or "japicmp").strip()
            run_status = str(run.get("status") or "").strip()
            api_count = int(run.get("api_count") or 0)
            if run_status == "success":
                comparison_status = (
                    "changes_detected" if api_count else "no_api_change"
                )
                api_data_available = True
                reason_code = ""
                failure_message = ""
                interpretation = (
                    f"对比成功，发现 {api_count} 个 API 变化。"
                    if api_count
                    else "对比成功，未发现可见 API 变化。"
                )
                recommended_action = (
                    "将变化 API 送入 Step5 做系统触达分析。"
                    if api_count
                    else "API 对比成功且未发现可见变化，可按本轮无变化处理。"
                )
            else:
                comparison_status = "failed"
                api_data_available = False
                api_count = None
                reason_code = canonical_reason_code(
                    run.get("reason_code")
                    or (
                        JAPICMP_EXECUTION_FAILED
                        if mode == "japicmp"
                        else "BINARY_API_COMPARISON_FAILED"
                    )
                )
                failure_message = str(run.get("error") or "").strip()
                interpretation = (
                    "API 对比失败，没有 API 数据，不能按无变化处理。"
                    f"技术原因：{failure_message or '未记录'}"
                )
                recommended_action = (
                    "查看失败原因和原始证据，修复后重跑该依赖的 Step4 对比。"
                )
        elif (
            change_type in {"新增", "未变"}
            or old_version in {"", "-"}
            or new_version in {"", "-"} and change_type != "移除"
        ):
            mode = "not_applicable"
            comparison_status = "not_applicable"
            api_data_available = False
            api_count = None
            reason_code = ""
            failure_message = ""
            interpretation = "该依赖没有可执行的新旧版本 API 对比范围。"
            recommended_action = "本项不适用，不要把它解释为“对比成功且无变化”。"
        else:
            mode = "japicmp" if change_type != "移除" else "old_jar_export"
            comparison_status = "failed"
            api_data_available = False
            api_count = None
            reason_code = "BINARY_API_COMPARISON_NOT_EXECUTED"
            failure_message = "没有找到该依赖的二进制 API 对比执行记录"
            interpretation = (
                "API 对比未执行或执行记录丢失，没有 API 数据，不能按无变化处理。"
            )
            recommended_action = "检查 Step4 运行日志和输入制品后重跑。"

        raw_reason = str(reason_code or "").strip()
        aliases = reason_code_aliases(raw_reason) if raw_reason else []
        run_reason = str((run or {}).get("reason_code") or "").strip()
        if raw_reason and run_reason and run_reason != raw_reason and run_reason not in aliases:
            aliases.append(run_reason)
        rows.append({
            "coord": coord,
            "old_version": old_version,
            "new_version": new_version,
            "change_type": change_type,
            "comparison_mode": mode,
            "comparison_status": comparison_status,
            "api_data_available": api_data_available,
            "changed_api_count": api_count,
            "reason_code": raw_reason,
            "reason_code_aliases": aliases,
            "failure_message": failure_message,
            "result_interpretation": interpretation,
            "recommended_action": recommended_action,
            "evidence_path": str((run or {}).get("evidence_path") or "").strip(),
            "origin_step": "step4",
            "old_jar_source": str((run or {}).get("old_jar_source") or "").strip(),
            "new_jar_source": str((run or {}).get("new_jar_source") or "").strip(),
        })
    gitdiff_run_by_coord = {
        str(item.get("coord") or "").strip(): dict(item)
        for item in (gitdiff_runs or [])
        if str(item.get("coord") or "").strip()
    }
    gitdiff_skip_by_coord = {
        str(item.get("coord") or "").strip(): dict(item)
        for item in (gitdiff_skipped or [])
        if str(item.get("coord") or "").strip()
    }
    gitdiff_pending_by_coord = {
        str(item.get("coord") or "").strip(): dict(item)
        for item in (gitdiff_pending or [])
        if str(item.get("coord") or "").strip()
    }
    behavior_run_by_coord = {
        str(item.get("coord") or "").strip(): dict(item)
        for item in (bytecode_behavior_runs or [])
        if str(item.get("coord") or "").strip()
    }
    missing_source_coords = {
        str(item.get("coord") or "").strip()
        for item in (changed_deps_missing_source or [])
        if str(item.get("coord") or "").strip()
    }

    for row in rows:
        coord = row["coord"]
        source_run = gitdiff_run_by_coord.get(coord)
        source_skip = gitdiff_skip_by_coord.get(coord)
        source_pending = gitdiff_pending_by_coord.get(coord)
        behavior_run = behavior_run_by_coord.get(coord)
        source_change_count = None
        source_reason_code = ""
        source_failure_reason = ""
        source_evidence_path = ""

        if source_run:
            source_change_count = int(source_run.get("api_changes") or 0)
            promoted_count = int(source_run.get("promoted_to_step5") or 0)
            source_diff_status = (
                "changes_detected" if source_change_count else "no_source_change"
            )
            source_diff_available = True
            source_analysis_complete = True
            source_evidence_path = str(source_run.get("out_file") or "")
            source_result_text = (
                f"源码对比成功，发现 {source_change_count} 条实现差异"
                f"（{promoted_count} 条进入 Step5）。"
                if source_change_count
                else "源码对比成功，未发现实现差异。"
            )
            source_has_actionable_changes = promoted_count > 0
            source_next_action = ""
        elif source_pending:
            source_diff_status = "pending"
            source_diff_available = False
            source_analysis_complete = False
            source_reason_code = canonical_reason_code(
                source_pending.get("reason_code")
                or "DEPENDENCY_SOURCE_REF_CONFIRMATION_REQUIRED"
            )
            source_failure_reason = str(
                source_pending.get("reason") or "源码版本范围尚未确认"
            )
            source_evidence_path = str(source_pending.get("out_file") or "")
            source_result_text = "等待确认新旧源码版本，尚未执行实现变化检查。"
            source_has_actionable_changes = False
            source_next_action = "确认 old/new 源码版本后重跑 Step4。"
        elif source_skip:
            fallback_complete = bool(
                source_skip.get("behavior_fallback_status") == "complete"
                or (behavior_run or {}).get("status") == "complete"
            )
            fallback_changes = int((behavior_run or {}).get("api_changes") or 0)
            source_reason_code = canonical_reason_code(
                source_skip.get("reason_code")
                or "DEPENDENCY_SOURCE_DIFF_UNAVAILABLE"
            )
            source_failure_reason = str(
                source_skip.get("reason") or "源码对比未完成"
            )
            source_evidence_path = str(
                source_skip.get("behavior_fallback_evidence")
                or (behavior_run or {}).get("evidence_path")
                or source_skip.get("out_file")
                or ""
            )
            source_diff_available = False
            if fallback_complete:
                source_change_count = fallback_changes
                source_diff_status = (
                    "jar_fallback_changes_detected"
                    if fallback_changes
                    else "jar_fallback_no_behavior_change"
                )
                source_analysis_complete = True
                source_result_text = (
                    "源码对比未完成；已通过发布 JAR 的方法实现检查补齐，"
                    f"发现 {fallback_changes} 条行为变化。"
                    if fallback_changes
                    else "源码对比未完成；已通过发布 JAR 的方法实现检查补齐，未发现行为变化。"
                )
                source_has_actionable_changes = fallback_changes > 0
                source_next_action = ""
            else:
                source_diff_status = "failed"
                source_analysis_complete = False
                source_result_text = (
                    "源码对比失败，发布 JAR 的方法实现检查也未完成；实现变化数据不可用。"
                )
                source_has_actionable_changes = False
                source_next_action = "修复源码版本或最终 JAR 行为对比后重跑 Step4。"
        elif coord in missing_source_coords:
            source_diff_status = "not_configured"
            source_diff_available = False
            source_analysis_complete = False
            source_reason_code = "DEPENDENCY_SOURCE_NOT_CONFIGURED"
            source_failure_reason = "未提供该依赖的源码仓库或源码目录"
            source_result_text = "未提供依赖源码，无法检查实现变化；当前证据不完整。"
            source_has_actionable_changes = False
            source_next_action = "补充依赖源码映射后重跑 Step4。"
        else:
            source_diff_status = "not_applicable"
            source_diff_available = False
            source_analysis_complete = True
            source_result_text = "本依赖不需要检查源码实现变化。"
            source_has_actionable_changes = False
            source_next_action = ""

        binary_status = row["comparison_status"]
        binary_complete = binary_status != "failed"
        binary_has_changes = binary_status == "changes_detected"
        analysis_complete = binary_complete and source_analysis_complete
        requires_action_before_conclusion = not analysis_complete
        can_treat_as_no_change = bool(
            binary_status == "no_api_change"
            and source_diff_status in {
                "no_source_change",
                "jar_fallback_no_behavior_change",
                "not_applicable",
            }
        )
        if binary_status == "failed":
            final_result_text = (
                "分析不完整：API 对比失败，没有 API 数据，不能按无变化处理。"
            )
            next_action = row["recommended_action"]
        elif not source_analysis_complete:
            final_result_text = (
                "分析不完整：二进制 API 结果可用，但源码行为变化证据不完整。"
            )
            next_action = source_next_action
        elif binary_has_changes or source_has_actionable_changes:
            final_result_text = "分析完整：已发现需要进入后续触达分析的变化。"
            next_action = "继续 Step5，判断这些变化是否触达当前系统。"
        elif can_treat_as_no_change:
            final_result_text = "分析完整：未发现可见 API 或行为变化，可以按无变化处理。"
            next_action = "无需修复；保留证据后继续。"
        else:
            final_result_text = "当前检查不适用，或没有可执行的对比范围。"
            next_action = source_next_action or row["recommended_action"]

        row.update({
            "binary_api_result_text": row["result_interpretation"],
            "implementation_check_status": source_diff_status,
            "implementation_data_available": source_diff_available,
            "implementation_change_count": source_change_count,
            "implementation_reason_code": source_reason_code,
            "implementation_failure_reason": source_failure_reason,
            "implementation_evidence_path": source_evidence_path,
            "implementation_check_result_text": source_result_text,
            "final_result_text": final_result_text,
            "analysis_complete": analysis_complete,
            "can_treat_as_no_change": can_treat_as_no_change,
            "requires_action_before_conclusion": requires_action_before_conclusion,
            "next_action": next_action,
        })

    return sorted(rows, key=lambda item: item["coord"])


def write_dependency_analysis_status(
    dep_rows,
    binary_runs,
    output_dir,
    *,
    gitdiff_runs=None,
    gitdiff_skipped=None,
    gitdiff_pending=None,
    bytecode_behavior_runs=None,
    changed_deps_missing_source=None,
):
    """Write the companion ledger that distinguishes zero changes from no data."""
    rows = build_dependency_analysis_status_rows(
        dep_rows,
        binary_runs,
        gitdiff_runs=gitdiff_runs,
        gitdiff_skipped=gitdiff_skipped,
        gitdiff_pending=gitdiff_pending,
        bytecode_behavior_runs=bytecode_behavior_runs,
        changed_deps_missing_source=changed_deps_missing_source,
    )
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    csv_path = output_path / DEPENDENCY_ANALYSIS_STATUS_CSV
    json_path = output_path / DEPENDENCY_ANALYSIS_STATUS_JSON
    md_path = output_path / DEPENDENCY_ANALYSIS_STATUS_MD
    public_rows = [
        dependency_analysis_status_public_row(row)
        for row in rows
    ]

    with open_csv_write(csv_path) as fh:
        writer = csv.DictWriter(fh, fieldnames=DEPENDENCY_ANALYSIS_STATUS_FIELDS)
        writer.writeheader()
        for row in public_rows:
            csv_row = {
                field: row.get(field, "")
                for field in DEPENDENCY_ANALYSIS_STATUS_FIELDS
            }
            csv_row["api_comparison_data_available"] = str(
                bool(row.get("api_comparison_data_available"))
            ).lower()
            for boolean_field in (
                "analysis_complete",
                "can_treat_as_no_change",
                "requires_action_before_conclusion",
                "implementation_data_available",
            ):
                csv_row[boolean_field] = str(
                    bool(row.get(boolean_field))
                ).lower()
            csv_row["api_change_count"] = (
                "" if row.get("api_change_count") is None
                else row.get("api_change_count")
            )
            csv_row["implementation_change_count"] = (
                "" if row.get("implementation_change_count") is None
                else row.get("implementation_change_count")
            )
            csv_row["api_comparison_reason_code_aliases"] = "|".join(
                row.get("api_comparison_reason_code_aliases") or []
            )
            writer.writerow(csv_row)

    status_counts = Counter(row["comparison_status"] for row in rows)
    source_status_counts = Counter(
        row["implementation_check_status"] for row in rows
    )
    failed_codes = sorted({
        reason_code
        for row in rows
        for reason_code in (
            row.get("reason_code"),
            row.get("implementation_reason_code"),
        )
        if reason_code and row.get("requires_action_before_conclusion")
    })
    payload = {
        "schema": "java-upgrade-analyzer.dependency-analysis-status.v1",
        "origin_step": "step4",
        "diagnostic_contract": diagnostic_contract_metadata(),
        "diagnostic_guidance_schema": REASON_GUIDANCE_SCHEMA,
        "diagnostic_guidance": build_catalog_guidance(
            failed_codes,
            origin_step="step4",
            observed_scope="dependency",
            source_components=("binary_api_diff",),
        ),
        "summary": {
            "total_dependencies": len(rows),
            "dependencies_with_api_changes": status_counts.get(
                "changes_detected", 0
            ),
            "dependencies_with_no_api_changes": status_counts.get(
                "no_api_change", 0
            ),
            "dependencies_with_failed_api_comparison": status_counts.get(
                "failed", 0
            ),
            "dependencies_without_applicable_api_comparison": (
                status_counts.get("not_applicable", 0)
            ),
            "dependencies_with_complete_analysis": sum(
                1 for row in rows if row.get("analysis_complete")
            ),
            "dependencies_requiring_action_before_conclusion": sum(
                1 for row in rows
                if row.get("requires_action_before_conclusion")
            ),
            "dependencies_that_can_be_treated_as_no_change": sum(
                1 for row in rows if row.get("can_treat_as_no_change")
            ),
            "implementation_check_status_counts": dict(
                sorted(source_status_counts.items())
            ),
        },
        "interpretation": {
            "analysis_complete": "true 表示该依赖本轮需要的二进制和源码行为证据均已形成。",
            "can_treat_as_no_change": "只有 true 才能把该依赖解释为本轮未发现变化。",
            "requires_action_before_conclusion": (
                "true 表示当前不能直接采用结论，必须按 next_action 处理并重新分析。"
            ),
        },
        "items": public_rows,
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    def md_cell(value):
        return str(value if value not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")

    md_lines = [
        "# 每个依赖的分析结果（先看这里）",
        "",
        "本表直接给出结果和下一步，不需要根据 API 行是否存在来猜测执行状态。",
        "",
        "- “可以按无变化处理”为“是”时，才表示相关对比成功且未发现变化。",
        "- “分析完整”为“否”时，即使 `all_changed_apis.csv` 没有该依赖，也不能解释为没有变化。",
        "",
        "| 依赖 | API 对比 | 实现变化检查 | 最终结论 | 分析完整 | 可按无变化处理 | 形成结论前需处理 | 下一步 |",
        "|---|---|---|---|:---:|:---:|:---:|---|",
    ]
    for row in rows:
        md_lines.append(
            f"| `{md_cell(row.get('coord'))}` | "
            f"{md_cell(row.get('binary_api_result_text'))} | "
            f"{md_cell(row.get('implementation_check_result_text'))} | "
            f"{md_cell(row.get('final_result_text'))} | "
            f"{'是' if row.get('analysis_complete') else '否'} | "
            f"{'是' if row.get('can_treat_as_no_change') else '否'} | "
            f"{'是' if row.get('requires_action_before_conclusion') else '否'} | "
            f"{md_cell(row.get('next_action'))} |"
        )
    if not rows:
        md_lines.append("| - | - | - | 本轮没有需要分析的依赖。 | 是 | 否 | 否 | - |")
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return rows, csv_path, json_path


def _dependency_review_focus(row):
    exact = int((row or {}).get("business_exact_referenced_api_count") or 0)
    candidate = int((row or {}).get("business_candidate_referenced_api_count") or 0)
    exact_occurrences = int(
        (row or {}).get("business_exact_reference_occurrence_count") or 0
    )
    candidate_occurrences = int(
        (row or {}).get("business_candidate_reference_occurrence_count") or 0
    )
    changed = int((row or {}).get("changed_api_count") or 0)
    scan_status = str((row or {}).get("business_bytecode_scan_status") or "").strip()
    if exact:
        focus = (
            f"业务最终制品直接引用 {exact} 个变更 API"
            f"（{exact_occurrences} 处精确字节码指令）"
        )
        if candidate:
            focus += (
                f"；另有 {candidate} 个签名不完整候选 API"
                f"（{candidate_occurrences} 处指令）"
            )
        return focus
    if candidate:
        return (
            f"业务最终制品存在 {candidate} 个签名不完整的候选引用"
            f"（{candidate_occurrences} 处字节码指令）；"
            "需 Step5 继续消歧"
        )
    if scan_status == "complete":
        return (
            f"未观察到业务字节码直接引用；按 {changed} 个变更 API 的规模排序，"
            "不代表无影响"
        )
    scan_status_label = {
        "incomplete": "不完整",
        "unavailable": "不可用",
        "not_collected": "未采集",
    }.get(scan_status, scan_status or "不可用")
    return (
        f"业务字节码排序证据{scan_status_label}；"
        f"暂按 {changed} 个变更 API 的规模排序"
    )


def _is_recommended_dependency(row):
    rank = int((row or {}).get("impact_priority_rank") or 0)
    return bool(rank and rank <= STEP4_RECOMMENDED_DEPENDENCY_LIMIT)


def write_changed_dependencies(
    api_rows,
    output_dir,
    dependency_status_rows=None,
    business_reference_summary=None,
):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    dependency_rows = build_changed_dependency_rows(api_rows)
    business_reference_summary = business_reference_summary or {}
    business_by_coord = business_reference_summary.get("by_coord") or {}
    scan_status = str(
        business_reference_summary.get("scan_status") or "not_collected"
    ).strip()
    status_by_coord = {
        str((item or {}).get("coord") or "").strip(): item
        for item in (dependency_status_rows or [])
        if str((item or {}).get("coord") or "").strip()
    }
    for row in dependency_rows:
        reference = business_by_coord.get(row["coord"]) or {}
        exact_count = int(
            reference.get("business_exact_referenced_api_count") or 0
        )
        candidate_count = int(
            reference.get("business_candidate_referenced_api_count") or 0
        )
        exact_occurrences = int(
            reference.get("business_exact_reference_occurrence_count") or 0
        )
        candidate_occurrences = int(
            reference.get("business_candidate_reference_occurrence_count") or 0
        )
        status_row = status_by_coord.get(row["coord"])
        if status_row is None:
            source_status = "unknown"
        elif str(status_row.get("implementation_data_available") or "").strip().lower() in {
            "1", "true", "yes", "y", "是",
        }:
            source_status = "available"
        elif str(status_row.get("implementation_check_status") or "").strip() == "not_applicable":
            source_status = "not_applicable"
        else:
            source_status = "unavailable"
        row.update({
            "business_exact_referenced_api_count": exact_count,
            "business_candidate_referenced_api_count": candidate_count,
            "business_exact_reference_occurrence_count": exact_occurrences,
            "business_candidate_reference_occurrence_count": candidate_occurrences,
            "business_reference_occurrence_count": (
                exact_occurrences + candidate_occurrences
            ),
            "business_bytecode_scan_status": scan_status,
            "dependency_source_status": source_status,
        })
    # Impact evidence determines dependency order. Change kind and source
    # availability remain visible facts but never receive an impact bonus.
    dependency_rows.sort(
        key=lambda row: (
            -int(row["business_exact_referenced_api_count"]),
            -int(row["business_candidate_referenced_api_count"]),
            -int(row["business_reference_occurrence_count"]),
            -int(row["changed_api_count"]),
            row["coord"],
        )
    )
    for rank, row in enumerate(dependency_rows, start=1):
        row["impact_priority_rank"] = rank
        row["review_focus"] = _dependency_review_focus(row)
        row["recommended"] = "true" if _is_recommended_dependency(row) else "false"
    csv_path = output_path / CHANGED_DEPENDENCIES_CSV
    md_path = output_path / CHANGED_DEPENDENCIES_MD
    fieldnames = [
        "selection_key",
        "coord",
        "dependency_name",
        "changed_api_count",
        "high_risk_api_count",
        "business_exact_referenced_api_count",
        "business_candidate_referenced_api_count",
        "business_exact_reference_occurrence_count",
        "business_candidate_reference_occurrence_count",
        "business_reference_occurrence_count",
        "business_bytecode_scan_status",
        "dependency_source_status",
        "impact_priority_rank",
        "recommended",
        "change_types",
        "symbol_kinds",
        "review_focus",
        "detail",
    ]
    with open_csv_write(csv_path) as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(dependency_rows)

    lines = [
        "# 发生 API 变化的依赖包",
        "",
        "本文件列出全部发生 API 变化、可进入系统触达分析的依赖包。",
        "",
        f"展示 {len(dependency_rows)} / {len(dependency_rows)} 个依赖包。",
        "",
        "## 如何选择定向分析范围",
        "",
        "1. 可以直接全量分析全部候选依赖包。",
        (
            "2. 仅当明确需要控制耗时时，可以先看 Top 10 影响复核优先项。"
            "依赖先按业务最终制品精确直接引用的变更 API 数排序，再按签名不完整候选引用数、"
            "引用指令数和变更 API 总数排序。"
        ),
        "3. 删除、签名变化等类型不获得额外权重；依赖源码是否可用只表示分析条件，不参与影响排序。",
        "4. 该排序只用于部分范围取舍，不表示系统建议缩小范围，也不代表 Step5 已确认有影响；未观察到直接引用也不等于无影响。",
        "5. 还可以从本文件列出的全部候选中选择；复制“依赖包”列中的完整坐标即可。",
        "6. 定向分析可直接回复，例如：`只分析 com.example:demo-lib`。",
        "",
        "完整 API 明细：`all_changed_apis.csv`。",
        f"业务字节码直接引用证据：`{BUSINESS_BYTECODE_CHANGED_API_REFS_CSV}`。",
        f"排序证据状态：`{BUSINESS_BYTECODE_PRIORITY_EVIDENCE_JSON}`。",
        f"全部依赖的直接结论：`{DEPENDENCY_ANALYSIS_STATUS_MD}`。",
        "依赖包明细目录：`s4_per_dependency/`。",
        "",
        "| 排名 | Top 10 | 依赖包 | 精确直接引用 API | 候选引用 API | 引用指令 | 变化 API 数 | 依赖源码 | 为什么先看 | 主要变化类型 | 明细 |",
        "|---:|:---:|---|---:|---:|---:|---:|---|---|---|---|",
    ]
    if dependency_rows:
        for row in dependency_rows:
            source_label = {
                "available": "可用",
                "unavailable": "不可用",
                "not_applicable": "不适用",
                "unknown": "未知",
            }.get(row["dependency_source_status"], row["dependency_source_status"])
            lines.append(
                f"| {row['impact_priority_rank']} | "
                f"{'是' if row['recommended'] == 'true' else '否'} | `{row['coord']}` | "
                f"{row['business_exact_referenced_api_count']} | "
                f"{row['business_candidate_referenced_api_count']} | "
                f"{row['business_reference_occurrence_count']} | "
                f"{row['changed_api_count']} | {source_label} | "
                f"{row['review_focus']} | "
                f"{row['change_types'] or '-'} | `{row['detail']}` |"
            )
    else:
        lines.append("| - | - | - | 0 | 0 | 0 | 0 | - | - | - | - |")
    failed_rows = [
        row for row in (dependency_status_rows or [])
        if row.get("comparison_status") == "failed"
    ]
    if failed_rows:
        lines.extend([
            "",
            "## API 对比失败、不能进入 Step5 的依赖",
            "",
            "以下依赖没有形成 API 数据，不能因为 `all_changed_apis.csv` 中没有记录而解释为“没有变化”。",
            "",
            "| 依赖包 | 原因码 | 失败原因 | 原始证据 |",
            "|---|---|---|---|",
        ])
        for row in failed_rows:
            failure_message = str(
                row.get("failure_message") or "-"
            ).replace("|", "\\|")
            lines.append(
                f"| `{row.get('coord')}` | `{row.get('reason_code') or '-'}` | "
                f"{failure_message} | "
                f"`{row.get('evidence_path') or '-'}` |"
            )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return csv_path, md_path


def _normalize_contract_value(row, field):
    return str((row or {}).get(field, '') or '').strip()


def _step5_dedup_key(row):
    return (
        _normalize_contract_value(row, 'coord'),
        _normalize_contract_value(row, 'api_name'),
        _normalize_contract_value(row, 'api_signature'),
        _normalize_contract_value(row, 'symbol_kind'),
        _normalize_contract_value(row, 'change_type'),
    )


def normalize_step5_input_rows(rows):
    """
    为 Step5 生成稳定、去重后的输入视图。

    规则：
      - 保留 raw 证据的同时，对 Step5 输入按 API 粒度归一化
      - 同一 API 若同时来自多个 source，优先 confirmed=true、severity 更高、source 更强的行
      - 归一化键必须包含 api_signature 与 symbol_kind，避免重载/字段/构造器串味
    """
    source_rank = {
        'japicmp': 0,
        'old_jar': 0,
        'classfile_contract': 0,
        'jar_bytecode': 0,
        'gitdiff': 1,
        'changelog': 2,
    }

    buckets = {}
    for row in rows or []:
        key = _step5_dedup_key(row)
        existing = buckets.get(key)
        if not existing:
            buckets[key] = dict(row)
            continue

        cur_confirmed = str(row.get('confirmed', '')).strip().lower() == 'true'
        old_confirmed = str(existing.get('confirmed', '')).strip().lower() == 'true'
        cur_sev = (row.get('severity') or '').strip()
        old_sev = (existing.get('severity') or '').strip()
        cur_source = (row.get('source') or '').strip()
        old_source = (existing.get('source') or '').strip()
        cur_rank = (
            0 if cur_confirmed else 1,
            {'P0': 0, 'P1': 1, 'P2': 2}.get(cur_sev, 9),
            source_rank.get(cur_source, 9),
        )
        old_rank = (
            0 if old_confirmed else 1,
            {'P0': 0, 'P1': 1, 'P2': 2}.get(old_sev, 9),
            source_rank.get(old_source, 9),
        )

        merged = dict(existing)
        if cur_rank < old_rank:
            merged.update(row)
        else:
            # 仍尽量补齐已有最佳行缺失的关键字段
            for field in ALL_CHANGED_APIS_FIELDS:
                if not str(merged.get(field, '') or '').strip() and str(row.get(field, '') or '').strip():
                    merged[field] = row[field]
        buckets[key] = merged

    normalized_rows = _enrich_changed_api_rows(buckets.values())
    normalized_rows.sort(
        key=lambda r: (
            _normalize_contract_value(r, 'coord'),
            _normalize_contract_value(r, 'api_name'),
            _normalize_contract_value(r, 'api_signature'),
            _normalize_contract_value(r, 'change_type'),
            _normalize_contract_value(r, 'source'),
        )
    )
    return normalized_rows


def _write_contract_csv(path, rows):
    with open_csv_write(path) as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS)
        writer.writeheader()
        writer.writerows(_enrich_changed_api_rows(rows or []))


def _load_json_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def write_per_dependency_outputs(
    report_dir,
    dep_row,
    raw_rows,
    removed_jar_export=None,
    gitdiff_auxiliary_rows=None,
    dependency_analysis=None,
):
    """
    为单个依赖写出 Step4 的 per-dependency 产物。

    约定：
      - removed_jar_symbols.csv：仅保存 old_jar 导出的原始符号
      - resolved_targets.csv：保存该 coord 归一化后的 Step5 输入视图
      - summary.json：保存该 coord 的 Step4 摘要，后续可由 Step5 继续补写
    """
    dep_row = dep_row or {}
    coord = str(dep_row.get('coord') or '').strip()
    if not coord:
        return None

    per_dependency_dir = get_per_dependency_dir(report_dir, coord)
    os.makedirs(per_dependency_dir, exist_ok=True)

    raw_rows = list(raw_rows or [])
    gitdiff_auxiliary_rows = list(gitdiff_auxiliary_rows or [])
    dependency_analysis = dict(dependency_analysis or {})
    normalized_rows = normalize_step5_input_rows(raw_rows)
    removed_rows = [row for row in raw_rows if str(row.get('source') or '').strip() == 'old_jar']

    removed_symbols_path = per_dependency_dir / PER_DEPENDENCY_REMOVED_JAR_SYMBOLS_FILE
    resolved_targets_path = per_dependency_dir / PER_DEPENDENCY_RESOLVED_TARGETS_FILE
    summary_path = per_dependency_dir / PER_DEPENDENCY_SUMMARY_FILE

    _write_contract_csv(removed_symbols_path, removed_rows)
    _write_contract_csv(resolved_targets_path, normalized_rows)

    existing_summary = _load_json_file(summary_path)
    source_counts = {}
    for row in raw_rows:
        source = str(row.get('source') or '').strip() or '(empty)'
        source_counts[source] = source_counts.get(source, 0) + 1

    step4_summary = {
        "status": (
            "incomplete"
            if dependency_analysis.get("comparison_status") == "failed"
            else "done"
        ),
        "raw_target_count": len(raw_rows),
        "resolved_target_count": len(normalized_rows),
        "removed_jar_symbol_count": len(removed_rows),
        "sources": sorted(source_counts.keys()),
        "source_counts": source_counts,
        "removed_jar": {
            "enabled": bool(removed_jar_export),
            "old_coord": str((removed_jar_export or {}).get("old_coord") or "").strip(),
            "old_jar": str((removed_jar_export or {}).get("old_jar") or "").strip(),
            "export_error": str((removed_jar_export or {}).get("error") or "").strip(),
            "class_count": int((removed_jar_export or {}).get("class_count") or 0),
            "errors": list((removed_jar_export or {}).get("errors") or []),
        },
        "gitdiff_auxiliary": {
            "count": len(gitdiff_auxiliary_rows),
            "reason": (
                "源码实现对比仅作为辅助证据；结构性 API 变化以发布 JAR 的 API 对比为准，"
                "只有新旧发布 JAR 都存在同一成员时，行为变化才进入 Step5。"
            ),
            "filter_reasons": sorted({
                str(row.get("filter_reason") or "").strip()
                for row in gitdiff_auxiliary_rows
                if str(row.get("filter_reason") or "").strip()
            }),
        },
        "binary_api_comparison": dependency_analysis,
        "artifacts": {
            "removed_jar_symbols_csv": str(removed_symbols_path),
            "resolved_targets_csv": str(resolved_targets_path),
        },
    }

    summary = dict(existing_summary) if isinstance(existing_summary, dict) else {}
    summary.update(
        {
            "coord": coord,
            "change_type": str(dep_row.get('change_type') or '').strip(),
            "old_version": str(dep_row.get('old_version') or '').strip(),
            "new_version": str(dep_row.get('new_version') or '').strip(),
            "base_coord": str(dep_row.get('base_coord') or '').strip(),
            "current_coord": str(dep_row.get('current_coord') or '').strip(),
            "artifacts": {
                "summary_json": str(summary_path),
                "removed_jar_symbols_csv": str(removed_symbols_path),
                "resolved_targets_csv": str(resolved_targets_path),
            },
            "step4": step4_summary,
        }
    )
    write_result(summary_path, json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    return {
        "coord": coord,
        "per_dependency_dir": str(per_dependency_dir),
        "raw_rows": raw_rows,
        "normalized_rows": normalized_rows,
        "summary_path": str(summary_path),
    }


# ══════════════════════════════════════════════════════════════════
# 摘要输出：展示关键复核点，但不在脚本内等待确认
# ══════════════════════════════════════════════════════════════════

def human_checkpoint_1(
    dep_rows,
    all_apis,
    output_dir,
    dependency_status_rows=None,
):
    """
    Step 4 完成后的摘要输出。
    展示：每个依赖的变更 API 数量，重点标出数量为 0 的，
    供用户核对证据并选择 Step5 的全量或部分分析范围。
    """
    print("\n" + "="*60)
    print("【Step4 摘要】依赖 API 变化识别完成")
    print("="*60)
    by_coord = {}
    for api in all_apis:
        c = (api.get('coord') or '').strip()
        if not c:
            continue
        by_coord.setdefault(c, []).append(api)

    zero_change = []
    failed_comparisons = []
    if dependency_status_rows is not None:
        zero_change = [
            row.get("coord")
            for row in dependency_status_rows
            if row.get("comparison_status") == "no_api_change"
            and row.get("coord")
        ]
        failed_comparisons = [
            row for row in dependency_status_rows
            if row.get("comparison_status") == "failed"
        ]
    else:
        for row in dep_rows or []:
            coord = (row.get('coord', '') or '').strip()
            change_type = (row.get('change_type', '') or '').strip()
            if not coord or change_type in ('未变', '新增', '移除'):
                continue
            if not by_coord.get(coord, []):
                zero_change.append(coord)

    print("\n先看什么：")
    print(f"  - 查看变化依赖概览：{os.path.join(output_dir, CHANGED_DEPENDENCIES_MD)}")
    print(f"  - 每个依赖的直接结论：{os.path.join(output_dir, DEPENDENCY_ANALYSIS_STATUS_MD)}")
    print(f"  - 核对完整 API 事实：{os.path.join(output_dir, 'all_changed_apis.csv')}")
    print("  - 是否影响当前系统：继续看 Step5 alerts.csv 和 Step6 report.md")
    print("\n确认 Step5 分析范围：")
    print("  - 全量分析：覆盖全部变化依赖，准确性覆盖最完整")
    print(f"  - 部分分析：从 {os.path.join(output_dir, CHANGED_DEPENDENCIES_MD)} 选择依赖，以控制耗时")
    print(f"  - 变更 API 总数：{len(all_apis)}")
    print(f"  - API 对比成功且未发现变化的依赖：{len(zero_change)}")
    print(f"  - API 对比失败、没有数据的依赖：{len(failed_comparisons)}")
    if failed_comparisons:
        print("  - 当前结论不完整：失败依赖修复前，不能完成全量 Step5 风险判断。")

    if failed_comparisons:
        print(
            f"\nAPI 对比失败、不能按无变化处理的依赖"
            f"（前 {min(50, len(failed_comparisons))} 个）："
        )
        for item in failed_comparisons[:50]:
            print(
                f"  - {item.get('coord')}：API 对比失败，不能按无变化处理；"
                f"诊断标识={item.get('reason_code') or 'BINARY_API_COMPARISON_FAILED'}；"
                f"技术原因={item.get('failure_message') or '未形成可验证结果'}；"
                f"下一步={item.get('recommended_action') or '修复后重跑 Step4'}"
            )
        if len(failed_comparisons) > 50:
            print(f"  ...（仅展示前 50，共 {len(failed_comparisons)}）")

    if zero_change:
        print(
            f"\nAPI 对比成功且未发现变化的依赖"
            f"（前 {min(50, len(zero_change))} 个）："
        )
        for c in zero_change[:50]:
            print(f"  - {c}")
        if len(zero_change) > 50:
            print(f"  ...（仅展示前 50，共 {len(zero_change)}）")
        print("\n说明：")
        print("  - 这些依赖的 API 对比已成功完成，未发现可见 API 变化。")
        print("  - 是否存在签名不变的实现变化，以逐依赖结果中的“实现变化检查”为准。")

    print(f"\n复核文件：")
    print(f"  - 摘要：{os.path.join(output_dir, 'summary.txt')}")
    print(f"  - 每个依赖的直接结论：{os.path.join(output_dir, DEPENDENCY_ANALYSIS_STATUS_MD)}")
    print(f"  - 机器可读明细：{os.path.join(output_dir, DEPENDENCY_ANALYSIS_STATUS_JSON)}")
    print(f"  - 依赖变化概览：{os.path.join(output_dir, CHANGED_DEPENDENCIES_MD)}")
    print(f"  - 完整变更 API：{os.path.join(output_dir, 'all_changed_apis.csv')}")
    print(f"  - 高风险/需关注 API：{os.path.join(output_dir, 'all_changed_apis_alerts.csv')}")
    print("="*60)


def _severity_rank(sev):
    s = (sev or '').strip()
    if s == 'P0':
        return 0
    if s == 'P1':
        return 1
    if s == 'P2':
        return 2
    return 9


def write_readable_outputs(dep_rows, output_dir, all_apis, jar_missing_deps,
                           japicmp_missing_deps, other_failed_deps,
                           changed_deps_missing_source, valid_count, invalid_count,
                           gitdiff_runs=None, gitdiff_skipped=None, gitdiff_pending=None,
                           timeout_items=None, source_branches=None,
                           dependency_status_rows=None):
    all_rows = load_csv(os.path.join(output_dir, "all_changed_apis.csv"))
    alerts = []
    for r in all_rows:
        sev = (r.get('severity') or '').strip()
        confirmed = str(r.get('confirmed', '')).strip().lower()
        source = (r.get('source') or '').strip()
        if sev in ('P0', 'P1') or confirmed == 'false' or source == 'changelog':
            alerts.append(r)
    alerts = _enrich_changed_api_rows(alerts)
    alerts.sort(key=lambda x: (_severity_rank(x.get('severity')), x.get('coord', ''), x.get('api_name', '')))

    alerts_path = os.path.join(output_dir, "all_changed_apis_alerts.csv")
    with open_csv_write(alerts_path) as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS)
        writer.writeheader()
        writer.writerows(alerts)

    by_coord = {}
    for api in all_apis:
        c = api.get('coord', '')
        if not c:
            continue
        by_coord.setdefault(c, []).append(api)

    failed_comparisons = []
    if dependency_status_rows is not None:
        zero_change = [
            row.get("coord")
            for row in dependency_status_rows
            if row.get("comparison_status") == "no_api_change"
            and row.get("coord")
        ]
        failed_comparisons = [
            row for row in dependency_status_rows
            if row.get("comparison_status") == "failed"
        ]
    else:
        zero_change = []
        for row in dep_rows:
            coord = row.get('coord', '')
            change_type = row.get('change_type', '')
            if not coord or change_type in ('未变', '新增', '移除'):
                continue
            if not by_coord.get(coord):
                zero_change.append(coord)

    by_sev = {'P0': 0, 'P1': 0, 'P2': 0}
    by_source = {}
    by_change_type = {}
    for r in all_rows:
        sev = (r.get('severity') or '').strip()
        if sev in by_sev:
            by_sev[sev] += 1
        by_source[r.get('source', '')] = by_source.get(r.get('source', ''), 0) + 1
        by_change_type[r.get('change_type', '')] = by_change_type.get(r.get('change_type', ''), 0) + 1

    summary_path = os.path.join(output_dir, "summary.txt")
    lines = []
    lines.append("Step4 依赖 API 变化摘要")
    lines.append("")
    lines.append("一、先看什么")
    lines.append("- 如果只决定系统触达分析范围，先打开 changed_dependencies.md，复制“依赖包”列中的完整坐标。")
    lines.append(f"- 先看 {DEPENDENCY_ANALYSIS_STATUS_MD}；它直接写明每个依赖的结论和下一步。")
    lines.append("- 如果要核对完整 API 事实，再打开 all_changed_apis.csv。")
    lines.append("- 如果报告提示发布 JAR 缺失、API 对比工具不可用或新旧源码版本待确认，再看本文件后面的缺口清单。")
    lines.append("")
    lines.append("二、本次是否能进入 Step5")
    lines.append(f"- 变更 API 有效行：{valid_count}")
    lines.append(f"- 契约校验失败：{invalid_count}")
    lines.append(f"- 高风险/需关注条目：{len(alerts)}")
    lines.append(f"- 发布 JAR 缺失：{len(jar_missing_deps)}")
    lines.append(f"- API 对比工具未安装：{len(japicmp_missing_deps)}")
    lines.append(f"- API 对比工具执行失败：{len(other_failed_deps)}")
    lines.append(f"- API 对比失败、没有数据：{len(failed_comparisons)}")
    lines.append(f"- 对比成功且无可见 API 变化：{len(zero_change)}")
    if (
        failed_comparisons
        or invalid_count
        or jar_missing_deps
        or japicmp_missing_deps
        or other_failed_deps
    ):
        lines.append(
            "- 结论：变更 API 清单不完整；成功依赖的 API 行仍有效，"
            "但失败依赖修复前不能完成全量 Step5 风险判断。"
        )
    elif valid_count:
        lines.append("- 结论：已生成完整变更 API 清单，可作为 Step5 调用链分析输入。")
    else:
        lines.append("- 结论：未发现可进入 Step5 的变更 API。")
    lines.append("")
    lines.append("三、复核入口")
    lines.append(f"- 依赖包选择清单：{os.path.abspath(os.path.join(output_dir, CHANGED_DEPENDENCIES_MD))}")
    lines.append(f"- 每个依赖的直接结论：{os.path.abspath(os.path.join(output_dir, DEPENDENCY_ANALYSIS_STATUS_MD))}")
    lines.append(f"- 机器可读状态：{os.path.abspath(os.path.join(output_dir, DEPENDENCY_ANALYSIS_STATUS_JSON))}")
    lines.append(f"- 完整变更 API 清单：{os.path.abspath(os.path.join(output_dir, 'all_changed_apis.csv'))}")
    lines.append(f"- 高风险/需关注 API：{os.path.abspath(alerts_path)}")
    lines.append(f"- 新旧源码版本匹配说明：{os.path.abspath(os.path.join(output_dir, 'git_ref_matches.txt'))}")
    lines.append(f"- 新旧源码版本匹配明细：{os.path.abspath(os.path.join(output_dir, 'git_ref_matches.json'))}")
    lines.append("")
    lines.append("四、判断口径")
    lines.append("- Step4 只说明依赖 API 发生了什么变化。")
    lines.append(f"- 是否可以按无变化处理，直接查看 {DEPENDENCY_ANALYSIS_STATUS_MD} 的“可按无变化处理”列。")
    lines.append("- API 变化清单中没有记录，不代表对比成功；必须同时确认逐依赖结果为“分析完整”。")
    lines.append("- Step4 不证明这些变化是否影响当前系统；是否触达业务代码以 Step5/Step6 为准。")
    lines.append("- 如提供了依赖源码，需确认依赖的新旧版本是否匹配到正确的源码版本。")
    lines.append("")
    lines.append("五、运行信息")
    lines.append(f"- 生成时间：{datetime.now().isoformat()}")
    if source_branches:
        lines.append(f"- 主工程分支范围：{source_branches[0]}..{source_branches[1]}")
        lines.append("- 依赖源码默认按依赖自身的新旧版本确定对比范围，不直接沿用主工程分支名。")
    lines.append("")
    lines.append("附录：统计分布")
    lines.append("")
    lines.append("严重级别分布")
    for k in ('P0', 'P1', 'P2'):
        lines.append(f"- {k}: {by_sev.get(k, 0)}")
    lines.append("")
    lines.append("证据来源分布")
    for k, v in sorted(by_source.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"- {k or '未标明来源'}: {v}")
    lines.append("")
    if gitdiff_runs is None:
        gitdiff_runs = []
    if gitdiff_skipped is None:
        gitdiff_skipped = []
    if gitdiff_pending is None:
        gitdiff_pending = []
    if timeout_items is None:
        timeout_items = []
    if gitdiff_runs or gitdiff_skipped or gitdiff_pending:
        lines.append("依赖源码对比")
        lines.append(f"- 已完成源码实现对比：{len(gitdiff_runs)}")
        if gitdiff_runs:
            top = sorted(gitdiff_runs, key=lambda x: (-int(x.get("api_changes", 0)), x.get("coord", "")))
            lines.append(f"- 已执行明细（前 {min(20, len(top))} 项）：")
            for it in top[:20]:
                ref_part = ""
                if it.get("base_ref") or it.get("cur_ref"):
                    ref_part = f"；refs={it.get('base_ref')}..{it.get('cur_ref')}（{it.get('ref_source')}）"
                match_part = ""
                if it.get("old_match_reason") or it.get("new_match_reason"):
                    match_part = (
                        f"；匹配原因=old[{it.get('old_match_reason') or '-'}]"
                        f"，new[{it.get('new_match_reason') or '-'}]"
                    )
                lines.append(
                    f"  - {it.get('coord')}：API 变化 {it.get('api_changes')}；行为变化 {it.get('behavior_changed')}{ref_part}{match_part}；证据文件={it.get('out_file')}"
                )
            if len(top) > 20:
                lines.append(f"  ...（仅展示前 20，共 {len(top)}）")
        lines.append(f"- 未完成源码实现对比：{len(gitdiff_skipped)}")
        if gitdiff_skipped:
            lines.append(f"- 跳过明细（前 {min(20, len(gitdiff_skipped))} 项）：")
            for it in gitdiff_skipped[:20]:
                recovery = (
                    "；发布 JAR 的方法实现检查已补齐证据"
                    if it.get("behavior_fallback_status") == "complete" else ""
                )
                lines.append(f"  - {it.get('coord')}：{it.get('reason')}{recovery}")
            if len(gitdiff_skipped) > 20:
                lines.append(f"  ...（仅展示前 20，共 {len(gitdiff_skipped)}）")
        lines.append(f"- 待人工确认 refs：{len(gitdiff_pending)}")
        if gitdiff_pending:
            lines.append(f"- 待确认明细（前 {min(20, len(gitdiff_pending))} 项）：")
            for it in gitdiff_pending[:20]:
                lines.append(f"  - {it.get('coord')}：{it.get('reason')}")
            if len(gitdiff_pending) > 20:
                lines.append(f"  ...（仅展示前 20，共 {len(gitdiff_pending)}）")
        lines.append("")
    if timeout_items:
        lines.append(f"超时项（前 {min(20, len(timeout_items))} 项）")
        for item in timeout_items[:20]:
            lines.append(
                f"- {item.get('coord')}：阶段={item.get('stage')}；超时={item.get('timeout_seconds')}s；原因={item.get('reason') or '-'}"
            )
        if len(timeout_items) > 20:
            lines.append(f"...（仅展示前 20，共 {len(timeout_items)}）")
        lines.append("")
    lines.append("变更类型分布")
    for k, v in sorted(by_change_type.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"- {k or '未标明类型'}: {v}")
    lines.append("")
    if jar_missing_deps:
        lines.append(f"发布 JAR 缺失（前 {min(20, len(jar_missing_deps))} 项）")
        for c in jar_missing_deps[:20]:
            lines.append(f"- {c}")
        if len(jar_missing_deps) > 20:
            lines.append(f"...（仅展示前 20，共 {len(jar_missing_deps)}）")
        lines.append("")
    if japicmp_missing_deps:
        lines.append(f"API 对比工具未安装（前 {min(20, len(japicmp_missing_deps))} 项）")
        for c in japicmp_missing_deps[:20]:
            lines.append(f"- {c}")
        if len(japicmp_missing_deps) > 20:
            lines.append(f"...（仅展示前 20，共 {len(japicmp_missing_deps)}）")
        lines.append("")
    if other_failed_deps:
        lines.append(f"API 对比工具执行失败（前 {min(20, len(other_failed_deps))} 项）")
        for c in other_failed_deps[:20]:
            lines.append(f"- {c}")
        if len(other_failed_deps) > 20:
            lines.append(f"...（仅展示前 20，共 {len(other_failed_deps)}）")
        lines.append("")
    if failed_comparisons:
        lines.append(
            f"API 对比失败、没有数据"
            f"（前 {min(50, len(failed_comparisons))} 项）"
        )
        lines.append(
            "以下依赖不能解释为零变化；完整字段见 "
            f"{DEPENDENCY_ANALYSIS_STATUS_JSON}。"
        )
        for item in failed_comparisons[:50]:
            lines.append(
                f"- {item.get('coord')}："
                "结果=API 对比失败，不能按无变化处理；"
                f"诊断标识={item.get('reason_code') or 'BINARY_API_COMPARISON_FAILED'}；"
                f"技术原因={item.get('failure_message') or '-'}；"
                f"证据={item.get('evidence_path') or '-'}"
            )
        if len(failed_comparisons) > 50:
            lines.append(f"...（仅展示前 50，共 {len(failed_comparisons)}）")
        lines.append("")
    if changed_deps_missing_source:
        uniq = {}
        for it in changed_deps_missing_source:
            if it.get('coord'):
                uniq[it['coord']] = it
        items = list(uniq.values())
        lines.append(f"升级依赖缺少源码映射（前 {min(20, len(items))} 项）")
        for it in items[:20]:
            lines.append(f"- {it.get('coord')}：{it.get('old_version')} -> {it.get('new_version')}")
        if len(items) > 20:
            lines.append(f"...（仅展示前 20，共 {len(items)}）")
        lines.append("")
    if zero_change:
        lines.append(
            f"API 对比成功且未发现可见变化"
            f"（前 {min(50, len(zero_change))} 项）"
        )
        for c in zero_change[:50]:
            lines.append(f"- {c}")
        if len(zero_change) > 50:
            lines.append(f"...（仅展示前 50，共 {len(zero_change)}）")
        lines.append("")
    if alerts:
        lines.append(f"十五、高风险/需关注 API（前 {min(50, len(alerts))} 项）")
        for r in alerts[:50]:
            lines.append(
                f"- {r.get('coord')}：{r.get('severity')}；{r.get('change_type')}；{r.get('api_name')}；来源={r.get('source')}；已确认={r.get('confirmed')}"
            )
    with open(summary_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write("\n".join(lines) + "\n")

    return alerts_path, summary_path


# ══════════════════════════════════════════════════════════════════
# 主函数
# ══════════════════════════════════════════════════════════════════

def main():
    # A Python process may invoke main() more than once in tests or embedded
    # orchestration.  Keep caching scoped to one Step4 run so live remote facts
    # never leak across runs, while still avoiding duplicate queries/fetches
    # within the run.
    _REPO_REFS_CACHE.clear()
    with _REMOTE_SOURCE_MATERIALIZATION_LOCK:
        _REMOTE_SOURCE_MATERIALIZATION_CACHE.clear()
        _REMOTE_SOURCE_MATERIALIZATION_KEY_LOCKS.clear()
    ap = argparse.ArgumentParser(description='Step 4：jar 包变更全量对比')
    ap.add_argument('--dep-changes',   required=True,
                    help='s1_dep_changes.csv')
    ap.add_argument('--context',       required=True,
                    help='s2_context.json')
    ap.add_argument('--output-dir',    required=True,
                    help='输出目录（.upgrade-report/evidence/api_changes/）')
    ap.add_argument('--coverage-output', default='',
                    help='Step4 覆盖率 JSON 输出路径；编排模式下写入 .runtime/coverage')
    ap.add_argument('--allow-degraded', action='store_true',
                    help='允许在缺少依赖源码映射等情况下继续执行（可能漏掉行为变更或截断调用链）')
    ap.add_argument('--japicmp-jar',
                    default='',
                    help='JApiCmp jar 路径')
    ap.add_argument('--dependency-repo-mappings', nargs='*', default=[],
                    help='依赖源码仓库根目录映射，格式：groupId:artifactId=D:\\repo\\dependency-a；对提供了源码仓库映射的依赖会按版本号模糊匹配 refs 并执行 git diff')
    ap.add_argument('--dependency-git-ref-overrides-json', default='',
                    help='用户确认的依赖 git ref 覆盖 JSON，例如 [{"coord":"g:a","old_ref":"v1","new_ref":"v2"}]')
    ap.add_argument('--git-diff-timeout', type=int, default=DEFAULT_GIT_DIFF_TIMEOUT,
                    help='单个依赖执行 git diff 的超时时间（秒）')
    ap.add_argument('--japicmp-timeout', type=int, default=DEFAULT_JAPICMP_TIMEOUT,
                    help='单个依赖执行 JApiCmp 的超时时间（秒）')
    ap.add_argument('--fetch-timeout', type=int, default=DEFAULT_FETCH_TIMEOUT,
                    help='单次远端 git ls-remote/fetch 的超时时间（秒）')
    ap.add_argument('--tool-install-timeout', type=int, default=DEFAULT_FETCH_TIMEOUT,
                    help='自动安装 JApiCmp 工具的超时时间（秒）；不会用于下载被分析依赖')
    ap.add_argument('--workers', type=int, default=int(os.environ.get("JUA_STEP4_WORKERS", "4") or "4"),
                    help='Step4 依赖级并行 worker 数；设为 1 可恢复串行执行')
    ap.add_argument('--skip-changed-classes', action='store_true',
                    help='跳过 changed_classes.json 的 class hash 计算，减少大批量依赖时的 I/O 开销')
    ap.add_argument('--source-branches', nargs=2,
                    metavar=('BASE', 'CURRENT'),
                    help='主项目上下文分支名，仅用于摘要展示；依赖源码 git diff 默认按依赖版本匹配 refs')
    ap.add_argument('--source-revisions', nargs=2,
                    metavar=('BASE_COMMIT', 'CURRENT_COMMIT'),
                    help='已固定的主项目 base/current commit；用于判断源码是否实际不同')
    args = ap.parse_args()
    orchestrated_input = load_orchestrated_step4_input(args.output_dir)
    if orchestrated_input:
        if not args.allow_degraded and orchestrated_input.get("allow_degraded"):
            args.allow_degraded = True
        args.japicmp_jar = args.japicmp_jar or str(orchestrated_input.get("japicmp_jar") or "")
        if not args.dependency_repo_mappings:
            args.dependency_repo_mappings = list(orchestrated_input.get("dependency_repo_mappings") or [])
        if not args.dependency_git_ref_overrides_json and orchestrated_input.get("dependency_git_ref_overrides"):
            args.dependency_git_ref_overrides_json = json.dumps(
                orchestrated_input.get("dependency_git_ref_overrides") or [],
                ensure_ascii=False,
            )
        if args.git_diff_timeout in (None, "") and orchestrated_input.get("step4_git_diff_timeout"):
            args.git_diff_timeout = int(orchestrated_input.get("step4_git_diff_timeout"))
        if args.japicmp_timeout in (None, "") and orchestrated_input.get("step4_japicmp_timeout"):
            args.japicmp_timeout = int(orchestrated_input.get("step4_japicmp_timeout"))
        if args.fetch_timeout in (None, "") and orchestrated_input.get("step4_fetch_timeout"):
            args.fetch_timeout = int(orchestrated_input.get("step4_fetch_timeout"))
        if args.tool_install_timeout in (None, "") and orchestrated_input.get("step4_tool_install_timeout"):
            args.tool_install_timeout = int(orchestrated_input.get("step4_tool_install_timeout"))
        if orchestrated_input.get("step4_workers"):
            args.workers = int(orchestrated_input.get("step4_workers"))
        if not args.source_branches:
            base_branch = str(orchestrated_input.get("base_branch") or "").strip()
            current_branch = str(orchestrated_input.get("current_branch") or "").strip()
            if base_branch and current_branch:
                args.source_branches = [base_branch, current_branch]
        if not args.source_revisions:
            base_commit = str(orchestrated_input.get("base_resolved_commit") or "").strip()
            current_commit = str(orchestrated_input.get("current_resolved_commit") or "").strip()
            if base_commit and current_commit:
                args.source_revisions = [base_commit, current_commit]

    if not args.japicmp_jar:
        args.japicmp_jar = japicmp_default_jar_path()

    os.makedirs(args.output_dir, exist_ok=True)
    cleanup_step4_generated_outputs(args.output_dir)
    timing = Step4TimingRecorder(infer_report_dir_from_output_dir(args.output_dir))
    timing.record(
        "step4.total",
        status="running",
        message="正在执行 Step4 依赖 API 变更分析",
    )
    try:
        dependency_git_ref_overrides = parse_dependency_git_ref_overrides(args.dependency_git_ref_overrides_json)
    except ValueError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        timing.record("input.dependency_git_ref_overrides", status="error", details=str(exc))
        timing.flush()
        return 2

    step_timer = PhaseTimer("step4", "total")
    load_inputs_timer = time.perf_counter()
    timing.record(
        "input.load",
        status="running",
        message="正在读取依赖变更清单和项目上下文",
    )
    dep_rows = load_csv(args.dep_changes)
    analysis_dep_rows = [
        row for row in dep_rows
        if str(row.get('change_type') or '').strip() != '未变'
    ]
    ctx      = load_json(args.context)
    jdk_current = ctx.get("jdk_current")
    if not args.source_revisions:
        base_revision = str(ctx.get("base_revision") or "").strip()
        current_revision = str(ctx.get("current_revision") or "").strip()
        if base_revision and current_revision:
            args.source_revisions = [base_revision, current_revision]
    timing.record(
        "input.load",
        status="success",
        elapsed=time.perf_counter() - load_inputs_timer,
        details={"dependencies": len(dep_rows), "changed_dependencies": len(ctx.get("changed_dependencies") or [])},
    )
    japicmp_planned_rows = [row for row in dep_rows if dependency_needs_japicmp(row)]
    compute_changed_classes_enabled = False
    if (not args.source_branches) and ctx.get("base_branch") and ctx.get("current_branch"):
        base_br = str(ctx.get("base_branch")).strip()
        cur_br = str(ctx.get("current_branch")).strip()
        if base_br and cur_br and base_br != cur_br:
            args.source_branches = [base_br, cur_br]

    # 解析依赖源码仓库映射
    dependency_paths = {}
    dependency_path_meta = {}
    maven_coord_locations_cache = {}
    source_mapping_timer = time.perf_counter()
    timing.record(
        "source_mapping.resolve",
        status="running",
        message="正在解析依赖源码仓库与模块映射",
    )

    def register_dependency_path(mapped_coord, repo_path, module_path, input_spec, input_coord, mapping_mode, repo_inferred_coords):
        if mapped_coord and mapped_coord not in dependency_paths:
            dependency_paths[mapped_coord] = {
                "repo_path": os.path.abspath(repo_path),
                "module_path": os.path.abspath(module_path or repo_path),
            }
        if mapped_coord:
            dependency_path_meta[mapped_coord] = {
                "coord": mapped_coord,
                "repo_path": os.path.abspath(repo_path),
                "module_path": os.path.abspath(module_path or repo_path),
                "input_spec": input_spec,
                "input_coord": input_coord,
                "mapping_mode": mapping_mode,
                "repo_inferred_coords": repo_inferred_coords,
            }

    for mapping in (args.dependency_repo_mappings or []):
        mapping = (mapping or '').strip()
        if not mapping:
            continue
        if '=' in mapping:
            coord, path = mapping.split('=', 1)
            coord = coord.strip()
            path = path.strip()
            abs_path = os.path.abspath(path)
            coord_locations = _cached_maven_coord_locations(
                abs_path,
                maven_coord_locations_cache,
            )
            inferred_coords = [item.get("coord") for item in coord_locations if item.get("coord")]
            location_by_coord = {item.get("coord"): item for item in coord_locations if item.get("coord")}
            if inferred_coords and coord:
                matched_coords = _filter_inferred_coords_by_prefix(inferred_coords, coord)
                if not matched_coords:
                    print(
                        f"❌ --dependency-repo-mappings 中的 coord={coord} 未能在源码仓库中匹配到实际模块：{abs_path}\n"
                        f"   仓库内推断出的坐标有：{', '.join(inferred_coords[:10]) or '(无)'}",
                        file=sys.stderr,
                    )
                    timing.record(
                        "source_mapping.resolve",
                        coord=coord,
                        status="error",
                        elapsed=time.perf_counter() - source_mapping_timer,
                        details={
                            "path": abs_path,
                            "reason": "coord_not_matched_in_repo",
                            "inferred_coords": inferred_coords[:20],
                        },
                    )
                    timing.record("step4.total", status="source_mapping_error", elapsed=step_timer.elapsed())
                    timing.flush()
                    return 2
                for matched_coord in matched_coords:
                    location = location_by_coord.get(matched_coord) or {}
                    artifact_coord = (
                        coord if artifact_classifier(coord) else matched_coord
                    )
                    register_dependency_path(
                        artifact_coord,
                        location.get("repo_root") or abs_path,
                        location.get("module_dir") or abs_path,
                        mapping,
                        coord,
                        "repo_inference_filtered",
                        inferred_coords,
                    )
                continue
            if coord:
                location = location_by_coord.get(coord) or {}
                register_dependency_path(
                    coord,
                    location.get("repo_root") or abs_path,
                    location.get("module_dir") or abs_path,
                    mapping,
                    coord,
                    "explicit",
                    inferred_coords,
                )
            continue

        abs_path = os.path.abspath(mapping)
        coord_locations = _cached_maven_coord_locations(
            abs_path,
            maven_coord_locations_cache,
        )
        coords = [item.get("coord") for item in coord_locations if item.get("coord")]
        for item in coord_locations:
            coord = item.get("coord")
            if coord:
                register_dependency_path(
                    coord,
                    item.get("repo_root") or abs_path,
                    item.get("module_dir") or abs_path,
                    mapping,
                    "",
                    "repo_inference_all",
                    coords,
                )

    # POM/Gradle metadata identifies a source module by GA, while Step1 rows
    # identify physical runtime artifacts by GA plus an optional classifier.
    # Expand an unqualified module mapping onto each full artifact identity once,
    # then keep all downstream ref/JAR lookups exact.
    for row in dep_rows:
        artifact_coord = str((row or {}).get("coord") or "").strip()
        module_coord = artifact_ga(artifact_coord)
        if (
            not artifact_coord
            or not module_coord
            or artifact_coord in dependency_paths
            or module_coord not in dependency_paths
        ):
            continue
        dependency_paths[artifact_coord] = dict(dependency_paths[module_coord])
        module_meta = dict(dependency_path_meta.get(module_coord) or {})
        dependency_path_meta[artifact_coord] = {
            **module_meta,
            "coord": artifact_coord,
            "module_coord": module_coord,
            "mapping_mode": "ga_module_expansion",
        }
    timing.record(
        "source_mapping.resolve",
        status="success",
        elapsed=time.perf_counter() - source_mapping_timer,
        details={
            "input_mappings": len(args.dependency_repo_mappings or []),
            "resolved_coords": len(dependency_paths),
        },
    )

    changed_dependency_coords = {
        dep['coord'] for dep in ctx.get('changed_dependencies', []) if dep.get('coord')
    }

    analysis_dep_rows = [
        row for row in dep_rows
        if str(row.get('change_type') or '').strip() != '未变'
    ]
    compute_changed_classes_enabled = (not args.skip_changed_classes) and len(analysis_dep_rows) <= 200
    if not compute_changed_classes_enabled:
        print("  ℹ️  changed_classes.json 已降级为轻量模式，跳过 class hash 计算以提升大批量依赖稳定性。", file=sys.stderr)

    preflight_timer = time.perf_counter()
    timing.record(
        "preflight.git_refs",
        status="running",
        message="正在预检依赖源码的 base/current Git 版本",
        details={"changed_dependencies": len(analysis_dep_rows)},
    )
    preflight_gitdiff_runs, preflight_gitdiff_pending = preflight_gitdiff_refs(
        analysis_dep_rows,
        dependency_paths,
        dependency_path_meta,
        dependency_git_ref_overrides,
        fetch_timeout=args.fetch_timeout,
    )
    (
        preflight_gitdiff_pending,
        preflight_gitdiff_skipped,
    ) = partition_git_ref_pending_items(preflight_gitdiff_pending)
    timing.record(
        "preflight.git_refs",
        status=(
            "pending" if preflight_gitdiff_pending
            else ("degraded" if preflight_gitdiff_skipped else "success")
        ),
        elapsed=time.perf_counter() - preflight_timer,
        details={
            "matched": len(preflight_gitdiff_runs),
            "pending": len(preflight_gitdiff_pending),
            "internally_skipped": len(preflight_gitdiff_skipped),
        },
    )
    if preflight_gitdiff_pending:
        source_repo_mappings = [
            dependency_path_meta[key] for key in sorted(dependency_path_meta.keys())
        ]
        pending_refs_path = write_git_ref_pending_file(args.output_dir, preflight_gitdiff_pending)
        write_git_ref_preflight_summary(
            args.output_dir,
            preflight_gitdiff_pending,
            preflight_gitdiff_runs,
        )
        ref_matches_json, ref_matches_txt = write_git_ref_match_outputs(
            output_dir=args.output_dir,
            gitdiff_runs=preflight_gitdiff_runs,
            gitdiff_skipped=preflight_gitdiff_skipped,
            gitdiff_pending=preflight_gitdiff_pending,
            source_repo_mappings=source_repo_mappings,
        )
        interaction = build_git_ref_confirmation_interaction(args.output_dir, preflight_gitdiff_pending)
        emit_progress(
            "step4",
            "preflight",
            f"依赖源码版本存在结果歧义，待确认={len(preflight_gitdiff_pending)}，已提前停止耗时分析",
            elapsed=step_timer.elapsed(),
        )
        print(
            "\n⚠️  Step4 预检发现依赖源码版本存在会改变分析范围的歧义，"
            "已提前停止，避免执行后续耗时分析。",
            file=sys.stderr,
        )
        print(f"  输出：{pending_refs_path}", file=sys.stderr)
        print(f"  输出：{ref_matches_json}", file=sys.stderr)
        print(f"  输出：{ref_matches_txt}", file=sys.stderr)
        timing.record("step4.total", status="awaiting_git_ref_confirmation", elapsed=step_timer.elapsed())
        timing_path = timing.flush()
        print(f"  输出：{timing_path}", file=sys.stderr)
        if os.environ.get("JUA_ORCHESTRATED") == "1":
            emit_interaction(interaction)
            return 0
        return 2

    if preflight_gitdiff_skipped:
        emit_progress(
            "step4",
            "preflight",
            (
                f"{len(preflight_gitdiff_skipped)} 个依赖的源码实现对比不可用，"
                "已自动切换到发布 JAR 分析"
            ),
            elapsed=step_timer.elapsed(),
        )
        print(
            f"  ℹ️  {len(preflight_gitdiff_skipped)} 个依赖的源码实现对比不可用；"
            "系统将自动检查发布 JAR 的 API 和方法实现，无需用户处理。",
            file=sys.stderr,
        )

    if japicmp_planned_rows and not os.path.exists(args.japicmp_jar):
        japicmp_preflight_timer = time.perf_counter()
        timing.record(
            "preflight.japicmp",
            status="running",
            message="正在检查并安装 JApiCmp 工具",
        )
        installed, resolved_japicmp_jar, install_error = auto_install_japicmp(
            args.japicmp_jar,
            timeout=args.tool_install_timeout,
        )
        args.japicmp_jar = resolved_japicmp_jar
        timing.record(
            "preflight.japicmp",
            status="installed" if installed else "missing",
            elapsed=time.perf_counter() - japicmp_preflight_timer,
            details={
                "planned_dependencies": len(japicmp_planned_rows),
                "japicmp_jar": args.japicmp_jar,
                "install_error": install_error or "",
            },
        )
        if not installed:
            planned_dependencies = [
                {
                    "coord": row.get("coord", ""),
                    "old_version": row.get("old_version", ""),
                    "new_version": row.get("new_version", ""),
                    "change_type": row.get("change_type", ""),
                }
                for row in japicmp_planned_rows
            ]
            # Persist an exact diagnostic, but do not turn a missing internal
            # analysis tool into a user decision.  JApiCmp is an accuracy
            # prerequisite: after automatic installation has failed, the run
            # is system-blocked and must not continue with weaker evidence.
            write_japicmp_preflight_details(
                args.output_dir,
                args.japicmp_jar,
                install_error,
                planned_dependencies,
            )
            print("\n❌ API 对比工具（JApiCmp）不可用，无法执行 Java 升级分析。", file=sys.stderr)
            print(f"   自动安装失败原因：{install_error}", file=sys.stderr)
            print("   已记录为系统环境阻塞；不会要求用户确认降级，也不会生成不完整 API 结论。", file=sys.stderr)
            timing.record("step4.total", status="blocked_by_system_japicmp_missing", elapsed=step_timer.elapsed())
            timing.flush()
            return 2
    preflight_plan_by_coord = {
        str(item.get("coord") or ""): item
        for item in preflight_gitdiff_runs
        if str(item.get("coord") or "")
    }
    preflight_skip_by_coord = {
        str(item.get("coord") or ""): item
        for item in preflight_gitdiff_skipped
        if str(item.get("coord") or "")
    }
    all_apis            = []
    jar_missing_deps    = []
    japicmp_missing_deps = []
    other_failed_deps   = []
    changed_classes_by_coord = {}
    changed_classes_errors = []
    changed_deps_missing_source = []
    gitdiff_runs = []
    gitdiff_skipped = []
    gitdiff_pending = []
    bytecode_behavior_runs = []
    timeout_items = []
    binary_runs = []

    report_dir = str(Path(args.output_dir).resolve().parent)
    artifact_resolve_timer = time.perf_counter()
    timing.record(
        "artifact_resolve",
        status="running",
        message="正在解析 Step1 留存的 base/current 依赖 JAR",
        details={"changed_dependencies": len(analysis_dep_rows)},
    )
    artifact_resolver = Step1ArtifactJarResolver(report_dir, args.output_dir)
    prepared_dep_rows = []
    artifact_jar_hits = 0
    for row in analysis_dep_rows:
        prepared = dict(row)
        base_evidence = artifact_resolver.resolve_for_row(row, "base")
        current_evidence = artifact_resolver.resolve_for_row(row, "current")
        prepared["_step4_base_jar_evidence"] = (
            base_evidence or artifact_resolver.failure_for_row(row, "base")
        )
        prepared["_step4_current_jar_evidence"] = (
            current_evidence or artifact_resolver.failure_for_row(row, "current")
        )
        if base_evidence:
            artifact_jar_hits += 1
            prepared["_step4_base_jar_path"] = base_evidence.get("path") or ""
        if current_evidence:
            artifact_jar_hits += 1
            prepared["_step4_current_jar_path"] = current_evidence.get("path") or ""
        prepared_dep_rows.append(prepared)
    prepared_dep_rows, artifact_replacements = pair_artifact_replacement_rows(prepared_dep_rows)
    prepared_dep_rows, same_gav_conflicts = collapse_same_gav_artifact_rows(
        prepared_dep_rows
    )
    if same_gav_conflicts:
        conflict_path = Path(args.output_dir) / "same_gav_identity_conflicts.json"
        conflict_path.write_text(
            json.dumps(
                {
                    "schema": "java-upgrade-analyzer.same-gav-conflicts.v1",
                    "items": same_gav_conflicts,
                },
                ensure_ascii=False,
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        print(
            "❌ Step1 对同一 GAV 留存了不同字节的 JAR，无法按逻辑依赖合并；"
            f"请复核 {conflict_path}",
            file=sys.stderr,
        )
        timing.record(
            "artifact_resolve",
            status="error",
            elapsed=time.perf_counter() - artifact_resolve_timer,
            details={"same_gav_identity_conflicts": len(same_gav_conflicts)},
        )
        timing.record(
            "step4.total",
            status="same_gav_identity_conflict",
            elapsed=step_timer.elapsed(),
        )
        timing.flush()
        return 2
    artifact_replacements_path = Path(args.output_dir) / "artifact_replacements.json"
    artifact_replacements_path.write_text(
        json.dumps(
            {
                "schema": "java-upgrade-analyzer.artifact-replacements.v1",
                "items": artifact_replacements,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    timing.record(
        "artifact_resolve",
        status="success",
        elapsed=time.perf_counter() - artifact_resolve_timer,
        details={
            "dependencies": len(analysis_dep_rows),
            "prepared_dependencies": len(prepared_dep_rows),
            "jar_hits": artifact_jar_hits,
            "artifact_replacements": len(artifact_replacements),
        },
    )

    workers = max(1, int(args.workers or 1))
    if len(prepared_dep_rows) <= 1:
        workers = 1
    total_dependencies = len(prepared_dep_rows)
    print(
        f"\nStep 4 开始：处理 {total_dependencies} 个需分析依赖"
        f"（跳过 {len(dep_rows) - total_dependencies} 个无需分析依赖，workers={workers}，"
        f"Step1 产物 jar 命中={artifact_jar_hits}）",
        file=sys.stderr,
    )
    emit_progress("step4", "plan", f"开始构建 jar 对比证据池，共 {total_dependencies} 个需分析依赖，workers={workers}")

    def process_dependency(i, row):
        result = {
            "index": i,
            "all_apis": [],
            "jar_missing_deps": [],
            "japicmp_missing_deps": [],
            "other_failed_deps": [],
            "changed_classes_by_coord": {},
            "changed_classes_errors": [],
            "changed_deps_missing_source": [],
            "gitdiff_runs": [],
            "gitdiff_skipped": [],
            "gitdiff_pending": [],
            "bytecode_behavior_runs": [],
            "timeout_items": [],
            "binary_runs": [],
            "per_dependency_record": None,
        }
        dependency_timer = time.perf_counter()
        coord      = row.get('coord', '')
        old_ver    = row.get('old_version', '-')
        new_ver    = row.get('new_version', '-')
        change     = row.get('change_type', '')
        scope      = row.get('scope', 'compile')
        timing.record(
            "dependency.total",
            coord=coord,
            old_version=old_ver,
            new_version=new_ver,
            status="running",
            message=f"正在处理依赖 {coord or '<empty>'}（{i}/{total_dependencies}）",
            details={
                "dependency_index": i,
                "dependency_total": total_dependencies,
                "change_type": change,
                "scope": scope,
            },
        )

        if not coord:
            timing.record("dependency.total", status="skipped", elapsed=time.perf_counter() - dependency_timer, details="empty_coord")
            return result
        is_removed_dependency = (change == '移除') or (new_ver == '-' and old_ver != '-')
        is_added_dependency = (change == '新增') or (old_ver == '-' and new_ver != '-')
        dependency_raw_apis = []
        dependency_removed_jar_export = {}
        dependency_gitdiff_apis = []
        dependency_gitdiff_auxiliary_rows = []
        dependency_old_jar = ""
        dependency_new_jar = ""

        is_focus_dependency = coord in changed_dependency_coords if changed_dependency_coords else True
        source_mapping = dependency_paths.get(coord) or {}
        has_source_repo = bool(source_mapping.get("repo_path"))
        if has_source_repo and is_ephemeral_dependency_source_mapping(source_mapping):
            has_source_repo = False
        emit_progress(
            "step4",
            "dependency",
            f"开始处理 {coord} ({old_ver}→{new_ver}) {'源码可用' if has_source_repo else scope}",
            current=i,
            total=total_dependencies,
            item=coord,
        )
        if is_focus_dependency and (not has_source_repo):
            result["changed_deps_missing_source"].append({
                "coord": coord,
                "old_version": old_ver,
                "new_version": new_ver,
            })

        preflight_source_skip = preflight_skip_by_coord.get(coord) or {}
        source_skip_for_behavior = dict(preflight_source_skip)
        if preflight_source_skip and not is_removed_dependency and not is_added_dependency:
            source_skip_timer = time.perf_counter()
            result["gitdiff_skipped"].append(dict(preflight_source_skip))
            print(
                f"    ℹ️  {coord} 的源码实现对比不可用，切换到发布 JAR 分析。",
                file=sys.stderr,
            )
            emit_progress(
                "step4",
                "gitdiff",
                "源码实现对比不可用，已切换到发布 JAR 分析",
                current=i,
                total=total_dependencies,
                elapsed=time.perf_counter() - source_skip_timer,
                item=coord,
            )
            timing.record(
                "dependency.gitdiff",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="skipped",
                elapsed=time.perf_counter() - source_skip_timer,
                details={
                    "reason_code": preflight_source_skip.get("reason_code"),
                    "resolution": preflight_source_skip.get("resolution"),
                },
            )
        elif has_source_repo and not is_removed_dependency and not is_added_dependency:
            # 4b: 有源码依赖做 git diff
            gitdiff_timer = time.perf_counter()
            timing.record(
                "dependency.gitdiff",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="running",
                message=f"正在对比依赖源码 Git diff：{coord}",
                details={"dependency_index": i, "dependency_total": total_dependencies},
            )
            emit_progress(
                "step4",
                "gitdiff",
                f"开始源码实现对比：{coord}",
                current=i,
                total=total_dependencies,
                item=coord,
            )
            lib_info = {
                'coord':         coord,
                'repo_path':     source_mapping.get("repo_path", ''),
                'module_path':   source_mapping.get("module_path", ''),
                'old_version':   old_ver,
                'new_version':   new_ver,
                'old_ref_override': (dependency_git_ref_overrides.get(coord) or {}).get('old_ref', ''),
                'new_ref_override': (dependency_git_ref_overrides.get(coord) or {}).get('new_ref', ''),
                'expected_old_commit': (dependency_git_ref_overrides.get(coord) or {}).get('expected_old_commit', ''),
                'expected_new_commit': (dependency_git_ref_overrides.get(coord) or {}).get('expected_new_commit', ''),
                'allow_local_source': bool((dependency_git_ref_overrides.get(coord) or {}).get('allow_local_source')),
                'allow_dirty_local_source': bool((dependency_git_ref_overrides.get(coord) or {}).get('allow_dirty_local_source')),
                'fetch_timeout': args.fetch_timeout,
            }
            fixed_plan = preflight_plan_by_coord.get(coord) or {}
            if fixed_plan:
                lib_info.update({
                    "base_ref": fixed_plan.get("base_ref"),
                    "cur_ref": fixed_plan.get("cur_ref"),
                    "old_source": fixed_plan.get("old_source") or {},
                    "new_source": fixed_plan.get("new_source") or {},
                    "old_match_reason": fixed_plan.get("old_match_reason") or "",
                    "new_match_reason": fixed_plan.get("new_match_reason") or "",
                })
            gitdiff_result = run_gitdiff(lib_info, args.output_dir, git_diff_timeout=args.git_diff_timeout)
            _out_file = gitdiff_result.get("out_file")
            apis = gitdiff_result.get("apis") or []
            err = gitdiff_result.get("error")
            meta = gitdiff_result.get("meta") or {}
            gitdiff_status = "success"
            gitdiff_details = {"out_file": _out_file or ""}
            if gitdiff_result.get("status") == "needs_user_confirmation":
                gitdiff_status = "pending"
                gitdiff_details = meta.get("reason") or err or ""
                pending_item = {
                    "coord": coord,
                    "old_version": old_ver,
                    "new_version": new_ver,
                    "reason": meta.get("reason") or err,
                    "pending_kind": classify_git_ref_pending_kind(
                        meta.get("reason") or err,
                        meta.get("old_reason"),
                        meta.get("new_reason"),
                    ),
                    "repo_path": meta.get("repo_path") or source_mapping.get("repo_path", ""),
                    "module_path": meta.get("module_path") or source_mapping.get("module_path", ""),
                    "old_reason": meta.get("old_reason") or "",
                    "new_reason": meta.get("new_reason") or "",
                    "old_candidates": meta.get("old_candidates") or [],
                    "new_candidates": meta.get("new_candidates") or [],
                    "old_ref_override": meta.get("old_ref_override") or "",
                    "new_ref_override": meta.get("new_ref_override") or "",
                    "mapping_mode": (dependency_path_meta.get(coord) or {}).get("mapping_mode"),
                    "out_file": os.path.abspath(_out_file) if _out_file else "",
                }
                user_pending, internal_skipped = partition_git_ref_pending_items([pending_item])
                if internal_skipped:
                    gitdiff_status = "skipped"
                    source_skip_for_behavior = dict(internal_skipped[0])
                    result["gitdiff_skipped"].extend(internal_skipped)
                    print(
                        "    ℹ️  源码版本在正式对比时失效，已自动切换到发布 JAR 分析。",
                        file=sys.stderr,
                    )
                    emit_progress(
                        "step4",
                        "gitdiff",
                        "源码版本解析故障，已切换到发布 JAR 分析",
                        current=i,
                        total=total_dependencies,
                        elapsed=time.perf_counter() - gitdiff_timer,
                        item=coord,
                    )
                else:
                    result["gitdiff_pending"].extend(user_pending)
                    print("    ⚠️  源码版本存在多组提交范围，已加入待用户确认清单。", file=sys.stderr)
                    emit_progress(
                        "step4",
                        "gitdiff",
                        "源码版本存在结果歧义，需要用户选择提交范围",
                        current=i,
                        total=total_dependencies,
                        elapsed=time.perf_counter() - gitdiff_timer,
                        item=coord,
                    )
            elif gitdiff_result.get("status") == "error":
                gitdiff_status = "error"
                gitdiff_details = err or ""
                print(f"    ⚠️  源码实现对比失败：{err}", file=sys.stderr)
                emit_progress(
                    "step4",
                    "gitdiff",
                    f"源码实现对比失败：{err}",
                    current=i,
                    total=total_dependencies,
                    elapsed=time.perf_counter() - gitdiff_timer,
                    item=coord,
                )
                generic_source_skip = {
                    "coord": coord,
                    "old_version": old_ver,
                    "new_version": new_ver,
                    "reason": err,
                    "reason_code": "DEPENDENCY_SOURCE_DIFF_UNAVAILABLE",
                    "resolution": "continue_with_final_artifact_analysis",
                    "user_attention_required": False,
                    "evidence_impact": "源码证据暂缺；等待发布 JAR 的方法实现检查结果",
                    "repo_path": meta.get("repo_path") or source_mapping.get("repo_path", ""),
                    "module_path": meta.get("module_path") or source_mapping.get("module_path", ""),
                    "old_candidates": meta.get("old_candidates") or [],
                    "new_candidates": meta.get("new_candidates") or [],
                    "out_file": os.path.abspath(_out_file) if _out_file else "",
                }
                source_skip_for_behavior = dict(generic_source_skip)
                result["gitdiff_skipped"].append(generic_source_skip)
                if meta.get("timed_out"):
                    result["timeout_items"].append(
                        {
                            "coord": coord,
                            "stage": "gitdiff",
                            "timeout_seconds": args.git_diff_timeout,
                            "reason": err,
                            "old_version": old_ver,
                            "new_version": new_ver,
                        }
                    )
            else:
                dependency_gitdiff_apis = list(apis)
                behavior_changed = sum(1 for a in apis if a.get("change_type") == "BEHAVIOR_CHANGED")
                structural_changed = len(apis) - behavior_changed
                print(
                    f"    → {len(apis)} 个源码差异（实现变化={behavior_changed}，"
                    f"结构变化={structural_changed}；等待发布 JAR 结果核验）",
                    file=sys.stderr,
                )
                emit_progress(
                    "step4",
                    "gitdiff",
                    f"源码实现对比完成，发现 {len(apis)} 个变化，等待发布 JAR 结果核验，涉及实现变化的文件={behavior_changed}",
                    current=i,
                    total=total_dependencies,
                    elapsed=time.perf_counter() - gitdiff_timer,
                    item=coord,
                )
                result["gitdiff_runs"].append(
                    {
                        "coord": coord,
                        "old_version": old_ver,
                        "new_version": new_ver,
                        "api_changes": len(apis),
                        "behavior_changed": behavior_changed,
                        "structural_source_changes": structural_changed,
                        "out_file": os.path.abspath(_out_file),
                        "base_ref": (meta or {}).get("base_ref"),
                        "cur_ref": (meta or {}).get("cur_ref"),
                        "ref_source": (meta or {}).get("ref_source"),
                        "old_match_reason": (meta or {}).get("old_reason"),
                        "new_match_reason": (meta or {}).get("new_reason"),
                        "old_candidates": (meta or {}).get("old_candidates") or [],
                        "new_candidates": (meta or {}).get("new_candidates") or [],
                        "old_source": fixed_plan.get("old_source") or {},
                        "new_source": fixed_plan.get("new_source") or {},
                        "current_source_status": str(
                            (fixed_plan.get("new_source") or {}).get("status") or ""
                        ),
                        "repo_path": (meta or {}).get("repo_path") or source_mapping.get("repo_path", ""),
                        "module_path": (meta or {}).get("module_path") or source_mapping.get("module_path", ""),
                        "module_rel_path": (meta or {}).get("module_rel_path"),
                        "mapping_mode": (dependency_path_meta.get(coord) or {}).get("mapping_mode"),
                    }
                )
            timing.record(
                "dependency.gitdiff",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status=gitdiff_status,
                elapsed=time.perf_counter() - gitdiff_timer,
                api_count=len(apis),
                details=gitdiff_details,
            )

        # 4a: 升级依赖做 JApiCmp；removed 依赖导出旧 jar 符号集作为 Step5 输入
        if is_removed_dependency:
            removed_timer = time.perf_counter()
            timing.record(
                "dependency.removed_jar_export",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="running",
                message=f"正在导出已移除依赖的旧版 JAR 符号：{coord}",
                details={"dependency_index": i, "dependency_total": total_dependencies},
            )
            emit_progress(
                "step4",
                "japicmp",
                f"开始导出 removed jar 旧版符号：{coord}",
                current=i,
                total=total_dependencies,
                item=coord,
            )
            removed_out_file, apis, jar_info, err = export_removed_jar_apis(
                coord,
                old_ver,
                args.output_dir,
                old_coord=_resolve_step4_side_coord(row, "base", coord),
                fetch_timeout=args.fetch_timeout,
                old_jar_path=row.get("_step4_base_jar_path") or "",
                old_jar_evidence=row.get("_step4_base_jar_evidence") or {},
            )
            dependency_removed_jar_export = {
                "out_file": os.path.abspath(removed_out_file),
                "old_coord": _resolve_step4_side_coord(row, "base", coord),
                "old_jar": (jar_info or {}).get("old_jar"),
                "old_jar_source": (jar_info or {}).get("old_jar_source") or "",
                "old_jar_evidence": (jar_info or {}).get("old_jar_evidence") or {},
                "class_count": len(list({_normalize_contract_value(item, "api_name") for item in apis if item.get("symbol_kind") == "class"})),
                "errors": list((jar_info or {}).get("errors") or []),
                "error": err,
            }
            if err:
                result["binary_runs"].append({
                    'coord': coord,
                    'status': 'failed',
                    'mode': 'old_jar_export',
                    'old_version': old_ver,
                    'new_version': new_ver,
                    'change_type': change,
                    'api_count': 0,
                    'evidence_path': os.path.abspath(removed_out_file),
                    'error': err,
                    'reason_code': str(
                        (jar_info or {}).get('reason_code')
                        or 'OLD_JAR_SYMBOL_EXPORT_FAILED'
                    ),
                    'old_jar_evidence': (jar_info or {}).get('old_jar_evidence') or {},
                })
                print(f"    ⚠️  removed jar 旧版符号导出失败：{err}", file=sys.stderr)
                emit_progress(
                    "step4",
                    "japicmp",
                    f"removed jar 旧版符号导出失败：{err}",
                    current=i,
                    total=total_dependencies,
                    elapsed=time.perf_counter() - removed_timer,
                    item=coord,
                )
                result["jar_missing_deps"].append(coord)
            else:
                result["binary_runs"].append({
                    'coord': coord,
                    'status': 'success',
                    'mode': 'old_jar_export',
                    'old_version': old_ver,
                    'new_version': new_ver,
                    'change_type': change,
                    'api_count': len(apis),
                    'evidence_path': os.path.abspath(removed_out_file),
                    'old_jar_source': str((jar_info or {}).get('old_jar_source') or ''),
                })
                dependency_raw_apis.extend(apis)
                result["all_apis"].extend(apis)
                print(f"    → {len(apis)} 个 removed jar 旧版符号", file=sys.stderr)
                emit_progress(
                    "step4",
                    "japicmp",
                    f"removed jar 符号导出完成，提取 {len(apis)} 个变化",
                    current=i,
                    total=total_dependencies,
                    elapsed=time.perf_counter() - removed_timer,
                    item=coord,
                )
            timing.record(
                "dependency.removed_jar_export",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="error" if err else "success",
                elapsed=time.perf_counter() - removed_timer,
                api_count=len(apis),
                details=err or {"old_jar_source": str((jar_info or {}).get("old_jar_source") or "")},
            )
        elif change != '未变' and old_ver != '-' and new_ver != '-':
            japicmp_timer = time.perf_counter()
            timing.record(
                "dependency.japicmp",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="running",
                message=f"正在执行发布 JAR API 对比：{coord}",
                details={"dependency_index": i, "dependency_total": total_dependencies},
            )
            emit_progress(
                "step4",
                "japicmp",
                f"开始 API 对比：{coord}",
                current=i,
                total=total_dependencies,
                item=coord,
            )
            _out_file, apis, jar_info, err = run_japicmp(
                coord,
                old_ver,
                new_ver,
                args.output_dir,
                args.japicmp_jar,
                japicmp_timeout=args.japicmp_timeout,
                fetch_timeout=args.fetch_timeout,
                old_coord=_resolve_step4_side_coord(row, "base", coord),
                new_coord=_resolve_step4_side_coord(row, "current", coord),
                old_jar_path=row.get("_step4_base_jar_path") or "",
                new_jar_path=row.get("_step4_current_jar_path") or "",
                old_jar_evidence=row.get("_step4_base_jar_evidence") or {},
                new_jar_evidence=row.get("_step4_current_jar_evidence") or {},
                jdk_current=jdk_current,
                cache_dir=(
                    infer_report_dir_from_output_dir(args.output_dir)
                    / RUNTIME_DIRNAME / RUNTIME_CACHE_DIRNAME
                    / JAPICMP_COMPARISON_CACHE_DIRNAME
                ),
            )
            result["binary_runs"].append({
                'coord': coord,
                'status': 'failed' if err else 'success',
                'mode': 'japicmp',
                'old_version': old_ver,
                'new_version': new_ver,
                'change_type': change,
                'api_count': len(apis),
                'evidence_path': os.path.abspath(_out_file),
                'old_jar_source': str((jar_info or {}).get('old_jar_source') or ''),
                'new_jar_source': str((jar_info or {}).get('new_jar_source') or ''),
                'parser_mode': str((jar_info or {}).get('parser_mode') or ''),
                'xml_error': str((jar_info or {}).get('xml_error') or ''),
                'missing_class_policy': str((jar_info or {}).get('missing_class_policy') or ''),
                'japicmp_version': str((jar_info or {}).get('japicmp_version') or ''),
                'japicmp_sha256': str((jar_info or {}).get('japicmp_sha256') or ''),
                'error': str(err or ''),
                'reason_code': str(
                    (jar_info or {}).get('reason_code')
                    or (JAPICMP_EXECUTION_FAILED if err else '')
                ),
                'old_jar_evidence': (jar_info or {}).get('old_jar_evidence') or {},
                'new_jar_evidence': (jar_info or {}).get('new_jar_evidence') or {},
            })
            if compute_changed_classes_enabled and jar_info and jar_info.get("old_jar") and jar_info.get("new_jar"):
                changed_classes_timer = time.perf_counter()
                timing.record(
                    "dependency.changed_classes",
                    coord=coord,
                    old_version=old_ver,
                    new_version=new_ver,
                    status="running",
                    message=f"正在计算 class 字节码变化：{coord}",
                )
                try:
                    result["changed_classes_by_coord"][coord] = {
                        "coord": coord,
                        "old_version": old_ver,
                        "new_version": new_ver,
                        "old_jar": jar_info["old_jar"],
                        "new_jar": jar_info["new_jar"],
                        **compute_changed_classes(jar_info["old_jar"], jar_info["new_jar"]),
                    }
                    timing.record(
                        "dependency.changed_classes",
                        coord=coord,
                        old_version=old_ver,
                        new_version=new_ver,
                        status="success",
                        elapsed=time.perf_counter() - changed_classes_timer,
                        details={"old_jar": jar_info["old_jar"], "new_jar": jar_info["new_jar"]},
                    )
                except Exception as e:
                    result["changed_classes_errors"].append(f"{coord}: {str(e)[:120]}")
                    timing.record(
                        "dependency.changed_classes",
                        coord=coord,
                        old_version=old_ver,
                        new_version=new_ver,
                        status="error",
                        elapsed=time.perf_counter() - changed_classes_timer,
                        details=str(e)[:200],
                    )
            if err:
                print(f"    ⚠️  API 对比工具执行失败：{err}", file=sys.stderr)
                emit_progress(
                    "step4",
                    "japicmp",
                    f"API 对比失败：{err}",
                    current=i,
                    total=total_dependencies,
                    elapsed=time.perf_counter() - japicmp_timer,
                    item=coord,
                )
                if (jar_info or {}).get('reason_code') == 'FINAL_ARTIFACT_JAR_EVIDENCE_MISSING':
                    result["jar_missing_deps"].append(coord)
                elif 'JApiCmp 未安装' in err:
                    result["japicmp_missing_deps"].append(coord)
                else:
                    result["other_failed_deps"].append(coord)
                    if '超时' in err:
                        result["timeout_items"].append(
                            {
                                "coord": coord,
                                "stage": "japicmp",
                                "timeout_seconds": args.japicmp_timeout,
                                "reason": err,
                                "old_version": old_ver,
                                "new_version": new_ver,
                            }
                        )
            else:
                print(f"    → 发现 {len(apis)} 个二进制不兼容 API 变化", file=sys.stderr)
                emit_progress(
                    "step4",
                    "japicmp",
                    f"API 对比完成，发现 {len(apis)} 个变化",
                    current=i,
                    total=total_dependencies,
                    elapsed=time.perf_counter() - japicmp_timer,
                    item=coord,
                )
            timing.record(
                "dependency.japicmp",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="error" if err else "success",
                elapsed=time.perf_counter() - japicmp_timer,
                external_process_count=(
                    int((jar_info or {}).get("external_process_count") or 0)
                ),
                api_count=len(apis),
                details=err or {
                    "old_jar_source": str((jar_info or {}).get("old_jar_source") or ""),
                    "new_jar_source": str((jar_info or {}).get("new_jar_source") or ""),
                    "parser_mode": str((jar_info or {}).get("parser_mode") or ""),
                    "comparison_cache_hit": bool(
                        (jar_info or {}).get("comparison_cache_hit")
                    ),
                },
            )
            dependency_old_jar = str((jar_info or {}).get("old_jar") or "")
            dependency_new_jar = str((jar_info or {}).get("new_jar") or "")
            dependency_raw_apis.extend(apis)
            result["all_apis"].extend(apis)

        if dependency_old_jar and dependency_new_jar:
            contract_timer = time.perf_counter()
            timing.record(
                "dependency.data_contract",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="running",
                message=f"正在对比 DTO/数据契约变化：{coord}",
            )
            try:
                contract_apis = collect_data_contract_changes(
                    dependency_old_jar,
                    dependency_new_jar,
                    coord=coord,
                    old_version=old_ver,
                    new_version=new_ver,
                    jdk_current=jdk_current,
                )
            except (OSError, ValueError, zipfile.BadZipFile, struct.error) as exc:
                contract_apis = []
                result["other_failed_deps"].append(coord)
                result["binary_runs"].append({
                    "coord": coord,
                    "status": "failed",
                    "mode": "data_contract",
                    "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                })
                timing.record(
                    "dependency.data_contract",
                    coord=coord,
                    old_version=old_ver,
                    new_version=new_ver,
                    status="error",
                    elapsed=time.perf_counter() - contract_timer,
                    details=f"{type(exc).__name__}: {str(exc)[:200]}",
                )
            else:
                dependency_raw_apis.extend(contract_apis)
                result["all_apis"].extend(contract_apis)
                result["binary_runs"].append({
                    "coord": coord,
                    "status": "success",
                    "mode": "data_contract",
                    "api_changes": len(contract_apis),
                })
                timing.record(
                    "dependency.data_contract",
                    coord=coord,
                    old_version=old_ver,
                    new_version=new_ver,
                    status="success",
                    elapsed=time.perf_counter() - contract_timer,
                    api_count=len(contract_apis),
                )

        if source_skip_for_behavior:
            behavior_timer = time.perf_counter()
            timing.record(
                "dependency.behavior_bytecode_fallback",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="running",
                message=f"正在检查发布 JAR 的方法实现变化：{coord}",
            )
            if dependency_old_jar and dependency_new_jar:
                try:
                    behavior_fallback = compare_jar_method_bodies(
                        dependency_old_jar,
                        dependency_new_jar,
                        coord=coord,
                        old_version=old_ver,
                        new_version=new_ver,
                        output_dir=args.output_dir,
                        target_jdk=jdk_current,
                    )
                except (OSError, ValueError, zipfile.BadZipFile) as exc:
                    behavior_fallback = {
                        "status": "insufficient",
                        "reason_code": "FINAL_JAR_BEHAVIOR_DIFF_UNAVAILABLE",
                        "errors": [f"{type(exc).__name__}:{str(exc)[:200]}"],
                        "rows": [],
                    }
            else:
                behavior_fallback = {
                    "status": "insufficient",
                    "reason_code": "FINAL_JAR_BEHAVIOR_DIFF_UNAVAILABLE",
                    "errors": ["final_artifact_dependency_jars_unavailable"],
                    "rows": [],
                }
            behavior_rows = list(behavior_fallback.get("rows") or [])
            behavior_run = {
                "coord": coord,
                "old_version": old_ver,
                "new_version": new_ver,
                "status": behavior_fallback.get("status") or "insufficient",
                "reason_code": behavior_fallback.get("reason_code") or "",
                "api_changes": len(behavior_rows),
                "modified_classes": int(behavior_fallback.get("modified_classes") or 0),
                "scanned_classes": int(behavior_fallback.get("scanned_classes") or 0),
                "javap_invocations": int(behavior_fallback.get("javap_invocations") or 0),
                "evidence_path": behavior_fallback.get("evidence_path") or "",
                "errors": list(behavior_fallback.get("errors") or []),
            }
            result["bytecode_behavior_runs"].append(behavior_run)
            if behavior_run["status"] == "complete":
                dependency_raw_apis.extend(behavior_rows)
                result["all_apis"].extend(behavior_rows)
                for skipped_item in result["gitdiff_skipped"]:
                    if skipped_item.get("coord") == coord:
                        skipped_item["resolution"] = "recovered_with_final_jar_method_bytecode_diff"
                        skipped_item["behavior_fallback_status"] = "complete"
                        skipped_item["behavior_fallback_evidence"] = behavior_run["evidence_path"]
                        skipped_item["evidence_impact"] = (
                            "源码实现对比未完成；发布 JAR 的方法实现检查已补齐变化识别"
                        )
                print(
                    f"    → 发布 JAR 的方法实现检查完成：发现 {len(behavior_rows)} 个变化候选",
                    file=sys.stderr,
                )
            else:
                print(
                    "    ⚠️  发布 JAR 的方法实现检查未完成；当前不能形成完整或无影响结论。",
                    file=sys.stderr,
                )
            emit_progress(
                "step4",
                "behavior-bytecode",
                (
                    f"发布 JAR 的方法实现检查{('完成' if behavior_run['status'] == 'complete' else '证据不足')}，"
                    f"发现变化候选={len(behavior_rows)}"
                ),
                current=i,
                total=total_dependencies,
                elapsed=time.perf_counter() - behavior_timer,
                item=coord,
            )
            timing.record(
                "dependency.behavior_bytecode_fallback",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status=behavior_run["status"],
                elapsed=time.perf_counter() - behavior_timer,
                external_process_count=behavior_run["javap_invocations"],
                api_count=len(behavior_rows),
                details={
                    "reason_code": behavior_run["reason_code"],
                    "evidence_path": behavior_run["evidence_path"],
                    "errors": behavior_run["errors"][:5],
                },
            )

        if dependency_gitdiff_apis:
            gitdiff_filter_timer = time.perf_counter()
            timing.record(
                "dependency.gitdiff_jar_truth_filter",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="running",
                message=f"正在用发布 JAR 结果核验源码实现变化：{coord}",
            )
            accepted_source_apis, rejected_source_apis = filter_gitdiff_rows_with_jar_truth(
                dependency_gitdiff_apis,
                old_jar=dependency_old_jar,
                new_jar=dependency_new_jar,
                coord=coord,
                old_ver=old_ver,
                new_ver=new_ver,
            )
            dependency_gitdiff_auxiliary_rows = rejected_source_apis
            aux_path = write_gitdiff_auxiliary_rows(args.output_dir, coord, rejected_source_apis)
            dependency_raw_apis.extend(accepted_source_apis)
            result["all_apis"].extend(accepted_source_apis)
            for run_item in result["gitdiff_runs"]:
                if run_item.get("coord") == coord:
                    run_item["promoted_to_step5"] = len(accepted_source_apis)
                    run_item["auxiliary_only"] = len(rejected_source_apis)
                    run_item["auxiliary_only_file"] = os.path.abspath(aux_path) if aux_path else ""
            print(
                f"    → 源码实现变化经发布 JAR 核验：进入后续分析={len(accepted_source_apis)}，"
                f"辅助证据={len(rejected_source_apis)}",
                file=sys.stderr,
            )
            emit_progress(
                "step4",
                "gitdiff",
                f"源码实现变化核验完成，进入后续分析={len(accepted_source_apis)}，仅作辅助证据={len(rejected_source_apis)}",
                current=i,
                total=total_dependencies,
                item=coord,
            )
            timing.record(
                "dependency.gitdiff_jar_truth_filter",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="success",
                elapsed=time.perf_counter() - gitdiff_filter_timer,
                api_count=len(accepted_source_apis),
                details={"auxiliary_only": len(rejected_source_apis)},
            )

        # 4c: changelog 分析任务文件（由 AI agent 后续填写）
        if change in ('大版本升级', '小版本升级') and (not has_source_repo):
            changelog_timer = time.perf_counter()
            timing.record(
                "dependency.changelog_task",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="running",
                message=f"正在生成 changelog 后续分析任务：{coord}",
            )
            analyze_changelog(coord, old_ver, new_ver, args.output_dir)
            timing.record(
                "dependency.changelog_task",
                coord=coord,
                old_version=old_ver,
                new_version=new_ver,
                status="success",
                elapsed=time.perf_counter() - changelog_timer,
            )
        result["per_dependency_record"] = {
            "coord": coord,
            "dep_row": {k: v for k, v in dict(row).items() if not str(k).startswith("_step4_")},
            "raw_rows": dependency_raw_apis,
            "removed_jar_export": dependency_removed_jar_export,
            "gitdiff_auxiliary_rows": dependency_gitdiff_auxiliary_rows,
        }
        emit_progress(
            "step4",
            "dependency",
            f"完成处理 {coord}",
            current=i,
            total=total_dependencies,
            elapsed=time.perf_counter() - dependency_timer,
            item=coord,
        )
        timing.record(
            "dependency.total",
            coord=coord,
            old_version=old_ver,
            new_version=new_ver,
            status="success",
            elapsed=time.perf_counter() - dependency_timer,
            api_count=len(dependency_raw_apis),
        )
        return result

    def dependency_worker_failure(index, row, exc):
        coord = str((row or {}).get("coord") or "").strip()
        old_version = str((row or {}).get("old_version") or "").strip()
        new_version = str((row or {}).get("new_version") or "").strip()
        message = f"{type(exc).__name__}: {exc}"[:500]
        print(
            f"    ⚠️  依赖 worker 异常，已记录为数据不可用：{coord}：{message}",
            file=sys.stderr,
        )
        timing.record(
            "dependency.total",
            coord=coord,
            old_version=old_version,
            new_version=new_version,
            status="error",
            details={
                "reason_code": "STEP4_DEPENDENCY_WORKER_FAILED",
                "error": message,
            },
        )
        return {
            "index": index,
            "all_apis": [],
            "jar_missing_deps": [],
            "japicmp_missing_deps": [],
            "other_failed_deps": [coord] if coord else [],
            "changed_classes_by_coord": {},
            "changed_classes_errors": [],
            "changed_deps_missing_source": [],
            "gitdiff_runs": [],
            "gitdiff_skipped": [],
            "gitdiff_pending": [],
            "bytecode_behavior_runs": [],
            "timeout_items": [],
            "binary_runs": [{
                "coord": coord,
                "status": "failed",
                "mode": "dependency_worker",
                "old_version": old_version,
                "new_version": new_version,
                "change_type": str((row or {}).get("change_type") or ""),
                "api_count": 0,
                "reason_code": "STEP4_DEPENDENCY_WORKER_FAILED",
                "error": message,
                "evidence_path": "",
            }],
            "per_dependency_record": {
                "coord": coord,
                "dep_row": {
                    key: value for key, value in dict(row or {}).items()
                    if not str(key).startswith("_step4_")
                },
                "raw_rows": [],
                "removed_jar_export": {},
                "gitdiff_auxiliary_rows": [],
            } if coord else None,
        }

    per_dependency_records = {}
    task_results = []
    dependencies_timer = time.perf_counter()
    timing.record(
        "dependencies.process_all",
        status="running",
        message=(
            f"正在并行处理 {len(prepared_dep_rows)} 个变更依赖"
            f"（workers={workers}）"
        ),
        details={"dependencies": len(prepared_dep_rows), "workers": workers},
    )
    if workers == 1:
        for i, row in enumerate(prepared_dep_rows, 1):
            try:
                task_results.append(process_dependency(i, row))
            except Exception as exc:
                task_results.append(dependency_worker_failure(i, row, exc))
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="step4-dep") as executor:
            futures = {
                executor.submit(process_dependency, i, row): (i, row)
                for i, row in enumerate(prepared_dep_rows, 1)
            }
            for future in as_completed(futures):
                index, row = futures[future]
                try:
                    task_results.append(future.result())
                except Exception as exc:
                    task_results.append(
                        dependency_worker_failure(index, row, exc)
                    )
    worker_failure_count = sum(
        1
        for result in task_results
        for run in (result.get("binary_runs") or [])
        if run.get("mode") == "dependency_worker"
        and run.get("status") == "failed"
    )
    timing.record(
        "dependencies.process_all",
        status="partial" if worker_failure_count else "success",
        elapsed=time.perf_counter() - dependencies_timer,
        details={
            "dependencies": len(prepared_dep_rows),
            "workers": workers,
            "worker_failures": worker_failure_count,
        },
    )

    for item in sorted(task_results, key=lambda value: value.get("index") or 0):
        all_apis.extend(item.get("all_apis") or [])
        jar_missing_deps.extend(item.get("jar_missing_deps") or [])
        japicmp_missing_deps.extend(item.get("japicmp_missing_deps") or [])
        other_failed_deps.extend(item.get("other_failed_deps") or [])
        changed_classes_by_coord.update(item.get("changed_classes_by_coord") or {})
        changed_classes_errors.extend(item.get("changed_classes_errors") or [])
        changed_deps_missing_source.extend(item.get("changed_deps_missing_source") or [])
        gitdiff_runs.extend(item.get("gitdiff_runs") or [])
        gitdiff_skipped.extend(item.get("gitdiff_skipped") or [])
        gitdiff_pending.extend(item.get("gitdiff_pending") or [])
        bytecode_behavior_runs.extend(item.get("bytecode_behavior_runs") or [])
        timeout_items.extend(item.get("timeout_items") or [])
        binary_runs.extend(item.get("binary_runs") or [])
        per_record = item.get("per_dependency_record")
        if per_record and per_record.get("coord"):
            per_dependency_records[per_record.get("coord")] = per_record

    # A late source-ref failure can still occur if repository state changes
    # after preflight.  Apply the same interaction boundary here so operational
    # failures never become user work merely because they happened later.
    gitdiff_pending, late_gitdiff_skipped = partition_git_ref_pending_items(gitdiff_pending)
    gitdiff_skipped.extend(late_gitdiff_skipped)

    dependency_status_rows, dependency_status_csv, dependency_status_json = (
        write_dependency_analysis_status(
            prepared_dep_rows,
            binary_runs,
            args.output_dir,
            gitdiff_runs=gitdiff_runs,
            gitdiff_skipped=gitdiff_skipped,
            gitdiff_pending=gitdiff_pending,
            bytecode_behavior_runs=bytecode_behavior_runs,
            changed_deps_missing_source=changed_deps_missing_source,
        )
    )
    dependency_status_by_coord = {
        item["coord"]: item for item in dependency_status_rows
    }

    # 写入汇总文件
    write_all_timer = time.perf_counter()
    timing.record(
        "write.all_changed_apis",
        status="running",
        message="正在汇总并写入全量变更 API",
        details={"raw_api_rows": len(all_apis)},
    )
    csv_file, valid_count, invalid_count = write_all_changed_apis(
        all_apis, args.output_dir)
    normalized_api_rows = load_csv(csv_file)
    timing.record(
        "rank.business_bytecode",
        status="running",
        message="正在收集业务最终制品对变更 API 的直接字节码引用，用于依赖优先级排序",
        details={"changed_api_count": len(normalized_api_rows)},
    )
    priority_started_at = time.perf_counter()
    business_reference_summary = collect_business_bytecode_priority_evidence(
        normalized_api_rows,
        args.output_dir,
    )
    timing.record(
        "rank.business_bytecode",
        status=(
            "success"
            if business_reference_summary.get("scan_status") == "complete"
            else "partial"
        ),
        elapsed=time.perf_counter() - priority_started_at,
        details={
            "scan_status": business_reference_summary.get("scan_status"),
            "matched_dependencies": len(
                business_reference_summary.get("by_coord") or {}
            ),
            "reason_codes": business_reference_summary.get("reason_codes") or [],
        },
    )
    write_changed_dependencies(
        normalized_api_rows,
        args.output_dir,
        dependency_status_rows=dependency_status_rows,
        business_reference_summary=business_reference_summary,
    )
    timing.record(
        "write.all_changed_apis",
        status="success",
        elapsed=time.perf_counter() - write_all_timer,
        api_count=valid_count,
        details={"invalid_count": invalid_count, "output": csv_file},
    )
    write_per_dep_timer = time.perf_counter()
    timing.record(
        "write.per_dependency_outputs",
        status="running",
        message="正在写入逐依赖 API 变更证据",
        details={"dependencies": len(per_dependency_records)},
    )
    for coord in sorted(per_dependency_records.keys()):
        item = per_dependency_records.get(coord) or {}
        write_per_dependency_outputs(
            report_dir=report_dir,
            dep_row=item.get("dep_row") or {},
            raw_rows=item.get("raw_rows") or [],
            removed_jar_export=item.get("removed_jar_export") or None,
            gitdiff_auxiliary_rows=item.get("gitdiff_auxiliary_rows") or [],
            dependency_analysis=dependency_status_by_coord.get(coord) or {},
        )
    timing.record(
        "write.per_dependency_outputs",
        status="success",
        elapsed=time.perf_counter() - write_per_dep_timer,
        details={"dependencies": len(per_dependency_records)},
    )

    changed_classes_write_timer = time.perf_counter()
    timing.record(
        "write.changed_classes",
        status="running",
        message="正在写入类级变更索引",
    )
    changed_classes_path = os.path.join(args.output_dir, "changed_classes.json")
    with open(changed_classes_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "meta": {
                    "what": "类级变更索引（按依赖聚合的 added/removed/modified 类集合）",
                    "why": "补充 all_changed_apis.csv 的证据维度，用于定位受影响的变更类集合",
                    "how_to_read": [
                        "deps[coord].added/removed/modified 是类全限定名列表",
                        "errors 记录提取失败的依赖（只保留前 50 条）",
                    ],
                    "enabled": compute_changed_classes_enabled,
                },
                "generated_at": datetime.now().isoformat(),
                "deps": changed_classes_by_coord,
                "errors": changed_classes_errors[:50],
            },
            f,
            ensure_ascii=False,
            indent=2,
        )
    timing.record(
        "write.changed_classes",
        status="success",
        elapsed=time.perf_counter() - changed_classes_write_timer,
        details={"enabled": compute_changed_classes_enabled, "dependencies": len(changed_classes_by_coord)},
    )

    print(f"\nStep 4 完成：", file=sys.stderr)
    print(f"  变更 API 总数：{valid_count}", file=sys.stderr)
    print(f"  数据验证失败：{invalid_count} 行", file=sys.stderr)
    print(f"  发布 JAR 缺失：{len(jar_missing_deps)} 个依赖", file=sys.stderr)
    print(f"  API 对比工具未安装：{len(japicmp_missing_deps)} 个依赖", file=sys.stderr)
    print(f"  API 对比工具执行失败：{len(other_failed_deps)} 个依赖", file=sys.stderr)
    print(f"  逐依赖对比状态：{dependency_status_csv}", file=sys.stderr)
    print(
        f"  用户直接结论：{Path(args.output_dir) / DEPENDENCY_ANALYSIS_STATUS_MD}",
        file=sys.stderr,
    )
    print(f"  源码版本待用户确认：{len(gitdiff_pending)} 个依赖", file=sys.stderr)
    print(f"  超时项：{len(timeout_items)}", file=sys.stderr)
    print(f"  输出：{csv_file}", file=sys.stderr)

    timeouts_path = os.path.join(args.output_dir, "timeouts.json")
    write_aux_timer = time.perf_counter()
    timing.record(
        "write.auxiliary_json",
        status="running",
        message="正在写入超时和 Git 版本待确认诊断文件",
    )
    with open(timeouts_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": datetime.now().isoformat(),
                "items": timeout_items,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )
    timing.record(
        "write.auxiliary_json",
        status="success",
        elapsed=time.perf_counter() - write_aux_timer,
        details={"timeouts": len(timeout_items), "gitdiff_pending": len(gitdiff_pending)},
    )
    pending_refs_path = os.path.join(args.output_dir, "git_ref_pending.json")
    with open(pending_refs_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": datetime.now().isoformat(),
                "items": gitdiff_pending,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    primary_binary_status_rows = [
        item for item in dependency_status_rows
        if item.get('comparison_status') != 'not_applicable'
    ]
    binary_failures = [
        item for item in primary_binary_status_rows
        if item.get('comparison_status') == 'failed'
    ]
    auxiliary_binary_failures = [
        item for item in binary_runs
        if item.get('mode') not in {'japicmp', 'old_jar_export', 'dependency_worker'}
        and item.get('status') != 'success'
    ]
    coverage_binary_failures = [
        *binary_failures,
        *auxiliary_binary_failures,
    ]
    binary_failure_reason_codes = sorted({
        str(item.get('reason_code') or '').strip()
        for item in coverage_binary_failures
        if str(item.get('reason_code') or '').strip()
    })
    text_fallbacks = [item for item in binary_runs if item.get('parser_mode') == 'text_fallback']
    missing_classes_ignored = [item for item in binary_runs if item.get('missing_class_policy') == 'ignored']
    successful_binary_status_rows = [
        item for item in primary_binary_status_rows
        if item.get('comparison_status') in {'changes_detected', 'no_api_change'}
    ]
    zero_change_status_rows = [
        item for item in primary_binary_status_rows
        if item.get('comparison_status') == 'no_api_change'
    ]
    binary_status = (
        'insufficient' if primary_binary_status_rows and len(binary_failures) == len(primary_binary_status_rows)
        else (
            'partial'
            if coverage_binary_failures or text_fallbacks or missing_classes_ignored
            else 'complete'
        )
    ) if primary_binary_status_rows else 'not_applicable'
    behavior_expected = [
        row for row in prepared_dep_rows
        if row.get('coord') in dependency_paths
        and row.get('old_version') not in ('', '-')
        and row.get('new_version') not in ('', '-')
    ]
    behavior_expected_coords = {
        str(row.get('coord') or '').strip()
        for row in behavior_expected
        if str(row.get('coord') or '').strip()
    }
    behavior_successful_coords = {
        str(item.get('coord') or '').strip()
        for item in gitdiff_runs
        if str(item.get('coord') or '').strip()
    } | {
        str(item.get('coord') or '').strip()
        for item in bytecode_behavior_runs
        if item.get('status') == 'complete' and str(item.get('coord') or '').strip()
    }
    behavior_successful_coords &= behavior_expected_coords
    behavior_uncovered_coords = behavior_expected_coords - behavior_successful_coords
    behavior_status = (
        'not_applicable' if not behavior_expected_coords
        else ('complete' if not behavior_uncovered_coords
              else ('partial' if behavior_successful_coords else 'insufficient'))
    )
    step4_coverage = {
        'schema': 'java-upgrade-analyzer.step4-coverage.v1',
        'binary_api_diff': {
            'status': binary_status,
            'reason_codes': (
                (['japicmp_or_old_jar_failed'] if coverage_binary_failures else [])
                + binary_failure_reason_codes
                + (['JAPICMP_TEXT_FALLBACK_USED'] if text_fallbacks else [])
                + (['JAPICMP_MISSING_CLASSES_IGNORED'] if missing_classes_ignored else [])
            ),
            'metrics': {
                'planned_dependencies': len(primary_binary_status_rows),
                'successful_dependencies': len(successful_binary_status_rows),
                'failed_dependencies': len(binary_failures),
                'zero_change_dependencies': len(zero_change_status_rows),
                'auxiliary_failed_checks': len(auxiliary_binary_failures),
                'text_fallbacks': len(text_fallbacks),
                'missing_classes_ignored': len(missing_classes_ignored),
            },
            'runs': binary_runs,
            'dependency_status_artifacts': [
                str(dependency_status_csv),
                str(dependency_status_json),
                str(Path(args.output_dir) / DEPENDENCY_ANALYSIS_STATUS_MD),
            ],
        },
        'behavior_diff': {
            'status': behavior_status,
            'reason_codes': (
                [] if behavior_status in {'complete', 'not_applicable'}
                else [
                    'dependency_source_or_git_ref_coverage_incomplete',
                    *sorted({
                        str(item.get('reason_code') or '').strip()
                        for item in [*gitdiff_skipped, *bytecode_behavior_runs]
                        if str(item.get('coord') or '').strip() in behavior_uncovered_coords
                        and str(item.get('reason_code') or '').strip()
                    }),
                ]
            ),
            'metrics': {
                'planned_dependencies': len(behavior_expected_coords),
                'successful_dependencies': len(behavior_successful_coords),
                'pending_dependencies': len(gitdiff_pending),
                'failed_or_skipped_dependencies': len(behavior_uncovered_coords),
                'missing_source_dependencies': len(changed_deps_missing_source),
                'source_gitdiff_dependencies': len({
                    str(item.get('coord') or '').strip() for item in gitdiff_runs
                    if str(item.get('coord') or '').strip()
                }),
                'jar_bytecode_fallback_dependencies': len({
                    str(item.get('coord') or '').strip() for item in bytecode_behavior_runs
                    if item.get('status') == 'complete' and str(item.get('coord') or '').strip()
                }),
            },
            'runs': bytecode_behavior_runs,
        },
    }
    for component_name in ('binary_api_diff', 'behavior_diff'):
        step4_coverage[component_name] = normalize_component_reason_codes(
            step4_coverage.get(component_name)
        )
    step4_reason_codes = sorted({
        reason_code
        for component_name in ('binary_api_diff', 'behavior_diff')
        for reason_code in (
            step4_coverage.get(component_name, {}).get('reason_codes') or ()
        )
    })
    step4_coverage.update({
        'origin_step': 'step4',
        'diagnostic_contract': diagnostic_contract_metadata(),
        'diagnostic_guidance_schema': REASON_GUIDANCE_SCHEMA,
        'diagnostic_guidance': build_catalog_guidance(
            step4_reason_codes,
            origin_step='step4',
            source_components=('binary_api_diff', 'behavior_diff'),
        ),
    })
    coverage_output = Path(args.coverage_output) if args.coverage_output else default_coverage_output_path(args.output_dir)
    coverage_write_timer = time.perf_counter()
    timing.record(
        "write.coverage",
        status="running",
        message="正在写入 Step4 证据覆盖率结果",
    )
    coverage_output.parent.mkdir(parents=True, exist_ok=True)
    coverage_output.write_text(
        json.dumps(step4_coverage, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    timing.record(
        "write.coverage",
        status="success",
        elapsed=time.perf_counter() - coverage_write_timer,
        details={"output": str(coverage_output)},
    )

    readable_write_timer = time.perf_counter()
    timing.record(
        "write.readable_outputs",
        status="running",
        message="正在生成 Step4 告警和可读摘要",
    )
    alerts_path, summary_path = write_readable_outputs(
        dep_rows=dep_rows,
        output_dir=args.output_dir,
        all_apis=all_apis,
        jar_missing_deps=jar_missing_deps,
        japicmp_missing_deps=japicmp_missing_deps,
        other_failed_deps=other_failed_deps,
        changed_deps_missing_source=changed_deps_missing_source,
        valid_count=valid_count,
        invalid_count=invalid_count,
        gitdiff_runs=gitdiff_runs,
        gitdiff_skipped=gitdiff_skipped,
        gitdiff_pending=gitdiff_pending,
        timeout_items=timeout_items,
        source_branches=args.source_branches,
        dependency_status_rows=dependency_status_rows,
    )
    timing.record(
        "write.readable_outputs",
        status="success",
        elapsed=time.perf_counter() - readable_write_timer,
        details={"alerts": alerts_path, "summary": summary_path},
    )
    ref_matches_timer = time.perf_counter()
    timing.record(
        "write.git_ref_matches",
        status="running",
        message="正在写入依赖源码 Git 版本匹配结果",
    )
    ref_matches_json, ref_matches_txt = write_git_ref_match_outputs(
        output_dir=args.output_dir,
        gitdiff_runs=gitdiff_runs,
        gitdiff_skipped=gitdiff_skipped,
        gitdiff_pending=gitdiff_pending,
        source_repo_mappings=[
            dependency_path_meta[key] for key in sorted(dependency_path_meta.keys())
        ],
    )
    timing.record(
        "write.git_ref_matches",
        status="success",
        elapsed=time.perf_counter() - ref_matches_timer,
        details={"json": ref_matches_json, "txt": ref_matches_txt},
    )
    print(f"  输出：{alerts_path}", file=sys.stderr)
    print(f"  输出：{summary_path}", file=sys.stderr)
    print(f"  输出：{ref_matches_json}", file=sys.stderr)
    print(f"  输出：{ref_matches_txt}", file=sys.stderr)
    print(f"  输出：{timeouts_path}", file=sys.stderr)
    print(f"  输出：{pending_refs_path}", file=sys.stderr)
    if changed_classes_by_coord:
        changed_dep_count = sum(
            1 for _, v in changed_classes_by_coord.items()
            if (v.get("counts", {}).get("added", 0)
                + v.get("counts", {}).get("removed", 0)
                + v.get("counts", {}).get("modified", 0)) > 0
        )
        print(f"  类级变更（字节码哈希）：{changed_dep_count} 个依赖（详情 {changed_classes_path}）", file=sys.stderr)
    if changed_deps_missing_source:
        uniq = {}
        for item in changed_deps_missing_source:
            uniq[item["coord"]] = item
        items = list(uniq.values())
        print(f"\n⚠️  升级依赖未提供源码：{len(items)} 个", file=sys.stderr)
        print("影响：这部分依赖无法通过源码识别“签名不变的实现变化”。", file=sys.stderr)
        for it in items[:10]:
            print(f"  - {it['coord']} ({it['old_version']}→{it['new_version']})", file=sys.stderr)
        print(
            "系统处理：记录源码证据缺口，并继续发布 JAR 分析；"
            "证据不足时限制最终结论。",
            file=sys.stderr,
        )
        print(
            "可选增强（不阻塞）：如需提高实现变化覆盖率，可补充依赖源码并重跑 Step4。",
            file=sys.stderr,
        )

    # 输出摘要，真正的交互暂停由 run_step.py 统一处理
    human_checkpoint_1(
        dep_rows,
        all_apis,
        args.output_dir,
        dependency_status_rows=dependency_status_rows,
    )
    print(
        "\nStep4 证据文件：dependency_analysis_status.*、changed_dependencies.md、"
        "summary.txt、all_changed_apis.csv、git_ref_matches.*",
        file=sys.stderr,
    )
    emit_progress(
        "step4",
        "done",
        f"Step4 完成，变更 API={valid_count}，待确认源码版本={len(gitdiff_pending)}，超时项={len(timeout_items)}",
        elapsed=step_timer.elapsed(),
    )
    timing.record(
        "step4.total",
        status=(
            "awaiting_git_ref_confirmation" if gitdiff_pending
            else ("completed_with_timeouts" if timeout_items else "done")
        ),
        elapsed=step_timer.elapsed(),
        api_count=valid_count,
    )
    timing_path = timing.flush()
    print(f"  输出：{timing_path}", file=sys.stderr)
    if gitdiff_pending:
        interaction = build_git_ref_confirmation_interaction(args.output_dir, gitdiff_pending)
        if os.environ.get("JUA_ORCHESTRATED") == "1":
            emit_interaction(interaction)
            return 0
        print("\n⚠️  存在会改变分析范围的源码版本歧义，请确认候选方案后重跑 Step4。", file=sys.stderr)
        return 2
    if timeout_items:
        print(
            "\n⚠️  Step4 存在超时项；系统已记录证据缺口并继续。"
            "若关键覆盖未补齐，最终报告将禁止完整或无影响结论。",
            file=sys.stderr,
        )
    return 0


if __name__ == '__main__':
    sys.exit(main())
