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

输出（全部写入 .upgrade-report/evidence/api_changes/ 目录）：
  [artifact]_[旧版]_vs_[新版]_binary.txt   — JApiCmp 完整原始输出（不裁剪）
  [artifact]_[旧版]_vs_[新版]_behavior.txt — changelog 行为变更记录
  [lib]_gitdiff_api_changes.txt            — 依赖源码 git diff 结果
  all_changed_apis.csv                     — 汇总（Step 5 的核心输入）

交互约束：
  脚本只负责产出证据与摘要，不负责等待用户确认
  进入下一步前是否停下、向用户展示哪些文件，由 run_step.py 统一调度
  "变更 API 数量 = 0 的依赖"仍需特别标出，便于后续交互时人工复核
"""

import argparse, csv, json, os, re, shutil, sys, time, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from pathlib import Path
from datetime import datetime
import hashlib, zipfile
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).parent))
from compat import (
    run_cmd, write_text, open_text, mvn_cmd, git_cmd, maven_repo_dir,
    infer_maven_coord_locations,
)

sys.path.insert(0, os.path.dirname(__file__))
from s4_contract import (
    ALL_CHANGED_APIS_FIELDS,
    DEFAULT_SEVERITY,
    PER_DEPENDENCY_DIRNAME,
    PER_DEPENDENCY_REMOVED_JAR_SYMBOLS_FILE,
    PER_DEPENDENCY_RESOLVED_TARGETS_FILE,
    PER_DEPENDENCY_SUMMARY_FILE,
    get_per_dependency_dir,
    validate_row,
)
from progress_logging import PhaseTimer, emit_progress
from pipeline_constants import (
    EVIDENCE_API_CHANGES_DIRNAME,
    EVIDENCE_DIRNAME,
    RUNTIME_DIRNAME,
    RUNTIME_STATE_DIRNAME,
)

INTERACTION_PREFIX = "JUA_STEP_INTERACTION_JSON:"
MAIN_STATE_FILE_NAME = "main_state.json"
DEFAULT_FETCH_TIMEOUT = None
DEFAULT_JAPICMP_TIMEOUT = None
DEFAULT_GIT_DIFF_TIMEOUT = None
DEFAULT_JAPICMP_COORD = "com.github.siom79.japicmp:japicmp:0.21.2:jar:jar-with-dependencies"
_WRITE_RESULT_LOCK = threading.RLock()


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
    with open_text(path) as f:
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
        "changed_classes.json",
        "timeouts.json",
        "git_ref_pending.json",
        "git_ref_matches.txt",
        "git_ref_matches.json",
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


def m2_repo_hint():
    return str(maven_repo_dir())

def _split_coord(coord: str):
    parts = (coord or "").strip().split(":")
    if len(parts) < 2:
        return None, None, None
    group_id = parts[0].strip()
    artifact_id = parts[1].strip()
    classifier = parts[2].strip() if len(parts) >= 3 and parts[2].strip() else None
    return group_id, artifact_id, classifier


def _resolve_step4_side_coord(row, side, fallback_coord=""):
    row = row or {}
    if side == "base":
        side_coord = str(row.get("base_coord") or "").strip()
    elif side == "current":
        side_coord = str(row.get("current_coord") or "").strip()
    else:
        side_coord = ""
    return side_coord or str(fallback_coord or row.get("coord") or "").strip()


def _safe_artifact_entry_filename(entry_name):
    raw = str(entry_name or "").replace("\\", "/").strip("/")
    safe = re.sub(r"[^A-Za-z0-9._/-]+", "_", raw).replace("/", "__")
    return safe or "unknown.jar"


class Step1ArtifactJarResolver:
    """Resolve dependency jars from Step1 final build artifacts before falling back to Maven.

    Step1 records the final deployable artifact and each packaged lib entry.  Reusing those
    nested jars keeps Step4 aligned with the exact artifacts that successfully built, and avoids
    repeatedly resolving/downloading jars that are already present in the packaged output.
    """

    def __init__(self, report_dir, output_dir):
        self.report_dir = Path(report_dir or ".").resolve()
        self.output_dir = Path(output_dir or ".").resolve()
        self.cache_dir = self.output_dir / "step4_artifact_jars"
        self.sides = self._load_sides()
        self._entry_cache = {}

    def _load_sides(self):
        provenance_path = self.report_dir / "build_provenance.json"
        if not provenance_path.is_file():
            return {}
        try:
            data = json.loads(provenance_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        sides = {}
        for item in data.get("sides") or []:
            side = str(item.get("side") or "").strip()
            artifact_path = str(item.get("artifact_path") or "").strip()
            if not side or not artifact_path:
                continue
            artifact = Path(artifact_path)
            if not artifact.is_file():
                retained_name = Path(artifact_path).name
                retained = self.report_dir / "s1_artifacts" / retained_name
                if retained.is_file():
                    artifact = retained
            if artifact.is_file():
                record = dict(item)
                record["artifact_path"] = str(artifact)
                sides[side] = record
        return sides

    def resolve_for_row(self, row, side):
        row = row or {}
        entry_field = "base_lib_entry" if side == "base" else "current_lib_entry"
        lib_entry = str(row.get(entry_field) or "").replace("\\", "/").strip()
        if not lib_entry:
            return None
        return self.resolve_entry(side, lib_entry)

    def resolve_entry(self, side, lib_entry):
        side_meta = self.sides.get(side) or {}
        artifact_path = side_meta.get("artifact_path")
        if not artifact_path or not lib_entry:
            return None
        key = (side, artifact_path, lib_entry)
        if key in self._entry_cache:
            cached = self._entry_cache[key]
            return dict(cached) if cached else None
        artifact = Path(artifact_path)
        target = self.cache_dir / side / _safe_artifact_entry_filename(lib_entry)
        try:
            with zipfile.ZipFile(artifact) as zf:
                names = set(zf.namelist())
                if lib_entry not in names:
                    self._entry_cache[key] = None
                    return None
                target.parent.mkdir(parents=True, exist_ok=True)
                info = zf.getinfo(lib_entry)
                if not target.exists() or target.stat().st_size != info.file_size:
                    with zf.open(info) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
        except Exception as exc:
            _ = exc
            self._entry_cache[key] = None
            return None
        evidence = {
            "path": str(target),
            "source": "step1_final_artifact",
            "side": side,
            "artifact_path": str(artifact),
            "artifact_sha256": str(side_meta.get("artifact_sha256") or ""),
            "lib_entry": lib_entry,
        }
        self._entry_cache[key] = dict(evidence)
        return evidence


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


def _ref_kind_priority(kind: str):
    return {
        "remote": 0,
    }.get((kind or "").strip(), 9)


def _is_dev_branch_name(branch_name: str):
    return "dev" in (branch_name or "").strip().lower()


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
        return [item for item in (inferred_coords or []) if item == coord_prefix]
    return [item for item in (inferred_coords or []) if item.startswith(coord_prefix + ":")]


def _list_repo_refs(repo_dir: str):
    repo_dir = os.path.abspath(repo_dir)
    cached = _REPO_REFS_CACHE.get(repo_dir)
    if cached is not None:
        return cached

    git = git_cmd()
    remotes_out, _remotes_err, remotes_rc = run_cmd(
        git + ["for-each-ref", "--format=%(refname:short)", "refs/remotes"],
        cwd=repo_dir,
        timeout=20,
    )
    remotes = []
    if remotes_rc == 0:
        remotes = [
            l.strip() for l in (remotes_out or "").splitlines()
            if l.strip() and not l.strip().endswith("/HEAD")
        ]
    result = {"tags": [], "heads": [], "remotes": remotes}
    _REPO_REFS_CACHE[repo_dir] = result
    return result


def _git_ref_exists(repo_dir: str, ref: str):
    ref = (ref or "").strip()
    if not ref:
        return False
    _out, _err, rc = run_cmd(git_cmd() + ["rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo_dir, timeout=10)
    return rc == 0


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


def list_repo_ref_candidates_for_version(repo_dir: str, version: str):
    version_norm = _normalize_version_text(version)
    if not version_norm:
        return [], version_norm, "version_empty"
    refs = _list_repo_refs(repo_dir)
    candidates = []
    for kind, ref_names in (("remotes", refs.get("remotes", [])),):
        normalized_kind = kind[:-1] if kind.endswith("s") else kind
        for ref_name in ref_names:
            match_info = _score_ref_match(ref_name, version_norm)
            if match_info:
                candidates.append(
                    (
                        match_info["score"],
                        _ref_kind_priority(normalized_kind),
                        0 if match_info["match_kind"] == "exact_boundary" else 1,
                        -len(match_info["prefix"]),
                        len(ref_name),
                        ref_name,
                        normalized_kind,
                        match_info,
                    )
                )
    candidates.sort(key=lambda x: (-x[0], x[1], x[2], x[3], x[4], x[5]))
    result = [
        {
            "ref": item[5],
            "kind": item[6],
            "score": item[0],
            "version": version_norm,
            "match_kind": item[7]["match_kind"],
            "prefix": item[7]["prefix"],
            "branch_name": item[7]["branch_name"],
            "remote_name": item[7]["remote_name"],
        }
        for item in candidates
    ]
    if not candidates:
        return result, version_norm, f"no_ref_match_for_version={version_norm}"
    return result, version_norm, None


def resolve_repo_ref_pair_for_versions(repo_dir: str, old_version: str, new_version: str):
    old_candidates, old_version_norm, old_error = list_repo_ref_candidates_for_version(repo_dir, old_version)
    new_candidates, new_version_norm, new_error = list_repo_ref_candidates_for_version(repo_dir, new_version)
    if old_error or new_error:
        return None, None, old_error, new_error, old_candidates, new_candidates

    expected_added_tokens, expected_removed_tokens = _build_token_delta(
        _extract_non_core_tokens(old_version_norm),
        _extract_non_core_tokens(new_version_norm),
    )
    version_delta_present = bool(_sum_counter(expected_added_tokens) or _sum_counter(expected_removed_tokens))

    pair_candidates = []
    for old_item in old_candidates:
        for new_item in new_candidates:
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
            pair_bonus = 0
            if same_prefix:
                pair_bonus += 30
            if same_remote:
                pair_bonus += 10
            if version_delta_present and old_item.get("ref") == new_item.get("ref"):
                pair_bonus -= 40
            pair_score = old_item.get("score", 0) + new_item.get("score", 0) + pair_bonus + delta_score
            pair_candidates.append(
                {
                    "old": old_item,
                    "new": new_item,
                    "pair_score": pair_score,
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
            -int(item["old"].get("score", 0)),
            -int(item["new"].get("score", 0)),
            len(item["old"].get("ref", "")),
            len(item["new"].get("ref", "")),
            item["old"].get("ref", ""),
            item["new"].get("ref", ""),
        )
    )
    if not pair_candidates:
        return None, None, old_error, new_error, old_candidates, new_candidates

    best = pair_candidates[0]
    if len(pair_candidates) > 1:
        runner_up = pair_candidates[1]
        if (
            runner_up["pair_score"] == best["pair_score"]
            and runner_up["delta_match_kind"] == best["delta_match_kind"]
            and runner_up["same_prefix"] == best["same_prefix"]
            and runner_up["same_remote"] == best["same_remote"]
        ):
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


def resolve_repo_ref_for_version(repo_dir: str, version: str, selected_ref: str = ""):
    candidates, version_norm, error = list_repo_ref_candidates_for_version(repo_dir, version)
    selected_ref = (selected_ref or "").strip()
    if selected_ref:
        for item in candidates:
            if item["ref"] == selected_ref:
                return selected_ref, (
                    f"selected_by_user(kind={item['kind']},score={item['score']},version={version_norm})"
                ), candidates
        if _git_ref_exists(repo_dir, selected_ref):
            return selected_ref, f"selected_by_user(kind=manual,score=-1,version={version_norm})", candidates
        return None, f"selected_ref_not_found={selected_ref}", candidates
    if error:
        return None, error, candidates
    best = candidates[0]
    if len(candidates) > 1:
        runner_up = candidates[1]
        if (
            runner_up.get("score") == best.get("score")
            and _ref_kind_priority(runner_up.get("kind")) == _ref_kind_priority(best.get("kind"))
        ):
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
        if not (coord and old_ref and new_ref):
            raise ValueError("dependency_git_ref_overrides_json 的每项都必须包含 coord/old_ref/new_ref")
        mapping[coord] = {"old_ref": old_ref, "new_ref": new_ref}
    return mapping


def build_git_ref_confirmation_interaction(output_dir, pending_items):
    files_to_review = []
    for name in ("git_ref_pending.json", "git_ref_matches.txt", "git_ref_matches.json", "summary.txt"):
        path = os.path.join(output_dir, name)
        if os.path.exists(path):
            files_to_review.append(os.path.abspath(path))
    question = (
        "已识别到依赖源码仓库，但以下依赖无法仅根据 old_version/new_version 自动确定 git refs。"
        "请逐项确认 old_ref/new_ref 后重跑 Step4；在确认前不要继续进入 Step5。"
    )
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "review",
        "step_id": "step4",
        "title": "step4 git refs 待人工确认",
        "question": question,
        "summary": f"共有 {len(pending_items)} 个依赖需要人工确认 git refs。",
        "reason_code": "step4_git_refs_need_confirmation",
        "files_to_review": files_to_review,
        "required_fields": ["action"],
        "options": [
            {
                "id": "rerun_current_step",
                "label": "确认 refs 后重跑",
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
                    "description": "按依赖显式指定 old_ref/new_ref，例如 [{\"coord\":\"g:a\",\"old_ref\":\"v1\",\"new_ref\":\"v2\"}]。",
                },
                "dependency_source_dirs": {
                    "type": "array",
                    "description": "若源码仓库映射有误，也可同时修正 dependency_source_dirs。",
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
                "at_least_one_of": ["dependency_git_ref_overrides", "dependency_source_dirs"],
                "description": "重跑 Step4 时，至少要确认 git refs，或修正 dependency_source_dirs。",
            },
            "restart_from_step": {
                "required_fields": ["restart_step_id"],
                "description": "从更早步骤重跑时，必须明确 restart_step_id。",
            },
        },
        "pending_git_ref_items": pending_items,
        "resume_hint": (
            "用户确认 old_ref/new_ref 后，可使用 --response-json 传回 "
            "action=rerun_current_step 与 dependency_git_ref_overrides 重跑 Step4；"
            "若问题源于 dependency_source_dirs 指向错误，也可同时修正 dependency_source_dirs 后重跑。"
        ),
        "next_action_rule": "只能向用户确认 git refs 并等待回复，不得直接继续执行后续步骤。",
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
            "请先确认是 git diff、JApiCmp 还是 dependency:get 超时，并在必要时放宽 Step4 超时参数后重跑；"
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
                    "description": "可选。放宽 Maven dependency:get 的超时时间（秒）。",
                },
                "dependency_source_dirs": {
                    "type": "array",
                    "description": "可选。若超时与源码映射范围过大有关，也可同时修正 dependency_source_dirs。",
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
                    "dependency_source_dirs"
                ],
                "description": "重跑 Step4 时，至少要调整一个超时参数，或修正 dependency_source_dirs。",
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
            "action=rerun_current_step 与 step4_git_diff_timeout/step4_japicmp_timeout/step4_fetch_timeout 重跑 Step4；"
            "若根因是 dependency_source_dirs 范围过大或映射错误，也可同时修正 dependency_source_dirs 后重跑。"
        ),
        "next_action_rule": "只能先处理超时导致的证据缺口并等待用户回复，不得直接继续执行后续步骤。",
        "must_wait_for_user_reply": True,
    }


def emit_interaction(interaction):
    print(f"{INTERACTION_PREFIX}{json.dumps(interaction, ensure_ascii=False)}")


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
        "--no-transfer-progress",
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


def build_japicmp_missing_interaction(output_dir, japicmp_jar, install_error, planned_dependencies):
    preflight_path = os.path.join(output_dir, "japicmp_preflight.json")
    payload = {
        "generated_at": datetime.now().isoformat(),
        "japicmp_jar": str(japicmp_jar or ""),
        "install_error": str(install_error or ""),
        "planned_dependencies": planned_dependencies,
        "impact": [
            "Step4 无法执行 JApiCmp 二进制 API 对比。",
            "这会漏掉仅通过 jar 二进制对比才能发现的删除、签名变化、字段变化、源码重编译不兼容等 API 变化。",
            "如果确认降级继续，后续 Step5/Step6 的结论必须视为二进制 API 证据不完整。",
        ],
        "manual_install": [
            f"mvn dependency:get -Dartifact={DEFAULT_JAPICMP_COORD}",
            "或提供 japicmp_jar 的绝对路径。",
        ],
    }
    Path(preflight_path).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "schema": "java-upgrade-analyzer.interaction.v2",
        "checkpoint": True,
        "hard_stop": True,
        "status": "awaiting_user_input",
        "kind": "review",
        "step_id": "step4",
        "title": "step4 缺少 JApiCmp，二进制 API 对比不可用",
        "question": (
            "Step4 需要 JApiCmp 执行依赖 jar 的二进制 API 对比。系统已尝试自动安装但失败。"
            "请优先安装 JApiCmp 或提供 japicmp_jar 后重跑 Step4；"
            "只有在你明确接受二进制 API 证据缺失的风险时，才允许 allow_degraded=true 降级继续。"
        ),
        "summary": f"共有 {len(planned_dependencies)} 个升级依赖需要 JApiCmp；当前工具不可用。",
        "reason_code": "step4_japicmp_missing_need_resolution",
        "files_to_review": [os.path.abspath(preflight_path)],
        "required_fields": ["action"],
        "options": [
            {
                "id": "rerun_current_step",
                "label": "处理 JApiCmp 后重跑",
                "description": "安装/提供 japicmp_jar 后重跑；或显式 allow_degraded=true 接受二进制 API 证据缺失后重跑。",
            },
            {
                "id": "restart_from_step",
                "label": "从更早步骤重跑",
                "description": "如输入或环境需要调整，可从 step1/step2/step4 重新处理。",
            },
            {
                "id": "cancel",
                "label": "取消",
                "description": "先人工安装 JApiCmp 或确认风险后再继续。",
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
                "japicmp_jar": {
                    "type": "string",
                    "description": "可选。JApiCmp jar-with-dependencies 的绝对路径。",
                },
                "allow_degraded": {
                    "type": "boolean",
                    "description": "可选。若设为 true，表示用户明确接受缺少 JApiCmp 二进制 API 对比证据后降级继续。",
                },
                "restart_step_id": {
                    "type": "string",
                    "enum": ["step1", "step2", "step4"],
                },
                "notes": {"type": "string"},
            },
        },
        "action_requirements": {
            "rerun_current_step": {
                "at_least_one_of": ["japicmp_jar", "allow_degraded"],
                "description": "重跑 Step4 时，要么提供 japicmp_jar，要么明确 allow_degraded=true。",
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
        "japicmp": {
            "expected_jar": str(japicmp_jar or ""),
            "install_error": str(install_error or ""),
            "manual_install": f"mvn dependency:get -Dartifact={DEFAULT_JAPICMP_COORD}",
        },
        "resume_hint": (
            "优先安装 JApiCmp 或提供 japicmp_jar 后 action=rerun_current_step；"
            "若用户确认风险，也可 action=rerun_current_step 且 allow_degraded=true。"
        ),
        "next_action_rule": "只能先处理 JApiCmp 缺失并等待用户回复，不得直接继续进入 Step5。",
        "must_wait_for_user_reply": True,
    }

def _jar_class_hash_map(jar_path: str) -> dict:
    m = {}
    with zipfile.ZipFile(jar_path) as zf:
        for entry in zf.namelist():
            if not entry.endswith(".class"):
                continue
            if entry.startswith("META-INF/") and not entry.startswith("META-INF/versions/"):
                continue
            if entry.endswith("module-info.class"):
                continue
            try:
                data = zf.read(entry)
            except Exception:
                continue
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


def find_jar_in_m2(group_id, artifact_id, version, classifier=None):
    """在本地 Maven 仓库查找 jar 文件（Windows/Linux/macOS 兼容路径）"""
    # 用 Path 逐级构建，不用 replace('.', '/') 避免 Windows 路径问题
    base = maven_repo_dir()
    for part in group_id.split('.'):
        base = base / part
    base = base / artifact_id / version
    # 优先找非 sources/javadoc 的 jar
    patterns = []
    if classifier:
        patterns.append(f"{artifact_id}-{version}-{classifier}.jar")
    patterns.extend([f"{artifact_id}-{version}.jar", f"{artifact_id}-{version}-*.jar"])
    for pattern in patterns:
        matches = list(base.glob(pattern)) if base.exists() else []
        matches = [m for m in matches
                   if 'sources' not in m.name and 'javadoc' not in m.name]
        if matches:
            return str(matches[0])
    return None

def fetch_jar_from_repo(coord, version, timeout=DEFAULT_FETCH_TIMEOUT):
    """尝试从 Maven 仓库下载 jar"""
    group_id, artifact_id, classifier = _split_coord(coord)
    if not group_id or not artifact_id or not version:
        return False, "invalid_coord"
    if classifier:
        artifact_expr = f"{group_id}:{artifact_id}:{version}:jar:{classifier}"
    else:
        artifact_expr = f"{group_id}:{artifact_id}:{version}"
    _stdout, stderr, rc = run_cmd(
        mvn_cmd() + ['dependency:get',
                     f'-Dartifact={artifact_expr}',
                     '--no-transfer-progress', '-q'],
        timeout=timeout
    )
    if rc == 0:
        return True, None
    if rc == -1 and '超时' in (stderr or ''):
        timeout_label = f"{timeout}s" if timeout not in (None, "") else "unbounded"
        return False, f"timeout({timeout_label})"
    return False, (stderr or 'dependency:get failed')[:160]


def _iter_jar_class_entries(jar_path):
    with zipfile.ZipFile(jar_path) as zf:
        for entry in sorted(zf.namelist()):
            if not entry.endswith('.class') or entry.startswith('META-INF/'):
                continue
            if entry.endswith('module-info.class') or entry.endswith('package-info.class'):
                continue
            yield entry[:-6].replace('/', '.')


def _run_javap_public_api_dump(jar_path, class_binary_name):
    stdout, stderr, rc = run_cmd(
        ['javap', '-classpath', jar_path, '-public', '-s', class_binary_name],
        timeout=60,
    )
    if rc != 0:
        raise RuntimeError((stderr or stdout or 'javap failed').strip()[:300] or 'javap failed')
    return stdout


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
        old_jar = find_jar_in_m2(group_id, artifact_id, old_ver, classifier=classifier)
        old_jar_source = "m2_repository" if old_jar else ""
    fetch_old_error = None
    if not old_jar:
        fetched, fetch_old_error = fetch_jar_from_repo(resolved_old_coord, old_ver, timeout=fetch_timeout)
        if fetched:
            old_jar = find_jar_in_m2(group_id, artifact_id, old_ver, classifier=classifier)
            old_jar_source = "m2_repository" if old_jar else ""
    if not old_jar:
        msg = (
            f"=== 无法导出 removed jar 符号：旧版 jar 未找到 ===\n"
            f"coord={resolved_old_coord}\nold_version={old_ver}\n"
            f"fetch_result={fetch_old_error or '未尝试/成功'}\n"
        )
        write_result(out_file, msg)
        return out_file, [], {"old_jar": None, "fetch_old_error": fetch_old_error}, "jar 未找到"

    apis = []
    errors = []
    class_count = 0
    for class_binary_name in _iter_jar_class_entries(old_jar):
        class_count += 1
        try:
            javap_text = _run_javap_public_api_dump(old_jar, class_binary_name)
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
    ]
    if errors:
        lines.append("errors:")
        lines.extend(f"  - {item}" for item in errors)
    write_result(out_file, "\n".join(lines) + "\n")
    return out_file, apis, {
        "old_jar": old_jar,
        "old_jar_source": old_jar_source,
        "old_jar_evidence": old_jar_evidence or {},
        "errors": errors,
    }, (None if apis else "未导出到任何 public/protected API")


# ══════════════════════════════════════════════════════════════════
# 4a. JApiCmp 二进制对比
# ══════════════════════════════════════════════════════════════════

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
):
    """
    对单个依赖运行 JApiCmp，返回 (output_file, changed_apis, error_msg)
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
        out_file = os.path.join(output_dir, f"invalid_coord_{old_ver}_vs_{new_ver}_binary.txt")
        msg = (
            f"=== 非法 Maven 坐标：{display_coord or coord} ===\n"
            f"old_coord={resolved_old_coord or '(空)'}\n"
            f"new_coord={resolved_new_coord or '(空)'}\n"
            "期望格式：groupId:artifactId 或 groupId:artifactId:classifier\n"
        )
        write_result(out_file, msg)
        return out_file, [], {"old_jar": None, "new_jar": None}, "非法坐标"
    safe_name = safe_artifact_id.replace('.', '-') + (f"_{safe_classifier}" if safe_classifier else "")
    out_file = os.path.join(output_dir,
        f"{safe_name}_{old_ver}_vs_{new_ver}_binary.txt")
    xml_file = os.path.join(output_dir,
        f"{safe_name}_{old_ver}_vs_{new_ver}_binary.xml")

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
    if not old_jar:
        old_jar = find_jar_in_m2(old_group_id, old_artifact_id, old_ver, classifier=old_classifier)
        old_jar_source = "m2_repository" if old_jar else ""
    if not new_jar:
        new_jar = find_jar_in_m2(new_group_id, new_artifact_id, new_ver, classifier=new_classifier)
        new_jar_source = "m2_repository" if new_jar else ""

    fetch_old_error = None
    fetch_new_error = None
    if not old_jar:
        print(f"  本地无 {resolved_old_coord}:{old_ver}，尝试下载...", file=sys.stderr)
        fetched, fetch_old_error = fetch_jar_from_repo(resolved_old_coord, old_ver, timeout=fetch_timeout)
        if fetched:
            old_jar = find_jar_in_m2(old_group_id, old_artifact_id, old_ver, classifier=old_classifier)
            old_jar_source = "m2_repository" if old_jar else ""
    if not new_jar:
        print(f"  本地无 {resolved_new_coord}:{new_ver}，尝试下载...", file=sys.stderr)
        fetched, fetch_new_error = fetch_jar_from_repo(resolved_new_coord, new_ver, timeout=fetch_timeout)
        if fetched:
            new_jar = find_jar_in_m2(new_group_id, new_artifact_id, new_ver, classifier=new_classifier)
            new_jar_source = "m2_repository" if new_jar else ""

    # 仍然找不到：明确记录，不跳过
    if not old_jar or not new_jar:
        old_hint_path = str(
            Path(m2_repo_hint())
            / Path(*old_group_id.split('.'))
            / old_artifact_id
            / old_ver
        )
        new_hint_path = str(
            Path(m2_repo_hint())
            / Path(*new_group_id.split('.'))
            / new_artifact_id
            / new_ver
        )
        msg = (
            f"=== 无法完成对比：{display_coord} ===\n"
            f"旧坐标：{resolved_old_coord}\n"
            f"新坐标：{resolved_new_coord}\n"
            f"旧版本 {old_ver} jar：{'已找到 ' + old_jar if old_jar else '❌ 未找到'}\n"
            f"新版本 {new_ver} jar：{'已找到 ' + new_jar if new_jar else '❌ 未找到'}\n\n"
            f"下载结果：old={fetch_old_error or '未尝试/成功'} new={fetch_new_error or '未尝试/成功'}\n\n"
            f"需要用户协助：\n"
            f"  1. 确认私服地址已在本机 Maven settings.xml 中配置（常见路径：~/.m2/settings.xml）\n"
            f"  2. 手动执行：mvn dependency:get -Dartifact={resolved_old_coord}:{old_ver}\n"
            f"  3. 手动执行：mvn dependency:get -Dartifact={resolved_new_coord}:{new_ver}\n"
            f"  4. 如果当前只有 jar 文件，请将旧版 jar 放到：\n"
            f"     {old_hint_path}\n"
            f"     并将新版 jar 放到：\n"
            f"     {new_hint_path}\n"
            f"  然后重新运行本步骤。\n"
        )
        write_result(out_file, msg)
        return out_file, [], {
            "old_jar": old_jar,
            "new_jar": new_jar,
            "old_jar_source": old_jar_source,
            "new_jar_source": new_jar_source,
            "old_jar_evidence": old_jar_evidence or {},
            "new_jar_evidence": new_jar_evidence or {},
            "fetch_old_error": fetch_old_error,
            "fetch_new_error": fetch_new_error,
        }, f"jar 未找到：{display_coord}（旧:{old_jar or '缺失'} 新:{new_jar or '缺失'}）"

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
        }, "JApiCmp 未安装"

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
        }, failure_msg[:100]
    raw_output = stdout or stderr or "(无输出)"

    # 完整保留原始输出
    header = (
        f"=== JApiCmp 对比报告 ===\n"
        f"依赖：{display_coord}\n"
        f"旧坐标：{resolved_old_coord}\n"
        f"新坐标：{resolved_new_coord}\n"
        f"旧版本：{old_ver}  ({old_jar})\n"
        f"新版本：{new_ver}  ({new_jar})\n"
        f"旧 jar 来源：{old_jar_source or 'unknown'}\n"
        f"新 jar 来源：{new_jar_source or 'unknown'}\n"
        f"执行时间：{datetime.now().isoformat()}\n"
        f"{'='*60}\n\n"
    )
    write_result(out_file, header + raw_output)

    # XML 是机器解析主证据；仅在工具未生成或 XML 不可解析时回退文本。
    parser_mode = 'xml'
    xml_error = ''
    try:
        changed_apis = parse_japicmp_xml(xml_file, coord, old_ver, new_ver)
    except (ET.ParseError, OSError, ValueError) as exc:
        parser_mode = 'text_fallback'
        xml_error = f"{type(exc).__name__}:{exc}"
        changed_apis = parse_japicmp_output(raw_output, coord, old_ver, new_ver)
        for row in changed_apis:
            row['reason_code'] = 'JAPICMP_TEXT_FALLBACK_USED'
            row['evidence_path'] = str(out_file)
            row['binary_compatible'] = row.get('binary_compatible') or 'unknown'
            row['source_compatible'] = row.get('source_compatible') or 'unknown'
    tool_sha256 = ''
    try:
        tool_sha256 = hashlib.sha256(Path(japicmp_jar).read_bytes()).hexdigest()
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
        if status in ('NEW', 'UNCHANGED'):
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
        flags = []
        for child in element.iter():
            if _xml_local_name(child) not in ('compatibilitychange', 'compatibility-change'):
                continue
            flag = _xml_attr(child, 'type', 'name') or (child.text or '').strip()
            if flag and flag not in flags:
                flags.append(flag)
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
        if not owner or is_jdk_standard_owner(owner):
            continue
        add_row(owner, class_element, 'class')
        for member in class_element.iter():
            if member is class_element:
                continue
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
    return build_api_signature_from_types(params)


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


def build_api_signature_from_types(type_exprs):
    normalized_params = []
    for type_expr in type_exprs or []:
        normalized = normalize_type_expression(type_expr)
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
    artifact   = coord.split(':')[-1]

    out_file = os.path.join(output_dir, f"{artifact}_gitdiff_api_changes.txt")

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

    if not os.path.isdir(os.path.join(repo_path, ".git")):
        msg = (
            f"=== 依赖源码目录不是 git 仓库：{coord} ===\n"
            f"路径：{os.path.abspath(repo_path)}\n\n"
            f"需要用户协助：\n"
            f"  1. 提供该依赖的 git 仓库根目录（包含 .git）\n"
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
    if override_old_ref or override_new_ref:
        resolved_old_ref, old_reason, old_candidates = resolve_repo_ref_for_version(
            repo_path, old_ver, selected_ref=override_old_ref
        )
        resolved_new_ref, new_reason, new_candidates = resolve_repo_ref_for_version(
            repo_path, new_ver, selected_ref=override_new_ref
        )
    else:
        (
            resolved_old_ref,
            resolved_new_ref,
            old_reason,
            new_reason,
            old_candidates,
            new_candidates,
        ) = resolve_repo_ref_pair_for_versions(repo_path, old_ver, new_ver)
    if (not resolved_old_ref) or (not resolved_new_ref):
        refs = _list_repo_refs(repo_path)
        sample_remotes = ", ".join(refs.get("remotes", [])[:15])
        msg = (
            f"=== 无法定位 git 对比 ref：{coord} ===\n"
            f"版本：{old_ver} → {new_ver}\n"
            f"分支匹配版本：old={_normalize_version_text(old_ver) or '-'} new={_normalize_version_text(new_ver) or '-'}\n"
            f"version 匹配结果：old={resolved_old_ref or '(未命中)'} ({old_reason or '-'}) "
            f"new={resolved_new_ref or '(未命中)'} ({new_reason or '-'})\n\n"
            f"已发现远端分支（仅展示前 15 个）：\n"
            f"  remotes: {sample_remotes or '(无)'}\n\n"
            f"说明：当前仅按远端分支匹配；只去掉版本号末尾的 -SNAPSHOT 后，"
            f"按“分支名包含版本号”筛选候选，且非 DEV 分支优先于 DEV 分支。\n"
            f"请修复：在该依赖仓库中提供分支名包含版本号的远端分支"
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

    base_ref = resolved_old_ref
    cur_ref = resolved_new_ref
    ref_source = "version"
    module_rel_path = ""
    if module_path:
        try:
            module_rel_path = Path(module_path).resolve().relative_to(Path(repo_path).resolve()).as_posix()
        except Exception:
            module_rel_path = ""

    diff_cmd_primary = git_cmd() + ['diff', '--function-context', '-U0', f'{base_ref}..{cur_ref}', '--']
    if module_rel_path and module_rel_path != '.':
        diff_cmd_primary.append(module_rel_path)
    else:
        diff_cmd_primary.extend(['*.java', '*.kt'])
    stdout, _stderr, rc = run_cmd(diff_cmd_primary, cwd=repo_path, timeout=git_diff_timeout)
    diff_cmd_used = diff_cmd_primary
    if rc not in (0, 1):  # git diff 无变更时返回 0，有变更时返回 1
        diff_cmd_fallback = git_cmd() + ['diff', '-U20', f'{base_ref}..{cur_ref}', '--']
        if module_rel_path and module_rel_path != '.':
            diff_cmd_fallback.append(module_rel_path)
        else:
            diff_cmd_fallback.extend(['*.java', '*.kt'])
        stdout2, stderr2, rc2 = run_cmd(diff_cmd_fallback, cwd=repo_path, timeout=git_diff_timeout)
        if rc2 not in (0, 1):
            write_result(out_file, f"git diff 执行失败（退出码 {rc2}）：{stderr2}")
            error_text = stderr2[:100]
            if rc2 == -1 and '超时' in (stderr2 or ''):
                timeout_label = f"{git_diff_timeout}s" if git_diff_timeout not in (None, "") else "unbounded"
                error_text = f"git diff 超时({timeout_label})"
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
        lines.append("=== Step4 依赖源码 git ref 匹配结果（需用户确认） ===")
    else:
        lines.append("=== Step4 依赖源码 git ref 匹配结果（已自动匹配，可抽查） ===")
    lines.append("说明：以下 old_version/new_version 到 git ref 的映射，将直接决定源码 diff 对比范围。")
    lines.append(
        "当前自动匹配策略：仅扫描远端分支 remotes；"
        "只去掉版本号末尾的 -SNAPSHOT 后，按分支名包含版本号命中；非 DEV 分支优先于 DEV 分支。"
    )
    if needs_user_confirmation:
        lines.append("要求：继续 Step5 前，请逐项确认“依赖坐标 -> 源码仓库 -> git refs”的映射是否正确；如有误，应通过对话修正 dependency_source_dirs 并重跑 Step4。")
    else:
        lines.append("说明：当前没有待人工确认的 ref；建议抽查“依赖坐标 -> 源码仓库 -> git refs”的映射是否符合预期。")
    lines.append(f"generated_at={payload['generated_at']}")
    lines.append("")
    lines.append(f"源码仓库映射：{len(source_repo_mappings)}")
    for item in source_repo_mappings:
        lines.append(
            f"- {item.get('coord')} | repo={item.get('repo_path')} | input={item.get('input_spec') or '(auto)'} | mapping={item.get('mapping_mode') or '-'}"
        )
        if item.get("module_path"):
            lines.append(f"  module_path={item.get('module_path')}")
        repo_coords = item.get("repo_inferred_coords") or []
        lines.append(f"  repo_inferred_coords={', '.join(repo_coords[:10]) or '(无)'}")
    if not source_repo_mappings:
        lines.append("- (无)")
    lines.append("")
    lines.append(f"已匹配：{len(gitdiff_runs)}")
    for item in gitdiff_runs:
        lines.append(
            f"- {item.get('coord')} | versions={item.get('old_version')}->{item.get('new_version')} "
            f"| selected={item.get('base_ref')}..{item.get('cur_ref')} | reason=old[{item.get('old_match_reason') or '-'}],new[{item.get('new_match_reason') or '-'}]"
        )
        if item.get("repo_path"):
            lines.append(f"  repo_path={item.get('repo_path')}")
        if item.get("module_path"):
            lines.append(f"  module_path={item.get('module_path')}")
        if item.get("module_rel_path"):
            lines.append(f"  module_rel_path={item.get('module_rel_path')}")
        old_candidates = item.get("old_candidates") or []
        new_candidates = item.get("new_candidates") or []
        lines.append(f"  old_candidates={', '.join(c.get('ref', '') for c in old_candidates[:10]) or '(无)'}")
        lines.append(f"  new_candidates={', '.join(c.get('ref', '') for c in new_candidates[:10]) or '(无)'}")
    if not gitdiff_runs:
        lines.append("- (无)")
    lines.append("")
    lines.append(f"待人工确认：{len(gitdiff_pending)}")
    for item in gitdiff_pending:
        lines.append(
            f"- {item.get('coord')} | versions={item.get('old_version')}->{item.get('new_version')} "
            f"| reason={item.get('reason') or '-'}"
        )
        old_candidates = item.get("old_candidates") or []
        new_candidates = item.get("new_candidates") or []
        lines.append(f"  old_candidates={', '.join(c.get('ref', '') for c in old_candidates[:10]) or '(无)'}")
        lines.append(f"  new_candidates={', '.join(c.get('ref', '') for c in new_candidates[:10]) or '(无)'}")
    if not gitdiff_pending:
        lines.append("- (无)")
    lines.append("")
    lines.append(f"未匹配/跳过：{len(gitdiff_skipped)}")
    for item in gitdiff_skipped:
        lines.append(
            f"- {item.get('coord')} | versions={item.get('old_version')}->{item.get('new_version')} "
            f"| reason={item.get('reason') or '-'}"
        )
        old_candidates = item.get("old_candidates") or []
        new_candidates = item.get("new_candidates") or []
        if old_candidates:
            lines.append(f"  old_candidates={', '.join(c.get('ref', '') for c in old_candidates[:10])}")
        if new_candidates:
            lines.append(f"  new_candidates={', '.join(c.get('ref', '') for c in new_candidates[:10])}")
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
    artifact = coord.split(':')[-1]
    safe = artifact.replace('.', '-')
    out_file = os.path.join(output_dir,
        f"{safe}_{old_ver}_vs_{new_ver}_behavior.txt")

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
            valid_rows.append(row)

    if invalid_rows:
        print(f"\n⚠️  {len(invalid_rows)} 行数据未通过契约验证，已跳过：",
              file=sys.stderr)
        for item in invalid_rows[:5]:
            print(f"  {item['row'].get('api_name', '?')}: "
                  f"{'; '.join(item['errors'])}", file=sys.stderr)

    with open(raw_out_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS)
        writer.writeheader()
        writer.writerows(valid_rows)

    normalized_rows = normalize_step5_input_rows(valid_rows)
    with open(out_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS)
        writer.writeheader()
        writer.writerows(normalized_rows)

    return out_file, len(normalized_rows), len(invalid_rows)


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
        'gitdiff': 0,
        'japicmp': 1,
        'old_jar': 1,
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

    normalized_rows = list(buckets.values())
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
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS)
        writer.writeheader()
        writer.writerows(rows or [])


def _load_json_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def write_per_dependency_outputs(report_dir, dep_row, raw_rows, removed_jar_export=None):
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
        "status": "done",
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

def human_checkpoint_1(dep_rows, all_apis, output_dir):
    """
    Step 4 完成后的摘要输出。
    展示：每个依赖的变更 API 数量，重点标出数量为 0 的，
    供 run_step.py 后续统一组织为用户交互材料。
    """
    print("\n" + "="*60)
    print("【人工抽查节点 1】Step 4 完成，请确认以下摘要")
    print("="*60)
    by_coord = {}
    for api in all_apis:
        c = (api.get('coord') or '').strip()
        if not c:
            continue
        by_coord.setdefault(c, []).append(api)

    zero_change = []
    rows = dep_rows or []
    for row in rows:
        coord = (row.get('coord', '') or '').strip()
        change_type = (row.get('change_type', '') or '').strip()
        if not coord:
            continue
        if change_type in ('未变', '新增', '移除'):
            continue
        apis_found = by_coord.get(coord, [])
        if not apis_found:
            zero_change.append(coord)
        else:
            p0 = sum(1 for a in apis_found if (a.get('severity') or '').strip() == 'P0')
            print(f"  ✓ {coord}: {len(apis_found)} 个变更 API（P0={p0}）")

    if zero_change:
        print(f"\n⚠️  以下依赖版本发生了变更，但未找到任何 API 变化（共 {len(zero_change)} 个）：")
        for c in zero_change[:50]:
            print(f"   - {c}")
        if len(zero_change) > 50:
            print(f"   ...（仅展示前 50，共 {len(zero_change)}）")
        print("\n  可能原因：")
        print("    A. jar 文件未找到，JApiCmp 未能执行（查看对应 _binary.txt 确认）")
        print("    B. JApiCmp 工具本身未安装或执行失败")
        print("    C. 该版本确实没有 binary incompatible 变更（正常）")
        print("    D. 变更只体现在 changelog 或签名不变的行为变更，需要源码 git diff/人工确认")

    print(f"\n全部变更 API：{len(all_apis)} 个")
    print(f"输出目录：{output_dir}")
    print("建议优先查看：summary.txt / all_changed_apis_alerts.csv")
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
                           timeout_items=None, source_branches=None):
    all_rows = load_csv(os.path.join(output_dir, "all_changed_apis.csv"))
    alerts = []
    for r in all_rows:
        sev = (r.get('severity') or '').strip()
        confirmed = str(r.get('confirmed', '')).strip().lower()
        source = (r.get('source') or '').strip()
        if sev in ('P0', 'P1') or confirmed == 'false' or source == 'changelog':
            alerts.append(r)
    alerts.sort(key=lambda x: (_severity_rank(x.get('severity')), x.get('coord', ''), x.get('api_name', '')))

    alerts_path = os.path.join(output_dir, "all_changed_apis_alerts.csv")
    with open(alerts_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ALL_CHANGED_APIS_FIELDS)
        writer.writeheader()
        writer.writerows(alerts)

    by_coord = {}
    for api in all_apis:
        c = api.get('coord', '')
        if not c:
            continue
        by_coord.setdefault(c, []).append(api)

    zero_change = []
    for row in dep_rows:
        coord = row.get('coord', '')
        change_type = row.get('change_type', '')
        if not coord:
            continue
        if change_type in ('未变', '新增', '移除'):
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
    lines.append("=== Step4 jar 对比摘要 ===")
    lines.append("用途：识别依赖升级引入的 API 契约变化/二进制不兼容/行为变更线索，作为 Step5 反向调用链分析的输入。")
    lines.append("注意：本步骤仅说明“依赖发生了什么变化”，不等于“影响当前系统”；是否影响以 Step5 reachable/uncertain 为准。")
    lines.append("抽查：优先看 all_changed_apis_alerts.csv 的 P0/P1；并抽查 *_binary.txt / *_gitdiff_api_changes.txt 的原始证据。")
    lines.append("确认：如提供了依赖源码，请务必打开 git_ref_matches.txt / git_ref_matches.json 确认 old_version/new_version 命中的 refs 是否正确。")
    lines.append(f"generated_at={datetime.now().isoformat()}")
    lines.append(f"all_changed_apis={os.path.abspath(os.path.join(output_dir, 'all_changed_apis.csv'))}")
    lines.append(f"alerts_csv={os.path.abspath(alerts_path)}")
    lines.append(f"git_ref_matches_txt={os.path.abspath(os.path.join(output_dir, 'git_ref_matches.txt'))}")
    lines.append(f"git_ref_matches_json={os.path.abspath(os.path.join(output_dir, 'git_ref_matches.json'))}")
    if source_branches:
        lines.append(f"project_source_branches={source_branches[0]}..{source_branches[1]}")
        lines.append("note=依赖源码仓库 git diff 默认优先按 old_version/new_version 模糊匹配其自身 refs，不直接沿用主项目分支名。")
    lines.append("")
    lines.append(f"变更 API（有效行）：{valid_count}")
    lines.append(f"契约校验失败：{invalid_count}")
    lines.append(f"告警条目：{len(alerts)}")
    lines.append("")
    lines.append("按严重级别：")
    for k in ('P0', 'P1', 'P2'):
        lines.append(f"  {k}: {by_sev.get(k, 0)}")
    lines.append("")
    lines.append("按来源：")
    for k, v in sorted(by_source.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"  {k or '(空)'}: {v}")
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
        lines.append("源码对比（git diff）：")
        lines.append(f"  已执行：{len(gitdiff_runs)}")
        if gitdiff_runs:
            top = sorted(gitdiff_runs, key=lambda x: (-int(x.get("api_changes", 0)), x.get("coord", "")))
            for it in top[:20]:
                ref_part = ""
                if it.get("base_ref") or it.get("cur_ref"):
                    ref_part = f" refs={it.get('base_ref')}..{it.get('cur_ref')}({it.get('ref_source')})"
                match_part = ""
                if it.get("old_match_reason") or it.get("new_match_reason"):
                    match_part = (
                        f" match=old[{it.get('old_match_reason') or '-'}]"
                        f",new[{it.get('new_match_reason') or '-'}]"
                    )
                lines.append(
                    f"  - {it.get('coord')} api_changes={it.get('api_changes')} behavior_changed={it.get('behavior_changed')}{ref_part}{match_part} out={it.get('out_file')}"
                )
            if len(top) > 20:
                lines.append(f"  ...（仅展示前 20，共 {len(top)}）")
        lines.append(f"  跳过：{len(gitdiff_skipped)}")
        if gitdiff_skipped:
            for it in gitdiff_skipped[:20]:
                lines.append(f"  - {it.get('coord')} reason={it.get('reason')}")
            if len(gitdiff_skipped) > 20:
                lines.append(f"  ...（仅展示前 20，共 {len(gitdiff_skipped)}）")
        lines.append(f"  待人工确认 refs：{len(gitdiff_pending)}")
        if gitdiff_pending:
            for it in gitdiff_pending[:20]:
                lines.append(f"  - {it.get('coord')} reason={it.get('reason')}")
            if len(gitdiff_pending) > 20:
                lines.append(f"  ...（仅展示前 20，共 {len(gitdiff_pending)}）")
        lines.append("")
    if timeout_items:
        lines.append(f"超时项：{len(timeout_items)}")
        for item in timeout_items[:20]:
            lines.append(
                f"  - {item.get('coord')} stage={item.get('stage')} timeout={item.get('timeout_seconds')}s reason={item.get('reason') or '-'}"
            )
        if len(timeout_items) > 20:
            lines.append(f"  ...（仅展示前 20，共 {len(timeout_items)}）")
        lines.append("")
    lines.append("按变更类型：")
    for k, v in sorted(by_change_type.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"  {k or '(空)'}: {v}")
    lines.append("")
    lines.append(f"jar 未找到：{len(jar_missing_deps)}")
    if jar_missing_deps:
        for c in jar_missing_deps[:20]:
            lines.append(f"  - {c}")
        if len(jar_missing_deps) > 20:
            lines.append(f"  ...（仅展示前 20，共 {len(jar_missing_deps)}）")
    lines.append("")
    lines.append(f"JApiCmp 未安装：{len(japicmp_missing_deps)}")
    if japicmp_missing_deps:
        for c in japicmp_missing_deps[:20]:
            lines.append(f"  - {c}")
        if len(japicmp_missing_deps) > 20:
            lines.append(f"  ...（仅展示前 20，共 {len(japicmp_missing_deps)}）")
    lines.append("")
    lines.append(f"其他 JApiCmp 失败：{len(other_failed_deps)}")
    if other_failed_deps:
        for c in other_failed_deps[:20]:
            lines.append(f"  - {c}")
        if len(other_failed_deps) > 20:
            lines.append(f"  ...（仅展示前 20，共 {len(other_failed_deps)}）")
    lines.append("")
    if changed_deps_missing_source:
        uniq = {}
        for it in changed_deps_missing_source:
            if it.get('coord'):
                uniq[it['coord']] = it
        items = list(uniq.values())
        lines.append(f"升级依赖缺少源码映射：{len(items)}")
        for it in items[:20]:
            lines.append(f"  - {it.get('coord')} ({it.get('old_version')}→{it.get('new_version')})")
        if len(items) > 20:
            lines.append(f"  ...（仅展示前 20，共 {len(items)}）")
        lines.append("")
    if zero_change:
        lines.append(f"版本已变更但未发现 API 变化：{len(zero_change)}")
        for c in zero_change[:50]:
            lines.append(f"  - {c}")
        if len(zero_change) > 50:
            lines.append(f"  ...（仅展示前 50，共 {len(zero_change)}）")
        lines.append("")
    if alerts:
        lines.append("告警 Top 50：")
        for r in alerts[:50]:
            lines.append(
                f"  {r.get('coord')} | {r.get('severity')} | {r.get('change_type')} | {r.get('api_name')} | confirmed={r.get('confirmed')} | source={r.get('source')}"
            )
    with open(summary_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write("\n".join(lines) + "\n")

    return alerts_path, summary_path


# ══════════════════════════════════════════════════════════════════
# 主函数
# ══════════════════════════════════════════════════════════════════

def main():
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
                    help='单个依赖通过 Maven 拉取 jar 的超时时间（秒）')
    ap.add_argument('--workers', type=int, default=int(os.environ.get("JUA_STEP4_WORKERS", "4") or "4"),
                    help='Step4 依赖级并行 worker 数；设为 1 可恢复串行执行')
    ap.add_argument('--skip-changed-classes', action='store_true',
                    help='跳过 changed_classes.json 的 class hash 计算，减少大批量依赖时的 I/O 开销')
    ap.add_argument('--source-branches', nargs=2,
                    metavar=('BASE', 'CURRENT'),
                    help='主项目上下文分支名，仅用于摘要展示；依赖源码 git diff 默认按依赖版本匹配 refs')
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
        if orchestrated_input.get("step4_workers"):
            args.workers = int(orchestrated_input.get("step4_workers"))
        if not args.source_branches:
            base_branch = str(orchestrated_input.get("base_branch") or "").strip()
            current_branch = str(orchestrated_input.get("current_branch") or "").strip()
            if base_branch and current_branch:
                args.source_branches = [base_branch, current_branch]

    if not args.japicmp_jar:
        args.japicmp_jar = japicmp_default_jar_path()

    os.makedirs(args.output_dir, exist_ok=True)
    cleanup_step4_generated_outputs(args.output_dir)
    try:
        dependency_git_ref_overrides = parse_dependency_git_ref_overrides(args.dependency_git_ref_overrides_json)
    except ValueError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 2

    step_timer = PhaseTimer("step4", "total")
    dep_rows = load_csv(args.dep_changes)
    ctx      = load_json(args.context)
    japicmp_planned_rows = [row for row in dep_rows if dependency_needs_japicmp(row)]
    if japicmp_planned_rows and not os.path.exists(args.japicmp_jar):
        installed, resolved_japicmp_jar, install_error = auto_install_japicmp(
            args.japicmp_jar,
            timeout=args.fetch_timeout,
        )
        args.japicmp_jar = resolved_japicmp_jar
        if (not installed) and (not args.allow_degraded):
            planned_dependencies = [
                {
                    "coord": row.get("coord", ""),
                    "old_version": row.get("old_version", ""),
                    "new_version": row.get("new_version", ""),
                    "change_type": row.get("change_type", ""),
                }
                for row in japicmp_planned_rows
            ]
            interaction = build_japicmp_missing_interaction(
                args.output_dir,
                args.japicmp_jar,
                install_error,
                planned_dependencies,
            )
            if os.environ.get("JUA_ORCHESTRATED") == "1":
                emit_interaction(interaction)
                return 0
            print("\n❌ JApiCmp 不可用，且未确认 allow_degraded=true。", file=sys.stderr)
            print(f"   自动安装失败原因：{install_error}", file=sys.stderr)
            print(f"   请执行：mvn dependency:get -Dartifact={DEFAULT_JAPICMP_COORD}", file=sys.stderr)
            print("   或提供 --japicmp-jar 后重跑 Step4；若确认降级，请显式设置 --allow-degraded。", file=sys.stderr)
            return 2
        if (not installed) and args.allow_degraded:
            print(
                "⚠️  JApiCmp 自动安装失败，但已显式 allow_degraded=true；"
                "Step4 将缺少二进制 API 对比证据。",
                file=sys.stderr,
            )
    compute_changed_classes_enabled = (not args.skip_changed_classes) and len(dep_rows) <= 200
    if not compute_changed_classes_enabled:
        print("  ℹ️  changed_classes.json 已降级为轻量模式，跳过 class hash 计算以提升大批量依赖稳定性。", file=sys.stderr)
    if (not args.source_branches) and ctx.get("base_branch") and ctx.get("current_branch"):
        base_br = str(ctx.get("base_branch")).strip()
        cur_br = str(ctx.get("current_branch")).strip()
        if base_br and cur_br and base_br != cur_br:
            args.source_branches = [base_br, cur_br]

    # 解析依赖源码仓库映射
    dependency_paths = {}
    dependency_path_meta = {}

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
            coord_locations = infer_maven_coord_locations(abs_path)
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
                    sys.exit(2)
                for matched_coord in matched_coords:
                    location = location_by_coord.get(matched_coord) or {}
                    register_dependency_path(
                        matched_coord,
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
        coord_locations = infer_maven_coord_locations(abs_path)
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

    changed_dependency_coords = {
        dep['coord'] for dep in ctx.get('changed_dependencies', []) if dep.get('coord')
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
    timeout_items = []
    binary_runs = []

    report_dir = str(Path(args.output_dir).resolve().parent)
    artifact_resolver = Step1ArtifactJarResolver(report_dir, args.output_dir)
    prepared_dep_rows = []
    artifact_jar_hits = 0
    for row in dep_rows:
        prepared = dict(row)
        base_evidence = artifact_resolver.resolve_for_row(row, "base")
        current_evidence = artifact_resolver.resolve_for_row(row, "current")
        if base_evidence:
            artifact_jar_hits += 1
            prepared["_step4_base_jar_path"] = base_evidence.get("path") or ""
            prepared["_step4_base_jar_evidence"] = base_evidence
        if current_evidence:
            artifact_jar_hits += 1
            prepared["_step4_current_jar_path"] = current_evidence.get("path") or ""
            prepared["_step4_current_jar_evidence"] = current_evidence
        prepared_dep_rows.append(prepared)

    workers = max(1, int(args.workers or 1))
    if len(dep_rows) <= 1:
        workers = 1
    print(f"\nStep 4 开始：处理 {len(dep_rows)} 个依赖（workers={workers}，Step1 产物 jar 命中={artifact_jar_hits}）", file=sys.stderr)
    emit_progress("step4", "plan", f"开始构建 jar 对比证据池，共 {len(dep_rows)} 个依赖，workers={workers}")

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

        if not coord:
            return result
        if change == '未变':
            return result

        is_removed_dependency = (change == '移除') or (new_ver == '-' and old_ver != '-')
        is_added_dependency = (change == '新增') or (old_ver == '-' and new_ver != '-')
        dependency_raw_apis = []
        dependency_removed_jar_export = {}

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
            total=len(dep_rows),
            item=coord,
        )
        if is_focus_dependency and (not has_source_repo):
            result["changed_deps_missing_source"].append({
                "coord": coord,
                "old_version": old_ver,
                "new_version": new_ver,
            })

        if has_source_repo and not is_removed_dependency and not is_added_dependency:
            # 4b: 有源码依赖做 git diff
            gitdiff_timer = time.perf_counter()
            emit_progress(
                "step4",
                "gitdiff",
                f"开始源码 diff：{coord}",
                current=i,
                total=len(dep_rows),
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
            }
            gitdiff_result = run_gitdiff(lib_info, args.output_dir, git_diff_timeout=args.git_diff_timeout)
            _out_file = gitdiff_result.get("out_file")
            apis = gitdiff_result.get("apis") or []
            err = gitdiff_result.get("error")
            meta = gitdiff_result.get("meta") or {}
            if gitdiff_result.get("status") == "needs_user_confirmation":
                print("    ⚠️  git refs 无法自动确定，已加入待人工确认清单。", file=sys.stderr)
                emit_progress(
                    "step4",
                    "gitdiff",
                    "源码 diff 需要人工确认 git refs",
                    current=i,
                    total=len(dep_rows),
                    elapsed=time.perf_counter() - gitdiff_timer,
                    item=coord,
                )
                result["gitdiff_pending"].append(
                    {
                        "coord": coord,
                        "old_version": old_ver,
                        "new_version": new_ver,
                        "reason": meta.get("reason") or err,
                        "repo_path": meta.get("repo_path") or source_mapping.get("repo_path", ""),
                        "module_path": meta.get("module_path") or source_mapping.get("module_path", ""),
                        "old_candidates": meta.get("old_candidates") or [],
                        "new_candidates": meta.get("new_candidates") or [],
                        "old_ref_override": meta.get("old_ref_override") or "",
                        "new_ref_override": meta.get("new_ref_override") or "",
                        "mapping_mode": (dependency_path_meta.get(coord) or {}).get("mapping_mode"),
                        "out_file": os.path.abspath(_out_file) if _out_file else "",
                    }
                )
            elif gitdiff_result.get("status") == "error":
                print(f"    ⚠️  git diff 失败：{err}", file=sys.stderr)
                emit_progress(
                    "step4",
                    "gitdiff",
                    f"源码 diff 失败：{err}",
                    current=i,
                    total=len(dep_rows),
                    elapsed=time.perf_counter() - gitdiff_timer,
                    item=coord,
                )
                result["gitdiff_skipped"].append(
                    {
                        "coord": coord,
                        "old_version": old_ver,
                        "new_version": new_ver,
                        "reason": err,
                        "repo_path": meta.get("repo_path") or source_mapping.get("repo_path", ""),
                        "module_path": meta.get("module_path") or source_mapping.get("module_path", ""),
                        "old_candidates": meta.get("old_candidates") or [],
                        "new_candidates": meta.get("new_candidates") or [],
                        "out_file": os.path.abspath(_out_file) if _out_file else "",
                    }
                )
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
                all_apis.extend(apis)
                dependency_raw_apis.extend(apis)
                behavior_changed = sum(1 for a in apis if a.get("change_type") == "BEHAVIOR_CHANGED")
                print(f"    → {len(apis)} 个源码差异（含 behavior_changed={behavior_changed}）", file=sys.stderr)
                emit_progress(
                    "step4",
                    "gitdiff",
                    f"源码 diff 完成，提取 {len(apis)} 个变化，behavior_changed={behavior_changed}",
                    current=i,
                    total=len(dep_rows),
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
                        "out_file": os.path.abspath(_out_file),
                        "base_ref": (meta or {}).get("base_ref"),
                        "cur_ref": (meta or {}).get("cur_ref"),
                        "ref_source": (meta or {}).get("ref_source"),
                        "old_match_reason": (meta or {}).get("old_reason"),
                        "new_match_reason": (meta or {}).get("new_reason"),
                        "old_candidates": (meta or {}).get("old_candidates") or [],
                        "new_candidates": (meta or {}).get("new_candidates") or [],
                        "repo_path": (meta or {}).get("repo_path") or source_mapping.get("repo_path", ""),
                        "module_path": (meta or {}).get("module_path") or source_mapping.get("module_path", ""),
                        "module_rel_path": (meta or {}).get("module_rel_path"),
                        "mapping_mode": (dependency_path_meta.get(coord) or {}).get("mapping_mode"),
                    }
                )

        # 4a: 升级依赖做 JApiCmp；removed 依赖导出旧 jar 符号集作为 Step5 输入
        if is_removed_dependency:
            removed_timer = time.perf_counter()
            emit_progress(
                "step4",
                "japicmp",
                f"开始导出 removed jar 旧版符号：{coord}",
                current=i,
                total=len(dep_rows),
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
                result["binary_runs"].append({'coord': coord, 'status': 'failed', 'mode': 'old_jar_export', 'error': err})
                print(f"    ⚠️  removed jar 旧版符号导出失败：{err}", file=sys.stderr)
                emit_progress(
                    "step4",
                    "japicmp",
                    f"removed jar 旧版符号导出失败：{err}",
                    current=i,
                    total=len(dep_rows),
                    elapsed=time.perf_counter() - removed_timer,
                    item=coord,
                )
                result["jar_missing_deps"].append(coord)
                if str((jar_info or {}).get("fetch_old_error") or "").startswith("timeout("):
                    result["timeout_items"].append(
                        {
                            "coord": coord,
                            "stage": "dependency_get",
                            "timeout_seconds": args.fetch_timeout,
                            "reason": (jar_info or {}).get("fetch_old_error"),
                            "old_version": old_ver,
                            "new_version": new_ver,
                        }
                    )
            else:
                result["binary_runs"].append({
                    'coord': coord,
                    'status': 'success',
                    'mode': 'old_jar_export',
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
                    total=len(dep_rows),
                    elapsed=time.perf_counter() - removed_timer,
                    item=coord,
                )
        elif old_ver != '-' and new_ver != '-':
            japicmp_timer = time.perf_counter()
            emit_progress(
                "step4",
                "japicmp",
                f"开始二进制对比：{coord}",
                current=i,
                total=len(dep_rows),
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
            )
            result["binary_runs"].append({
                'coord': coord,
                'status': 'failed' if err else 'success',
                'mode': 'japicmp',
                'old_jar_source': str((jar_info or {}).get('old_jar_source') or ''),
                'new_jar_source': str((jar_info or {}).get('new_jar_source') or ''),
                'parser_mode': str((jar_info or {}).get('parser_mode') or ''),
                'xml_error': str((jar_info or {}).get('xml_error') or ''),
                'missing_class_policy': str((jar_info or {}).get('missing_class_policy') or ''),
                'japicmp_version': str((jar_info or {}).get('japicmp_version') or ''),
                'japicmp_sha256': str((jar_info or {}).get('japicmp_sha256') or ''),
                'error': str(err or ''),
            })
            if compute_changed_classes_enabled and jar_info and jar_info.get("old_jar") and jar_info.get("new_jar"):
                try:
                    result["changed_classes_by_coord"][coord] = {
                        "coord": coord,
                        "old_version": old_ver,
                        "new_version": new_ver,
                        "old_jar": jar_info["old_jar"],
                        "new_jar": jar_info["new_jar"],
                        **compute_changed_classes(jar_info["old_jar"], jar_info["new_jar"]),
                    }
                except Exception as e:
                    result["changed_classes_errors"].append(f"{coord}: {str(e)[:120]}")
            if err:
                print(f"    ⚠️  JApiCmp 失败：{err}", file=sys.stderr)
                emit_progress(
                    "step4",
                    "japicmp",
                    f"二进制对比失败：{err}",
                    current=i,
                    total=len(dep_rows),
                    elapsed=time.perf_counter() - japicmp_timer,
                    item=coord,
                )
                if 'jar 未找到' in err:
                    result["jar_missing_deps"].append(coord)
                    if str(jar_info.get("fetch_old_error") or "").startswith("timeout(") or str(
                        jar_info.get("fetch_new_error") or ""
                    ).startswith("timeout("):
                        result["timeout_items"].append(
                            {
                                "coord": coord,
                                "stage": "dependency_get",
                                "timeout_seconds": args.fetch_timeout,
                                "reason": jar_info.get("fetch_old_error") or jar_info.get("fetch_new_error"),
                                "old_version": old_ver,
                                "new_version": new_ver,
                            }
                        )
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
                print(f"    → {len(apis)} 个 binary incompatible 变更", file=sys.stderr)
                emit_progress(
                    "step4",
                    "japicmp",
                    f"二进制对比完成，提取 {len(apis)} 个变化",
                    current=i,
                    total=len(dep_rows),
                    elapsed=time.perf_counter() - japicmp_timer,
                    item=coord,
                )
            dependency_raw_apis.extend(apis)
            result["all_apis"].extend(apis)

        # 4c: changelog 分析任务文件（由 AI agent 后续填写）
        if change in ('大版本升级', '小版本升级') and (not has_source_repo):
            analyze_changelog(coord, old_ver, new_ver, args.output_dir)
        result["per_dependency_record"] = {
            "coord": coord,
            "dep_row": {k: v for k, v in dict(row).items() if not str(k).startswith("_step4_")},
            "raw_rows": dependency_raw_apis,
            "removed_jar_export": dependency_removed_jar_export,
        }
        emit_progress(
            "step4",
            "dependency",
            f"完成处理 {coord}",
            current=i,
            total=len(dep_rows),
            elapsed=time.perf_counter() - dependency_timer,
            item=coord,
        )
        return result

    per_dependency_records = {}
    task_results = []
    if workers == 1:
        for i, row in enumerate(prepared_dep_rows, 1):
            task_results.append(process_dependency(i, row))
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="step4-dep") as executor:
            futures = [
                executor.submit(process_dependency, i, row)
                for i, row in enumerate(prepared_dep_rows, 1)
            ]
            for future in as_completed(futures):
                task_results.append(future.result())

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
        timeout_items.extend(item.get("timeout_items") or [])
        binary_runs.extend(item.get("binary_runs") or [])
        per_record = item.get("per_dependency_record")
        if per_record and per_record.get("coord"):
            per_dependency_records[per_record.get("coord")] = per_record

    # 写入汇总文件
    csv_file, valid_count, invalid_count = write_all_changed_apis(
        all_apis, args.output_dir)
    for coord in sorted(per_dependency_records.keys()):
        item = per_dependency_records.get(coord) or {}
        write_per_dependency_outputs(
            report_dir=report_dir,
            dep_row=item.get("dep_row") or {},
            raw_rows=item.get("raw_rows") or [],
            removed_jar_export=item.get("removed_jar_export") or None,
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

    print(f"\nStep 4 完成：", file=sys.stderr)
    print(f"  变更 API 总数：{valid_count}", file=sys.stderr)
    print(f"  数据验证失败：{invalid_count} 行", file=sys.stderr)
    print(f"  jar 未找到：{len(jar_missing_deps)} 个依赖", file=sys.stderr)
    print(f"  JApiCmp 未安装：{len(japicmp_missing_deps)} 个依赖", file=sys.stderr)
    print(f"  其他 JApiCmp 失败：{len(other_failed_deps)} 个依赖", file=sys.stderr)
    print(f"  git ref 待人工确认：{len(gitdiff_pending)} 个依赖", file=sys.stderr)
    print(f"  超时项：{len(timeout_items)}", file=sys.stderr)
    print(f"  输出：{csv_file}", file=sys.stderr)

    timeouts_path = os.path.join(args.output_dir, "timeouts.json")
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

    binary_failures = [item for item in binary_runs if item.get('status') != 'success']
    text_fallbacks = [item for item in binary_runs if item.get('parser_mode') == 'text_fallback']
    missing_classes_ignored = [item for item in binary_runs if item.get('missing_class_policy') == 'ignored']
    binary_status = (
        'insufficient' if binary_runs and len(binary_failures) == len(binary_runs)
        else ('partial' if binary_failures or text_fallbacks or missing_classes_ignored else 'complete')
    ) if binary_runs else 'not_applicable'
    behavior_expected = [
        row for row in dep_rows
        if row.get('change_type') != '未变'
        and row.get('old_version') not in ('', '-')
        and row.get('new_version') not in ('', '-')
    ]
    behavior_status = (
        'not_applicable' if not behavior_expected
        else ('complete' if len(gitdiff_runs) == len(behavior_expected)
              else ('partial' if gitdiff_runs else 'insufficient'))
    )
    step4_coverage = {
        'schema': 'java-upgrade-analyzer.step4-coverage.v1',
        'binary_api_diff': {
            'status': binary_status,
            'reason_codes': (
                (['japicmp_or_old_jar_failed'] if binary_failures else [])
                + (['JAPICMP_TEXT_FALLBACK_USED'] if text_fallbacks else [])
                + (['JAPICMP_MISSING_CLASSES_IGNORED'] if missing_classes_ignored else [])
            ),
            'metrics': {
                'planned_dependencies': len(binary_runs),
                'successful_dependencies': len(binary_runs) - len(binary_failures),
                'failed_dependencies': len(binary_failures),
                'text_fallbacks': len(text_fallbacks),
                'missing_classes_ignored': len(missing_classes_ignored),
            },
            'runs': binary_runs,
        },
        'behavior_diff': {
            'status': behavior_status,
            'reason_codes': [] if behavior_status in {'complete', 'not_applicable'} else [
                'dependency_source_or_git_ref_coverage_incomplete'
            ],
            'metrics': {
                'planned_dependencies': len(behavior_expected),
                'successful_dependencies': len(gitdiff_runs),
                'pending_dependencies': len(gitdiff_pending),
                'failed_or_skipped_dependencies': len(gitdiff_skipped),
                'missing_source_dependencies': len(changed_deps_missing_source),
            },
        },
    }
    coverage_output = Path(args.coverage_output) if args.coverage_output else default_coverage_output_path(args.output_dir)
    coverage_output.parent.mkdir(parents=True, exist_ok=True)
    coverage_output.write_text(
        json.dumps(step4_coverage, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
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
        print(f"\n⚠️  检测到升级依赖未提供源码路径映射：{len(items)} 个（将无法通过 git diff 识别“签名不变的行为变更”）", file=sys.stderr)
        for it in items[:10]:
            print(f"  - {it['coord']} ({it['old_version']}→{it['new_version']})", file=sys.stderr)
        print("\n建议：在运行 Step4 时提供依赖源码路径（本地 git repo 根目录）", file=sys.stderr)
        print("  只要给到 repo 根目录，调度层会自动扫描 pom.xml 并展开多模块坐标。", file=sys.stderr)
        print("  方式1：命令行参数 --dependency-repo-mappings /abs/path/to/repo", file=sys.stderr)
        print("        标准格式：--dependency-repo-mappings groupId:artifactId=/abs/path/to/repo", file=sys.stderr)
        print("  方式2：先将 dependency_repo_mappings 写入 .upgrade-report/.runtime/state/main_state.json 的当前步骤输入", file=sys.stderr)
        print("示例：", file=sys.stderr)
        print('  {"dependency_repo_mappings":["/abs/path/internal-repo"]}', file=sys.stderr)
        print('  {"dependency_repo_mappings":[{"coord":"com.myco:lib-a","path":"/abs/path/internal-repo"}]}', file=sys.stderr)

    # 输出摘要，真正的交互暂停由 run_step.py 统一处理
    human_checkpoint_1(dep_rows, all_apis, args.output_dir)
    print(
        "\nStep 4 交互提示：进入 Step5 前，"
        "请由调度层统一提示用户复核 summary.txt、all_changed_apis.csv、git_ref_matches.* 等证据文件。",
        file=sys.stderr,
    )
    emit_progress(
        "step4",
        "done",
        f"Step4 完成，变更 API={valid_count}，待确认 git refs={len(gitdiff_pending)}，超时项={len(timeout_items)}",
        elapsed=step_timer.elapsed(),
    )
    if gitdiff_pending:
        interaction = build_git_ref_confirmation_interaction(args.output_dir, gitdiff_pending)
        if os.environ.get("JUA_ORCHESTRATED") == "1":
            emit_interaction(interaction)
            return 0
        print("\n⚠️  存在待人工确认的 git refs，请查看 git_ref_pending.json 后重跑 Step4。", file=sys.stderr)
        return 2
    if timeout_items:
        interaction = build_timeout_resolution_interaction(args.output_dir, timeout_items)
        if os.environ.get("JUA_ORCHESTRATED") == "1":
            emit_interaction(interaction)
            return 0
        print("\n⚠️  Step4 存在超时导致的证据缺口，请查看 timeouts.json 后重跑 Step4。", file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
