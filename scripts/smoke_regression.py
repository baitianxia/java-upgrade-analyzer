#!/usr/bin/env python3
"""
最小回归脚本：
1. 验证 Step 1 对裸 Maven tree / 前置日志噪声的解析
2. 验证 Step 2 在非 Git 工作区与 Git 子目录下的回退逻辑
3. 验证 Step 3 的依赖 jar 兼容性扫描
4. 验证 Step 4/5 的反向调用链链路
5. 验证 Step 6 最终报告生成
"""

import argparse
import base64
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
from compat import run_cmd as compat_run_cmd, open_text, git_cmd
from confidence_weighted_tracer import (
    build_api_target_keys,
    build_api_identity_key,
    is_framework_boundary,
    is_system_code_touched,
    trace_api_with_confidence_weighting,
)
import enhanced_source_analyzer as source_analyzer_module
from enhanced_output_formatter import explain_reason_code
import s1_dep_diff as s1_dep_diff_module
from enhanced_source_analyzer import (
    analyze_file,
    extract_call_edges_enhanced,
    infer_invocation_return_type,
    infer_param_type_from_expression,
)
import run_step as run_step_module
from s5_call_chain_engine_integrated import (
    build_enhanced_source_graph,
    _parse_javap_signature_block,
    check_apis_that_need_bridge,
)
from s4_jar_compare import (
    extract_api_signature_from_declaration,
    normalize_step5_input_rows,
    parse_gitdiff_apis,
    parse_japicmp_output,
    split_parameters_preserving_generics,
)
from s4_contract import ALL_CHANGED_APIS_FIELDS


SCRIPT_DIR = Path(__file__).resolve().parent
EXIT_AWAITING_USER = 4
SMOKE_GROUPS = ("all", "core", "step5", "orchestrator")


@dataclass(frozen=True)
class SmokeWorkspace:
    base_tmp: Path
    project_dir: Path
    report_dir: Path
    fake_home: Path
    fake_bin: Path
    fake_mvn: Path
    source_dir: Path
    dep_repo: Path
    multi_dep_repo: Path
    dep_branch_repo: Path
    deep_repo: Path
    adapter_repo: Path
    bridge_repo: Path


def run_script(script_name, args, cwd=None, env=None, allow_awaiting=False):
    """
    执行脚本并验证返回码

    Args:
        allow_awaiting: 是否允许 EXIT_AWAITING_USER。只有在明确知道是 checkpoint 场景时才设为 True。
                        设为 False 时，任何 await 都视为测试失败，暴露调度状态机问题。
    """
    cmd = [sys.executable, str(SCRIPT_DIR / script_name), *(args or [])]
    merged_env = dict(env or {})
    stdout, stderr, rc = compat_run_cmd(cmd, cwd=str(cwd) if cwd else None, env=merged_env)

    allowed_rcs = {0}
    if allow_awaiting and script_name == "run_step.py":
        # 只有在明确知道是 checkpoint 场景时才接受 awaiting
        # 这确保调度状态机按预期进入 checkpoint，而不是静默失败
        allowed_rcs.add(EXIT_AWAITING_USER)

    if rc == EXIT_AWAITING_USER and not allow_awaiting:
        raise RuntimeError(
            f"命令意外进入等待用户交互状态（EXIT={rc}）：{' '.join(cmd)}\n"
            f"这暴露了调度状态机/恢复协议的问题，请检查 main_state.json 和 interaction.json\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )

    if rc not in allowed_rcs:
        raise RuntimeError(
            f"命令失败: {' '.join(cmd)}\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )
    return stdout, stderr


def run_script_with_rc(script_name, args, cwd=None, env=None):
    cmd = [sys.executable, str(SCRIPT_DIR / script_name), *(args or [])]
    stdout, stderr, rc = compat_run_cmd(cmd, cwd=str(cwd) if cwd else None, env=dict(env or {}))
    return stdout, stderr, rc


def read_csv(path):
    with open_text(path) as f:
        return list(csv.DictReader(f))


def _read_json_file(path):
    with open_text(path) as f:
        return json.load(f)


def read_json(path):
    path = Path(path)
    if path.exists():
        return _read_json_file(path)
    with open_text(path) as f:
        return json.load(f)


def main_state_meta(main_state):
    return dict((main_state or {}).get("state") or {})


def main_state_step_input(main_state, step_id):
    return dict(((main_state or {}).get(step_id) or {}).get("input") or {})


def main_state_step_output(main_state, step_id):
    return dict(((main_state or {}).get(step_id) or {}).get("output") or {})


def write_text(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def copy_file(src, dst):
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    return shutil.copy(src, dst)


def main_state_path(report_dir):
    return Path(report_dir) / ".runtime" / "state" / run_step_module.MAIN_STATE_FILE_NAME


def interaction_path(report_dir):
    return Path(report_dir) / ".runtime" / "state" / "interaction.json"


def dep_changes_path(report_dir):
    return Path(report_dir) / "evidence" / "dependencies" / "dep_changes.csv"


def deps_current_resolved_path(report_dir):
    return Path(report_dir) / "evidence" / "dependencies" / "deps_current_resolved.csv"


def context_path(report_dir):
    return Path(report_dir) / "evidence" / "context" / "context.json"


def minimal_valid_app_class_bytes():
    # 由 `public class App {}` 编译得到的最小合法 class，用于让 smoke 的
    # 最终制品能被 javap 正常读取，避免把 fake 字节串误当成业务字节码回归。
    return base64.b64decode(
        "yv66vgAAAEQADQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClW"
        "BwAIAQADQXBwAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAClNvdXJjZUZpbGUBAAhBcHAuamF2"
        "YQAhAAcAAgAAAAAAAQABAAUABgABAAkAAAAdAAEAAQAAAAUqtwABsQAAAAEACgAAAAYAAQAAAAEA"
        "AQALAAAAAgAM"
    )


def minimal_valid_legacy_api_class_bytes(include_multi_line=True):
    # 由以下源码编译得到，用于让 Step4 的 jar truth 校验能通过 javap
    # 读取真实公开方法，而不是依赖 fake class 字节串：
    #
    # package com.example.lib;
    # public class LegacyApi {
    #   public String singleLine() { return "x"; }
    #   public String multiLine() { return "x"; }      // v1 only
    #   public static String bridgeMethod() { return "x"; }
    # }
    if include_multi_line:
        payload = (
            "yv66vgAAAEQAEwoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClW"
            "CAAIAQABeAcACgEAGWNvbS9leGFtcGxlL2xpYi9MZWdhY3lBcGkBAARDb2RlAQAPTGluZU51bWJl"
            "clRhYmxlAQAKc2luZ2xlTGluZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAJbXVsdGlMaW5lAQAM"
            "YnJpZGdlTWV0aG9kAQAKU291cmNlRmlsZQEADkxlZ2FjeUFwaS5qYXZhACEACQACAAAAAAAEAAEA"
            "BQAGAAEACwAAAB0AAQABAAAABSq3AAGxAAAAAQAMAAAABgABAAAAAgABAA0ADgABAAsAAAAbAAEA"
            "AQAAAAMSB7AAAAABAAwAAAAGAAEAAAADAAEADwAOAAEACwAAABsAAQABAAAAAxIHsAAAAAEADAAA"
            "AAYAAQAAAAQACQAQAA4AAQALAAAAGwABAAAAAAADEgewAAAAAQAMAAAABgABAAAABQABABEAAAAC"
            "ABI="
        )
    else:
        payload = (
            "yv66vgAAAEQAEgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClW"
            "CAAIAQABeAcACgEAGWNvbS9leGFtcGxlL2xpYi9MZWdhY3lBcGkBAARDb2RlAQAPTGluZU51bWJl"
            "clRhYmxlAQAKc2luZ2xlTGluZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAMYnJpZGdlTWV0aG9k"
            "AQAKU291cmNlRmlsZQEADkxlZ2FjeUFwaS5qYXZhACEACQACAAAAAAADAAEABQAGAAEACwAAAB0A"
            "AQABAAAABSq3AAGxAAAAAQAMAAAABgABAAAAAgABAA0ADgABAAsAAAAbAAEAAQAAAAMSB7AAAAAB"
            "AAwAAAAGAAEAAAADAAkADwAOAAEACwAAABsAAQAAAAAAAxIHsAAAAAEADAAAAAYAAQAAAAQAAQAQ"
            "AAAAAgAR"
        )
    return base64.b64decode(payload)


def create_fake_jar(path, marker=b""):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            "com/example/lib/LegacyApi.class",
            minimal_valid_legacy_api_class_bytes(include_multi_line=marker != b"v2"),
        )
        zf.writestr(
            "com/example/lib/RiskMarker.class",
            b"javax/xml/bind setAccessible java/lang/SecurityManager com/sun/" + (marker or b""),
        )
        zf.writestr(
            "META-INF/spring.factories",
            "org.springframework.boot.autoconfigure.EnableAutoConfiguration=demo.AutoConfig\n",
        )


def build_embedded_maven_jar_bytes(group_id, artifact_id, version, marker=b""):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(
            f"META-INF/maven/{group_id}/{artifact_id}/pom.properties",
            f"groupId={group_id}\nartifactId={artifact_id}\nversion={version}\n",
        )
        zf.writestr(
            "com/example/lib/Embedded.class",
            b"embedded-marker:" + (marker or b""),
        )
    return buffer.getvalue()


def create_fake_boot_jar(path, embedded_deps):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("BOOT-INF/classes/com/example/App.class", minimal_valid_app_class_bytes())
        for dep in embedded_deps:
            group_id, artifact_id, version = dep
            zf.writestr(
                f"BOOT-INF/lib/{artifact_id}-{version}.jar",
                build_embedded_maven_jar_bytes(group_id, artifact_id, version, marker=artifact_id.encode("utf-8")),
            )


def create_scoped_runtime_evidence(report_dir, dependencies):
    """Create a final-artifact fixture whose dependency classes match source fixtures."""
    report_dir = Path(report_dir)
    artifact_path = report_dir / "evidence" / "dependencies" / "s1_artifacts" / "current.jar"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_rows = []
    with zipfile.ZipFile(artifact_path, "w") as outer:
        outer.writestr("BOOT-INF/classes/com/example/App.class", minimal_valid_app_class_bytes())
        for coord, version, class_names in dependencies:
            group_id, artifact_id = coord.split(":", 1)
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as jar:
                jar.writestr(
                    f"META-INF/maven/{group_id}/{artifact_id}/pom.properties",
                    f"groupId={group_id}\nartifactId={artifact_id}\nversion={version}\n",
                )
                for class_name in class_names:
                    jar.writestr(class_name.replace(".", "/") + ".class", b"fixture-class")
            lib_entry = f"BOOT-INF/lib/{artifact_id}-{version}.jar"
            outer.writestr(lib_entry, nested.getvalue())
            resolved_rows.append({
                "coord": coord,
                "version": version,
                "scope": "runtime",
                "lib_entry": lib_entry,
                "resolution_status": "resolved",
            })

    resolved_path = report_dir / "evidence" / "dependencies" / "deps_current_resolved.csv"
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    with resolved_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["coord", "version", "scope", "lib_entry", "resolution_status"],
        )
        writer.writeheader()
        writer.writerows(resolved_rows)
    digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    write_text(
        report_dir / "evidence" / "dependencies" / "build_provenance.json",
        json.dumps({
            "schema": "java-upgrade-analyzer.build-provenance.v1",
            "both_builds_succeeded": True,
            "sides": [{
                "side": "current",
                "source_mode": "fixture_final_artifact",
                "artifact_path": str(artifact_path),
                "artifact_sha256": digest,
                "build_succeeded": True,
            }],
        }, ensure_ascii=False, indent=2) + "\n",
    )


def commit_source_fixture(repo_dir):
    git = git_cmd()
    run_external_cmd(git + ["init"], repo_dir)
    run_external_cmd(git + ["config", "user.name", "Trae Smoke"], repo_dir)
    run_external_cmd(git + ["config", "user.email", "smoke@example.com"], repo_dir)
    run_external_cmd(git + ["add", "."], repo_dir)
    run_external_cmd(git + ["commit", "-m", "runtime source fixture"], repo_dir)


def write_scoped_ref_evidence(report_dir, coord_repositories):
    items = []
    for coord, repo_dir in coord_repositories:
        items.append({
            "coord": coord,
            "repo_path": str(Path(repo_dir).resolve()),
            "module_rel_path": ".",
            "cur_ref": "HEAD",
            "status": "matched",
        })
    write_text(
        Path(report_dir) / "evidence" / "api_changes" / "git_ref_matches.json",
        json.dumps({"matched_items": items}, ensure_ascii=False, indent=2) + "\n",
    )


def commit_business_fixture_and_update_provenance(project_dir, report_dir, message):
    git = git_cmd()
    run_external_cmd(git + ["add", "src/main/java"], project_dir)
    _stdout, _stderr, status_rc = compat_run_cmd(
        git + ["diff", "--cached", "--quiet"],
        cwd=str(project_dir),
    )
    if status_rc != 0:
        run_external_cmd(git + ["commit", "-m", message], project_dir)
    revision_stdout, _revision_stderr = run_external_cmd(
        git + ["rev-parse", "HEAD"],
        project_dir,
    )
    revision = revision_stdout.strip()
    provenance_path = Path(report_dir) / "evidence" / "dependencies" / "build_provenance.json"
    provenance = read_json(provenance_path)
    current = next(item for item in provenance.get("sides") or [] if item.get("side") == "current")
    current["revision"] = revision
    current["source_mode"] = "checkout_build"
    write_text(
        provenance_path,
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n",
    )


def refresh_fixture_business_bytecode(report_dir, source_files):
    report_dir = Path(report_dir)
    artifact_path = report_dir / "evidence" / "dependencies" / "s1_artifacts" / "current.jar"
    with tempfile.TemporaryDirectory(prefix="jua-smoke-javac-") as tmp:
        classes_dir = Path(tmp) / "classes"
        classes_dir.mkdir()
        stdout, stderr, rc = compat_run_cmd(
            ["javac", "-d", str(classes_dir), *[str(Path(path)) for path in source_files]],
            cwd=str(report_dir.parent),
        )
        if rc != 0:
            raise RuntimeError(f"fixture javac failed\nstdout:\n{stdout}\nstderr:\n{stderr}")
        compiled_classes = {
            class_file.relative_to(classes_dir).as_posix(): class_file.read_bytes()
            for class_file in sorted(classes_dir.rglob("*.class"))
        }
        dependency_prefixes = {
            "deep-lib-": "com/example/deep/",
            "adapter-lib-": "com/example/adapter/",
            "bridge-lib-": "com/example/bridge/",
        }
        replacement = artifact_path.with_suffix(".tmp.jar")
        with zipfile.ZipFile(artifact_path) as original, zipfile.ZipFile(replacement, "w") as updated:
            for info in original.infolist():
                if info.filename.startswith("BOOT-INF/classes/"):
                    continue
                dependency_prefix = next(
                    (
                        class_prefix
                        for artifact_prefix, class_prefix in dependency_prefixes.items()
                        if info.filename.startswith(f"BOOT-INF/lib/{artifact_prefix}")
                    ),
                    "",
                )
                if dependency_prefix:
                    nested_output = io.BytesIO()
                    with zipfile.ZipFile(io.BytesIO(original.read(info.filename))) as nested_original, zipfile.ZipFile(nested_output, "w") as nested_updated:
                        for nested_info in nested_original.infolist():
                            if not (
                                nested_info.filename.startswith(dependency_prefix)
                                and nested_info.filename.endswith(".class")
                            ):
                                nested_updated.writestr(
                                    nested_info,
                                    nested_original.read(nested_info.filename),
                                )
                        for relative, class_bytes in compiled_classes.items():
                            if relative.startswith(dependency_prefix):
                                nested_updated.writestr(relative, class_bytes)
                    updated.writestr(info, nested_output.getvalue())
                    continue
                updated.writestr(info, original.read(info.filename))
            for relative, class_bytes in compiled_classes.items():
                if relative.startswith("com/example/") and any(
                    relative.startswith(prefix)
                    for prefix in (
                        "com/example/BridgeApp",
                        "com/example/NestedBridgeApp",
                        "com/example/BridgeChainApp",
                    )
                ):
                    updated.writestr(f"BOOT-INF/classes/{relative}", class_bytes)
        os.replace(replacement, artifact_path)

    provenance_path = report_dir / "evidence" / "dependencies" / "build_provenance.json"
    provenance = read_json(provenance_path)
    current = next(item for item in provenance.get("sides") or [] if item.get("side") == "current")
    current["artifact_sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    write_text(
        provenance_path,
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n",
    )


def create_plain_jar(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("com/example/App.class", minimal_valid_app_class_bytes())


def run_external_cmd(cmd, cwd):
    stdout, stderr, rc = compat_run_cmd(cmd, cwd=str(cwd))
    if rc != 0:
        raise RuntimeError(
            f"命令失败: {' '.join(str(c) for c in cmd)}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return stdout, stderr


def create_remote_refs(repo_dir, ref_to_branch):
    git = git_cmd()
    for ref_name, branch_name in (ref_to_branch or {}).items():
        commit, _ = run_external_cmd(git + ["rev-parse", branch_name], repo_dir)
        run_external_cmd(
            git + ["update-ref", f"refs/remotes/{ref_name}", commit.strip()],
            repo_dir,
        )


def init_source_repo(repo_dir):
    src_dir = repo_dir / "src" / "main" / "java" / "com" / "example" / "lib"
    src_dir.mkdir(parents=True, exist_ok=True)
    git = git_cmd()
    run_external_cmd(git + ["init"], repo_dir)
    run_external_cmd(git + ["config", "user.name", "Trae Smoke"], repo_dir)
    run_external_cmd(git + ["config", "user.email", "smoke@example.com"], repo_dir)
    write_text(
        repo_dir / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo-lib</artifactId>
  <version>1.0.0</version>
</project>
""",
    )

    # 【测试用例】包含单行方法体的源码，用于验证解析器正确处理
    # 问题场景: void f() { doWork(); } 这种单行方法会导致后续行被吞掉
    write_text(
        src_dir / "LegacyApi.java",
        """package com.example.lib;
public class LegacyApi {
    // 单行方法体
    public String singleLine() { return "old"; }
    // 后续方法，不应被吞掉
    public String multiLine() {
        return "old-multi";
    }
    // 同文件另一个类
}
class Helper {
    public void helpMethod() { doHelp(); }
    public void anotherMethod() { doAnother(); }
}
""",
    )
    run_external_cmd(git + ["add", "."], repo_dir)
    run_external_cmd(git + ["commit", "-m", "base"], repo_dir)
    run_external_cmd(git + ["branch", "-M", "base"], repo_dir)
    run_external_cmd(git + ["tag", "v1.0.0"], repo_dir)

    # 变更：删除 multiLine 方法，修改 singleLine 方法
    write_text(
        src_dir / "LegacyApi.java",
        """package com.example.lib;
public class LegacyApi {
    // 单行方法体
    public String singleLine() { return "new"; }
    // 同文件另一个类也变了
}
class Helper {
    public void helpMethod() { doNewHelp(); }
    public void anotherMethod() { doAnother(); }
}
""",
    )
    run_external_cmd(git + ["checkout", "-b", "current"], repo_dir)
    run_external_cmd(git + ["add", "."], repo_dir)
    run_external_cmd(git + ["commit", "-m", "behavior change"], repo_dir)
    run_external_cmd(git + ["tag", "v2.0.0"], repo_dir)
    create_remote_refs(
        repo_dir,
        {
            "origin/v1.0.0": "base",
            "origin/v2.0.0": "current",
        },
    )


def init_multimodule_source_repo(repo_dir):
    demo_src_dir = repo_dir / "demo-lib" / "src" / "main" / "java" / "com" / "example" / "lib"
    extra_src_dir = repo_dir / "demo-lib-extra" / "src" / "main" / "java" / "com" / "example" / "extra"
    demo_src_dir.mkdir(parents=True, exist_ok=True)
    extra_src_dir.mkdir(parents=True, exist_ok=True)
    git = git_cmd()
    run_external_cmd(git + ["init"], repo_dir)
    run_external_cmd(git + ["config", "user.name", "Trae Smoke"], repo_dir)
    run_external_cmd(git + ["config", "user.email", "smoke@example.com"], repo_dir)
    write_text(
        repo_dir / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo-parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <modules>
    <module>demo-lib</module>
    <module>demo-lib-extra</module>
  </modules>
</project>
""",
    )
    write_text(
        repo_dir / "demo-lib" / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>demo-parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>demo-lib</artifactId>
</project>
""",
    )
    write_text(
        repo_dir / "demo-lib-extra" / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>demo-parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>demo-lib-extra</artifactId>
</project>
""",
    )
    write_text(
        demo_src_dir / "LegacyApi.java",
        """package com.example.lib;
public class LegacyApi {
  public static String oldMethod() {
    return "old";
  }
  public static String bridgeMethod() {
    return "bridge-old";
  }
}
""",
    )
    write_text(
        extra_src_dir / "ExtraApi.java",
        """package com.example.extra;
import com.example.lib.LegacyApi;
public class ExtraApi {
  public static String stable() {
    return "stable";
  }
  public static String callLegacy() {
    return LegacyApi.bridgeMethod();
  }
}
""",
    )
    run_external_cmd(git + ["add", "."], repo_dir)
    run_external_cmd(git + ["commit", "-m", "base"], repo_dir)
    run_external_cmd(git + ["branch", "-M", "base"], repo_dir)
    run_external_cmd(git + ["tag", "v1.0.0"], repo_dir)

    write_text(
        demo_src_dir / "LegacyApi.java",
        """package com.example.lib;
public class LegacyApi {
  public static String oldMethod() {
    return "old";
  }
  public static String bridgeMethod() {
    return "new-behavior";
  }
}
""",
    )
    run_external_cmd(git + ["checkout", "-b", "current"], repo_dir)
    run_external_cmd(git + ["add", "."], repo_dir)
    run_external_cmd(git + ["commit", "-m", "behavior change"], repo_dir)
    run_external_cmd(git + ["tag", "v2.0.0"], repo_dir)
    create_remote_refs(
        repo_dir,
        {
            "origin/v1.0.0": "base",
            "origin/v2.0.0": "current",
        },
    )


def init_version_branch_repo(repo_dir):
    src_dir = repo_dir / "src" / "main" / "java" / "com" / "example" / "lib"
    src_dir.mkdir(parents=True, exist_ok=True)
    git = git_cmd()
    run_external_cmd(git + ["init"], repo_dir)
    run_external_cmd(git + ["config", "user.name", "Trae Smoke"], repo_dir)
    run_external_cmd(git + ["config", "user.email", "smoke@example.com"], repo_dir)
    write_text(
        repo_dir / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo-lib</artifactId>
  <version>1.0.0</version>
</project>
""",
    )

    write_text(
        src_dir / "LegacyApi.java",
        """package com.example.lib;
public class LegacyApi {
  public static String oldMethod() {
    return "old";
  }
}
""",
    )
    run_external_cmd(git + ["add", "."], repo_dir)
    run_external_cmd(git + ["commit", "-m", "release 1.0"], repo_dir)
    run_external_cmd(git + ["branch", "-M", "release-1.0.0"], repo_dir)

    write_text(
        src_dir / "LegacyApi.java",
        """package com.example.lib;
public class LegacyApi {
  public static String oldMethod() {
    return "branch-new-behavior";
  }
}
""",
    )
    run_external_cmd(git + ["checkout", "-b", "release-2.0.0"], repo_dir)
    run_external_cmd(git + ["add", "."], repo_dir)
    run_external_cmd(git + ["commit", "-m", "release 2.0"], repo_dir)
    create_remote_refs(
        repo_dir,
        {
            "origin/release-1.0.0": "release-1.0.0",
            "origin/release-2.0.0": "release-2.0.0",
        },
    )


def build_maven_tree(version):
    return "\n".join(
        [
            "com.example:demo-app:jar:1.0-SNAPSHOT",
            f"+- com.example:demo-lib:jar:{version}:compile",
            f"+- com.example:deep-lib:jar:{version}:compile",
            "+- com.example:adapter-lib:jar:1.0.0:compile",
            "+- org.springframework:spring-core:jar:5.3.31:compile",
            "\\- junit:junit:jar:4.13.2:test",
            "",
        ]
    )


def build_multimodule_maven_tree(demo_version, other_version):
    return "\n".join(
        [
            "[INFO] --- maven-dependency-plugin:3.6.0:tree (default-cli) @ module-a ---",
            f"[INFO] +- com.example:demo-lib:jar:{demo_version}:compile",
            "[INFO] +- org.springframework:spring-core:jar:5.3.31:compile",
            "[INFO] +- org.slf4j:slf4j-api:jar:1.7.36:compile",
            "[INFO] \\- junit:junit:jar:4.13.2:test",
            "[INFO] --- maven-dependency-plugin:3.6.0:tree (default-cli) @ module-b ---",
            f"[INFO] \\- com.example:other-lib:jar:{other_version}:compile",
            "",
        ]
    )


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def parse_smoke_args(argv):
    parser = argparse.ArgumentParser(description="java-upgrade-analyzer smoke regression")
    parser.add_argument(
        "--keep-tmp",
        action="store_true",
        help="保留临时目录，便于手工排查。",
    )
    parser.add_argument(
        "--group",
        choices=SMOKE_GROUPS,
        default="all",
        help="按主题执行回归子集：core=步骤1-4，step5=调用链与报告，orchestrator=run_step 编排链路。",
    )
    return parser.parse_args(argv)


def create_smoke_workspace(base_tmp):
    workspace = SmokeWorkspace(
        base_tmp=base_tmp,
        project_dir=base_tmp / "project",
        report_dir=(base_tmp / "project" / ".upgrade-report"),
        fake_home=base_tmp / "fake-home",
        fake_bin=base_tmp / "fake-bin",
        fake_mvn=(base_tmp / "fake-bin" / "mvn"),
        source_dir=(base_tmp / "project" / "src" / "main" / "java" / "com" / "example"),
        dep_repo=base_tmp / "demo-lib-repo",
        multi_dep_repo=base_tmp / "demo-multi-repo",
        dep_branch_repo=base_tmp / "demo-lib-branch-repo",
        deep_repo=base_tmp / "deep-lib-repo",
        adapter_repo=base_tmp / "adapter-lib-repo",
        bridge_repo=base_tmp / "bridge-lib-repo",
    )
    workspace.source_dir.mkdir(parents=True, exist_ok=True)
    workspace.report_dir.mkdir(parents=True, exist_ok=True)
    workspace.fake_bin.mkdir(parents=True, exist_ok=True)
    return workspace


def fake_maven_script_text():
    return """#!/usr/bin/env python3
import base64
import io
import os
import sys
import zipfile
from pathlib import Path


def find_git_root(start):
    current = Path(start).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return current


def current_branch(root):
    fixture_ref = root / ".step1-fixture-ref"
    if fixture_ref.is_file():
        return fixture_ref.read_text(encoding="utf-8").strip()
    branch_hint = os.environ.get("JUA_GIT_BRANCH_HINT", "").strip()
    if branch_hint:
        return branch_hint
    git_path = root / ".git"
    if git_path.is_file():
        git_ref = git_path.read_text(encoding="utf-8").strip()
        if git_ref.startswith("gitdir:"):
            git_path = (root / git_ref.split(":", 1)[1].strip()).resolve()
    head = (git_path / "HEAD").read_text(encoding="utf-8").strip()
    if head.startswith("ref:"):
        return head.rsplit("/", 1)[-1]
    return "HEAD"


def current_version(branch):
    if branch == "base":
        return "1.0.0"
    if branch == "current":
        return "2.0.0"
    return "2.0.0"


def other_version(branch):
    if branch == "base":
        return "1.0.0"
    if branch == "current":
        return "1.1.0"
    return "1.1.0"


def select_module(args):
    if "-pl" in args:
        value = args[args.index("-pl") + 1]
        return value.split(",")[0].strip().lstrip(":")
    return "."


def create_plain_jar(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("com/example/App.class", minimal_valid_app_class_bytes())


def minimal_valid_app_class_bytes():
    return base64.b64decode(
        "yv66vgAAAEQADQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClW"
        "BwAIAQADQXBwAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAClNvdXJjZUZpbGUBAAhBcHAuamF2"
        "YQAhAAcAAgAAAAAAAQABAAUABgABAAkAAAAdAAEAAQAAAAUqtwABsQAAAAEACgAAAAYAAQAAAAEA"
        "AQALAAAAAgAM"
    )


def create_boot_jar(path, deps):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as outer:
        outer.writestr("BOOT-INF/classes/com/example/App.class", minimal_valid_app_class_bytes())
        for group_id, artifact_id, version in deps:
            local_jar = (
                Path.home() / ".m2" / "repository" / Path(*group_id.split("."))
                / artifact_id / version / f"{artifact_id}-{version}.jar"
            )
            if local_jar.is_file():
                nested_bytes = local_jar.read_bytes()
            else:
                nested = io.BytesIO()
                with zipfile.ZipFile(nested, "w") as inner:
                    inner.writestr(
                        f"META-INF/maven/{group_id}/{artifact_id}/pom.properties",
                        f"groupId={group_id}\\nartifactId={artifact_id}\\nversion={version}\\n".encode("utf-8"),
                    )
                nested_bytes = nested.getvalue()
            outer.writestr(f"BOOT-INF/lib/{artifact_id}-{version}.jar", nested_bytes)


def print_dependency_list(module, branch):
    print("[INFO] The following files have been resolved:")
    if module == "module-a":
        version = current_version(branch)
        print(f"[INFO]    com.example:demo-lib:jar:{version}:runtime -- /tmp/demo-lib-{version}.jar")
    elif module == "module-b":
        version = other_version(branch)
        print(f"[INFO]    com.example:other-lib:jar:{version}:runtime -- /tmp/other-lib-{version}.jar")
    else:
        version = current_version(branch)
        print(f"[INFO]    com.example:demo-lib:jar:{version}:runtime -- /tmp/demo-lib-{version}.jar")


def main():
    args = sys.argv[1:]
    root = find_git_root(os.getcwd())
    branch = current_branch(root)
    module = select_module(args)
    if "package" in args:
        if module == "module-a":
            create_boot_jar(root / "module-a" / "target" / f"module-a-{current_version(branch)}.jar", [("com.example", "demo-lib", current_version(branch))])
        elif module == "module-b":
            create_boot_jar(root / "module-b" / "target" / f"module-b-{other_version(branch)}.jar", [("com.example", "other-lib", other_version(branch))])
        else:
            create_boot_jar(root / "target" / f"demo-app-{current_version(branch)}.jar", [("com.example", "demo-lib", current_version(branch))])
        print("[INFO] BUILD SUCCESS")
        return 0
    if "dependency:list" in args:
        print_dependency_list(module, branch)
        return 0
    print("[INFO] fake mvn noop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""


def initialize_smoke_project(workspace):
    project_dir = workspace.project_dir
    source_dir = workspace.source_dir
    write_text(
        project_dir / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo-app</artifactId>
  <version>1.0-SNAPSHOT</version>
  <properties>
    <java.version>17</java.version>
    <spring-boot.version>2.7.18</spring-boot.version>
  </properties>
</project>
""",
    )
    (project_dir / "module-a").mkdir(parents=True, exist_ok=True)
    (project_dir / "module-b").mkdir(parents=True, exist_ok=True)
    write_text(
        project_dir / "module-a" / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>module-a</artifactId>
  <version>1.0.0</version>
</project>
""",
    )
    write_text(
        project_dir / "module-b" / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>module-b</artifactId>
  <version>1.0.0</version>
</project>
""",
    )
    write_text(project_dir / "s1_deps_base.txt", build_maven_tree("1.0.0"))
    write_text(project_dir / "s1_deps_current.txt", build_maven_tree("2.0.0"))
    write_text(project_dir / ".step1-fixture-ref", "base\n")
    write_text(
        project_dir / "s1_deps_base_noisy.txt",
        "[INFO] Scanning for projects...\n"
        "Downloading from central: https://repo.maven.apache.org/maven2/demo/demo.pom\n"
        "Progress (1): 1.2 kB\n"
        "Downloaded from central: https://repo.maven.apache.org/maven2/demo/demo.pom (3.1 kB at 5 kB/s)\n"
        + build_maven_tree("1.0.0"),
    )
    write_text(
        source_dir / "App.java",
        """package com.example;
import com.example.lib.LegacyApi;
public class App {
  public void run() {
    LegacyApi.oldMethod();
  }
}
""",
    )
    write_text(workspace.fake_mvn, fake_maven_script_text())
    workspace.fake_mvn.chmod(0o755)
    git = git_cmd()
    run_external_cmd(git + ["init"], project_dir)
    run_external_cmd(git + ["config", "user.name", "Trae Smoke"], project_dir)
    run_external_cmd(git + ["config", "user.email", "smoke@example.com"], project_dir)
    run_external_cmd(git + ["add", "."], project_dir)
    run_external_cmd(git + ["commit", "-m", "base"], project_dir)
    run_external_cmd(git + ["branch", "-M", "base"], project_dir)
    run_external_cmd(git + ["checkout", "-b", "current"], project_dir)
    write_text(project_dir / ".step1-fixture-ref", "current\n")
    run_external_cmd(git + ["add", ".step1-fixture-ref"], project_dir)
    run_external_cmd(git + ["commit", "-m", "current"], project_dir)
    write_text(project_dir / ".git" / "info" / "exclude", ".upgrade-report*\n")


def build_smoke_dep_env(workspace):
    dep_env = os.environ.copy()
    dep_env["HOME"] = str(workspace.fake_home)
    dep_env["PATH"] = f"{workspace.fake_bin}{os.pathsep}{dep_env.get('PATH', '')}"
    return dep_env


def seed_fake_local_m2(workspace):
    create_fake_jar(
        workspace.fake_home / ".m2" / "repository" / "com" / "example" / "demo-lib" / "2.0.0" / "demo-lib-2.0.0.jar",
        marker=b"v2",
    )
    create_fake_jar(
        workspace.fake_home / ".m2" / "repository" / "com" / "example" / "demo-lib" / "1.0.0" / "demo-lib-1.0.0.jar"
    )
    create_fake_jar(
        workspace.fake_home / ".m2" / "repository" / "com" / "example" / "deep-lib" / "2.0.0" / "deep-lib-2.0.0.jar",
        marker=b"v2",
    )
    create_fake_jar(
        workspace.fake_home / ".m2" / "repository" / "com" / "example" / "deep-lib" / "1.0.0" / "deep-lib-1.0.0.jar"
    )
    create_fake_jar(
        workspace.fake_home
        / ".m2"
        / "repository"
        / "com"
        / "github"
        / "siom79"
        / "japicmp"
        / "japicmp"
        / "0.21.2"
        / "japicmp-0.21.2-jar-with-dependencies.jar"
    )


def initialize_support_repositories(workspace):
    init_source_repo(workspace.dep_repo)
    init_multimodule_source_repo(workspace.multi_dep_repo)
    init_version_branch_repo(workspace.dep_branch_repo)

    deep_source_dir = workspace.deep_repo / "src" / "main" / "java" / "com" / "example" / "deep"
    deep_source_dir.mkdir(parents=True, exist_ok=True)
    write_text(
        deep_source_dir / "DeepApi.java",
        """package com.example.deep;
public class DeepApi {
  public static String removedCall() {
    return "deep";
  }
}
""",
    )

    adapter_source_dir = workspace.adapter_repo / "src" / "main" / "java" / "com" / "example" / "adapter"
    adapter_source_dir.mkdir(parents=True, exist_ok=True)
    write_text(
        adapter_source_dir / "AdapterFacade.java",
        """package com.example.adapter;
import com.example.deep.DeepApi;
public class AdapterFacade {
  public static String callDeep() {
    return DeepApi.removedCall();
  }
}
""",
    )
    write_text(
        adapter_source_dir / "NestedAdapter.java",
        """package com.example.adapter;
public class NestedAdapter {
  public static class Inner {
    public static String callDeep() {
      return AdapterFacade.callDeep();
    }
  }
}
""",
    )

    bridge_source_dir = workspace.bridge_repo / "src" / "main" / "java" / "com" / "example" / "bridge"
    bridge_source_dir.mkdir(parents=True, exist_ok=True)
    write_text(
        bridge_source_dir / "BridgeFacade.java",
        """package com.example.bridge;
import com.example.adapter.AdapterFacade;
public class BridgeFacade {
  public static String callAdapter() {
    return AdapterFacade.callDeep();
  }
}
""",
    )
    for repo_dir in (workspace.deep_repo, workspace.adapter_repo, workspace.bridge_repo):
        commit_source_fixture(repo_dir)


def run_core_pipeline_smoke(workspace, dep_env):
    project_dir = workspace.project_dir
    report_dir = workspace.report_dir
    source_dir = workspace.source_dir
    dep_repo = workspace.dep_repo
    multi_dep_repo = workspace.multi_dep_repo
    dep_branch_repo = workspace.dep_branch_repo
    base_tmp = workspace.base_tmp

    run_script(
        "s1_dep_diff.py",
        [
            "--base", "base",
            "--current", "current",
            "--tool", "maven",
            "--work-dir", str(project_dir),
            "--output", str(report_dir / "evidence" / "dependencies" / "dep_changes.csv"),
        ],
        cwd=project_dir,
        env=dep_env,
    )
    run_script("gate.py", ["--step", "step1_scope", "--report-dir", str(report_dir)], cwd=project_dir)

    dep_rows = read_csv(report_dir / "evidence" / "dependencies" / "dep_changes.csv")
    changed = [r for r in dep_rows if r.get("coord") == "com.example:demo-lib"]
    assert_true(changed, "Step 1 未识别 demo-lib 的版本变更")
    assert_true(changed[0].get("new_version") == "2.0.0", "Step 1 解析到的当前版本错误")

    run_script(
        "s2_context_from_deps.py",
        [
            "--dep-changes", str(report_dir / "evidence" / "dependencies" / "dep_changes.csv"),
            "--base", "HEAD",
            "--current", "HEAD",
            "--work-dir", str(project_dir),
            "--output", str(report_dir / "evidence" / "context" / "context.json"),
        ],
        cwd=project_dir,
    )
    run_script("gate.py", ["--step", "context", "--report-dir", str(report_dir)], cwd=project_dir)

    context = read_json(report_dir / "evidence" / "context" / "context.json")
    assert_true(context.get("build_tool") == "maven", "Step 2 未正确识别 Maven 项目")
    assert_true(str(context.get("jdk_current")) == "17", "Step 2 未正确读取工作区 pom.xml 的 JDK 版本")

    nested_repo = base_tmp / "nested-repo"
    nested_module = nested_repo / "module-a"
    nested_module.mkdir(parents=True, exist_ok=True)
    git = git_cmd()
    run_external_cmd(git + ["init"], nested_repo)
    run_external_cmd(git + ["config", "user.name", "Trae Smoke"], nested_repo)
    run_external_cmd(git + ["config", "user.email", "smoke@example.com"], nested_repo)
    write_text(
        nested_module / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>nested-module</artifactId>
  <version>1.0.0</version>
  <properties>
    <java.version>17</java.version>
  </properties>
</project>
""",
    )
    run_external_cmd(git + ["add", "."], nested_repo)
    run_external_cmd(git + ["commit", "-m", "base"], nested_repo)
    run_external_cmd(git + ["branch", "-M", "base"], nested_repo)
    write_text(
        nested_module / "pom.xml",
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>nested-module</artifactId>
  <version>1.0.0</version>
  <properties>
    <java.version>21</java.version>
  </properties>
</project>
""",
    )
    run_external_cmd(git + ["checkout", "-b", "current"], nested_repo)
    run_external_cmd(git + ["add", "."], nested_repo)
    run_external_cmd(git + ["commit", "-m", "jdk upgrade"], nested_repo)

    nested_report = nested_repo / ".upgrade-report"
    nested_report.mkdir(parents=True, exist_ok=True)
    run_script(
        "s2_context_from_deps.py",
        [
            "--dep-changes", str(report_dir / "evidence" / "dependencies" / "dep_changes.csv"),
            "--base", "base",
            "--current", "current",
            "--work-dir", str(nested_module),
            "--output", str(nested_report / "evidence" / "context" / "context.json"),
        ],
        cwd=nested_module,
    )
    nested_context = read_json(nested_report / "evidence" / "context" / "context.json")
    assert_true(nested_context.get("build_tool") == "maven", "Step 2 未正确识别 Git 子目录中的 Maven 模块")
    assert_true(str(nested_context.get("jdk_base")) == "17", "Step 2 未正确读取 Git 子目录基准分支的 JDK")
    assert_true(str(nested_context.get("jdk_current")) == "21", "Step 2 未正确读取 Git 子目录当前分支的 JDK")

    run_script(
        "s3_scan.py",
        [
            "--all",
            "--source-dirs", str(project_dir),
            "--output-dir", str(report_dir / "evidence" / "static_scan"),
            "--dep-changes", str(report_dir / "evidence" / "dependencies" / "dep_changes.csv"),
        ],
        cwd=project_dir,
        env=dep_env,
    )
    run_script("gate.py", ["--step", "scan", "--report-dir", str(report_dir)], cwd=project_dir)

    dep_compat_rows = read_csv(report_dir / "evidence" / "static_scan" / "s3_dependency_compat.csv")
    risk_types = {r.get("风险类型") for r in dep_compat_rows}
    assert_true("javax_reference" in risk_types, "Step 3 未扫出依赖 jar 的 javax 风险")
    assert_true("spring_factories" in risk_types, "Step 3 未扫出依赖 jar 的 spring.factories 风险")

    run_script(
        "s4_jar_compare.py",
        [
            "--dep-changes", str(report_dir / "evidence" / "dependencies" / "dep_changes.csv"),
            "--context", str(report_dir / "evidence" / "context" / "context.json"),
            "--output-dir", str(report_dir / "evidence" / "api_changes"),
            "--source-branches", "base", "current",
            "--dependency-repo-mappings", f"com.example:demo-lib={dep_repo}",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    gitdiff_rows = read_csv(report_dir / "evidence" / "api_changes" / "all_changed_apis.csv")
    behavior_rows = [
        r for r in gitdiff_rows
        if r.get("coord") == "com.example:demo-lib"
        and r.get("change_type") == "BEHAVIOR_CHANGED"
        and r.get("source") == "gitdiff"
    ]
    assert_true(behavior_rows, "Step 4 未识别源码可用依赖的方法体行为变更")
    assert_true(
        any("com.example.lib" in r.get("api_name", "") for r in behavior_rows),
        "Step 4 git diff 未为 api_name 生成完整 FQCN",
    )
    removed_rows = [
        r for r in gitdiff_rows
        if r.get("coord") == "com.example:demo-lib"
        and r.get("change_type") == "REMOVED"
    ]
    assert_true(
        not any(r.get("source") == "gitdiff" for r in removed_rows),
        "Step 4 不应仅凭源码 diff 将结构性删除作为主变更 API；删除/签名变化应以 jar/JApiCmp 为主",
    )
    auxiliary_rows = read_csv(report_dir / "evidence" / "api_changes" / "demo-lib_gitdiff_auxiliary_only.csv")
    assert_true(
        any(r.get("change_type") == "REMOVED" and "multiLine" in r.get("api_name", "") for r in auxiliary_rows),
        "Step 4 应将未经 jar 证实的源码结构性删除保留为辅助证据",
    )
    assert_true(
        not any("Helper" in r.get("api_name", "") for r in behavior_rows),
        "Step 4 不应将源码中的包可见 Helper 类当作依赖 jar 公开 API 行为变更",
    )

    branch_match_dir = report_dir / "s4_jar_compare_branch_match"
    run_script(
        "s4_jar_compare.py",
        [
            "--dep-changes", str(report_dir / "evidence" / "dependencies" / "dep_changes.csv"),
            "--context", str(report_dir / "evidence" / "context" / "context.json"),
            "--output-dir", str(branch_match_dir),
            "--source-branches", "base", "current",
            "--dependency-repo-mappings", f"com.example:demo-lib={dep_branch_repo}",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    branch_summary = (branch_match_dir / "summary.txt").read_text(encoding="utf-8")
    branch_gitdiff = (branch_match_dir / "demo-lib_gitdiff_api_changes.txt").read_text(encoding="utf-8")
    branch_ref_match_txt = (branch_match_dir / "git_ref_matches.txt").read_text(encoding="utf-8")
    branch_ref_match_json = read_json(branch_match_dir / "git_ref_matches.json")
    assert_true(
        (
            "refs=origin/release-1.0.0..origin/release-2.0.0（version）" in branch_summary
            or "refs=origin/release-1.0.0..origin/release-2.0.0(version)" in branch_summary
        ),
        "Step 4 未按依赖版本号命中 release-* 形态的源码 refs",
    )
    assert_true(
        (
            "matched_by_version(" in branch_summary
            or "matched_by_version_pair(" in branch_summary
        ) and (
            "matched_by_version(" in branch_gitdiff
            or "matched_by_version_pair(" in branch_gitdiff
        ),
        "Step 4 未输出版本匹配命中原因",
    )
    assert_true(
        (
            "当前没有待确认项；可按需抽查" in branch_ref_match_txt
            or "已自动匹配，可抽查" in branch_ref_match_txt
        )
        and (
            "ref=origin/release-1.0.0..origin/release-2.0.0" in branch_ref_match_txt
            or "selected=origin/release-1.0.0..origin/release-2.0.0" in branch_ref_match_txt
        ),
        "Step 4 未产出 release-* 版本命中的 git ref 匹配摘要",
    )
    assert_true(
        branch_ref_match_json.get("need_user_confirmation") is False
        and (branch_ref_match_json.get("matched_items") or [{}])[0].get("base_ref") == "origin/release-1.0.0",
        "Step 4 未在 git_ref_matches.json 中写入 release-* 版本命中的 ref 结果",
    )
    assert_true(
        (branch_ref_match_json.get("source_repo_mappings") or [{}])[0].get("repo_path"),
        "Step 4 未在 git_ref_matches.json 中写入源码仓库映射关系",
    )

    runtime_expand_report = project_dir / ".upgrade-report-runtime-expand"
    runtime_expand_report.mkdir(parents=True, exist_ok=True)
    copy_file(report_dir / "evidence" / "dependencies" / "dep_changes.csv", runtime_expand_report / "evidence" / "dependencies" / "dep_changes.csv")
    runtime_expand_context = dict(context)
    runtime_expand_context["changed_dependencies"] = [
        {
            "coord": "com.example:demo-lib",
            "group_id": "com.example",
            "artifact_id": "demo-lib",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "change_type": "小版本升级",
            "scope": "compile",
        }
    ]
    runtime_expand_context["changed_dependency_coords"] = ["com.example:demo-lib"]
    write_text(
        runtime_expand_report / "evidence" / "context" / "context.json",
        json.dumps(runtime_expand_context, ensure_ascii=False, indent=2) + "\n",
    )
    write_text(
        runtime_expand_report / "main_state_seed.json",
        json.dumps(
            {
                "dependency_repo_mappings": [
                    {"path": str(dep_repo)},
                    str(dep_repo),
                ]
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
    )
    runtime_expand_stdout, runtime_expand_stderr, runtime_expand_rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step4",
            "--project-dir", str(project_dir),
            "--report-dir", str(runtime_expand_report),
            "--seed-json", str(runtime_expand_report / "main_state_seed.json"),
            "--base-branch", "base",
            "--current-branch", "current",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        runtime_expand_rc == 1
        and "缺少最终制品 JAR 证据" in (runtime_expand_stdout + runtime_expand_stderr),
        "只有源码映射时，Step4 应保留辅助证据并拒绝生成正式 API 结论："
        f"rc={runtime_expand_rc}, stdout={runtime_expand_stdout[-500:]}, "
        f"stderr={runtime_expand_stderr[-500:]}",
    )
    runtime_expand_rows = read_csv(
        runtime_expand_report / "evidence" / "api_changes" /
        "demo-lib_gitdiff_auxiliary_only.csv"
    )
    runtime_expand_behavior_rows = [
        r for r in runtime_expand_rows
        if r.get("coord") == "com.example:demo-lib"
        and r.get("change_type") == "BEHAVIOR_CHANGED"
        and r.get("source") == "gitdiff"
    ]
    runtime_expand_ckpt = read_json(main_state_path(runtime_expand_report))
    expanded_internal_paths = main_state_step_input(runtime_expand_ckpt, "step4").get("dependency_repo_mappings", [])
    expected_internal_mapping = f"com.example:demo-lib={dep_repo.resolve()}"
    assert_true(
        runtime_expand_behavior_rows,
        "run_step 未将源码路径自动展开后用于 Step4 git diff 辅助证据",
    )
    assert_true(
        any("singleLine" in r.get("api_name", "") or "multiLine" in r.get("api_name", "") for r in runtime_expand_behavior_rows),
        "run_step Step4 git diff 未生成完整 FQCN api_name（当前测试fixture使用singleLine/multiLine）"
    )
    assert_true(
        expanded_internal_paths == [expected_internal_mapping],
        "run_step 未将 seed_json.dependency_repo_mappings 归一化为完整坐标映射",
    )
    direct_helper_coords = run_step_module._collect_relevant_dependency_coords(
        runtime_expand_report,
        ctx=runtime_expand_context,
    )
    assert_true(
        "com.example:demo-lib" in direct_helper_coords,
        "_collect_relevant_dependency_coords(ctx=...) 未兼容 changed_dependencies 回退",
    )

    dependency_source_report = project_dir / ".upgrade-report-dependency-source-dirs"
    dependency_source_report.mkdir(parents=True, exist_ok=True)
    copy_file(report_dir / "evidence" / "dependencies" / "dep_changes.csv", dependency_source_report / "evidence" / "dependencies" / "dep_changes.csv")
    write_text(
        dependency_source_report / "evidence" / "context" / "context.json",
        json.dumps(runtime_expand_context, ensure_ascii=False, indent=2) + "\n",
    )
    write_text(
        dependency_source_report / "main_state_seed.json",
        json.dumps({"dependency_source_dirs": [str(dep_repo)]}, ensure_ascii=False, indent=2) + "\n",
    )
    dependency_source_stdout, dependency_source_stderr, dependency_source_rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step4",
            "--project-dir", str(project_dir),
            "--report-dir", str(dependency_source_report),
            "--seed-json", str(dependency_source_report / "main_state_seed.json"),
            "--base-branch", "base",
            "--current-branch", "current",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        dependency_source_rc == 1
        and "缺少最终制品 JAR 证据" in (dependency_source_stdout + dependency_source_stderr),
        "只有 dependency_source_dirs 时，Step4 应保留辅助证据并拒绝生成正式 API 结论",
    )
    dependency_source_rows = read_csv(
        dependency_source_report / "evidence" / "api_changes" /
        "demo-lib_gitdiff_auxiliary_only.csv"
    )
    dependency_source_behavior_rows = [
        r for r in dependency_source_rows
        if r.get("coord") == "com.example:demo-lib"
        and r.get("change_type") == "BEHAVIOR_CHANGED"
        and r.get("source") == "gitdiff"
    ]
    dependency_source_ckpt = read_json(main_state_path(dependency_source_report))
    assert_true(
        main_state_step_input(dependency_source_ckpt, "step4").get("dependency_source_dirs") == [str(dep_repo.resolve())],
        "run_step 未保留用户提供的 dependency_source_dirs",
    )
    assert_true(
        main_state_step_input(dependency_source_ckpt, "step4").get("dependency_repo_mappings") == [expected_internal_mapping],
        "dependency_source_dirs 未自动推断 Step4 所需的 dependency_repo_mappings",
    )
    assert_true(
        dependency_source_behavior_rows,
        "仅提供 dependency_source_dirs 时，Step4 未生成源码 diff 辅助证据",
    )

    prefix_internal_mapping_report = project_dir / ".upgrade-report-prefix-internal-mapping"
    prefix_internal_mapping_report.mkdir(parents=True, exist_ok=True)
    copy_file(report_dir / "evidence" / "dependencies" / "dep_changes.csv", prefix_internal_mapping_report / "evidence" / "dependencies" / "dep_changes.csv")
    write_text(
        prefix_internal_mapping_report / "evidence" / "context" / "context.json",
        json.dumps(runtime_expand_context, ensure_ascii=False, indent=2) + "\n",
    )
    write_text(
        prefix_internal_mapping_report / "main_state_seed.json",
        json.dumps(
            {"dependency_repo_mappings": [{"coord": "com.example", "path": str(dep_repo)}]},
            ensure_ascii=False,
            indent=2,
        ) + "\n",
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step4",
            "--project-dir", str(project_dir),
            "--report-dir", str(prefix_internal_mapping_report),
            "--seed-json", str(prefix_internal_mapping_report / "main_state_seed.json"),
            "--base-branch", "base",
            "--current-branch", "current",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        rc == 1 and "缺少最终制品 JAR 证据" in (stdout + stderr),
        "groupId 前缀源码映射推断后仍应拒绝缺少最终制品的正式 API 结论",
    )
    prefix_internal_mapping_ckpt = read_json(main_state_path(prefix_internal_mapping_report))
    prefix_internal_paths = main_state_step_input(prefix_internal_mapping_ckpt, "step4").get("dependency_repo_mappings", [])
    assert_true(
        prefix_internal_paths == [expected_internal_mapping],
        "groupId 前缀形式的 dependency_repo_mappings 未按源码仓库真实模块展开",
    )

    runtime_full_expand_report = project_dir / ".upgrade-report-runtime-full-expand"
    runtime_full_expand_report.mkdir(parents=True, exist_ok=True)
    copy_file(report_dir / "evidence" / "dependencies" / "dep_changes.csv", runtime_full_expand_report / "evidence" / "dependencies" / "dep_changes.csv")
    copy_file(
        report_dir / "evidence" / "dependencies" / "deps_current_resolved.csv",
        runtime_full_expand_report / "evidence" / "dependencies" / "deps_current_resolved.csv",
    )
    copy_file(
        report_dir / "evidence" / "dependencies" / "build_provenance.json",
        runtime_full_expand_report / "evidence" / "dependencies" / "build_provenance.json",
    )
    write_text(
        runtime_full_expand_report / "evidence" / "context" / "context.json",
        json.dumps(runtime_expand_context, ensure_ascii=False, indent=2) + "\n",
    )
    write_text(
        runtime_full_expand_report / "main_state_seed.json",
        json.dumps(
            {"dependency_repo_mappings": [f"com.example:demo-lib={multi_dep_repo}"]},
            ensure_ascii=False,
            indent=2,
        ) + "\n",
    )
    run_script(
        "run_step.py",
        [
            "--step", "step4",
            "--project-dir", str(project_dir),
            "--report-dir", str(runtime_full_expand_report),
            "--seed-json", str(runtime_full_expand_report / "main_state_seed.json"),
            "--base-branch", "base",
            "--current-branch", "current",
        ],
        cwd=project_dir,
        env=dep_env,
        allow_awaiting=True,
    )
    runtime_full_expand_rows = read_csv(runtime_full_expand_report / "evidence" / "api_changes" / "all_changed_apis.csv")
    runtime_full_expand_behavior_rows = [
        r for r in runtime_full_expand_rows
        if r.get("coord") == "com.example:demo-lib"
        and r.get("change_type") == "BEHAVIOR_CHANGED"
        and r.get("source") == "gitdiff"
    ]
    runtime_full_expand_extra_gitdiff_rows = [
        r for r in runtime_full_expand_rows
        if r.get("coord") == "com.example:demo-lib-extra"
        and r.get("source") == "gitdiff"
    ]
    runtime_full_expand_demo_gitdiff = (
        runtime_full_expand_report / "evidence" / "api_changes" / "demo-lib_gitdiff_api_changes.txt"
    ).read_text(encoding="utf-8")
    runtime_full_expand_ref_matches = (
        runtime_full_expand_report / "evidence" / "api_changes" / "git_ref_matches.txt"
    ).read_text(encoding="utf-8")
    runtime_full_expand_ref_matches_json = read_json(
        runtime_full_expand_report / "evidence" / "api_changes" / "git_ref_matches.json"
    )
    runtime_full_expand_ckpt = read_json(main_state_path(runtime_full_expand_report))
    full_expanded_internal_paths = set(
        main_state_step_output(runtime_full_expand_ckpt, "step4").get("dependency_repo_mappings", [])
    )
    assert_true(
        full_expanded_internal_paths == {f"com.example:demo-lib={multi_dep_repo.resolve()}"},
        "run_step 在提供完整坐标时应只固化当前变更依赖的源码仓库映射",
    )
    assert_true(
        "bridgeMethod" in runtime_full_expand_demo_gitdiff,
        "run_step 在提供完整坐标时未将自动展开结果用于 Step4 git diff",
    )
    assert_true(
        not runtime_full_expand_extra_gitdiff_rows,
        "Step4 多模块 git diff 将 demo-lib 的变更错误归到了 demo-lib-extra",
    )
    assert_true(
        "demo-lib-extra/src/main/java" not in runtime_full_expand_demo_gitdiff,
        "demo-lib 的 git diff 结果不应包含其他模块目录",
    )
    source_repo_mappings = runtime_full_expand_ref_matches_json.get("source_repo_mappings") or []
    demo_lib_repo_mapping = next((item for item in source_repo_mappings if item.get("coord") == "com.example:demo-lib"), {})
    matched_items = runtime_full_expand_ref_matches_json.get("matched_items") or []
    demo_lib_match = next((item for item in matched_items if item.get("coord") == "com.example:demo-lib"), {})
    assert_true(
        (
            (
                "模块路径：" in runtime_full_expand_ref_matches
                and "模块相对路径：demo-lib" in runtime_full_expand_ref_matches
            )
            or (
                "module_path=" in runtime_full_expand_ref_matches
                and "module_rel_path=demo-lib" in runtime_full_expand_ref_matches
            )
        ),
        "git_ref_matches.txt 应展示模块路径信息，便于人工复核多模块映射",
    )
    assert_true(
        {"com.example:demo-lib", "com.example:demo-lib-extra"}.issubset(
            set(demo_lib_repo_mapping.get("repo_inferred_coords") or [])
        ),
        "git_ref_matches.json 未保留多模块源码仓库中实际源码模块的推断坐标信息",
    )
    assert_true(
        str(demo_lib_match.get("module_rel_path")) == "demo-lib",
        "git_ref_matches.json 未记录 demo-lib 的模块相对路径",
    )
    assert_true(
        not any(item.get("coord") == "com.example:demo-lib-extra" for item in matched_items),
        "未发生版本变更的 demo-lib-extra 不应生成 git ref 匹配项",
    )

    dependency_multi_report = project_dir / ".upgrade-report-dependency-source-multi"
    dependency_multi_report.mkdir(parents=True, exist_ok=True)
    copy_file(report_dir / "evidence" / "dependencies" / "dep_changes.csv", dependency_multi_report / "evidence" / "dependencies" / "dep_changes.csv")
    write_text(
        dependency_multi_report / "evidence" / "context" / "context.json",
        json.dumps(runtime_expand_context, ensure_ascii=False, indent=2) + "\n",
    )
    write_text(
        dependency_multi_report / "main_state_seed.json",
        json.dumps({"dependency_source_dirs": [str(multi_dep_repo)]}, ensure_ascii=False, indent=2) + "\n",
    )
    dependency_multi_stdout, dependency_multi_stderr, dependency_multi_rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step4",
            "--project-dir", str(project_dir),
            "--report-dir", str(dependency_multi_report),
            "--seed-json", str(dependency_multi_report / "main_state_seed.json"),
            "--base-branch", "base",
            "--current-branch", "current",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        dependency_multi_rc == 1
        and "缺少最终制品 JAR 证据" in (dependency_multi_stdout + dependency_multi_stderr),
        "多模块源码映射不得绕过最终制品门控",
    )
    dependency_multi_ckpt = read_json(main_state_path(dependency_multi_report))
    dependency_multi_internal_paths = set(
        main_state_step_input(dependency_multi_ckpt, "step4").get("dependency_repo_mappings", [])
    )
    assert_true(
        dependency_multi_internal_paths == {f"com.example:demo-lib={multi_dep_repo.resolve()}"},
        "dependency_source_dirs 未自动识别当前变更依赖的多模块源码仓库映射",
    )

    return SimpleNamespace(
        runtime_expand_context=runtime_expand_context,
        runtime_full_expand_report=runtime_full_expand_report,
        dependency_multi_report=dependency_multi_report,
        expected_internal_mapping=expected_internal_mapping,
    )


def main():
    cli_args = parse_smoke_args(sys.argv[1:])
    base_tmp = Path(tempfile.mkdtemp(prefix="java-upgrade-smoke-"))
    try:
        workspace = create_smoke_workspace(base_tmp)
        project_dir = workspace.project_dir
        report_dir = workspace.report_dir
        source_dir = workspace.source_dir

        parsed = parse_japicmp_output(
            "*! MODIFIED METHOD: com.example.lib.LegacyApi.oldMethod(java.lang.String, java.util.List<java.lang.Integer>)",
            "com.example:demo-lib",
            "1.0.0",
            "2.0.0",
        )
        assert_true(isinstance(parsed, list), "Step 4 parse_japicmp_output 必须返回列表")
        assert_true(parsed and parsed[0].get("api_name") == "com.example.lib.LegacyApi.oldMethod", "Step 4 未正确解析 JApiCmp 方法全名")
        assert_true(
            parsed[0].get("api_signature") == "(java.lang.String, java.util.List<java.lang.Integer>)",
            "Step 4 未正确保留泛型参数签名",
        )
        assert_true(parsed[0].get("symbol_kind") == "method", "普通方法变更应标记为 method")
        parsed_field = parse_japicmp_output(
            "*! REMOVED FIELD: com.example.lib.LegacyApi.legacyFlag",
            "com.example:demo-lib",
            "1.0.0",
            "2.0.0",
        )
        assert_true(parsed_field and parsed_field[0].get("symbol_kind") == "field", "字段变更应标记为 field")
        parsed_constructor = parse_japicmp_output(
            "*! REMOVED METHOD: com.example.lib.LegacyApi.LegacyApi(java.lang.String)",
            "com.example:demo-lib",
            "1.0.0",
            "2.0.0",
        )
        assert_true(parsed_constructor and parsed_constructor[0].get("symbol_kind") == "constructor", "构造器变更应标记为 constructor")
        assert_true(
            split_parameters_preserving_generics("String, List<Map<String, Integer>>, int[]") ==
            ["String", "List<Map<String, Integer>>", "int[]"],
            "Step 4 泛型参数分割退化",
        )
        assert_true(
            extract_api_signature_from_declaration(
                "public String test(@jakarta.validation.NotNull final java.lang.String value, String... args) {"
            ) == "(java.lang.String, String[])",
            "Step 4 方法声明签名提取应去掉注解/修饰符并规范化 varargs",
        )
        parsed_gitdiff_behavior = parse_gitdiff_apis(
            """diff --git a/src/main/java/com/example/lib/LegacyApi.java b/src/main/java/com/example/lib/LegacyApi.java
@@
 public class LegacyApi {
   public static String oldMethod(String value) {
-    return value.trim();
+    return value.strip();
   }
 }
""",
            "com.example:demo-lib",
            "1.0.0",
            "2.0.0",
        )
        assert_true(
            any(
                row.get("change_type") == "BEHAVIOR_CHANGED" and
                row.get("api_signature") == "(String)"
                for row in parsed_gitdiff_behavior
            ),
            "Step 4 git diff 行为变更应保留参数签名，避免重载方法丢失精度",
        )
        normalized_rows = normalize_step5_input_rows(
            [
                {
                    "coord": "com.example:demo-lib",
                    "old_version": "1.0.0",
                    "new_version": "2.0.0",
                    "change_type": "REMOVED",
                    "api_name": "com.example.lib.LegacyApi.oldMethod",
                    "api_simple": "oldMethod",
                    "symbol_kind": "method",
                    "api_signature": "(String)",
                    "confirmed": "true",
                    "severity": "P0",
                    "source": "japicmp",
                },
                {
                    "coord": "com.example:demo-lib",
                    "old_version": "1.0.0",
                    "new_version": "2.0.0",
                    "change_type": "REMOVED",
                    "api_name": "com.example.lib.LegacyApi.oldMethod",
                    "api_simple": "oldMethod",
                    "symbol_kind": "method",
                    "api_signature": "(String)",
                    "confirmed": "false",
                    "severity": "P2",
                    "source": "changelog",
                },
                {
                    "coord": "com.example:demo-lib",
                    "old_version": "1.0.0",
                    "new_version": "2.0.0",
                    "change_type": "REMOVED",
                    "api_name": "com.example.lib.LegacyApi.oldMethod",
                    "api_simple": "oldMethod",
                    "symbol_kind": "method",
                    "api_signature": "(int)",
                    "confirmed": "true",
                    "severity": "P0",
                    "source": "japicmp",
                },
            ]
        )
        assert_true(
            len(normalized_rows) == 2,
            "Step4 归一化输入应合并同一签名 API，同时保留不同重载签名",
        )
        normalized_signatures = sorted(row.get("api_signature") for row in normalized_rows)
        assert_true(
            normalized_signatures == ["(String)", "(int)"],
            "Step4 归一化输入必须按 api_signature 区分重载方法",
        )
        package_project = base_tmp / "package-based-step1"
        package_module_dir = package_project / "module-a" / "target"
        package_module_dir.mkdir(parents=True, exist_ok=True)
        create_fake_boot_jar(
            package_module_dir / "module-a-1.0.0.jar",
            [("com.example", "demo-lib", "2.0.0")],
        )

        def fake_packaged_run_cmd(cmd, cwd=None, timeout=300, input_text=None, env=None, **_kwargs):
            joined = " ".join(str(part) for part in cmd)
            if "dependency:list" in joined:
                return (
                    "[INFO] The following files have been resolved:\n"
                    "[INFO]    com.example:demo-lib:jar:2.0.0:runtime -- /tmp/demo-lib-2.0.0.jar\n",
                    "",
                    0,
                )
            if "package" in joined:
                return "package ok", "", 0
            raise AssertionError(f"未预期的命令: {joined}")

        with mock.patch.object(s1_dep_diff_module, "run_cmd", side_effect=fake_packaged_run_cmd), \
             mock.patch.object(s1_dep_diff_module, "mvn_cmd", return_value=["mvn"]):
            packaged_deps, packaged_meta = s1_dep_diff_module.collect_maven_deps_for_workspace(
                str(package_project),
                primary_module="module-a",
            )
        parsed_runtime_deps = s1_dep_diff_module.parse_maven_dependency_list(
            "[INFO] The following files have been resolved:\n"
            "[INFO]    xmlpull:xmlpull:jar:1.1.3.1:compile -- /tmp/xmlpull-1.1.3.1.jar\n"
            "[INFO]    com.example:demo-lib:jar::2.0.0:runtime -- /tmp/demo-lib-2.0.0.jar\n"
            "[INFO]    com.example:demo-lib:jar:jdk8:2.0.0:runtime -- /tmp/demo-lib-2.0.0-jdk8.jar\n"
            "[INFO]    org.slf4j:slf4j-api:1.7.36:test\n"
        )
        assert_true(
            parsed_runtime_deps.get("xmlpull:xmlpull", {}).get("version") == "1.1.3.1",
            "Step1 解析 dependency:list 时，不应把 version 错写成 scope",
        )
        assert_true(
            parsed_runtime_deps.get("xmlpull:xmlpull", {}).get("scope") == "compile",
            "Step1 解析 dependency:list 时，应正确保留 scope 字段",
        )
        assert_true(
            parsed_runtime_deps.get("com.example:demo-lib", {}).get("version") == "2.0.0",
            "Step1 解析 dependency:list 时，应兼容空 classifier 格式",
        )
        assert_true(
            parsed_runtime_deps.get("com.example:demo-lib:jdk8", {}).get("version") == "2.0.0",
            "Step1 解析 dependency:list 时，应兼容带 classifier 的格式",
        )
        assert_true(
            parsed_runtime_deps.get("org.slf4j:slf4j-api", {}).get("version") == "1.7.36",
            "Step1 解析 dependency:list 时，应兼容不带绝对路径的常见输出",
        )
        assert_true(packaged_meta.get("mode") == "final_artifact", "fat jar 场景应优先输出最终产物依赖")
        assert_true("com.example:demo-lib" in packaged_deps, "fat jar 场景未从最终产物提取到 demo-lib")
        assert_true(packaged_deps["com.example:demo-lib"].get("scope") == "packaged", "最终产物依赖 scope 应标记为 packaged")

        base_artifact = package_project / "artifacts" / "module-a-base.jar"
        current_artifact = package_project / "artifacts" / "module-a-current.jar"
        create_fake_boot_jar(base_artifact, [("com.example", "demo-lib", "1.0.0")])
        create_fake_boot_jar(current_artifact, [("com.example", "demo-lib", "2.0.0")])
        direct_packaged_deps, direct_packaged_meta = s1_dep_diff_module.collect_packaged_deps_from_artifact_path(
            str(current_artifact)
        )
        assert_true(
            direct_packaged_meta.get("artifact_input_mode") == "user_provided",
            "用户提供编译包路径时应标记为 user_provided 模式",
        )
        assert_true(
            direct_packaged_deps.get("com.example:demo-lib", {}).get("version") == "2.0.0",
            "直接产物模式未正确解析当前产物中的 demo-lib 版本",
        )
        duplicate_entry_artifact = package_project / "artifacts" / "module-a-duplicate-entries.jar"
        with zipfile.ZipFile(duplicate_entry_artifact, "w") as outer:
            outer.writestr("BOOT-INF/classes/com/example/App.class", b"app")
            outer.writestr(
                "BOOT-INF/lib/demo-lib-2.0.0.jar",
                build_embedded_maven_jar_bytes("com.example", "demo-lib", "2.0.0", marker=b"one"),
            )
            outer.writestr(
                "BOOT-INF/lib/demo-lib-shadow-2.0.0.jar",
                build_embedded_maven_jar_bytes("com.example", "demo-lib", "2.0.0", marker=b"two"),
            )
        _, duplicate_entry_meta = s1_dep_diff_module.collect_packaged_deps_from_artifact_path(
            str(duplicate_entry_artifact)
        )
        duplicate_entry_rows = duplicate_entry_meta.get("dep_entries") or duplicate_entry_meta.get("deps") or []
        assert_true(
            len(duplicate_entry_rows) == 2,
            "Step1 应保留编译包中同坐标的多个物理嵌套 jar，而不是在输出前折叠成一条",
        )
        assert_true(
            {
                row.get("lib_entry")
                for row in duplicate_entry_rows
            } == {
                "BOOT-INF/lib/demo-lib-2.0.0.jar",
                "BOOT-INF/lib/demo-lib-shadow-2.0.0.jar",
            },
            "物理条目视图应保留每个嵌套 jar 的实际 lib_entry",
        )
        duplicate_change_rows = s1_dep_diff_module._build_step1_change_rows([], duplicate_entry_rows)
        assert_true(
            len(duplicate_change_rows) == 2,
            "s1_dep_changes 的构造逻辑应按物理条目输出新增依赖，不应提前合并",
        )
        filename_only_artifact = package_project / "artifacts" / "module-a-filename-only.jar"
        filename_only_artifact.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(filename_only_artifact, "w") as outer:
            outer.writestr("BOOT-INF/classes/com/example/App.class", b"app")
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as inner:
                inner.writestr("com/example/NoPom.class", b"no-pom")
            outer.writestr("BOOT-INF/lib/demo-lib-2.0.0.jar", nested.getvalue())
        try:
            s1_dep_diff_module.collect_packaged_deps_from_artifact_path(str(filename_only_artifact))
            raise AssertionError("filename-only 嵌套 jar 在无补全信息时应报错")
        except RuntimeError as exc:
            assert_true(
                isinstance(exc, s1_dep_diff_module.ArtifactCoordinateInputRequiredError),
                "无补全信息时应抛出 ArtifactCoordinateInputRequiredError，供上层转换为 need_more_input",
            )
        enriched_packaged_deps, _ = s1_dep_diff_module.collect_packaged_deps_from_artifact_path(
            str(filename_only_artifact),
            runtime_deps={
                "com.example:demo-lib": {
                    "key": "com.example:demo-lib",
                    "group_id": "com.example",
                    "artifact_id": "demo-lib",
                    "version": "2.0.0",
                    "scope": "runtime",
                    "remark": "source:dependency:list(runtime)",
                    "classifier": "",
                    "packaged_present": "",
                    "packaged_match_source": "",
                }
            },
        )
        assert_true(
            enriched_packaged_deps.get("com.example:demo-lib", {}).get("version") == "2.0.0",
            "直接产物模式在补充 runtime 坐标后仍未正确解析 filename-only 嵌套 jar",
        )
        mismatched_runtime_packaged_deps, _ = s1_dep_diff_module.collect_packaged_deps_from_artifact_path(
            str(current_artifact),
            runtime_deps={
                "com.example:demo-lib": {
                    "key": "com.example:demo-lib",
                    "group_id": "com.example",
                    "artifact_id": "demo-lib",
                    "version": "3.0.0",
                    "scope": "runtime",
                    "remark": "source:dependency:list(runtime)",
                    "classifier": "",
                    "packaged_present": "",
                    "packaged_match_source": "",
                }
            },
        )
        assert_true(
            mismatched_runtime_packaged_deps.get("com.example:demo-lib", {}).get("version") == "2.0.0",
            "runtime 补全命中同坐标时不应改写编译产物中已解析出的版本号",
        )
        netty_runtime_dep = {
            "io.netty:netty-resolver-dns-native-macos:osx-x86_64": {
                "key": "io.netty:netty-resolver-dns-native-macos:osx-x86_64",
                "group_id": "io.netty",
                "artifact_id": "netty-resolver-dns-native-macos",
                "version": "4.1.130.Final",
                "scope": "runtime",
                "remark": "source:dependency:list(runtime)",
                "classifier": "osx-x86_64",
                "packaged_present": "",
                "packaged_match_source": "",
            }
        }
        for netty_name in (
            "netty-resolver-dns-native-macos-osx-x86_64-4.1.130.Final.jar",
            "netty-resolver-dns-native-macos-4.1.130.Final-osx-x86_64.jar",
        ):
            netty_classifier_artifact = package_project / "artifacts" / f"module-a-{netty_name}"
            with zipfile.ZipFile(netty_classifier_artifact, "w") as outer:
                outer.writestr("BOOT-INF/classes/com/example/App.class", b"app")
                nested = io.BytesIO()
                with zipfile.ZipFile(nested, "w") as inner:
                    inner.writestr("com/example/NoPom.class", b"no-pom")
                outer.writestr(f"BOOT-INF/lib/{netty_name}", nested.getvalue())
            enriched_netty_deps, _ = s1_dep_diff_module.collect_packaged_deps_from_artifact_path(
                str(netty_classifier_artifact),
                runtime_deps=netty_runtime_dep,
            )
            assert_true(
                enriched_netty_deps.get("io.netty:netty-resolver-dns-native-macos:osx-x86_64", {}).get("version") == "4.1.130.Final",
                f"直接产物模式应能补齐 filename-only classifier 依赖坐标: {netty_name}",
            )

        thin_project = base_tmp / "thin-step1"
        thin_module_dir = thin_project / "module-a" / "target"
        thin_module_dir.mkdir(parents=True, exist_ok=True)
        create_plain_jar(thin_module_dir / "module-a-1.0.0.jar")

        def fake_runtime_run_cmd(cmd, cwd=None, timeout=300, input_text=None, env=None, **_kwargs):
            joined = " ".join(str(part) for part in cmd)
            if "dependency:list" in joined:
                return (
                    "[INFO] The following files have been resolved:\n"
                    "[INFO]    com.example:demo-lib:jar:2.0.0:runtime -- /tmp/demo-lib-2.0.0.jar\n"
                    "[INFO]    org.slf4j:slf4j-api:jar:1.7.36:runtime -- /tmp/slf4j-api-1.7.36.jar\n",
                    "",
                    0,
                )
            if "package" in joined:
                return "package ok", "", 0
            raise AssertionError(f"未预期的命令: {joined}")

        with mock.patch.object(s1_dep_diff_module, "run_cmd", side_effect=fake_runtime_run_cmd), \
             mock.patch.object(s1_dep_diff_module, "mvn_cmd", return_value=["mvn"]):
            try:
                s1_dep_diff_module.collect_maven_deps_for_workspace(
                    str(thin_project),
                    primary_module="module-a",
                )
                raise AssertionError("thin jar 场景应直接报错，不应再回退到 runtime dependency:list")
            except RuntimeError as exc:
                assert_true("只比较最终打包依赖" in str(exc), "thin jar 报错信息应明确说明当前只比较最终打包依赖")
        string_row = next(row for row in normalized_rows if row.get("api_signature") == "(String)")
        assert_true(
            string_row.get("source") == "japicmp" and string_row.get("confirmed") == "true",
            "Step4 归一化输入应优先保留 confirmed=true 且更高优先级 source 的证据",
        )
        assert_true(
            build_api_identity_key(
                {
                    "coord": "com.example:demo-lib",
                    "api_name": "com.example.lib.LegacyApi.oldMethod",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                }
            )
            != build_api_identity_key(
                {
                    "coord": "com.example:demo-lib",
                    "api_name": "com.example.lib.LegacyApi.oldMethod",
                    "api_signature": "(int)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                }
            ),
            "Step5 依赖源码映射需求 key 必须区分重载方法签名",
        )
        fq_signature_keys = build_api_target_keys(
            {
                "api_name": "com.example.lib.LegacyApi.oldMethod",
                "api_simple": "oldMethod",
                "api_signature": "(java.lang.String)",
                "symbol_kind": "method",
            }
        )
        assert_true(
            fq_signature_keys == [
                "com.example.lib.LegacyApi.oldMethod(java.lang.String)",
                "com.example.lib.LegacyApi.oldMethod(String)",
                "com.example.lib.LegacyApi.oldMethod",
            ],
            "Step5 目标 key 在已知 FQCN 时应优先保留精确签名和精确名称，不应退化到 simple fallback",
        )

        write_text(
            source_dir / "AstMainlineApp.java",
            """package com.example;
import org.springframework.stereotype.Service;
import com.example.service.DemoService;

@Service
public class AstMainlineApp {
  private final DemoService demoService = new DemoService();

  public DemoService getDemoService() {
    return demoService;
  }

  public String invoke() {
    return getDemoService().run();
  }
}
""",
        )
        ast_service_dir = source_dir / "service"
        ast_service_dir.mkdir(parents=True, exist_ok=True)
        write_text(
            ast_service_dir / "DemoService.java",
            """package com.example.service;
public class DemoService {
  public String run() {
    return "ok";
  }
}
""",
        )
        analyzer_root = {
            "root": str(project_dir / "src" / "main" / "java"),
            "owner_type": "business",
            "owner_coord": "BUSINESS",
            "module": "project",
        }
        analyzed_methods, parser_info = analyze_file(
            str(source_dir / "AstMainlineApp.java"),
            analyzer_root,
            prefer_tree_sitter=True,
            return_diagnostics=True,
        )
        invoke_method = next((m for m in analyzed_methods if m.method_name == "invoke"), None)
        assert_true(invoke_method is not None, "源码分析器未识别 invoke 方法")
        assert_true("DemoService" in invoke_method.field_types.get("demoService", ""), "AST 主链路未保留字段类型信息")
        assert_true(
            "Service" in invoke_method.class_annotations or "Service" in invoke_method.annotations,
            "AST 主链路未保留类/方法注解上下文",
        )
        invoke_edges = extract_call_edges_enhanced(invoke_method, include_low_confidence=False)
        assert_true(any("run" in edge.callee_key for edge in invoke_edges), "AST 主链路未能为方法体提取调用边")
        assert_true(
            any(edge.callee_key.endswith(".run()") for edge in invoke_edges),
            "零参数方法调用边应统一带上 ()，否则严格签名模式无法命中",
        )
        method_stub = SimpleNamespace(
            param_types={"paramClazz": "java.lang.Class"},
            field_types={},
            local_var_types={},
            class_fqcn="com.example.AstMainlineApp",
            local_method_return_types={},
            known_method_return_types={},
        )
        assert_true(
            infer_param_type_from_expression("paramClazz.getCanonicalName()", method_stub) == "String",
            "方法调用参数表达式应能识别稳定 JDK 返回类型，否则严格签名模式会丢失调用边签名",
        )
        assert_true(
            infer_param_type_from_expression("TxnServiceAttribute.class", method_stub) == "Class",
            ".class 字面量应归一化为 Class，否则调用点签名会与方法声明签名失配",
        )
        overload_stub = SimpleNamespace(
            class_fqcn="com.example.ClientFactory",
            local_method_return_types={},
            known_method_return_types={},
            known_method_return_types_by_signature={
                "com.example.ClientFactory": {
                    "getClient": {
                        "()": "com.example.LegacyClient",
                        "(String)": "com.example.NamedClient",
                    }
                }
            },
        )
        assert_true(
            infer_invocation_return_type(
                "com.example.ClientFactory",
                "getClient",
                overload_stub,
                invocation_signature="()",
            ) == "com.example.LegacyClient",
            "返回值推断应优先按零参数签名命中对应重载",
        )
        assert_true(
            infer_invocation_return_type(
                "com.example.ClientFactory",
                "getClient",
                overload_stub,
                invocation_signature="(String)",
            ) == "com.example.NamedClient",
            "返回值推断应优先按参数签名区分同名重载",
        )
        parsed_interface_meta = _parse_javap_signature_block(
            """Compiled from "DemoService.java"
public interface com.example.service.DemoService extends java.lang.Object {
  public abstract java.lang.String doWork();
    descriptor: ()Ljava/lang/String;
}
""",
            "com.example.service.DemoService",
        )
        assert_true(
            parsed_interface_meta.get("kind") == "interface",
            "javap 元数据解析应保留 interface/class kind，否则 jar 补强会把接口当成普通类",
        )
        assert_true(
            parsed_interface_meta.get("methods", {}).get("doWork", {}).get("()") == "java.lang.String",
            "javap 元数据解析应保留接口方法的返回值签名",
        )
        if source_analyzer_module.TREE_SITTER_AVAILABLE:
            assert_true(parser_info.get("actual_parser") == "tree_sitter", "tree-sitter 可用时 Java 文件应优先走 AST 主链路")
        else:
            assert_true(parser_info.get("actual_parser") == "skipped", "tree-sitter 不可用时不得用正则生成 Java 分析结论")
            assert_true(parser_info.get("fallback_reason") == "tree_sitter_unavailable", "tree-sitter 缺失时应记录明确未分析原因")

        with mock.patch.object(source_analyzer_module, "TREE_SITTER_AVAILABLE", False), mock.patch.object(
            source_analyzer_module,
            "_tree_sitter_auto_install_enabled",
            return_value=False,
        ):
            _, forced_regex_info = analyze_file(
                str(source_dir / "AstMainlineApp.java"),
                analyzer_root,
                prefer_tree_sitter=True,
                return_diagnostics=True,
            )
        assert_true(forced_regex_info.get("actual_parser") == "skipped", "强制关闭 tree-sitter 后不得用正则生成 Java 分析结论")
        assert_true(forced_regex_info.get("fallback_reason") == "tree_sitter_unavailable", "强制关闭 tree-sitter 时应记录 unavailable")
        if source_analyzer_module.TREE_SITTER_AVAILABLE:
            with mock.patch.object(source_analyzer_module.TreeSitterAnalyzer, "analyze", side_effect=RuntimeError("boom")):
                _, forced_fallback_info = analyze_file(
                    str(source_dir / "AstMainlineApp.java"),
                    analyzer_root,
                    prefer_tree_sitter=True,
                    return_diagnostics=True,
                )
            assert_true(forced_fallback_info.get("actual_parser") == "skipped", "tree-sitter 运行异常时不得用正则生成 Java 分析结论")
            assert_true(
                forced_fallback_info.get("fallback_reason", "").startswith("tree_sitter_runtime_error"),
                "tree-sitter 运行异常时应记录 runtime_error 原因",
            )

        ast_helper_dir = source_dir / "helper"
        ast_client_dir = source_dir / "client"
        ast_helper_dir.mkdir(parents=True, exist_ok=True)
        ast_client_dir.mkdir(parents=True, exist_ok=True)
        write_text(
            ast_client_dir / "Client.java",
            """package com.example.client;
public class Client {
  public String call(String input) {
    return input.trim();
  }
}
""",
        )
        write_text(
            ast_helper_dir / "Helper.java",
            """package com.example.helper;
import com.example.client.Client;
public class Helper {
  public Client makeClient() {
    return new Client();
  }
}
""",
        )
        write_text(
            source_dir / "JavaAstChainApp.java",
            """package com.example;
import com.example.helper.Helper;
public class JavaAstChainApp {
  private final Helper helper = new Helper();

  public String runChain(String input) {
    var client = helper.makeClient();
    return client.call(input);
  }

  public void runRef() {
    Runnable task = this::consume;
  }

  private void consume() {
  }
}
""",
        )
        write_text(
            source_dir / "CtorService.java",
            """package com.example;
public class CtorService {
  public CtorService() {
    init();
  }

  private void init() {
  }
}
""",
        )
        write_text(
            source_dir / "ConstructorAstApp.java",
            """package com.example;
public class ConstructorAstApp {
  public void runCtor() {
    new CtorService();
  }
}
""",
        )
        write_text(
            source_dir / "User.java",
            """package com.example;
public class User {
  public String name() {
    return "ok";
  }
}
""",
        )
        write_text(
            source_dir / "LambdaAstApp.java",
            """package com.example;
import java.util.List;
public class LambdaAstApp {
  public void runLambda(List<User> users) {
    users.stream().map(u -> u.name());
  }
}
""",
        )
        write_text(
            source_dir / "FieldLambdaAstApp.java",
            """package com.example;
import java.util.List;
public class FieldLambdaAstApp {
  private final List<User> users;

  public FieldLambdaAstApp(List<User> users) {
    this.users = users;
  }

  public void runFieldLambda() {
    this.users.stream().map(u -> u.name());
  }
}
""",
        )
        write_text(
            source_dir / "EntityOnly.java",
            """package com.example;
public class EntityOnly {
}
""",
        )
        write_text(
            source_dir / "ClassLiteralCaller.java",
            """package com.example;
public class ClassLiteralCaller {
  private final UnifiedParameterFacility unifiedParameterFacility = new UnifiedParameterFacility();

  public void run(String key) {
    unifiedParameterFacility.loadParameterNoThrows(key, TxnServiceAttribute.class);
  }
}
""",
        )
        write_text(
            source_dir / "UnifiedParameterFacility.java",
            """package com.example;
public class UnifiedParameterFacility {
  public Object loadParameterNoThrows(String key, Class clazz) {
    return null;
  }
}
""",
        )
        write_text(
            source_dir / "TxnServiceAttribute.java",
            """package com.example;
public class TxnServiceAttribute {
}
""",
        )
        write_text(
            source_dir / "LegacyClient.java",
            """package com.example;
public class LegacyClient {
  public String call() {
    return "legacy";
  }
}
""",
        )
        write_text(
            source_dir / "NamedClient.java",
            """package com.example;
public class NamedClient {
  public String call() {
    return "named";
  }
}
""",
        )
        write_text(
            source_dir / "OverloadFactoryAstApp.java",
            """package com.example;
public class OverloadFactoryAstApp {
  LegacyClient getClient() {
    return new LegacyClient();
  }

  NamedClient getClient(String tag) {
    return new NamedClient();
  }

  String runDefault() {
    var client = getClient();
    return client.call();
  }

  String runNamed() {
    var client = getClient("vip");
    return client.call();
  }
}
""",
        )
        if source_analyzer_module.TREE_SITTER_AVAILABLE:
            ast_graph_result = build_enhanced_source_graph([analyzer_root])
            ast_reverse_edges = ast_graph_result["graph"].reverse_edges
            assert_true(
                any(edge.caller_qualified_key.endswith("JavaAstChainApp.runChain") for edge in ast_reverse_edges.get("com.example.helper.Helper.makeClient()", [])),
                "Java AST 主链路未识别字段调用 helper.makeClient()",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("JavaAstChainApp.runChain") for edge in ast_reverse_edges.get("com.example.client.Client.call(String)", [])),
                "Java AST 主链路未识别跨文件 var 链式调用 client.call(String)",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("JavaAstChainApp.runRef") for edge in ast_reverse_edges.get("com.example.JavaAstChainApp.consume()", [])),
                "Java AST 主链路未识别 this::consume 方法引用",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("ConstructorAstApp.runCtor") for edge in ast_reverse_edges.get("com.example.CtorService.CtorService()", [])),
                "Java AST 主链路未识别 new CtorService() 构造器调用",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("com.example.CtorService.CtorService") for edge in ast_reverse_edges.get("com.example.CtorService.init()", [])),
                "Java AST 主链路未将构造器内部调用纳入反向图",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("LambdaAstApp.runLambda") for edge in ast_reverse_edges.get("com.example.User.name()", [])),
                "Java AST 主链路未识别 lambda 参数类型传播后的 u.name()",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("FieldLambdaAstApp.runFieldLambda") for edge in ast_reverse_edges.get("com.example.User.name()", [])),
                "Java AST 主链路未识别字段泛型上下文里的 lambda 参数类型传播",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("ClassLiteralCaller.run") for edge in ast_reverse_edges.get("com.example.UnifiedParameterFacility.loadParameterNoThrows(String, Class)", [])),
                ".class 字面量调用应生成与方法声明兼容的 Class 签名边",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("ClassLiteralCaller.run") for edge in ast_reverse_edges.get("method:loadParameterNoThrows", [])),
                "带签名调用边入图时应补无签名 reverse_edges key，避免继续回溯时 key miss",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("OverloadFactoryAstApp.runDefault") for edge in ast_reverse_edges.get("com.example.LegacyClient.call()", [])),
                "AST 主链路应按零参数重载返回值推断 var client 的真实类型",
            )
            assert_true(
                any(edge.caller_qualified_key.endswith("OverloadFactoryAstApp.runNamed") for edge in ast_reverse_edges.get("com.example.NamedClient.call()", [])),
                "AST 主链路应按带参重载返回值推断 var client 的真实类型",
            )
            entity_methods, entity_parser_info = analyze_file(
                str(source_dir / "EntityOnly.java"),
                analyzer_root,
                prefer_tree_sitter=True,
                return_diagnostics=True,
            )
            assert_true(not entity_methods, "无方法 Java 文件不应生成伪方法")
            assert_true(
                entity_parser_info.get("actual_parser") == "tree_sitter",
                "无方法 Java 文件不应被误判为 tree-sitter 运行时失败",
            )

        initialize_smoke_project(workspace)
        dep_env = build_smoke_dep_env(workspace)
        seed_fake_local_m2(workspace)
        initialize_support_repositories(workspace)
        core_runtime = run_core_pipeline_smoke(workspace, dep_env)

        if cli_args.group == "core":
            print("SMOKE PASS [core]")
            print(f"workspace={project_dir}")
            print(f"report={report_dir}")
            return 0

        if cli_args.group != "step5":
            run_step5_smoke_cases(workspace, dep_env, core_runtime)

        if cli_args.group == "step5":
            print("SMOKE PASS [step5]")
            print(f"workspace={project_dir}")
            print(f"report={report_dir}")
            return 0


        run_orchestrator_smoke_cases(workspace, dep_env)

        if cli_args.group == "orchestrator":
            print("SMOKE PASS [orchestrator]")
        else:
            print("SMOKE PASS [all]")
        print(f"workspace={project_dir}")
        print(f"report={report_dir}")
        return 0
    finally:
        if not cli_args.keep_tmp:
            shutil.rmtree(base_tmp, ignore_errors=True)


def run_step5_smoke_cases(workspace, dep_env, core_runtime):
    project_dir = workspace.project_dir
    report_dir = workspace.report_dir
    source_dir = workspace.source_dir
    dep_repo = workspace.dep_repo
    deep_repo = workspace.deep_repo
    adapter_repo = workspace.adapter_repo
    bridge_repo = workspace.bridge_repo
    adapter_source_dir = adapter_repo / "src" / "main" / "java" / "com" / "example" / "adapter"
    runtime_expand_context = core_runtime.runtime_expand_context
    runtime_full_expand_report = core_runtime.runtime_full_expand_report
    dependency_multi_report = core_runtime.dependency_multi_report
    expected_internal_mapping = core_runtime.expected_internal_mapping

    write_text(
        source_dir / "BridgeApp.java",
        """package com.example;
        import com.example.extra.ExtraApi;
        public class BridgeApp {
          public String runBridge() {
return ExtraApi.callLegacy();
          }
        }
        """,
    )
    _multi_bridge_stdout, multi_bridge_stderr, multi_bridge_rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(runtime_full_expand_report),
            "--response-json",
            json.dumps(
                {
                    "action": "continue",
                    "notes": "Step4 结果已复核，继续验证多模块依赖源码映射自动发现",
                },
                ensure_ascii=False,
            ),
        ],
        cwd=project_dir,
    )
    assert_true(
        multi_bridge_rc == EXIT_AWAITING_USER,
        f"多模块依赖源码映射自动发现后，Step5 应在确认点进入 awaiting_user_input: {multi_bridge_stderr}",
    )
    multi_bridge_interaction = read_json(interaction_path(runtime_full_expand_report))
    assert_true(
        multi_bridge_interaction.get("step_id") == "step5",
        "多模块依赖源码映射自动发现后，Step5 未进入正确的交互确认点",
    )
    multi_bridge_summary = read_json(runtime_full_expand_report / "evidence" / "call_chain" / "summary.json")
    multi_bridge_per_dependency = read_json(
        runtime_full_expand_report / "evidence" / "api_changes" / run_step_module.PER_DEPENDENCY_DIRNAME / "com.example_demo-lib" / "summary.json"
    )
    multi_bridge_api = (multi_bridge_summary.get("not_found_apis") or [{}])[0]
    assert_true(
        multi_bridge_summary.get("not_found_in_static_analysis") == 1,
        "repo 根目录自动展开后，未打包模块不得形成行为变更调用链",
    )
    assert_true(
        multi_bridge_api.get("reason_code") == "NO_STATIC_PATH",
        "排除未打包模块后，Step5 应基于完整 current 制品给出静态未找到路径",
    )
    assert_true(
        multi_bridge_api.get("business_reach_depth") == 0,
        "未打包的 demo-lib-extra 源码不得把变更 API 错误回溯到业务代码",
    )
    assert_true(
        multi_bridge_api.get("dependency_chain_coords") == [],
        "未打包的 demo-lib-extra 不得出现在依赖调用链中",
    )
    assert_true(
        multi_bridge_per_dependency.get("step5", {}).get("final_status") == "not_found_in_static_analysis",
        "repo 根目录自动展开后，per_dependency summary 未写入 final_status",
    )
    assert_true(
        multi_bridge_per_dependency.get("step5", {}).get("selected_api") == multi_bridge_api.get("api"),
        "repo 根目录自动展开后，per_dependency summary 未写入代表 API",
    )
    assert_true(
        "自动发现依赖源码映射" in multi_bridge_stderr,
        "run_step Step5 未输出自动发现依赖源码映射日志",
    )

    _dependency_multi_bridge_stdout, dependency_multi_bridge_stderr, dependency_multi_bridge_rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(dependency_multi_report),
        ],
        cwd=project_dir,
    )
    assert_true(
        dependency_multi_bridge_rc == 1
        and "缺少最终制品 JAR 证据" in dependency_multi_bridge_stderr,
        "多模块源码映射不得绕过 Step4 最终制品门控进入 Step5",
    )
    dependency_multi_auxiliary = read_csv(
        dependency_multi_report / "evidence" / "api_changes" /
        "demo-lib_gitdiff_auxiliary_only.csv"
    )
    assert_true(
        not (dependency_multi_report / "evidence" / "call_chain" / "summary.json").exists(),
        "缺少最终制品时不得生成 Step5 正式分析结果",
    )
    assert_true(
        any(
            row.get("coord") == "com.example:demo-lib"
            and row.get("source") == "gitdiff"
            for row in dependency_multi_auxiliary
        ),
        "缺少最终制品时，Step4 应保留源码 diff 辅助证据供补齐制品后复核",
    )
    dependency_multi_main_state = read_json(main_state_path(dependency_multi_report))
    dependency_multi_step4_mappings = (
        ((dependency_multi_main_state.get("step4") or {}).get("input") or {}).get("dependency_repo_mappings") or []
    )
    assert_true(
        (dependency_multi_main_state.get("state") or {}).get("current_step") == "step4"
        and (dependency_multi_main_state.get("state") or {}).get("status") == "blocked_by_system"
        and any(str(item).startswith("com.example:demo-lib=") for item in dependency_multi_step4_mappings),
        "系统阻塞时应停留在 Step4 并保留自动派生的多模块源码映射",
    )

    interactive_step4_report = project_dir / ".upgrade-report-step4-interactive"
    interactive_step4_report.mkdir(parents=True, exist_ok=True)
    copy_file(
        report_dir / "evidence" / "dependencies" / "dep_changes.csv",
        interactive_step4_report / "evidence" / "dependencies" / "dep_changes.csv",
    )
    copy_file(
        report_dir / "evidence" / "dependencies" / "deps_current_resolved.csv",
        interactive_step4_report / "evidence" / "dependencies" / "deps_current_resolved.csv",
    )
    copy_file(
        report_dir / "evidence" / "dependencies" / "build_provenance.json",
        interactive_step4_report / "evidence" / "dependencies" / "build_provenance.json",
    )
    write_text(
        interactive_step4_report / "evidence" / "context" / "context.json",
        json.dumps(runtime_expand_context, ensure_ascii=False, indent=2) + "\n",
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step4",
            "--project-dir", str(project_dir),
            "--report-dir", str(interactive_step4_report),
            "--base-branch", "base",
            "--current-branch", "current",
            "--dependency-repo-mappings", f"com.example:demo-lib={dep_repo}",
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(rc == EXIT_AWAITING_USER, "Step4 待交互应返回 awaiting user 退出码")
    interactive_step4_ckpt = read_json(main_state_path(interactive_step4_report))
    interactive_step4_json = read_json(interaction_path(interactive_step4_report))
    assert_true(
        main_state_meta(interactive_step4_ckpt).get("status") == "awaiting_user_input",
        "Step4 无自动确认时应进入 awaiting_user_input",
    )
    assert_true(interactive_step4_json.get("step_id") == "step4", "Step4 interaction.json 未写入正确 step_id")
    assert_true(interactive_step4_json.get("files_to_review"), "Step4 待交互未提供 files_to_review")
    assert_true(
        any(str(item).endswith("evidence/api_changes/changed_dependencies.md") for item in interactive_step4_json.get("files_to_review", [])),
        "依赖 API 变化确认未提供依赖包维度的人读选择页",
    )
    assert_true(
        any(str(item).endswith("evidence/api_changes/all_changed_apis.csv") for item in interactive_step4_json.get("files_to_review", [])),
        "依赖 API 变化确认未提供完整 API 事实文件",
    )
    assert_true(
        ((interactive_step4_json.get("response_schema") or {}).get("properties") or {}).get("action"),
        "Step4 待交互未提供 response_schema.action",
    )
    assert_true(
        ((interactive_step4_json.get("response_schema") or {}).get("properties") or {}).get("dependency_source_dirs"),
        "Step4 待交互未提供 dependency_source_dirs 修改入口",
    )
    assert_true(
        (interactive_step4_json.get("input_normalization") or {}).get("enabled") is True,
        "Step4 待交互未提供 input_normalization.enabled",
    )
    assert_true(
        "rerun_current_step" in ((interactive_step4_json.get("input_normalization") or {}).get("allowed_actions") or []),
        "Step4 input_normalization 未暴露 rerun_current_step 动作",
    )
    assert_true(interactive_step4_json.get("runtime_rules"), "Step4 待交互未提供 runtime_rules")
    assert_true(interactive_step4_json.get("rules_file"), "Step4 待交互未提供 rules_file")
    assert_true(
        interactive_step4_json.get("must_wait_for_user_reply") is True,
        "Step4 待交互未标记 must_wait_for_user_reply",
    )
    assert_true(interactive_step4_json.get("resume_command_examples"), "Step4 待交互未提供恢复命令模板")
    step4_actions = {item.get("action") for item in interactive_step4_json.get("resume_command_examples", []) if isinstance(item, dict)}
    assert_true("continue" in step4_actions, "Step4 恢复模板未包含 continue")
    assert_true("rerun_current_step" in step4_actions, "Step4 恢复模板未包含 rerun_current_step")
    assert_true("restart_from_step" in step4_actions, "Step4 恢复模板未包含 restart_from_step")
    assert_true("cancel" in step4_actions, "Step4 恢复模板未包含 cancel")
    assert_true(
        "rerun_current_step" in {item.get("id") for item in interactive_step4_json.get("options", [])},
        "Step4 待交互未提供修正映射后重跑动作",
    )
    assert_true(
        "restart_from_step" in {item.get("id") for item in interactive_step4_json.get("options", [])},
        "Step4 待交互未提供从指定步骤重跑动作",
    )
    assert_true('"files_to_review"' in stdout, "stdout 未输出 files_to_review")
    assert_true('"runtime_rules"' in stdout, "stdout 未输出 runtime_rules")
    assert_true("【分析已暂停，等待你的确认】" in stderr, "依赖 API 变化确认未输出用户任务卡")
    assert_true("为什么暂停" in stderr, "依赖 API 变化确认未解释暂停原因")
    assert_true("AWAITING USER INPUT" not in stderr, "用户任务卡仍暴露英文状态机提示")
    assert_true("awaiting_*" not in stderr, "用户任务卡仍暴露内部运行规则")
    step4_event_line = next(line for line in stdout.splitlines() if line.startswith("JUA_CONFIRMATION_JSON:"))
    step4_stdout_event = json.loads(step4_event_line.split(":", 1)[1])
    assert_true(step4_stdout_event.get("schema") == "java-upgrade-analyzer.confirmation.v1", "机器输出不是单个 confirmation JSON")
    assert_true(step4_stdout_event.get("must_wait_for_user_reply") is True, "机器 confirmation JSON 未暴露 must_wait_for_user_reply")
    assert_true('"input_normalization"' in stdout, "Step4 stdout 未输出 input_normalization")
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(interactive_step4_report),
            "--response-json",
            json.dumps(
                {
                    "action": "rerun_current_step",
                    "dependency_source_dirs": [str(dep_repo)],
                    "notes": "通过对话修正依赖源码目录后重跑 Step4",
                },
                ensure_ascii=False,
            ),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(rc == EXIT_AWAITING_USER, "Step4 通过对话修正 dependency_source_dirs 后应重跑并进入待交互退出码")
    interactive_step4_ckpt = read_json(main_state_path(interactive_step4_report))
    interactive_step4_json = read_json(interaction_path(interactive_step4_report))
    assert_true(main_state_meta(interactive_step4_ckpt).get("completed_step") == "step4", "Step4 修正映射后应重跑并停回 step4 确认点")
    assert_true(main_state_meta(interactive_step4_ckpt).get("status") == "awaiting_user_input", "Step4 修正映射后应重新进入 awaiting_user_input")
    assert_true(
        main_state_step_output(interactive_step4_ckpt, "step4").get("dependency_repo_mappings") == [expected_internal_mapping],
        "Step4 通过对话修正 dependency_source_dirs 后，派生的 dependency_repo_mappings 未写回 step4.output",
    )
    assert_true(interactive_step4_json.get("step_id") == "step4", "Step4 重跑后 interaction 应仍指向 step4")

    interactive_step4_restart_report = project_dir / ".upgrade-report-step4-restart"
    interactive_step4_restart_report.mkdir(parents=True, exist_ok=True)
    copy_file(
        report_dir / "evidence" / "dependencies" / "dep_changes.csv",
        interactive_step4_restart_report / "evidence" / "dependencies" / "dep_changes.csv",
    )
    copy_file(
        report_dir / "evidence" / "dependencies" / "deps_current_resolved.csv",
        interactive_step4_restart_report / "evidence" / "dependencies" / "deps_current_resolved.csv",
    )
    copy_file(
        report_dir / "evidence" / "dependencies" / "build_provenance.json",
        interactive_step4_restart_report / "evidence" / "dependencies" / "build_provenance.json",
    )
    write_text(
        interactive_step4_restart_report / "evidence" / "context" / "context.json",
        json.dumps(runtime_expand_context, ensure_ascii=False, indent=2) + "\n",
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step4",
            "--project-dir", str(project_dir),
            "--report-dir", str(interactive_step4_restart_report),
            "--base-branch", "base",
            "--current-branch", "current",
            "--dependency-repo-mappings", f"com.example:demo-lib={dep_repo}",
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(rc == EXIT_AWAITING_USER, "Step4 restart 场景首次待交互应返回 awaiting user 退出码")
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(interactive_step4_restart_report),
            "--response-json",
            json.dumps(
                {
                    "action": "restart_from_step",
                    "restart_step_id": "step2",
                    "notes": "从 step2 重新开始",
                },
                ensure_ascii=False,
            ),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(rc == EXIT_AWAITING_USER, "Step4 应支持通过对话指定 restart_from_step 并进入待交互退出码")
    interactive_step4_restart_ckpt = read_json(main_state_path(interactive_step4_restart_report))
    interactive_step4_restart_json = read_json(interaction_path(interactive_step4_restart_report))
    assert_true(main_state_meta(interactive_step4_restart_ckpt).get("completed_step") == "step2", "restart_from_step=step2 后应重新执行 step2")
    assert_true(main_state_meta(interactive_step4_restart_ckpt).get("status") == "awaiting_user_input", "restart_from_step=step2 后应停在 step2 确认点")
    assert_true(interactive_step4_restart_json.get("step_id") == "step2", "restart_from_step=step2 后 interaction 应指向 step2")

    s4_dir = report_dir / "evidence" / "api_changes"
    s4_dir.mkdir(parents=True, exist_ok=True)
    with open(s4_dir / "all_changed_apis.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:demo-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.lib.LegacyApi.oldMethod",
                "api_simple": "oldMethod",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P0",
                "source": "japicmp",
            }
        )

    # Phase 7.5 removed: run_step.py now directly passes all_changed_apis.csv to step5
    # Step 5 processes all entries without filtering
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(s4_dir / "all_changed_apis.csv"),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(report_dir / "evidence" / "call_chain"),
            "--max-depth", "3",
        ],
        cwd=project_dir,
    )
    run_script("gate.py", ["--step", "call_chain", "--report-dir", str(report_dir)], cwd=project_dir)
    strict_gate_report = project_dir / ".upgrade-report-strict-gate"
    write_text(
        strict_gate_report / "evidence" / "call_chain" / "summary.json",
        json.dumps(
            {
                "reachable": 1,
                "uncertain": 1,
                "not_analyzed": 0,
                "not_found_in_static_analysis": 0,
                "uncertain_apis": [{"api": "com.example.Demo.test", "reason": "需要人工确认"}],
                "not_analyzed_apis": [],
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
    )
    _stdout, strict_gate_stderr, strict_gate_rc = run_script_with_rc(
        "gate.py",
        ["--step", "call_chain", "--report-dir", str(strict_gate_report), "--strict-risk-gate"],
        cwd=project_dir,
    )
    assert_true(strict_gate_rc == 1, "严格模式下，存在 uncertain 的调用链结果应阻断")
    assert_true("严格模式下调用链仍存在未完成项" in strict_gate_stderr, "严格模式门控失败原因不明确")

    summary = read_json(report_dir / "evidence" / "call_chain" / "summary.json")
    # 该 fixture 在 Step1 最终制品生成后才追加 App.java，因此源码与已留存制品并不对齐。
    # 不得用后来出现的源码把不存在于制品中的调用判为 reachable，应显式暴露冲突。
    assert_true(
        summary.get("uncertain") == 1,
        "源码晚于最终制品时，Step5 应暴露源码/字节码冲突，而不是伪造 reachable",
    )
    conflict_api = (summary.get("uncertain_apis") or [{}])[0]
    assert_true(
        conflict_api.get("reason_code") == "SOURCE_BYTECODE_EDGE_CONFLICT",
        "源码/最终制品不一致时缺少 SOURCE_BYTECODE_EDGE_CONFLICT",
    )
    parser_usage = summary.get("meta", {}).get("graph_stats", {}).get("parser_usage", {})
    assert_true(isinstance(parser_usage, dict), "Step 5 summary 未暴露 parser_usage 统计")
    assert_true(
        parser_usage.get("tree_sitter", 0) + parser_usage.get("regex", 0) >= 1,
        "Step 5 parser_usage 统计为空，无法观测主链路/降级路径",
    )
    business_bytecode = summary.get("meta", {}).get("graph_stats", {}).get("business_bytecode", {})
    assert_true(
        not any("Bad magic number" in str(item) for item in (business_bytecode.get("failures") or [])),
        "Step 5 smoke 的业务字节码补边不应再因 fake class 触发 Bad magic number",
    )

    # 后续用例专门验证源码图解析，不再复用上面故意制造为过期的制品契约。
    # 缺少制品时，正向源码证据仍可成立，但负向结论必须保持覆盖不足。
    for stale_contract in (
        report_dir / "build_provenance.json",
        report_dir / "s1_deps_current_resolved.csv",
        report_dir / "evidence" / "dependencies" / "build_provenance.json",
        report_dir / "evidence" / "dependencies" / "deps_current_resolved.csv",
    ):
        if stale_contract.exists():
            stale_contract.unlink()

    instance_changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_instance_apis.csv"
    with open(instance_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:demo-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.lib.InstanceApi.doWork",
                "api_simple": "doWork",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P0",
                "source": "japicmp",
            }
        )
    write_text(
        source_dir / "InstanceApp.java",
        """package com.example;
    import com.example.lib.InstanceApi;
    public class InstanceApp {
      public void runInstance() {
InstanceApi api = new InstanceApi();
api.doWork();
      }
    }
    """,
    )
    instance_chain_dir = report_dir / "s5_call_chain_instance"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(instance_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(instance_chain_dir),
            "--max-depth", "3",
        ],
        cwd=project_dir,
    )
    instance_summary = read_json(instance_chain_dir / "summary.json")
    assert_true(instance_summary.get("reachable") == 1, "Step 5 未将实例方法调用识别为可达")
    instance_api = instance_summary.get("reachable_apis", [])[0]
    assert_true(instance_api.get("reason_code") == "SYSTEM_CODE_REACHED", "实例方法调用不应退化为 uncertain")

    write_text(
        source_dir / "DirectService.java",
        """package com.example;
    import com.thirdparty.api.DirectApi;
    public class DirectService {
      public void callThirdParty() {
DirectApi.doWork();
      }
    }
    """,
    )
    direct_thirdparty_apis = report_dir / "evidence" / "api_changes" / "all_changed_direct_thirdparty_apis.csv"
    with open(direct_thirdparty_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.thirdparty:direct-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.thirdparty.api.DirectApi.doWork",
                "api_simple": "doWork",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P1",
                "source": "japicmp",
            }
        )
    direct_thirdparty_dir = report_dir / "s5_call_chain_direct_thirdparty"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(direct_thirdparty_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(direct_thirdparty_dir),
            "--max-depth", "3",
        ],
        cwd=project_dir,
    )
    direct_thirdparty_summary = read_json(direct_thirdparty_dir / "summary.json")
    assert_true(
        direct_thirdparty_summary.get("reachable") == 1,
        "业务代码直接调用第三方 API 时，Step5 不应因缺少 bridge source 而阻塞或降级"
    )
    assert_true(
        direct_thirdparty_summary.get("not_analyzed", 0) == 0,
        "直接第三方调用命中后不应退化为 DEPENDENCY_SOURCE_MAPPING_MISSING"
    )
    api_bridge_requirements = check_apis_that_need_bridge(
        [
            {
                "coord": "com.example:demo-lib",
                "api_name": "com.example.lib.LegacyApi.oldMethod",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
        ],
        str(project_dir / ".upgrade-report"),
        [str(project_dir / "src" / "main" / "java")],
        business_graph=None,
        dependency_source_mappings=[f"com.example:demo-lib={dep_repo / 'src' / 'main' / 'java'}"],
    )
    bridge_info = api_bridge_requirements[
        build_api_identity_key(
            {
                "coord": "com.example:demo-lib",
                "api_name": "com.example.lib.LegacyApi.oldMethod",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
        )
    ]
    assert_true(
        bridge_info.get("needs_bridge") is True and bridge_info.get("has_dependency_source_mapping") is True,
        "Step5 需要区分“需要跨依赖分析”和“当前依赖已有源码映射”",
    )
    invalid_mapping_requirements = check_apis_that_need_bridge(
        [
            {
                "coord": "com.example:demo-lib",
                "api_name": "com.example.lib.LegacyApi.oldMethod",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
        ],
        str(project_dir / ".upgrade-report"),
        [str(project_dir / "src" / "main" / "java")],
        business_graph=None,
        dependency_source_mappings=["com.example:demo-lib=/tmp/not-exists-java-upgrade-analyzer"],
    )
    invalid_mapping_info = invalid_mapping_requirements[
        build_api_identity_key(
            {
                "coord": "com.example:demo-lib",
                "api_name": "com.example.lib.LegacyApi.oldMethod",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
        )
    ]
    assert_true(
        invalid_mapping_info.get("has_dependency_source_mapping") is False,
        "Step5 不应把不存在目录的 dependency_source_mappings 误判为有效映射",
    )
    missing_mapping_result = trace_api_with_confidence_weighting(
        {
            "coord": "com.example:demo-lib",
            "api_name": "com.example.lib.LegacyApi.oldMethod",
            "api_simple": "oldMethod",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
        },
        SimpleNamespace(reverse_edges={}, methods_by_id={}),
        {},
        max_total_cost=3,
        needs_bridge=True,
        has_dependency_source_mapping=False,
        allow_degraded=True,
    )
    mapped_but_unresolved_result = trace_api_with_confidence_weighting(
        {
            "coord": "com.example:demo-lib",
            "api_name": "com.example.lib.LegacyApi.oldMethod",
            "api_simple": "oldMethod",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
        },
        SimpleNamespace(reverse_edges={}, methods_by_id={}),
        {},
        max_total_cost=3,
        needs_bridge=True,
        has_dependency_source_mapping=True,
        allow_degraded=True,
    )
    assert_true(
        missing_mapping_result.reason_code == "DEPENDENCY_SOURCE_MAPPING_MISSING",
        "缺失映射时 tracer 应退化为 DEPENDENCY_SOURCE_MAPPING_MISSING",
    )
    assert_true(
        mapped_but_unresolved_result.reason_code == "NO_STATIC_PATH",
        "已有依赖源码映射但静态图未命中时，不应误报 DEPENDENCY_SOURCE_MAPPING_MISSING",
    )

    impl_method = SimpleNamespace(
        owner_type="business",
        class_name="DemoServiceImpl",
        modifiers=["public"],
        annotations=[],
        class_annotations=[],
        is_static=False,
        is_interface=False,
        class_fqcn="com.example.service.DemoServiceImpl",
    )
    assert_true(
        is_system_code_touched(impl_method, {}) is True,
        "当前语义下，非测试业务实现类应被视为系统触达"
    )
    demo_application_method = SimpleNamespace(
        owner_type="business",
        class_name="DemoApplication",
        modifiers=["public", "static"],
        annotations=[],
        class_annotations=[],
        is_static=True,
        is_interface=False,
        class_fqcn="com.example.DemoApplication",
    )
    assert_true(
        is_system_code_touched(demo_application_method, {}) is True,
        "DemoApplication 这类真实入口类应被识别为系统触达"
    )
    order_main_method = SimpleNamespace(
        owner_type="business",
        class_name="OrderMain",
        modifiers=["public", "static"],
        annotations=[],
        class_annotations=[],
        is_static=True,
        is_interface=False,
        class_fqcn="com.example.OrderMain",
    )
    assert_true(
        is_system_code_touched(order_main_method, {}) is True,
        "OrderMain 这类真实入口类应被识别为系统触达"
    )
    app_config_method = SimpleNamespace(
        owner_type="business",
        class_name="AppConfig",
        modifiers=["public", "static"],
        annotations=[],
        class_annotations=[],
        is_static=True,
        is_interface=False,
        class_fqcn="com.example.AppConfig",
    )
    assert_true(
        is_system_code_touched(app_config_method, {}) is True,
        "当前语义下，业务配置类方法也应被视为系统触达"
    )
    helper_static_method = SimpleNamespace(
        owner_type="business",
        class_name="DateHelper",
        modifiers=["public", "static"],
        annotations=[],
        class_annotations=[],
        is_static=True,
        is_interface=False,
        class_fqcn="com.example.DateHelper",
    )
    assert_true(
        is_system_code_touched(helper_static_method, {}) is True,
        "当前语义下，业务工具类静态方法也应被视为系统触达"
    )
    formatter_missing_bridge = explain_reason_code(
        "DEPENDENCY_SOURCE_MAPPING_MISSING",
        SimpleNamespace(dependency_chain_coords=["com.example:demo-lib"], reason_code="DEPENDENCY_SOURCE_MAPPING_MISSING"),
    )
    assert_true(
        "dependency_source_dirs" in (formatter_missing_bridge.get("action") or ""),
        "DEPENDENCY_SOURCE_MAPPING_MISSING 的动作建议应明确指向 dependency_source_dirs"
    )
    formatter_no_static = explain_reason_code(
        "NO_STATIC_PATH",
        SimpleNamespace(dependency_chain_coords=[], reason_code="NO_STATIC_PATH"),
    )
    assert_true(
        "源码图" in (formatter_no_static.get("reason") or ""),
        "NO_STATIC_PATH 应被 formatter 识别并输出可读解释"
    )
    mapper_method = SimpleNamespace(
        owner_type="dependency",
        class_name="OrderMapper",
        modifiers=["public"],
        annotations=[],
        class_annotations=["Mapper"],
        is_static=False,
        is_interface=True,
        class_fqcn="com.example.mapper.OrderMapper",
    )
    assert_true(
        is_framework_boundary(
            mapper_method,
            {
                "com.example.mapper.OrderMapper": {
                    "kind": "interface",
                    "implementations": [],
                    "annotations": ["Mapper"],
                }
            },
        ) is True,
        "类级 @Mapper 注解的接口应被识别为框架边界"
    )

    service_dir = source_dir / "service"
    service_dir.mkdir(parents=True, exist_ok=True)
    write_text(
        service_dir / "DemoService.java",
        """package com.example.service;
    public interface DemoService {
      String doWork();
    }
    """,
    )
    write_text(
        service_dir / "DemoServiceImpl.java",
        """package com.example.service;
    public class DemoServiceImpl implements DemoService {
      @Override
      public String doWork() {
return "ok";
      }
    }
    """,
    )
    write_text(
        source_dir / "InterfaceApp.java",
        """package com.example;
    import com.example.service.DemoService;
    import com.example.service.DemoServiceImpl;
    public class InterfaceApp {
      public String runInterface() {
DemoService service = new DemoServiceImpl();
return service.doWork();
      }
    }
    """,
    )
    write_text(
        source_dir / "AutowiredApp.java",
        """package com.example;
    import com.example.service.DemoService;
    import org.springframework.beans.factory.annotation.Autowired;
    public class AutowiredApp {
      @Autowired
      private DemoService injectedService;

      private DemoService pickService() {
return this.injectedService;
      }

      public String runAutowired() {
var service = pickService();
return service.doWork();
      }
    }
    """,
    )
    interface_changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_interface_apis.csv"
    with open(interface_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:service-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.service.DemoService.doWork",
                "api_simple": "doWork",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P1",
                "source": "japicmp",
            }
        )
    interface_chain_dir = report_dir / "s5_call_chain_interface"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(interface_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(interface_chain_dir),
            "--max-depth", "3",
        ],
        cwd=project_dir,
    )
    interface_summary = read_json(interface_chain_dir / "summary.json")
    assert_true(interface_summary.get("reachable") == 1, "接口 API 应能映射到实现类调用并识别为可达")
    interface_api = interface_summary.get("reachable_apis", [])[0]
    assert_true(interface_api.get("api") == "com.example.service.DemoService.doWork", "接口 API 名在 Step5 汇总中应保持不变")

    autowired_chain_dir = report_dir / "s5_call_chain_autowired"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(interface_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(autowired_chain_dir),
            "--max-depth", "4",
        ],
        cwd=project_dir,
    )
    autowired_summary = read_json(autowired_chain_dir / "summary.json")
    assert_true(autowired_summary.get("reachable") >= 1, "Autowired/var/工厂返回链路应能被 Step5 识别")
    autowired_payload = [
        item for item in autowired_summary.get("reachable_apis", [])
        if item.get("api") == "com.example.service.DemoService.doWork"
    ]
    assert_true(autowired_payload, "Autowired 场景未命中接口 API")

    write_text(
        source_dir / "SearchRepository.java",
        """package com.example;
    public interface SearchRepository {
      String search(int page, String keyword);
    }
    """,
    )
    write_text(
        source_dir / "SearchController.java",
        """package com.example;
    public class SearchController {
      private SearchRepository repository;

      public String runSearch(String keyword) {
return searchPage(1, keyword);
      }

      private String searchPage(int page, String keyword) {
return repository.search(page, keyword);
      }
    }
    """,
    )
    helper_chain_changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_helper_chain_apis.csv"
    with open(helper_chain_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:search-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.SearchRepository.search",
                "api_simple": "search",
                "symbol_kind": "method",
                "api_signature": "(int, String)",
                "confirmed": "true",
                "severity": "P1",
                "source": "japicmp",
            }
        )
    helper_chain_dir = report_dir / "s5_call_chain_helper_chain"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(helper_chain_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(helper_chain_dir),
            "--max-depth", "4",
        ],
        cwd=project_dir,
    )
    helper_chain_summary = read_json(helper_chain_dir / "summary.json")
    assert_true(
        helper_chain_summary.get("reachable") == 1,
        "带参数的内部 helper 方法调用链未继续向上回溯到系统入口",
    )

    write_text(
        service_dir / "OverloadService.java",
        """package com.example.service;
    public class OverloadService {
      public String target(String value) {
return value;
      }
      public Integer target(Integer value) {
return value;
      }
    }
    """,
    )
    write_text(
        service_dir / "ConstructedService.java",
        """package com.example.service;
    public class ConstructedService {
      public ConstructedService() {}
    }
    """,
    )
    write_text(
        source_dir / "OverloadApp.java",
        """package com.example;
    import com.example.service.OverloadService;
    public class OverloadApp {
      private final OverloadService overloadService = new OverloadService();
      public String runOverload() {
return overloadService.target("demo");
      }
    }
    """,
    )
    write_text(
        source_dir / "OverloadFallbackApp.java",
        """package com.example;
    import com.example.service.OverloadService;
    public class OverloadFallbackApp {
      private final OverloadService overloadService = new OverloadService();
      private UnknownRequest request;
      public String runFallback() {
return overloadService.target(request.getParam());
      }
    }
    """,
    )
    write_text(
        source_dir / "ConstructorApp.java",
        """package com.example;
    import com.example.service.ConstructedService;
    public class ConstructorApp {
      public void build() {
new ConstructedService();
      }
    }
    """,
    )
    overload_changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_overload_apis.csv"
    with open(overload_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:service-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.service.OverloadService.target",
                "api_simple": "target",
                "symbol_kind": "method",
                "api_signature": "(String)",
                "confirmed": "true",
                "severity": "P1",
                "source": "japicmp",
            }
        )
    overload_chain_dir = report_dir / "s5_call_chain_overload"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(overload_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(overload_chain_dir),
            "--max-depth", "4",
        ],
        cwd=project_dir,
    )
    overload_summary = read_json(overload_chain_dir / "summary.json")
    assert_true(overload_summary.get("reachable") == 1, "重载方法在提供 api_signature 时应命中正确调用链")
    overload_api = overload_summary.get("reachable_apis", [])[0]
    assert_true(overload_api.get("api") == "com.example.service.OverloadService.target", "重载场景下 API 名应保持稳定")

    write_text(
        source_dir / "OverloadApp.java",
        """package com.example;
    public class OverloadApp {
      public String runOverload() {
return "noop";
      }
    }
    """,
    )
    overload_fallback_chain_dir = report_dir / "s5_call_chain_overload_fallback"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(overload_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(overload_fallback_chain_dir),
            "--max-depth", "4",
        ],
        cwd=project_dir,
    )
    overload_fallback_summary = read_json(overload_fallback_chain_dir / "summary.json")
    assert_true(
        overload_fallback_summary.get("reachable") == 1,
        "调用点参数类型推断不完整时，仍应能通过 FQCN 无签名键命中调用链",
    )

    overload_missing_signature_apis = report_dir / "evidence" / "api_changes" / "all_changed_overload_missing_signature.csv"
    with open(overload_missing_signature_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[field for field in ALL_CHANGED_APIS_FIELDS if field != "api_signature"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:service-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.service.OverloadService.target",
                "api_simple": "target",
                "symbol_kind": "method",
                "confirmed": "true",
                "severity": "P1",
                "source": "japicmp",
            }
        )
    overload_missing_signature_dir = report_dir / "s5_call_chain_overload_missing_signature"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(overload_missing_signature_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(overload_missing_signature_dir),
            "--max-depth", "4",
            "--allow-degraded",
        ],
        cwd=project_dir,
    )
    overload_missing_signature_summary = read_json(overload_missing_signature_dir / "summary.json")
    assert_true(
        overload_missing_signature_summary.get("not_analyzed") == 1,
        "重载方法缺少 api_signature 时应停止精确追踪并标记为 not_analyzed",
    )
    overload_missing_signature_api = overload_missing_signature_summary.get("not_analyzed_apis", [])[0]
    assert_true(
        overload_missing_signature_api.get("reason_code") == "MISSING_API_SIGNATURE",
        "严格签名模式下缺少 api_signature 应输出 MISSING_API_SIGNATURE",
    )

    constructor_changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_constructor_apis.csv"
    with open(constructor_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:service-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.service.ConstructedService.ConstructedService",
                "api_simple": "ConstructedService",
                "symbol_kind": "constructor",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P1",
                "source": "japicmp",
            }
        )
    constructor_chain_dir = report_dir / "s5_call_chain_constructor"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(constructor_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(constructor_chain_dir),
            "--max-depth", "4",
        ],
        cwd=project_dir,
    )
    constructor_summary = read_json(constructor_chain_dir / "summary.json")
    assert_true(constructor_summary.get("reachable") == 1, "零参数构造器变更应能命中 new 调用链")

    field_changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_field_apis.csv"
    with open(field_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:service-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.service.ConstructedService.legacyFlag",
                "api_simple": "legacyFlag",
                "symbol_kind": "field",
                "api_signature": "",
                "confirmed": "true",
                "severity": "P1",
                "source": "japicmp",
            }
        )
    field_chain_dir = report_dir / "s5_call_chain_field"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(field_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(field_chain_dir),
            "--max-depth", "3",
            "--allow-degraded",
        ],
        cwd=project_dir,
    )
    field_summary = read_json(field_chain_dir / "summary.json")
    field_reason_candidates = [
        item.get("reason_code")
        for item in field_summary.get("not_analyzed_apis", [])
    ]
    assert_true(
        "MISSING_API_SIGNATURE" not in field_reason_candidates,
        "字段变更不应再被误判为缺少方法签名",
    )

    missing_symbol_kind_apis = report_dir / "evidence" / "api_changes" / "all_changed_missing_symbol_kind.csv"
    with open(missing_symbol_kind_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[field for field in ALL_CHANGED_APIS_FIELDS if field != "symbol_kind"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:service-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.service.OverloadService.target",
                "api_simple": "target",
                "api_signature": "(String)",
                "confirmed": "true",
                "severity": "P1",
                "source": "japicmp",
            }
        )
    missing_symbol_kind_dir = report_dir / "s5_call_chain_missing_symbol_kind"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(missing_symbol_kind_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(missing_symbol_kind_dir),
            "--max-depth", "4",
            "--allow-degraded",
        ],
        cwd=project_dir,
    )
    missing_symbol_kind_summary = read_json(missing_symbol_kind_dir / "summary.json")
    assert_true(
        missing_symbol_kind_summary.get("reachable") == 1,
        "缺少 symbol_kind 但提供了方法签名时，Step5 应自动推断为 method 并继续分析",
    )
    missing_symbol_kind_api = missing_symbol_kind_summary.get("reachable_apis", [])[0]
    assert_true(
        missing_symbol_kind_api.get("symbol_kind") == "method",
        "缺少 symbol_kind 但提供了方法签名时，Step5 未回填自动推断的 method 类型",
    )

    not_found_changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_not_found_apis.csv"
    with open(not_found_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:service-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.service.UnusedService.noPath",
                "api_simple": "noPath",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P2",
                "source": "japicmp",
            }
        )
    not_found_chain_dir = report_dir / "s5_call_chain_not_found"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(not_found_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(not_found_chain_dir),
            "--max-depth", "3",
            "--allow-degraded",
        ],
        cwd=project_dir,
    )
    not_found_summary = read_json(not_found_chain_dir / "summary.json")
    not_found_api = not_found_summary.get("not_analyzed_apis", [])[0]
    assert_true(
        not_found_summary.get("not_analyzed", 0) >= 1,
        "缺少依赖映射且允许降级时，未找到路径场景应进入 not_analyzed",
    )
    assert_true(
        not_found_api.get("reason_code") in {
            "DEPENDENCY_SOURCE_MAPPING_MISSING",
            "RUNTIME_DEPENDENCY_JARS_UNAVAILABLE",
            "ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE",
            "CURRENT_FINAL_ARTIFACT_REQUIRED",
        },
        "缺少依赖映射或最终制品字节码时应输出明确的覆盖不足原因",
    )
    assert_true(
        "deprecated_aliases" in not_found_summary,
        "summary.json 应显式声明 deprecated_aliases，帮助旧消费方迁移",
    )
    assert_true(
        "not_reachable" not in not_found_summary,
        "summary.json 不应继续把 not_reachable 作为正式顶层字段输出",
    )
    assert_true(
        not_found_summary.get("deprecated_aliases", {}).get("not_reachable", {}).get("replacement") == "not_found_in_static_analysis",
        "deprecated_aliases 未正确声明 not_reachable 的替代字段",
    )

    write_text(
        source_dir / "BridgeApp.java",
        """package com.example;
    import com.example.adapter.AdapterFacade;
    public class BridgeApp {
      public void runBridge() {
AdapterFacade.callDeep();
      }
    }
    """,
    )

    bridge_runtime_report = project_dir / ".upgrade-report-bridge-runtime"
    create_scoped_runtime_evidence(
        bridge_runtime_report,
        [
            ("com.example:deep-lib", "2.0.0", ["com.example.deep.DeepApi"]),
            (
                "com.example:adapter-lib",
                "2.0.0",
                ["com.example.adapter.AdapterFacade", "com.example.adapter.NestedAdapter$Inner"],
            ),
            ("com.example:bridge-lib", "2.0.0", ["com.example.bridge.BridgeFacade"]),
        ],
    )
    write_scoped_ref_evidence(
        bridge_runtime_report,
        [
            ("com.example:deep-lib", deep_repo),
            ("com.example:adapter-lib", adapter_repo),
            ("com.example:bridge-lib", bridge_repo),
        ],
    )
    commit_business_fixture_and_update_provenance(
        project_dir,
        bridge_runtime_report,
        "bridge runtime business entry",
    )
    refresh_fixture_business_bytecode(
        bridge_runtime_report,
        [
            source_dir / "BridgeApp.java",
            adapter_source_dir / "AdapterFacade.java",
            deep_repo / "src" / "main" / "java" / "com" / "example" / "deep" / "DeepApi.java",
        ],
    )
    bridge_changed_apis = bridge_runtime_report / "evidence" / "api_changes" / "all_changed_apis_bridge.csv"
    with open(bridge_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:deep-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.deep.DeepApi.removedCall",
                "api_simple": "removedCall",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P0",
                "source": "japicmp",
            }
        )

    # Phase 7.5 removed: step5 reads bridge_changed_apis.csv directly
    bridge_call_chain_dir = report_dir / "s5_call_chain_bridge"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(bridge_changed_apis),
            "--report-dir", str(bridge_runtime_report),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--dependency-source-mappings", f"com.example:deep-lib={deep_repo / 'src' / 'main' / 'java'}",
            "--dependency-source-mappings", f"com.example:adapter-lib={adapter_repo / 'src' / 'main' / 'java'}",
            "--output-dir", str(bridge_call_chain_dir),
            "--max-depth", "3",
        ],
        cwd=project_dir,
    )
    bridge_summary = read_json(bridge_call_chain_dir / "summary.json")
    assert_true(bridge_summary.get("reachable") == 1, "跨依赖 Step 5 未把业务 -> A -> B 识别为可达")
    bridge_api = bridge_summary.get("reachable_apis", [])[0]
    assert_true(bridge_api.get("business_reach_depth") == 2, "跨依赖 Step 5 未在第2跳回溯到业务源码")
    assert_true(bridge_api.get("direct_callers") == 0, "跨依赖 Step 5 不应把跨依赖命中当成业务直接调用")
    assert_true(
        bridge_api.get("dependency_chain_coords") == ["com.example:adapter-lib"],
        "跨依赖 Step 5 未正确记录单级依赖链路"
    )

    write_text(
        adapter_source_dir / "NestedAdapter.java",
        """package com.example.adapter;
    public class NestedAdapter {
      public static class Inner {
public static String callDeep() {
  return AdapterFacade.callDeep();
}
      }
    }
    """,
    )
    write_text(
        source_dir / "NestedBridgeApp.java",
        """package com.example;
    import com.example.adapter.NestedAdapter;
    public class NestedBridgeApp {
      public void runNestedBridge() {
NestedAdapter.Inner.callDeep();
      }
    }
""",
    )
    commit_business_fixture_and_update_provenance(
        project_dir,
        bridge_runtime_report,
        "nested bridge business entry",
    )
    refresh_fixture_business_bytecode(
        bridge_runtime_report,
        [
            source_dir / "BridgeApp.java",
            source_dir / "NestedBridgeApp.java",
            adapter_source_dir / "AdapterFacade.java",
            adapter_source_dir / "NestedAdapter.java",
            deep_repo / "src" / "main" / "java" / "com" / "example" / "deep" / "DeepApi.java",
        ],
    )
    nested_bridge_changed_apis = bridge_runtime_report / "evidence" / "api_changes" / "all_changed_apis_nested_bridge.csv"
    with open(nested_bridge_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:adapter-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.adapter.NestedAdapter.Inner.callDeep",
                "api_simple": "callDeep",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P1",
                "source": "bridge-forward",
            }
        )
    nested_bridge_dir = report_dir / "s5_call_chain_nested_bridge"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(nested_bridge_changed_apis),
            "--report-dir", str(bridge_runtime_report),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--dependency-source-mappings", f"com.example:deep-lib={deep_repo / 'src' / 'main' / 'java'}",
            "--dependency-source-mappings", f"com.example:adapter-lib={adapter_repo / 'src' / 'main' / 'java'}",
            "--output-dir", str(nested_bridge_dir),
            "--max-depth", "3",
        ],
        cwd=project_dir,
    )
    nested_bridge_summary = read_json(nested_bridge_dir / "summary.json")
    assert_true(nested_bridge_summary.get("reachable") == 1, "嵌套类跨依赖调用未被识别为可达")
    nested_bridge_api = nested_bridge_summary.get("reachable_apis", [])[0]
    assert_true(
        nested_bridge_api.get("api") == "com.example.adapter.NestedAdapter.Inner.callDeep",
        "嵌套类 API 名未保留完整类层级"
    )

    guarded_chain_dir = report_dir / "s5_call_chain_guarded"
    # Phase 7.5 removed: use all_changed_apis_bridge.csv (main bridge test input)
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(bridge_changed_apis),
            "--report-dir", str(bridge_runtime_report),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(guarded_chain_dir),
            "--max-depth", "3",
            "--max-methods", "1",
            "--allow-degraded",
        ],
        cwd=project_dir,
    )
    guarded_summary = read_json(guarded_chain_dir / "summary.json")
    assert_true(
        ((guarded_summary.get("meta") or {}).get("graph_stats") or {}).get("truncated") is True,
        "Step 5 在超小索引阈值下未暴露 graph truncation"
    )
    assert_true(
        "max_methods" in (((guarded_summary.get("meta") or {}).get("graph_stats") or {}).get("truncation_reasons") or []),
        "Step 5 graph_stats 未记录 max_methods 截断原因"
    )

    (source_dir / "NestedBridgeApp.java").unlink()
    (source_dir / "BridgeApp.java").unlink()

    write_text(
        source_dir / "BridgeChainApp.java",
        """package com.example;
    import com.example.bridge.BridgeFacade;
    public class BridgeChainApp {
      public void runBridgeChain() {
BridgeFacade.callAdapter();
      }
    }
""",
    )
    commit_business_fixture_and_update_provenance(
        project_dir,
        bridge_runtime_report,
        "multi-hop bridge business entry",
    )
    refresh_fixture_business_bytecode(
        bridge_runtime_report,
        [
            source_dir / "BridgeChainApp.java",
            bridge_repo / "src" / "main" / "java" / "com" / "example" / "bridge" / "BridgeFacade.java",
            adapter_source_dir / "AdapterFacade.java",
            deep_repo / "src" / "main" / "java" / "com" / "example" / "deep" / "DeepApi.java",
        ],
    )

    # Phase 7.5 removed: step5 reads bridge_changed_apis.csv directly with both bridge dirs
    bridge_chain_dir = report_dir / "s5_call_chain_bridge_chain"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(bridge_changed_apis),
            "--report-dir", str(bridge_runtime_report),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--dependency-source-mappings",
            f"com.example:deep-lib={deep_repo / 'src' / 'main' / 'java'}",
            "--dependency-source-mappings",
            f"com.example:bridge-lib={bridge_repo / 'src' / 'main' / 'java'}",
            "--dependency-source-mappings",
            f"com.example:adapter-lib={adapter_repo / 'src' / 'main' / 'java'}",
            "--output-dir", str(bridge_chain_dir),
            "--max-depth", "4",
        ],
        cwd=project_dir,
    )
    bridge_chain_summary = read_json(bridge_chain_dir / "summary.json")
    assert_true(bridge_chain_summary.get("reachable") == 1, "多级跨依赖 Step 5 未把业务 -> A -> B -> C 识别为可达")
    bridge_chain_api = bridge_chain_summary.get("reachable_apis", [])[0]
    assert_true(bridge_chain_api.get("business_reach_depth") == 3, "多级跨依赖 Step 5 未在第3跳回溯到业务源码")
    assert_true(
        bridge_chain_api.get("dependency_chain_coords") == ["com.example:adapter-lib", "com.example:bridge-lib"],
        "多级跨依赖 Step 5 未正确记录依赖链"
    )

    # Step6 的这组断言专门验证 reachable 证据透传。沿用冲突用例中已经生成的
    # 源码路径证据，但显式构造 reachable 分类，避免把两个独立测试目标混在一起。
    step6_reachable_entry = dict(conflict_api)
    step6_reachable_entry.update({
        "analysis_status": "reachable",
        "reason_code": "SYSTEM_CODE_REACHED",
        "reason": "已回溯到系统代码",
        "reachable_note": "已回溯到系统代码",
    })
    step6_summary = dict(summary)
    step6_summary.update({
        "reachable": 1,
        "uncertain": 0,
        "not_analyzed": 0,
        "not_found_in_static_analysis": 0,
        "reachable_apis": [step6_reachable_entry],
        "uncertain_apis": [],
        "not_analyzed_apis": [],
        "not_found_apis": [],
    })
    write_text(
        report_dir / "evidence" / "call_chain" / "summary.json",
        json.dumps(step6_summary, ensure_ascii=False, indent=2) + "\n",
    )

    run_script(
        "s6_report.py",
        [
            "--report-dir", str(report_dir),
            "--output-findings", str(report_dir / "s6_findings.json"),
            "--output-report", str(report_dir / "s6_report.md"),
        ],
        cwd=project_dir,
    )
    findings = read_json(report_dir / "s6_findings.json")
    report_text = (report_dir / "s6_report.md").read_text(encoding="utf-8")
    assert_true(findings.get("scan_stats", {}).get("dep_compat", 0) > 0, "Step 6 未汇总依赖 jar 扫描结果")
    assert_true("分析结果总表" in report_text, "Step 6 报告未展示新主表")
    assert_true(findings.get("p0", [])[0].get("reason_code") == "SYSTEM_CODE_REACHED", "Step 6 未透传 reachable 风险的 reason_code")
    assert_true(findings.get("p0", [])[0].get("evidence_paths"), "Step 6 未透传 reachable 风险的 evidence_paths")
    assert_true(
        findings.get("scan_stats", {}).get("call_chain_not_analyzed") == 0,
        "Step 6 findings 未保留 not_analyzed 统计字段",
    )
    assert_true(
        "call_chain_not_found_in_static_analysis" in findings.get("scan_stats", {}),
        "Step 6 findings 未暴露新的 not_found_in_static_analysis 统计字段",
    )
    user_conclusion_report = report_dir / "s6_report_user_conclusions.md"
    user_conclusion_findings = report_dir / "s6_findings_user_conclusions.json"
    synthetic_s5_dir = report_dir / "evidence" / "call_chain"
    synthetic_summary = {
        "status": "done",
        "reachable": 0,
        "uncertain": 0,
        "not_analyzed": 3,
        "not_found_in_static_analysis": 0,
        "user_conclusion_summary": {
            "可能影响": 1,
            "需要补充输入": 1,
            "当前无法确认": 1,
        },
        "quality_gate": {
            "confirmed_impact": 0,
            "probable_impact": 1,
            "inconclusive": 1,
            "needs_input": 1,
        },
        "not_analyzed_apis": [
            {
                "coord": "com.example:demo-lib",
                "api": "com.example.lib.LegacyApi.behaviorChanged",
                "api_name": "com.example.lib.LegacyApi.behaviorChanged",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "BEHAVIOR_CHANGED",
                "severity": "P2",
                "reason_code": "BEHAVIOR_CHANGED_RUNTIME_VERIFICATION",
                "reason": "behavior changed",
                "user_conclusion": "可能影响",
                "recommended_action": "运行相关业务测试",
            },
            {
                "coord": "com.example:demo-lib",
                "api": "com.example.lib.LegacyApi.bridgeMissing",
                "api_name": "com.example.lib.LegacyApi.bridgeMissing",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P1",
                "reason_code": "DEPENDENCY_SOURCE_MAPPING_MISSING",
                "reason": "缺失依赖源码映射",
                "user_conclusion": "需要补充输入",
                "recommended_action": "补 dependency_source_dirs",
            },
            {
                "coord": "com.example:demo-lib",
                "api": "com.example.lib.LegacyApi.reflective",
                "api_name": "com.example.lib.LegacyApi.reflective",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P1",
                "reason_code": "RESOURCE_OR_REFLECTION",
                "reason": "资源或反射调用",
                "user_conclusion": "当前无法确认",
            },
        ],
    }
    write_text(synthetic_s5_dir / "summary.json", json.dumps(synthetic_summary, ensure_ascii=False, indent=2))
    run_script(
        "s6_report.py",
        [
            "--report-dir", str(report_dir),
            "--output-findings", str(user_conclusion_findings),
            "--output-report", str(user_conclusion_report),
        ],
        cwd=project_dir,
    )
    synthetic_findings = read_json(user_conclusion_findings)
    synthetic_report_text = user_conclusion_report.read_text(encoding="utf-8")
    assert_true(
        "分析结果总表" in synthetic_report_text,
        "Step 6 报告未呈现分析结果总表",
    )
    assert_true(
        "com.example.lib.LegacyApi.behaviorChanged" in synthetic_report_text,
        "Step 6 报告未在主表中呈现可能影响 API",
    )
    assert_true(
        "com.example.lib.LegacyApi.bridgeMissing" in synthetic_report_text,
        "Step 6 报告未在主表中呈现需要补充输入 API",
    )
    assert_true(
        "com.example.lib.LegacyApi.reflective" in synthetic_report_text,
        "Step 6 报告未在主表中呈现当前无法确认 API",
    )
    impacted_dep = (synthetic_findings.get("impacted_dependencies") or [{}])[0]
    assert_true(
        impacted_dep.get("probable_impact") == 1 and impacted_dep.get("needs_input") == 1 and impacted_dep.get("not_analyzed") == 1,
        "Step 6 依赖聚合表未同步拆分 probable_impact / needs_input / not_analyzed",
    )

    empty_changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_apis_empty.csv"
    with open(empty_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()

    # Phase 7.5 removed: fallback/FQCN tests no longer applicable

    empty_chain_dir = report_dir / "s5_call_chain_empty"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(empty_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(empty_chain_dir),
            "--max-depth", "3",
        ],
        cwd=project_dir,
    )
    empty_summary = read_json(empty_chain_dir / "summary.json")
    assert_true(empty_summary.get("status") == "skipped", "空变更集时 Step 5 应标记为 skipped")
    assert_true(empty_summary.get("skip_reason") == "no_changed_apis", "空变更集时 Step 5 skip_reason 应为 no_changed_apis")

    behavior_changed_apis = report_dir / "evidence" / "api_changes" / "all_changed_behavior_candidates.csv"
    with open(behavior_changed_apis, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ALL_CHANGED_APIS_FIELDS,
        )
        writer.writeheader()
        writer.writerow(
            {
                "coord": "com.example:demo-lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "BEHAVIOR_CHANGED",
                "api_name": "com.example.lib.LegacyApi.oldMethod",
                "api_simple": "oldMethod",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "false",
                "severity": "P2",
                "source": "gitdiff",
            }
        )
    behavior_chain_dir = report_dir / "s5_call_chain_behavior"
    run_script(
        "s5_call_chain.py",
        [
            "--all-changed-apis", str(behavior_changed_apis),
            "--source-dirs", str(project_dir / "src" / "main" / "java"),
            "--output-dir", str(behavior_chain_dir),
            "--max-depth", "3",
        ],
        cwd=project_dir,
    )
    behavior_summary = read_json(behavior_chain_dir / "summary.json")
    assert_true(behavior_summary.get("not_analyzed") >= 1, "行为变更命中业务路径时应进入 not_analyzed，而非 reachable/uncertain")
    behavior_api = behavior_summary.get("not_analyzed_apis", [])[0]
    assert_true(
        behavior_api.get("reason_code") == "ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE",
        "缺少最终制品时，API 级裁决应优先暴露字节码覆盖不完整",
    )
    assert_true(
        any(
            path.get("stop_reason") == "BEHAVIOR_CHANGED_RUNTIME_VERIFICATION"
            for path in behavior_api.get("path_details") or []
        ),
        "行为变更调用路径应保留运行时验证专用原因码",
    )


def run_orchestrator_smoke_cases(workspace, dep_env):
    base_tmp = workspace.base_tmp
    project_dir = workspace.project_dir
    dep_repo = workspace.dep_repo

    orchestrated_report = project_dir / ".upgrade-report-orchestrated"
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(orchestrated_report),
            "--base-branch", "base",
            "--current-branch", "current",
            "--target-module", ".",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "run_step Step1 首次编排应进入 awaiting_user_input，以等待用户确认或补充信息",
    )
    orchestrated_ckpt = read_json(main_state_path(orchestrated_report))
    orchestrated_interaction = read_json(interaction_path(orchestrated_report))
    assert_true(main_state_meta(orchestrated_ckpt).get("completed_step") == "step1", "run_step Step1 未写入正确主状态")
    assert_true(orchestrated_interaction.get("step_id") == "step1", "run_step Step1 首轮交互未停在 step1")
    assert_true(
        main_state_meta(orchestrated_ckpt).get("status") == "awaiting_user_input",
        "run_step Step1 首轮执行后应进入 awaiting_user_input"
    )

    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--describe-step1-contract",
        ],
        cwd=project_dir,
    )
    assert_true(rc == 0, "Step1 静态前置协议导出命令应成功返回")
    static_contract = json.loads(stdout)
    assert_true(
        static_contract.get("schema") == "java-upgrade-analyzer.step1-contract.v1",
        "Step1 静态前置协议 schema 不正确",
    )
    assert_true(
        "base_artifact_path" in json.dumps(static_contract.get("fields") or {}, ensure_ascii=False),
        "Step1 静态前置协议未暴露 base_artifact_path",
    )
    assert_true(
        "primary_module" in json.dumps(static_contract.get("fields") or {}, ensure_ascii=False),
        "Step1 静态前置协议未暴露 primary_module",
    )
    assert_true(
        "allow_checkout" not in json.dumps(static_contract.get("fields") or {}, ensure_ascii=False),
        "Step1 静态前置协议 fields 不应再暴露 allow_checkout",
    )
    assert_true(
        "allow_checkout" in json.dumps(static_contract.get("forbidden") or [], ensure_ascii=False),
        "Step1 静态前置协议应明确把 allow_checkout 列为禁止项",
    )
    assert_true(
        (static_contract.get("first_turn_collection") or {}).get("strategy") == "completion_oriented",
        "Step1 静态前置协议未明确首轮收参策略",
    )
    assert_true(
        run_step_module.build_step1_preflight_interaction(
            {
                "analysis_mode": "artifact_inputs",
                "base_artifact_path": "/tmp/base-app.jar",
                "current_artifact_path": "/tmp/current-app.jar",
                "base_branch": "base",
                "current_branch": "current",
                "primary_module": "app-module",
                "tool": "maven",
            }
        ) is None,
        "Step1 在 artifact 输入已完整时不应继续返回 preflight interaction",
    )
    assert_true(
        run_step_module.build_step1_preflight_interaction(
            {
                "analysis_mode": "artifact_inputs",
                "base_artifact_path": "/tmp/base-app.jar",
                "current_artifact_path": "/tmp/current-app.jar",
                "primary_module": "app-module",
                "tool": "maven",
            }
        ) is None,
        "Step1 在两侧产物已提供时，不应因为 branch/source_project_dir 尚未提供就提前阻塞 preflight",
    )
    assert_true(
        run_step_module.build_step1_preflight_interaction(
            {
                "analysis_mode": "checkout_build",
                "base_branch": "base",
                "current_branch": "current",
                "primary_module": "app-module",
                "tool": "maven",
            }
        ) is None,
        "Step1 在 checkout_build 输入已完整时不应继续返回 preflight interaction",
    )
    switched_run_context = run_step_module.merge_user_response_into_run_context(
        {
            "analysis_mode": "artifact_inputs",
            "base_artifact_path": "/tmp/base-app.jar",
            "current_artifact_path": "/tmp/current-app.jar",
        },
        {
            "action": "continue",
            "analysis_mode": "checkout_build",
            "base_branch": "base",
            "current_branch": "current",
        },
        project_dir,
    )
    switched_mode_info = run_step_module.infer_step1_mode_fields(switched_run_context)
    assert_true(
        not switched_run_context.get("base_artifact_path") and not switched_run_context.get("current_artifact_path"),
        "用户显式切到 checkout_build 时，应清理旧的 artifact 路径，避免模式锁死",
    )
    assert_true(
        switched_mode_info.get("analysis_mode") == "checkout_build",
        "用户显式切到 checkout_build 后，Step1 模式推导仍不正确",
    )
    fake_current_jdk = base_tmp / "fake-jdk-current"
    write_text(
        fake_current_jdk / "bin" / "java",
        "#!/bin/sh\nexit 0\n",
    )
    (fake_current_jdk / "bin" / "java").chmod(0o755)
    worktree_calls = []

    def fake_worktree_run_cmd(cmd, cwd=None, timeout=300, input_text=None, env=None, **_kwargs):
        joined = " ".join(str(part) for part in cmd)
        worktree_calls.append({"cmd": list(cmd), "cwd": cwd, "env": dict(env or {})})
        if cmd[:3] == ["git", "worktree", "add"] or (len(cmd) >= 3 and cmd[1:3] == ["worktree", "add"]):
            temp_dir = Path(cmd[-2])
            temp_dir.mkdir(parents=True, exist_ok=True)
            return "", "", 0
        if cmd[:3] == ["git", "worktree", "remove"] or (len(cmd) >= 3 and cmd[1:3] == ["worktree", "remove"]):
            return "", "", 0
        if "dependency:list" in joined:
            return (
                "[INFO] The following files have been resolved:\n"
                "[INFO]    com.example:demo-lib:jar:2.0.0:runtime -- /tmp/demo-lib-2.0.0.jar\n",
                "",
                0,
            )
        raise AssertionError(f"未预期的命令: {joined}")

    with mock.patch.object(s1_dep_diff_module, "run_cmd", side_effect=fake_worktree_run_cmd), \
         mock.patch.object(s1_dep_diff_module, "git_cmd", return_value=["git"]), \
         mock.patch.object(s1_dep_diff_module, "mvn_cmd", return_value=["mvn"]):
        runtime_deps, runtime_meta = s1_dep_diff_module.get_runtime_deps_by_switching_branch(
            "feature/test",
            str(project_dir),
            primary_module="app-module",
            jdk_home=str(fake_current_jdk),
            side="current",
            artifact_path="/tmp/current-app.jar",
        )
    assert_true(runtime_meta.get("branch") == "feature/test", "worktree 模式未保留 branch 元信息")
    assert_true(any("worktree" in " ".join(item["cmd"]) and "add" in item["cmd"] for item in worktree_calls), "Step1 分支分析未改用 git worktree add")
    assert_true(not any("stash" in " ".join(item["cmd"]) for item in worktree_calls), "Step1 分支分析不应再执行 git stash")
    dependency_list_calls = [item for item in worktree_calls if "dependency:list" in " ".join(item["cmd"])]
    assert_true(bool(runtime_deps), "worktree 模式未返回 runtime 依赖")
    assert_true(
        dependency_list_calls and dependency_list_calls[0]["env"].get("JAVA_HOME") == str(fake_current_jdk.resolve()),
        "Step1 分支分析未按 current_jdk_home 注入 JAVA_HOME",
    )
    assert_true(
        dependency_list_calls and dependency_list_calls[0]["env"].get("JUA_GIT_BRANCH_HINT") == "feature/test",
        "Step1 分支分析未向 worktree 子进程透传分支提示，可能导致 detached HEAD 场景误判版本",
    )
    checkout_override_capture = {}

    def fake_collect_packaged_with_manual_override(*_args, **kwargs):
        checkout_override_capture["manual_coord_overrides"] = kwargs.get("manual_coord_overrides")
        return (
            {"com.example:demo-lib": {"coord": "com.example:demo-lib", "remark": "source:final_artifact(manual_override)"}},
            {"mode": "final_artifact"},
        )

    with mock.patch.object(
        s1_dep_diff_module,
        "build_java_env",
        return_value={"JAVA_HOME": "/fake/jdk", "PATH": "/fake/jdk/bin"},
    ), mock.patch.object(
        s1_dep_diff_module,
        "create_branch_worktree",
        return_value=project_dir / ".tmp-worktree-manual-override",
    ), mock.patch.object(
        s1_dep_diff_module,
        "collect_maven_deps_for_workspace",
        side_effect=fake_collect_packaged_with_manual_override,
    ), mock.patch.object(
        s1_dep_diff_module,
        "remove_branch_worktree",
    ):
        packaged_deps, packaged_meta = s1_dep_diff_module.get_packaged_deps_by_switching_branch(
            "feature/manual-override",
            str(project_dir),
            primary_module="app-module",
            manual_coord_overrides={
                ("demo-lib", "2.0.0"): {
                    "group_id": "com.example",
                    "artifact_id": "demo-lib",
                    "coord": "com.example:demo-lib",
                }
            },
        )
    assert_true(
        checkout_override_capture.get("manual_coord_overrides", {}).get(("demo-lib", "2.0.0"), {}).get("coord") == "com.example:demo-lib",
        "Step1 checkout_build 包装层未向 workspace 收集逻辑透传 manual_coord_overrides",
    )
    assert_true(
        packaged_meta.get("branch") == "feature/manual-override" and "com.example:demo-lib" in packaged_deps,
        "Step1 checkout_build 包装层在透传 manual_coord_overrides 后未保留分支与 resolved 结果",
    )
    host_jdk_calls = []

    def fake_host_jdk_run_cmd(cmd, cwd=None, timeout=300, input_text=None, env=None, **_kwargs):
        joined = " ".join(str(part) for part in cmd)
        host_jdk_calls.append({"cmd": list(cmd), "cwd": cwd, "env": dict(env or {})})
        if cmd[:3] == ["git", "worktree", "add"] or (len(cmd) >= 3 and cmd[1:3] == ["worktree", "add"]):
            temp_dir = Path(cmd[-2])
            temp_dir.mkdir(parents=True, exist_ok=True)
            return "", "", 0
        if cmd[:3] == ["git", "worktree", "remove"] or (len(cmd) >= 3 and cmd[1:3] == ["worktree", "remove"]):
            return "", "", 0
        if "dependency:list" in joined:
            return (
                "[INFO] The following files have been resolved:\n"
                "[INFO]    com.example:demo-lib:jar:2.0.0:runtime -- /tmp/demo-lib-2.0.0.jar\n",
                "",
                0,
            )
        raise AssertionError(f"未预期的命令: {joined}")

    with mock.patch.dict(os.environ, {"JAVA_HOME": str(fake_current_jdk.resolve())}, clear=False), \
         mock.patch.object(s1_dep_diff_module, "run_cmd", side_effect=fake_host_jdk_run_cmd), \
         mock.patch.object(s1_dep_diff_module, "git_cmd", return_value=["git"]), \
         mock.patch.object(s1_dep_diff_module, "mvn_cmd", return_value=["mvn"]):
        s1_dep_diff_module.get_runtime_deps_by_switching_branch(
            "feature/base",
            str(project_dir),
            primary_module="app-module",
            jdk_field="base_jdk_home",
            jdk_home="",
            side="base",
            artifact_path="/tmp/base-app.jar",
        )
    host_dependency_list_calls = [item for item in host_jdk_calls if "dependency:list" in " ".join(item["cmd"])]
    assert_true(
        host_dependency_list_calls and host_dependency_list_calls[0]["env"].get("JAVA_HOME") == str(fake_current_jdk.resolve()),
        "Step1 在 base_jdk_home 未提供时，应回落主机 JAVA_HOME",
    )
    try:
        s1_dep_diff_module.get_runtime_deps_by_switching_branch(
            "feature/test",
            str(project_dir),
            primary_module="app-module",
            jdk_home="/not-exists-jdk",
            side="current",
            artifact_path="/tmp/current-app.jar",
        )
        raise AssertionError("无效 JDK Home 应被转换为结构化阻塞错误")
    except s1_dep_diff_module.Step1CommandExecutionBlockedError as exc:
        assert_true(exc.stage == "prepare_java_env", "无效 JDK Home 应标记为 prepare_java_env")
        assert_true(exc.side == "current", "无效 JDK Home 时应保留 side=current")
    cleanup_dir = project_dir / ".tmp-worktree-remove-failure"
    cleanup_dir.mkdir(parents=True, exist_ok=True)
    with mock.patch.object(
        s1_dep_diff_module,
        "run_cmd",
        return_value=("", "remove failed", 1),
    ), mock.patch.object(
        s1_dep_diff_module,
        "git_cmd",
        return_value=["git"],
    ):
        try:
            s1_dep_diff_module.remove_branch_worktree(cleanup_dir, str(project_dir))
            raise AssertionError("worktree remove 失败时应抛出异常")
        except RuntimeError:
            pass
    assert_true(cleanup_dir.exists(), "worktree remove 失败时不应继续强删目录，避免留下脏的 Git worktree 元数据")

    try:
        s1_dep_diff_module._collect_runtime_deps_for_artifact_input(
            str(project_dir),
            "",
            str(project_dir),
            primary_module="app-module",
            jdk_home="/fake/jdk",
            side="current",
            artifact_path="/tmp/current-app.jar",
        )
        raise AssertionError("source_project_dir 未确认 revision 时不应执行坐标补全")
    except s1_dep_diff_module.SourceRevisionConfirmationRequiredError as exc:
        assert_true(exc.side == "current", "source-only 阻塞应保留 current 侧信息")

    try:
        with mock.patch.object(
            s1_dep_diff_module,
            "build_java_env",
            return_value={"JAVA_HOME": "/fake/jdk", "PATH": "/fake/jdk/bin"},
        ), mock.patch.object(
            s1_dep_diff_module,
            "create_branch_worktree",
            return_value=project_dir / ".tmp-worktree",
        ), mock.patch.object(
            s1_dep_diff_module,
            "collect_runtime_deps_for_workspace",
            side_effect=RuntimeError("[ERROR] invalid target release: 8"),
        ), mock.patch.object(
            s1_dep_diff_module,
            "remove_branch_worktree",
            side_effect=RuntimeError("remove failed"),
        ):
            s1_dep_diff_module.get_runtime_deps_by_switching_branch(
                "feature/test",
                str(project_dir),
                primary_module="app-module",
                jdk_home="/fake/jdk",
                side="current",
                artifact_path="/tmp/current-app.jar",
            )
        raise AssertionError("cleanup 失败不应覆盖原始结构化阻塞错误")
    except s1_dep_diff_module.Step1CommandExecutionBlockedError as exc:
        assert_true(exc.stage == "mvn_dependency_list", "cleanup 失败后应保留原始阻塞阶段")
        assert_true("临时 worktree 清理失败" in exc.stderr_excerpt, "cleanup 失败应追加到原始错误摘要，而不是覆盖它")


    blocked_report = project_dir / ".upgrade-report-step1-blocked"
    blocked_report.mkdir(parents=True, exist_ok=True)
    blocked_seed_json_path = blocked_report / "main_state_seed.json"
    write_text(
        blocked_seed_json_path,
        json.dumps(
            {
                "analysis_mode": "checkout_build",
                "base_branch": "base",
                "current_branch": "current",
                "base_jdk_home": "/not-exists-jdk",
                "target_module": ".",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(blocked_report),
            "--seed-json", str(blocked_seed_json_path),
        ],
        cwd=project_dir,
    )
    assert_true(rc == EXIT_AWAITING_USER, "Maven 环境阻塞时 Step1 应进入 awaiting user，而不是直接失败")
    blocked_ckpt = read_json(main_state_path(blocked_report))
    blocked_interaction = read_json(interaction_path(blocked_report))
    assert_true(main_state_meta(blocked_ckpt).get("status") == "awaiting_user_input", "Maven 环境阻塞时主状态应进入 awaiting_user_input")
    assert_true(blocked_interaction.get("kind") == "execution_blocked", "Maven 环境阻塞时应暴露 execution_blocked")
    assert_true(blocked_interaction.get("reason_code") == "step1_maven_command_blocked", "Maven 环境阻塞时 reason_code 不正确")
    assert_true("JDK Home 无效" in json.dumps(blocked_interaction, ensure_ascii=False), "Maven 环境阻塞时未暴露真实错误摘要")
    assert_true(
        "base_jdk_home" in json.dumps(blocked_interaction.get("response_schema") or {}, ensure_ascii=False),
        "Maven 环境阻塞时未向 agent 暴露 base_jdk_home",
    )
    base_fallback_error = s1_dep_diff_module.build_step1_command_blocked_error(
        stage="mvn_dependency_list",
        command="mvn dependency:list",
        exc=RuntimeError("[ERROR] invalid target release: 8"),
        side="base",
        jdk_field="base_jdk_home",
        jdk_home="/fake/jdk-base",
        source_mode="branch_checkout",
        artifact_path="/tmp/base-app.jar",
    )
    base_fallback_interaction = s1_dep_diff_module.build_step1_command_blocked_interaction(base_fallback_error)
    assert_true(
        "base_jdk_home" in json.dumps(base_fallback_interaction.get("response_schema") or {}, ensure_ascii=False),
        "base 侧使用独立 JDK 变量时，交互应提示 base_jdk_home",
    )
    assert_true(
        "current_jdk_home" not in json.dumps(base_fallback_interaction.get("response_schema") or {}, ensure_ascii=False),
        "base 侧使用独立 JDK 变量时，不应误导提示 current_jdk_home",
    )

    step1_preflight_report = project_dir / ".upgrade-report-step1-preflight"
    step1_preflight_report.mkdir(parents=True, exist_ok=True)
    step1_preflight_seed_json_path = step1_preflight_report / "main_state_seed.json"
    write_text(
        step1_preflight_seed_json_path,
        json.dumps(
            {
                "analysis_mode": "artifact_inputs",
                "base_artifact_path": "artifact-inputs/base-app.jar",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(step1_preflight_report),
            "--seed-json", str(step1_preflight_seed_json_path),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(rc == EXIT_AWAITING_USER, "Step1 缺少入口输入时应进入 awaiting user，而不是直接失败")
    step1_preflight_ckpt = read_json(main_state_path(step1_preflight_report))
    step1_preflight_interaction = read_json(interaction_path(step1_preflight_report))
    assert_true(
        main_state_meta(step1_preflight_ckpt).get("current_step") == "step1",
        "Step1 前置输入契约交互时 current_step 应停留在 step1",
    )
    assert_true(
        not main_state_meta(step1_preflight_ckpt).get("completed_step"),
        "Step1 前置输入契约交互时不应把 step1 记成已完成",
    )
    assert_true(
        step1_preflight_interaction.get("reason_code") == "missing_step1_entry_inputs",
        "Step1 前置输入契约交互的 reason_code 不正确",
    )
    missing_coord_interaction = s1_dep_diff_module.build_step1_missing_input_interaction(
        [
            {
                "side": "base",
                "side_cn": "基准侧",
                "artifact_path": "/tmp/base-app.jar",
                "branch_field": "base_branch",
                "source_field": "base_source_project_dir",
            }
        ]
    )
    assert_true(
        (missing_coord_interaction.get("input_normalization") or {}).get("required_fields") == ["base_branch"],
        "Step1 缺坐标交互的 input_normalization.required_fields 应与真实缺失字段保持一致",
    )
    preflight_input_modes = step1_preflight_interaction.get("input_modes") or []
    assert_true(
        len(preflight_input_modes) == 2,
        "Step1 前置输入契约交互应明确暴露两种输入方式",
    )
    preflight_schema = step1_preflight_interaction.get("response_schema") or {}
    preflight_properties = (preflight_schema.get("properties") or {})
    for field_name in (
        "base_artifact_path",
        "current_artifact_path",
        "base_branch",
        "current_branch",
        "primary_module",
    ):
        assert_true(
            field_name in preflight_properties,
            f"Step1 前置输入契约交互未向 agent 暴露 {field_name}",
        )
    assert_true(
        "可选输入方式" in stderr and "自动切分支构建" in stderr,
        "分析对象前置交互未向用户说明可选输入方式",
    )

    artifact_input_dir = project_dir / "artifact-inputs"
    artifact_input_dir.mkdir(parents=True, exist_ok=True)
    create_fake_boot_jar(
        artifact_input_dir / "base-app.jar",
        [("com.example", "demo-lib", "1.0.0")],
    )
    create_fake_boot_jar(
        artifact_input_dir / "current-app.jar",
        [("com.example", "demo-lib", "2.0.0")],
    )
    artifact_seed_json_path = project_dir / ".upgrade-report-artifact-input" / "main_state_seed.json"
    artifact_seed_json_path.parent.mkdir(parents=True, exist_ok=True)
    write_text(
        artifact_seed_json_path,
        json.dumps(
            {
                "base_artifact_path": "artifact-inputs/base-app.jar",
                "current_artifact_path": "artifact-inputs/current-app.jar",
                "base_branch": "base",
                "current_branch": "current",
                "target_module": ".",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    artifact_input_report = artifact_seed_json_path.parent
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(artifact_input_report),
            "--seed-json", str(artifact_seed_json_path),
        ],
        cwd=project_dir,
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "直接产物模式下的 Step1 首轮应进入 awaiting_user_input，而不是直接返回 0",
    )
    artifact_input_ckpt = read_json(main_state_path(artifact_input_report))
    artifact_input_rows = read_csv(dep_changes_path(artifact_input_report))
    demo_rows = [row for row in artifact_input_rows if row.get("coord") == "com.example:demo-lib"]
    assert_true(main_state_meta(artifact_input_ckpt).get("completed_step") == "step1", "直接产物模式未写入 step1 主状态")
    assert_true(
        main_state_step_input(artifact_input_ckpt, "step1").get("base_artifact_path", "").replace("\\", "/").endswith("artifact-inputs/base-app.jar"),
        "run_step 未将 seed_json.base_artifact_path 写入 step1.input",
    )
    assert_true(
        main_state_step_input(artifact_input_ckpt, "step1").get("current_artifact_path", "").replace("\\", "/").endswith("artifact-inputs/current-app.jar"),
        "run_step 未将 seed_json.current_artifact_path 写入 step1.input",
    )
    assert_true(demo_rows, "直接产物模式未产出 demo-lib 的依赖变更")
    assert_true(
        demo_rows[0].get("old_version") == "1.0.0" and demo_rows[0].get("new_version") == "2.0.0",
        "直接产物模式输出的依赖变更版本不正确",
    )
    assert_true(
        main_state_step_input(artifact_input_ckpt, "step1").get("base_branch", "") == "base",
        "直接产物模式未保留显式提供的 base_branch",
    )
    assert_true(
        main_state_step_input(artifact_input_ckpt, "step1").get("current_branch", "") == "current",
        "直接产物模式未保留显式提供的 current_branch",
    )
    artifact_source_report = project_dir / ".upgrade-report-artifact-source"
    artifact_source_report.mkdir(parents=True, exist_ok=True)
    filename_only_current_artifact = artifact_input_dir / "current-app-no-pom.jar"
    with zipfile.ZipFile(filename_only_current_artifact, "w") as outer:
        outer.writestr("BOOT-INF/classes/com/example/App.class", b"app")
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as inner:
            inner.writestr("com/example/NoPom.class", b"no-pom")
        outer.writestr("BOOT-INF/lib/demo-lib-2.0.0.jar", nested.getvalue())
    artifact_source_seed_json_path = artifact_source_report / "main_state_seed.json"
    write_text(
        artifact_source_seed_json_path,
        json.dumps(
            {
                "base_artifact_path": "artifact-inputs/base-app.jar",
                "current_artifact_path": "artifact-inputs/current-app-no-pom.jar",
                "base_branch": "base",
                "current_branch": "current",
                "current_source_project_dir": ".",
                "target_module": ".",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(artifact_source_report),
            "--seed-json", str(artifact_source_seed_json_path),
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "artifact + source_project_dir 模式下的 Step1 首轮应进入 awaiting_user_input，而不是直接返回 0",
    )
    artifact_source_ckpt = read_json(main_state_path(artifact_source_report))
    artifact_source_rows = read_csv(dep_changes_path(artifact_source_report))
    artifact_source_demo = [row for row in artifact_source_rows if row.get("coord") == "com.example:demo-lib"]
    assert_true(
        main_state_step_input(artifact_source_ckpt, "step1").get("current_source_project_dir", "").replace("\\", "/").endswith("/project"),
        "artifact 模式未保留 current_source_project_dir",
    )
    assert_true(
        artifact_source_demo and artifact_source_demo[0].get("new_version") == "2.0.0",
        "artifact + branch/source_project_dir 模式未优先用已确认分支补全 filename-only 嵌套 jar 坐标",
    )
    artifact_source_progress = [
        json.loads(line)
        for line in (
            artifact_source_report / ".runtime" / "observability" / "step1_progress.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    current_ref_events = [
        row for row in artifact_source_progress
        if row.get("phase") == "ref_resolution" and row.get("side") == "current"
    ]
    assert_true(
        current_ref_events
        and (current_ref_events[-1].get("details") or {}).get("resolved_commit"),
        "Step1 进度日志未记录 current 分支解析后的不可变 commit",
    )
    artifact_source_provenance = read_json(
        artifact_source_report / "evidence" / "dependencies" / "build_provenance.json"
    )
    current_provenance = next(
        item for item in artifact_source_provenance.get("sides") or []
        if item.get("side") == "current"
    )
    assert_true(
        current_provenance.get("requested_ref") == "current"
        and current_provenance.get("revision")
        and current_provenance.get("ref_resolution_mode") == "exact",
        "Step1 构建来源未保留按需坐标补全实际采用的 current ref/commit",
    )
    artifact_base_source_report = project_dir / ".upgrade-report-artifact-base-source"
    artifact_base_source_report.mkdir(parents=True, exist_ok=True)
    filename_only_base_artifact = artifact_input_dir / "base-app-no-pom.jar"
    with zipfile.ZipFile(filename_only_base_artifact, "w") as outer:
        outer.writestr("BOOT-INF/classes/com/example/App.class", b"app")
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as inner:
            inner.writestr("com/example/NoPom.class", b"no-pom")
        outer.writestr("BOOT-INF/lib/demo-lib-1.0.0.jar", nested.getvalue())
    artifact_base_source_seed_json_path = artifact_base_source_report / "main_state_seed.json"
    write_text(
        artifact_base_source_seed_json_path,
        json.dumps(
            {
                "base_artifact_path": "artifact-inputs/base-app-no-pom.jar",
                "current_artifact_path": "artifact-inputs/current-app.jar",
                "base_source_project_dir": ".",
                "current_branch": "current",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(artifact_base_source_report),
            "--seed-json", str(artifact_base_source_seed_json_path),
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "artifact + base_source_project_dir 模式在缺少 primary_module 时应进入 awaiting_user_input",
    )
    artifact_base_source_ckpt = read_json(main_state_path(artifact_base_source_report))
    artifact_base_source_interaction = read_json(interaction_path(artifact_base_source_report))
    assert_true(
        main_state_step_input(artifact_base_source_ckpt, "step1").get("base_source_project_dir", "").replace("\\", "/").endswith("/project"),
        "artifact 模式未保留 base_source_project_dir",
    )
    assert_true(
        main_state_meta(artifact_base_source_ckpt).get("current_step") == "step1"
        and not main_state_meta(artifact_base_source_ckpt).get("completed_step"),
        "artifact + base_source_project_dir 模式在缺少 primary_module 时应停留在 step1",
    )
    assert_true(
        artifact_base_source_interaction.get("reason_code") == "missing_step1_target_module",
        "artifact + base_source_project_dir 模式的待补参 reason_code 不正确",
    )
    assert_true(
        "target_module" in json.dumps(artifact_base_source_interaction.get("response_schema") or {}, ensure_ascii=False),
        "artifact + base_source_project_dir 模式未要求补充 target_module",
    )
    artifact_missing_input_report = project_dir / ".upgrade-report-artifact-missing-input"
    artifact_missing_input_report.mkdir(parents=True, exist_ok=True)
    artifact_missing_input_seed_json_path = artifact_missing_input_report / "main_state_seed.json"
    write_text(
        artifact_missing_input_seed_json_path,
        json.dumps(
            {
                "base_artifact_path": "artifact-inputs/base-app.jar",
                "current_artifact_path": "artifact-inputs/current-app-no-pom.jar",
                "base_branch": "base",
                "target_module": ".",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(artifact_missing_input_report),
            "--seed-json", str(artifact_missing_input_seed_json_path),
        ],
        cwd=project_dir,
    )
    assert_true(rc == EXIT_AWAITING_USER, "Step1 缺业务信息时应进入 awaiting user，而不是直接失败")
    artifact_missing_ckpt = read_json(main_state_path(artifact_missing_input_report))
    artifact_missing_interaction = read_json(interaction_path(artifact_missing_input_report))
    assert_true(
        main_state_meta(artifact_missing_ckpt).get("status") == "awaiting_user_input",
        "Step1 缺业务信息时主状态应进入 awaiting_user_input",
    )
    assert_true(
        main_state_meta(artifact_missing_ckpt).get("current_step") == "step1",
        "Step1 缺业务信息时 current_step 应停留在 step1，不能提前推进到 step2",
    )
    assert_true(
        not main_state_meta(artifact_missing_ckpt).get("completed_step"),
        "Step1 缺业务信息时不应把 step1 记成已完成",
    )
    assert_true(
        artifact_missing_interaction.get("step_id") == "step1",
        "Step1 缺业务信息时 interaction.step_id 不正确",
    )
    assert_true(
        "current_branch" in json.dumps(artifact_missing_interaction.get("response_schema") or {}, ensure_ascii=False),
        "Step1 缺业务信息时未优先请求 current_branch",
    )
    missing_inputs = artifact_missing_interaction.get("missing_inputs") or []
    assert_true(
        bool(missing_inputs),
        "Step1 缺业务信息时 interaction.json 未写入 missing_inputs",
    )
    assert_true(
        missing_inputs[0].get("field") == "current_branch",
        "Step1 缺业务信息时首要缺失字段应为 current_branch",
    )
    assert_true(
        missing_inputs[0].get("side") == "current",
        "Step1 缺业务信息时 missing_inputs.side 应标记为 current",
    )
    assert_true(
        "pom.properties" in str(missing_inputs[0].get("reason") or ""),
        "Step1 缺业务信息时 missing_inputs.reason 应说明缺失原因",
    )
    artifact_followup_report = project_dir / ".upgrade-report-artifact-followup"
    artifact_followup_report.mkdir(parents=True, exist_ok=True)
    unresolved_current_artifact = artifact_input_dir / "current-app-unresolved.jar"
    with zipfile.ZipFile(unresolved_current_artifact, "w") as outer:
        outer.writestr("BOOT-INF/classes/com/example/App.class", b"app")
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as inner:
            inner.writestr("com/example/Unknown.class", b"unknown")
        outer.writestr("BOOT-INF/lib/mystery-lib-2.0.0.jar", nested.getvalue())
    artifact_followup_seed_json_path = artifact_followup_report / "main_state_seed.json"
    write_text(
        artifact_followup_seed_json_path,
        json.dumps(
            {
                "base_artifact_path": "artifact-inputs/base-app.jar",
                "current_artifact_path": "artifact-inputs/current-app-unresolved.jar",
                "base_branch": "base",
                "current_branch": "current",
                "target_module": ".",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(artifact_followup_report),
            "--seed-json", str(artifact_followup_seed_json_path),
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(rc == EXIT_AWAITING_USER, "branch 已提供但坐标仍无法补全时，Step1 也应进入 awaiting user")
    artifact_followup_interaction = read_json(interaction_path(artifact_followup_report))
    assert_true(
        artifact_followup_interaction.get("reason_code") == "unresolved_dependency_coordinates_after_enrichment",
        "branch 已提供但坐标仍无法补全时，Step1 应显式暴露 follow-up 交互原因",
    )
    assert_true(
        artifact_followup_interaction.get("unresolved_items"),
        "branch 已提供但坐标仍无法补全时，应显式暴露未识别的嵌套依赖",
    )
    assert_true(
        "仍不足以安全输出最终依赖" in stderr,
        "branch 已提供但坐标仍无法补全时，stderr 应明确说明不是通用失败",
    )
    followup_options = {item.get("id") for item in artifact_followup_interaction.get("options", []) if isinstance(item, dict)}
    assert_true(
        "confirm_unresolved" in followup_options,
        "branch 已提供但坐标仍无法补全时，Step1 follow-up 交互应允许人工确认 unresolved 后继续",
    )
    assert_true(
        "manual_coord_overrides" in json.dumps(artifact_followup_interaction.get("response_schema") or {}, ensure_ascii=False),
        "branch 已提供但坐标仍无法补全时，Step1 follow-up 交互应允许人工补充坐标",
    )
    artifact_followup_confirm_response = artifact_followup_report / "user_response_confirm.json"
    write_text(
        artifact_followup_confirm_response,
        json.dumps(
            {
                "action": "confirm_unresolved",
                "notes": "保留 unresolved 行，后续步骤跳过这些行",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(artifact_followup_report),
            "--response-file", str(artifact_followup_confirm_response),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "人工确认 unresolved 后，Step1 应先完成并停在 step1 确认点",
    )
    artifact_followup_rows = read_csv(dep_changes_path(artifact_followup_report))
    unresolved_rows = [row for row in artifact_followup_rows if row.get("resolution_status") == "unresolved"]
    assert_true(unresolved_rows, "人工确认 unresolved 后，s1_dep_changes.csv 应保留 unresolved 行")
    assert_true(
        any((row.get("coord") or "").startswith("mystery-lib:2.0.0") for row in unresolved_rows),
        "人工确认 unresolved 后，未识别依赖应以 artifact:version 形式保留在 s1_dep_changes.csv",
    )
    pseudo_resolved_rows = [
        row for row in artifact_followup_rows
        if row.get("coord") == "com.example:mystery-lib" and row.get("resolution_status") == "resolved"
    ]
    assert_true(
        not pseudo_resolved_rows,
        "人工确认 unresolved 后，Step1 不应再为同一依赖额外保留 resolved 的伪变更行",
    )
    assert_true(
        not (context_path(artifact_followup_report)).exists(),
        "人工确认 unresolved 后，首次恢复不应直接执行 step2",
    )
    artifact_followup_current_rows = read_csv(deps_current_resolved_path(artifact_followup_report))
    current_unresolved_rows = [
        row for row in artifact_followup_current_rows if row.get("resolution_status") == "unresolved"
    ]
    assert_true(
        any((row.get("coord") or "").startswith("mystery-lib:2.0.0") for row in current_unresolved_rows),
        "人工确认 unresolved 后，s1_deps_current_resolved.csv 应保留 current 侧 unresolved 行",
    )
    assert_true(
        not any((row.get("coord") or "") == "legacy-only:1.0.0" for row in artifact_followup_current_rows),
        "s1_deps_current_resolved.csv 不应混入 base 侧 unresolved 依赖",
    )
    artifact_followup_manual_response = artifact_followup_report / "user_response_manual.json"
    write_text(
        artifact_followup_manual_response,
        json.dumps(
            {
                "action": "rerun_current_step",
                "manual_coord_overrides": ["mystery-lib:2.0.0 -> com.example:mystery-lib"],
                "primary_module": ".",
                "modules": ["."],
                "notes": "人工补充 mystery-lib 坐标后重跑 step1",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(artifact_followup_report),
            "--response-file", str(artifact_followup_manual_response),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    artifact_followup_ckpt = read_json(main_state_path(artifact_followup_report))
    assert_true(
        main_state_meta(artifact_followup_ckpt).get("completed_step") == "step1"
        and main_state_meta(artifact_followup_ckpt).get("current_step") in {"step1", "step2"},
        "人工补充坐标后，主状态应表现为 Step1 已完成或重新进入常规 step1 确认点",
    )
    artifact_followup_rows = read_csv(dep_changes_path(artifact_followup_report))
    resolved_demo_rows = [
        row for row in artifact_followup_rows
        if row.get("coord") == "com.example:mystery-lib" and row.get("resolution_status") == "resolved"
    ]
    assert_true(
        resolved_demo_rows,
        "人工补充坐标后，Step1 应将该依赖转为 resolved 行",
    )
    fallback_inputs = artifact_missing_interaction.get("fallback_inputs") or []
    assert_true(
        fallback_inputs and fallback_inputs[0].get("field") == "current_source_project_dir",
        "Step1 缺业务信息时 fallback_inputs 应明确 current_source_project_dir",
    )
    assert_true(
        "current_branch" in str(artifact_missing_interaction.get("question") or ""),
        "Step1 缺业务信息时交互问题文案未明确输出缺失字段",
    )
    assert_true(
        "JUA_STEP_INTERACTION_JSON:" not in stdout and "JUA_STEP_INTERACTION_JSON:" not in stderr,
        "Step1 缺业务信息时不应向用户泄露内部交互协议前缀",
    )
    artifact_missing_continue_response = artifact_missing_input_report / "user_response.json"
    write_text(
        artifact_missing_continue_response,
        json.dumps(
            {
                "action": "continue",
                "current_branch": "current",
                "notes": "补充当前侧分支后重跑 step1",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(artifact_missing_input_report),
            "--response-file", str(artifact_missing_continue_response),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "Step1 缺业务信息后补充分支，应先重跑 step1 并停在 step1 确认点",
    )
    artifact_missing_resume_ckpt = read_json(main_state_path(artifact_missing_input_report))
    artifact_missing_resume_interaction = read_json(interaction_path(artifact_missing_input_report))
    assert_true(
        main_state_meta(artifact_missing_resume_ckpt).get("completed_step") == "step1",
        "Step1 缺业务信息后补充分支，恢复执行后应先完成 step1",
    )
    assert_true(
        artifact_missing_resume_interaction.get("step_id") == "step1",
        "Step1 缺业务信息后补充分支，恢复执行后 interaction 应仍指向 step1",
    )
    assert_true(
        not (context_path(artifact_missing_input_report)).exists(),
        "Step1 缺业务信息后补充分支，首次恢复不应直接执行 step2",
    )
    assert_true(
        "正在分析：分析对象与依赖范围" in stderr and "正在分析：升级上下文" not in stderr,
        "Step1 缺业务信息后补充分支，恢复日志应只显示 step1，不能直接跳到 step2",
    )
    artifact_branch_fallback_report = project_dir / ".upgrade-report-artifact-branch-fallback"
    artifact_branch_fallback_report.mkdir(parents=True, exist_ok=True)
    artifact_branch_fallback_seed_json_path = artifact_branch_fallback_report / "main_state_seed.json"
    write_text(
        artifact_branch_fallback_seed_json_path,
        json.dumps(
            {
                "base_artifact_path": "artifact-inputs/base-app.jar",
                "current_artifact_path": "artifact-inputs/current-app-no-pom.jar",
                "base_branch": "base",
                "current_branch": "current",
                "target_module": ".",
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(artifact_branch_fallback_report),
            "--seed-json", str(artifact_branch_fallback_seed_json_path),
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "artifact + current_branch 模式下的 Step1 首轮应进入 awaiting_user_input，而不是直接返回 0",
    )
    artifact_branch_fallback_rows = read_csv(dep_changes_path(artifact_branch_fallback_report))
    artifact_branch_demo = [row for row in artifact_branch_fallback_rows if row.get("coord") == "com.example:demo-lib"]
    assert_true(
        artifact_branch_demo and artifact_branch_demo[0].get("new_version") == "2.0.0",
        "artifact + current_branch 模式未自动使用分支补全 filename-only 嵌套 jar 坐标",
    )

    interactive_report = project_dir / ".upgrade-report-interactive"
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(interactive_report),
            "--base-branch", "base",
            "--current-branch", "current",
            "--target-module", ".",
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(rc == EXIT_AWAITING_USER, "待交互应返回 awaiting user 退出码")
    interaction_ckpt = read_json(main_state_path(interactive_report))
    interaction_json = read_json(interaction_path(interactive_report))
    assert_true(
        main_state_meta(interaction_ckpt).get("status") == "awaiting_user_input",
        "无自动确认时主状态应进入 awaiting_user_input",
    )
    assert_true(
        ((main_state_meta(interaction_ckpt).get("pending_interaction") or {}).get("step_id")) == "step1",
        "主状态未记录正确的 pending_interaction",
    )
    assert_true(interaction_json.get("step_id") == "step1", "interaction.json 未写入正确 step_id")
    assert_true((interaction_json.get("exit_code")) == EXIT_AWAITING_USER, "interaction.json 未暴露 awaiting user 退出码")
    assert_true(f'"exit_code": {EXIT_AWAITING_USER}' in stdout, "stdout 未输出 awaiting user 退出码")
    assert_true('"status": "awaiting_user_input"' in stdout, "stdout 未输出结构化待交互状态")
    assert_true('"hard_stop": true' in stdout, "stdout 未输出 hard_stop 标记")
    assert_true('"must_wait_for_user_reply": true' in stdout, "stdout 未输出 must_wait_for_user_reply")
    assert_true(interaction_json.get("hard_stop") is True, "interaction.json 未标记 hard_stop")
    assert_true("【分析已暂停，等待你的确认】" in stderr, "stderr 未输出用户任务卡")
    assert_true("为什么暂停" in stderr, "stderr 未说明暂停原因")
    assert_true("AWAITING USER INPUT" not in stderr, "stderr 仍暴露英文状态机提示")
    assert_true(interaction_json.get("runtime_rules"), "interaction.json 未写入 runtime_rules")
    assert_true(
        (interaction_json.get("input_normalization") or {}).get("enabled") is True,
        "interaction.json 未写入 input_normalization.enabled",
    )
    assert_true(
        "rerun_current_step" in ((interaction_json.get("input_normalization") or {}).get("allowed_actions") or []),
        "interaction.json input_normalization 未暴露 rerun_current_step",
    )
    assert_true(
        (interaction_json.get("input_normalization") or {}).get("action_examples"),
        "interaction.json 未写入 input_normalization.action_examples",
    )
    assert_true(interaction_json.get("resume_command_examples"), "interaction.json 未写入恢复命令模板")
    resume_actions = {item.get("action") for item in interaction_json.get("resume_command_examples", []) if isinstance(item, dict)}
    assert_true("continue" in resume_actions, "step1 恢复模板未包含 continue")
    assert_true("rerun_current_step" in resume_actions, "step1 恢复模板未包含 rerun_current_step")
    assert_true("restart_from_step" in resume_actions, "step1 恢复模板未包含 restart_from_step")
    assert_true("cancel" in resume_actions, "step1 恢复模板未包含 cancel")
    assert_true("NEXT ACTION ONLY" not in stderr, "stderr 仍暴露内部 next action 规则")
    step1_event_line = next(line for line in stdout.splitlines() if line.startswith("JUA_CONFIRMATION_JSON:"))
    step1_stdout_event = json.loads(step1_event_line.split(":", 1)[1])
    assert_true(step1_stdout_event.get("schema") == "java-upgrade-analyzer.confirmation.v1", "stdout 未输出单个 confirmation JSON")
    assert_true("next_action_rule" in step1_stdout_event, "confirmation JSON 未暴露 next_action_rule")
    assert_true('"input_normalization"' in stdout, "stdout 未输出 input_normalization")
    assert_true(
        "rerun_current_step" in {item.get("id") for item in interaction_json.get("options", [])},
        "step1 待交互未提供按模块重跑动作",
    )
    assert_true(
        "restart_from_step" in {item.get("id") for item in interaction_json.get("options", [])},
        "step1 待交互未提供从指定步骤重跑动作",
    )
    manifest_steps = read_json(SCRIPT_DIR / "step_manifest.json").get("steps", [])
    manifest_statuses = {step.get("id"): ((step.get("interaction") or {}).get("status")) for step in manifest_steps}
    assert_true(manifest_statuses.get("step4") == "awaiting_user_input", "step_manifest step4 仍未同步为 awaiting_user_input")
    assert_true(manifest_statuses.get("step5") == "awaiting_user_input", "step_manifest step5 仍未同步为 awaiting_user_input")
    continue_response = project_dir / "step1_continue_response.json"
    write_text(
        continue_response,
        json.dumps({"action": "continue", "notes": "最终打包依赖范围可信，继续"}, ensure_ascii=False, indent=2),
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(interactive_report),
            "--response-file", str(continue_response),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(
        rc in {0, EXIT_AWAITING_USER},
        "结构化 continue 答复后应要么完成 step2 返回 0，要么进入下一个待交互状态返回 awaiting user 退出码",
    )
    interaction_ckpt = read_json(main_state_path(interactive_report))
    assert_true(main_state_meta(interaction_ckpt).get("completed_step") == "step2", "待交互恢复后应推进到 step2")
    if rc == EXIT_AWAITING_USER:
        resumed_interaction = read_json(interaction_path(interactive_report))
        assert_true(resumed_interaction.get("step_id") == "step2", "待交互恢复后若继续停顿，应停在 step2 交互点")
    assert_true(
        ((main_state_meta(interaction_ckpt).get("last_user_response") or {}).get("payload") or {}).get("notes") == "最终打包依赖范围可信，继续",
        "response-file 未写回主状态 state.last_user_response",
    )

    step2_resume_report = project_dir / ".upgrade-report-step2-resume"
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(step2_resume_report),
            "--base-branch", "base",
            "--current-branch", "current",
            "--target-module", ".",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "step2_resume 首轮 Step1 应进入 awaiting_user_input，而不是直接返回 0",
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(step2_resume_report),
            "--response-json",
            json.dumps(
                {
                    "action": "continue",
                    "notes": "继续进入 Step2 上下文确认",
                },
                ensure_ascii=False,
            ),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(rc == EXIT_AWAITING_USER, "Step2 待交互应返回 awaiting user 退出码")
    step2_interaction = read_json(interaction_path(step2_resume_report))
    assert_true(step2_interaction.get("step_id") == "step2", "Step2 交互点未正确写入 interaction.json")
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(step2_resume_report),
            "--response-json",
            json.dumps(
                {
                    "action": "continue",
                    "base_branch": "base",
                    "current_branch": "current",
                    "notes": "修正 Step2 上下文口径",
                },
                ensure_ascii=False,
            ),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(
        rc == 0,
        "Step2 恢复后应成功进入 Step3\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}",
    )
    step2_resume_ckpt = read_json(main_state_path(step2_resume_report))
    step2_resume_ctx = read_json(context_path(step2_resume_report))
    assert_true(main_state_meta(step2_resume_ckpt).get("completed_step") == "step3", "Step2 恢复后应继续执行到 step3")
    assert_true(step2_resume_ctx.get("base_branch") == "base", "Step2 恢复后未回写 s2_context.json.base_branch")
    assert_true(step2_resume_ctx.get("current_branch") == "current", "Step2 恢复后未回写 s2_context.json.current_branch")
    assert_true(
        len(step2_resume_ctx.get("changed_dependencies") or []) > 0,
        "Step2 恢复后未重建 changed_dependencies",
    )

    step2_hint_accept_report = project_dir / ".upgrade-report-step2-hint-accept"
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(step2_hint_accept_report),
            "--base-branch", "base",
            "--current-branch", "current",
            "--target-module", ".",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "step2_hint_accept 首轮 Step1 应进入 awaiting_user_input，而不是直接返回 0",
    )
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(step2_hint_accept_report),
            "--response-json",
            json.dumps(
                {
                    "action": "continue",
                    "notes": "继续进入 Step2 上下文确认",
                },
                ensure_ascii=False,
            ),
        ],
        cwd=project_dir,
        env={},
    )
    assert_true(rc == EXIT_AWAITING_USER, "source_repo_hints 场景下 Step2 待交互应返回 awaiting user 退出码")
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(step2_hint_accept_report),
            "--response-json",
            json.dumps(
                {
                    "action": "continue",
                    "base_branch": "base",
                    "current_branch": "current",
                    "source_repo_hints": [str(dep_repo)],
                    "accept_suggested_mappings": True,
                    "notes": "接受源码线索自动识别出的依赖源码目录",
                },
                ensure_ascii=False,
            ),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(
        rc == 0,
        "接受 source_repo_hints 建议后应成功进入 Step3\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}",
    )
    step2_hint_accept_ckpt = read_json(main_state_path(step2_hint_accept_report))
    step2_hint_accept_main_state = read_json(main_state_path(step2_hint_accept_report))
    step2_hint_accept_runtime = (
        ((step2_hint_accept_main_state.get("step2") or {}).get("input") or {})
    )
    assert_true(
        step2_hint_accept_runtime.get("dependency_source_dirs") == [str(dep_repo.resolve())],
        "accept_suggested_mappings 未把 source_repo_hints 建议落为 dependency_source_dirs",
    )
    assert_true(
        main_state_step_input(step2_hint_accept_ckpt, "step2").get("dependency_source_dirs") == [str(dep_repo.resolve())],
        "接受 source_repo_hints 建议后，step2.input 未保留 dependency_source_dirs",
    )

    module_report = project_dir / ".upgrade-report-module-scope"
    write_text(project_dir / "s1_deps_base_modules.txt", build_multimodule_maven_tree("1.0.0", "1.0.0"))
    write_text(project_dir / "s1_deps_current_modules.txt", build_multimodule_maven_tree("2.0.0", "1.1.0"))
    module_direct_report = project_dir / ".upgrade-report-module-direct"
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(module_direct_report),
            "--base-branch", "base",
            "--current-branch", "current",
            "--primary-module", "module-a",
            "--modules", "module-a",
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "首轮已显式传入模块范围时，Step1 应直接按模块结果进入待交互\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}",
    )
    module_direct_rows = read_csv(dep_changes_path(module_direct_report))
    module_direct_coords = {row.get("coord") for row in module_direct_rows}
    assert_true("com.example:demo-lib" in module_direct_coords, "首轮模块级 Step1 未保留目标模块依赖")
    assert_true("com.example:other-lib" not in module_direct_coords, "首轮模块级 Step1 不应包含其他模块依赖")

    (project_dir / "module-a" / "target").mkdir(parents=True, exist_ok=True)
    create_fake_boot_jar(
        project_dir / "module-a" / "target" / "module-a-2.0.0.jar",
        [("com.example", "demo-lib", "2.0.0")],
    )
    module_packaged_report = project_dir / ".upgrade-report-module-packaged"
    run_script(
        "s1_dep_diff.py",
        [
            "--base", "base",
            "--current", "current",
            "--primary-module", "module-a",
            "--modules", "module-a",
            "--work-dir", str(project_dir),
            "--output", str(dep_changes_path(module_packaged_report)),
        ],
        cwd=project_dir,
        env=dep_env,
    )
    packaged_current_rows = read_csv(deps_current_resolved_path(module_packaged_report))
    packaged_current_by_coord = {row.get("coord"): row for row in packaged_current_rows}
    assert_true(
        packaged_current_by_coord.get("com.example:demo-lib", {}).get("packaged_present") == "true",
        "指定模块存在 fat jar 时，demo-lib 应标记为已进入最终制品",
    )
    assert_true(
        "junit:junit" not in packaged_current_by_coord,
        "指定模块 fat jar 未包含 junit 时，不应再把 tree-only 依赖混入最终制品结果",
    )
    packaged_changes = read_csv(dep_changes_path(module_packaged_report))
    junit_rows = [row for row in packaged_changes if row.get("coord") == "junit:junit"]
    assert_true(
        not junit_rows,
        "当前 final_artifact 口径下，不应再把 junit 这类 tree-only 依赖写入 s1_dep_changes.csv",
    )
    packaged_summary_text = (
        module_packaged_report / "evidence" / "dependencies" / "dep_summary.txt"
    ).read_text(encoding="utf-8")
    assert_true(
        (
            "current 打包模式：final_artifact" in packaged_summary_text
            or "current_packaging_mode=final_artifact" in packaged_summary_text
        ),
        "Step1 摘要应标明当前侧已启用 final_artifact 校准",
    )
    assert_true("current_tree_only=" not in packaged_summary_text, "final_artifact 口径下不应再输出 dependency:tree-only 摘要")

    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(module_report),
            "--base-branch", "base",
            "--current-branch", "current",
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(rc == EXIT_AWAITING_USER, "模块场景首次 Step1 待交互应返回 awaiting user 退出码")
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(module_report),
            "--response-json",
            json.dumps(
                {
                    "action": "continue",
                    "target_module": "module-a",
                    "notes": "先收敛到 module-a",
                },
                ensure_ascii=False,
            ),
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(
        rc in {0, EXIT_AWAITING_USER},
        "按模块重跑 Step1 应成功返回或重新进入待交互\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}",
    )
    module_ckpt = read_json(main_state_path(module_report))
    module_interaction = read_json(interaction_path(module_report))
    module_output = dep_changes_path(module_report)
    assert_true(main_state_meta(module_ckpt).get("completed_step") == "step1", "按模块重跑后应仍停留在 step1 确认点")
    assert_true(main_state_meta(module_ckpt).get("status") == "awaiting_user_input", "按模块重跑后应重新进入 awaiting_user_input")
    assert_true(module_interaction.get("step_id") == "step1", "按模块重跑后 interaction 应重新指向 step1")
    if module_output.exists():
        module_rows = read_csv(module_output)
        module_coords = {row.get("coord") for row in module_rows}
        assert_true("com.example:demo-lib" in module_coords, "模块级 Step1 未保留目标模块依赖")
        assert_true("com.example:other-lib" not in module_coords, "模块级 Step1 不应继续包含其他模块依赖")
    else:
        assert_true(
            module_interaction.get("kind") == "execution_blocked",
            "按模块重跑后若未生成新产物，必须显式暴露 execution_blocked，而不是静默复用旧 root 结果",
        )
    assert_true(
        main_state_step_input(module_ckpt, "step1").get("primary_module") == "module-a",
        "结构化答复未写回 step1.input.primary_module",
    )
    assert_true(
        main_state_step_input(module_ckpt, "step1").get("modules") == ["module-a"],
        "结构化答复未写回 step1.input.modules",
    )

    module_stale_report = project_dir / ".upgrade-report-module-stale"
    write_text(module_stale_report / "s1_deps_base.txt", build_maven_tree("1.0.0"))
    write_text(module_stale_report / "s1_deps_current.txt", build_maven_tree("2.0.0"))
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step1",
            "--project-dir", str(project_dir),
            "--report-dir", str(module_stale_report),
            "--base-branch", "base",
            "--current-branch", "current",
            "--primary-module", "module-a",
            "--modules", "module-a",
        ],
        cwd=project_dir,
        env={**dep_env},
    )
    assert_true(
        rc == EXIT_AWAITING_USER,
        "report_dir 中残留旧 root 依赖树时，Step1 仍应按模块范围重跑并进入待交互，而不是复用旧结果\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}",
    )
    stale_ckpt = read_json(main_state_path(module_stale_report))
    stale_interaction = read_json(interaction_path(module_stale_report))
    stale_rows = read_csv(dep_changes_path(module_stale_report))
    stale_coords = {row.get("coord") for row in stale_rows}
    assert_true(main_state_meta(stale_ckpt).get("status") == "awaiting_user_input", "模块范围与旧 root 依赖树并存时，应以新的模块级结果进入 awaiting_user_input")
    assert_true(main_state_meta(stale_ckpt).get("completed_step") == "step1", "模块范围与旧 root 依赖树并存时，应完成新的 step1 并重新进入确认点")
    assert_true(stale_interaction.get("step_id") == "step1", "模块范围与旧 root 依赖树并存时，interaction 应重新指向 step1")
    assert_true("com.example:demo-lib" in stale_coords, "旧 root 依赖树残留时，新的模块级 Step1 仍应保留目标模块依赖")
    assert_true("com.example:other-lib" not in stale_coords, "旧 root 依赖树残留时，新的模块级 Step1 不应复用其他模块依赖")

    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(orchestrated_report),
            "--response-json",
            json.dumps({"action": "continue", "notes": "继续进入 Step2"}, ensure_ascii=False),
        ],
        cwd=project_dir,
    )
    assert_true(
        rc in {0, EXIT_AWAITING_USER},
        "run_step auto 从 step1 恢复后应要么完成到 step3，要么停在 step2 待交互",
    )
    orchestrated_ckpt = read_json(main_state_path(orchestrated_report))
    assert_true(main_state_meta(orchestrated_ckpt).get("completed_step") == "step2", "run_step auto 未从主状态续跑到 step2")
    if rc == EXIT_AWAITING_USER:
        orchestrated_interaction = read_json(interaction_path(orchestrated_report))
        assert_true(orchestrated_interaction.get("step_id") == "step2", "run_step auto 首次恢复后若停顿，应停在 step2")
    else:
        assert_true(main_state_meta(orchestrated_ckpt).get("current_step") == "step3", "run_step Step2 未指向 step3")

    if main_state_meta(orchestrated_ckpt).get("status") == "awaiting_user_input":
        stdout, stderr, rc = run_script_with_rc(
            "run_step.py",
            [
                "--step", "auto",
                "--project-dir", str(project_dir),
                "--report-dir", str(orchestrated_report),
                "--response-json",
                json.dumps(
                    {
                        "action": "continue",
                        "base_branch": "base",
                        "current_branch": "current",
                        "source_dirs": [str((project_dir / "src" / "main" / "java").resolve())],
                        "dependency_source_dirs": [str(dep_repo.resolve())],
                        "notes": "清理 step2 待交互，继续进入 step3/step4",
                    },
                    ensure_ascii=False,
                ),
            ],
            cwd=project_dir,
            env={**dep_env},
        )
        assert_true(
            rc == 0,
            "orchestrated step2 恢复后应成功进入 step3\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}",
        )

    (dep_changes_path(orchestrated_report)).unlink()
    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(orchestrated_report),
            "--base-branch", "base",
            "--current-branch", "current",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        rc in {0, EXIT_AWAITING_USER},
        "checkpoint 自愈后应要么完成 step1->step2，要么重跑 step1 后重新进入待交互",
    )
    repaired_ckpt = read_json(main_state_path(orchestrated_report))
    assert_true(main_state_meta(repaired_ckpt).get("completed_step") == "step1", "主状态自愈后应回退到缺失产物对应的 step1")
    assert_true(main_state_meta(repaired_ckpt).get("current_step") == "step2", "主状态自愈后重跑 step1 应重新指向 step2")
    if rc == EXIT_AWAITING_USER:
        repaired_interaction = read_json(interaction_path(orchestrated_report))
        assert_true(repaired_interaction.get("step_id") == "step1", "主状态自愈后若需再次确认，应回到 step1 交互点")
    assert_true(
        (repaired_ckpt.get("integrity_repair") or {}).get("restart_from_step") in {None, "step1"},
        "主状态自愈后的 integrity_repair 字段不符合预期"
    )
    assert_true((dep_changes_path(orchestrated_report)).exists(), "checkpoint 自愈后未重新生成缺失产物")

    # 【修复】不手动清空 pending_interaction，而是通过正确的交互流程继续
    # 这确保调度状态机和恢复协议按预期工作
    repaired_ckpt_after_interaction = read_json(main_state_path(orchestrated_report))

    # 如果自愈后仍然在 step1 的 checkpoint，需要通过交互继续
    if main_state_meta(repaired_ckpt_after_interaction).get("status") == "awaiting_user_input":
        # 先确认 step1 的依赖范围
        run_script(
            "run_step.py",
            [
                "--step", "auto",
                "--project-dir", str(project_dir),
                "--report-dir", str(orchestrated_report),
                "--response-json",
                json.dumps({"action": "continue", "notes": "确认依赖范围，继续"}, ensure_ascii=False),
            ],
            cwd=project_dir,
            allow_awaiting=True,  # 允许进入下一个 checkpoint
        )

    pre_step3_ckpt = read_json(main_state_path(orchestrated_report))
    if main_state_meta(pre_step3_ckpt).get("status") == "awaiting_user_input":
        pre_step3_interaction = read_json(interaction_path(orchestrated_report))
        if pre_step3_interaction.get("step_id") == "step2":
            stdout, stderr, rc = run_script_with_rc(
                "run_step.py",
                [
                    "--step", "auto",
                    "--project-dir", str(project_dir),
                    "--report-dir", str(orchestrated_report),
                    "--response-json",
                    json.dumps(
                        {
                            "action": "continue",
                            "base_branch": "base",
                            "current_branch": "current",
                            "source_dirs": [str((project_dir / "src" / "main" / "java").resolve())],
                        "dependency_source_dirs": [str(dep_repo.resolve())],
                            "notes": "补齐 step2 确认后继续进入 step3",
                        },
                        ensure_ascii=False,
                    ),
                ],
                cwd=project_dir,
                env={**dep_env},
            )
            assert_true(
                rc == 0,
                "进入 step3 前若仍停在 step2，应可通过 continue 成功推进\n"
                f"stdout:\n{stdout}\n"
                f"stderr:\n{stderr}",
            )
            pre_step3_ckpt = read_json(main_state_path(orchestrated_report))
    assert_true(
        main_state_meta(pre_step3_ckpt).get("status") != "awaiting_user_input",
        "进入 step3 前不应仍残留待交互主状态",
    )

    run_script(
        "run_step.py",
        [
            "--step", "step3",
            "--project-dir", str(project_dir),
            "--report-dir", str(orchestrated_report),
        ],
        cwd=project_dir,
        env=dep_env,
    )

    stdout, stderr, rc = run_script_with_rc(
        "run_step.py",
        [
            "--step", "step4",
            "--project-dir", str(project_dir),
            "--report-dir", str(orchestrated_report),
            "--base-branch", "base",
            "--current-branch", "current",
        ],
        cwd=project_dir,
        env=dep_env,
    )
    assert_true(
        rc in {0, EXIT_AWAITING_USER},
        "step4 首轮应要么完成，要么进入待交互 checkpoint\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}",
    )

    # Step4 完成后的 checkpoint 确认
    step4_ckpt = read_json(main_state_path(orchestrated_report))
    step5_invoked_via_resume = False
    step5_stdout = ""
    step5_stderr = ""
    step5_rc = None
    if main_state_meta(step4_ckpt).get("status") == "awaiting_user_input":
        stdout, stderr, rc = run_script_with_rc(
            "run_step.py",
            [
                "--step", "auto",
                "--project-dir", str(project_dir),
                "--report-dir", str(orchestrated_report),
                "--response-json",
                json.dumps({"action": "continue", "notes": "接受 Step4 证据池"}, ensure_ascii=False),
            ],
            cwd=project_dir,
        )
        assert_true(
            rc in {0, EXIT_AWAITING_USER},
            "Step4 恢复后应要么完成 step5，要么进入 step5 待交互\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}",
        )
        if rc == EXIT_AWAITING_USER:
            resumed_interaction = read_json(interaction_path(orchestrated_report))
            assert_true(resumed_interaction.get("step_id") == "step5", "Step4 恢复后若继续停顿，应停在 step5")
            step5_invoked_via_resume = True
            step5_stdout, step5_stderr, step5_rc = stdout, stderr, rc

    if not step5_invoked_via_resume:
        step5_stdout, step5_stderr, step5_rc = run_script_with_rc(
            "run_step.py",
            [
                "--step", "step5",
                "--project-dir", str(project_dir),
                "--report-dir", str(orchestrated_report),
                # 【修复】不显式传 --source-dirs，测试从 context 恢复的场景
                # 但提供 --allow-degraded 以避免阻塞
                "--allow-degraded",
                "--max-depth", "3",
            ],
            cwd=project_dir,
            env={},
        )
    assert_true(
        step5_rc == EXIT_AWAITING_USER,
        "Step5 在无自动确认时应进入待交互状态\n"
        f"stdout:\n{step5_stdout}\n"
        f"stderr:\n{step5_stderr}",
    )
    # Phase 7.5 removed: step5 processes all_changed_apis.csv directly (no filtering)
    orchestrated_all_changed = read_csv(orchestrated_report / "evidence" / "api_changes" / "all_changed_apis.csv")
    assert_true(orchestrated_all_changed, "orchestrated step5 未产出分析结果")
    orchestrated_summary = read_json(orchestrated_report / "evidence" / "call_chain" / "summary.json")
    orchestrated_per_dependency = read_json(
        orchestrated_report / "evidence" / "api_changes" / run_step_module.PER_DEPENDENCY_DIRNAME / "com.example_demo-lib" / "summary.json"
    )
    orchestrated_total = orchestrated_summary.get("total_apis", 0)
    assert_true(orchestrated_total >= 1, "orchestrated step5 应处理 all_changed_apis.csv 中的全部 API")
    step5_interaction = read_json(interaction_path(orchestrated_report))
    step5_actions = {item.get("id") for item in step5_interaction.get("options", [])}
    step5_props = (step5_interaction.get("response_schema") or {}).get("properties", {})
    assert_true(step5_interaction.get("step_id") == "step5", "Step5 交互点未正确写入 interaction.json")
    assert_true("rerun_current_step" in step5_actions, "Step5 交互未提供 rerun_current_step")
    assert_true("dependency_source_dirs" in step5_props, "Step5 交互未暴露 dependency_source_dirs 字段")
    assert_true("dependency_source_mappings" not in step5_props, "Step5 交互不应再暴露 dependency_source_mappings 字段")
    assert_true(
        orchestrated_per_dependency.get("step5", {}).get("final_status"),
        "orchestrated Step5 未写出 per_dependency final_status",
    )

    run_script(
        "run_step.py",
        [
            "--step", "auto",
            "--project-dir", str(project_dir),
            "--report-dir", str(orchestrated_report),
            "--response-json",
            json.dumps({"action": "continue", "notes": "接受 Step5 影响结论，生成最终报告"}, ensure_ascii=False),
        ],
        cwd=project_dir,
    )
    orchestrated_ckpt = read_json(main_state_path(orchestrated_report))
    assert_true(main_state_meta(orchestrated_ckpt).get("completed_step") == "step6", "run_step Step6 未写入完成状态")
    assert_true(main_state_meta(orchestrated_ckpt).get("current_step") == "done", "run_step Step6 后 current_step 应为 done")
    assert_true(
        bool(main_state_step_output(orchestrated_ckpt, "step5")),
        "run_step 主状态未保留 step5 的输出结果"
    )
    orchestrated_report_text = (orchestrated_report / "deliverables" / "report.md").read_text(encoding="utf-8")
    assert_true("# Java 升级兼容性分析报告" in orchestrated_report_text, "run_step 链路未生成最终报告")
    assert_true("分析结果总表" in orchestrated_report_text, "run_step 链路未在 Step6 报告中呈现分析结果总表")



if __name__ == "__main__":
    sys.exit(main())
