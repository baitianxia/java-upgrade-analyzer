#!/usr/bin/env python3
"""Validate the public Claude Code skill from a clean copied checkout."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

from compat import git_cmd, run_cmd, subprocess_platform_kwargs


PUBLIC_SCRIPT_RE = re.compile(r"\$\{CLAUDE_SKILL_DIR\}/(scripts/[A-Za-z0-9_./-]+\.py)")
REPORT_ARG_RE = re.compile(r"--report-dir\s+([^\s\\]+)")
PHASE_HEADING_RE = re.compile(
    r"^### Phase\s+\d+\s+\[(?P<mode>AUTO|CHECKPOINT)\].*$",
    re.MULTILINE,
)
PHASE_STEP_RE = re.compile(r"^- 对应步骤：`(?P<step>step[1-6])`", re.MULTILINE)

# Public-contract metamorphic variants change only a supported custom Manifest
# attribute on both sides.  The attribute values alter artifact bytes while
# leaving the declared removed-method truth unchanged.
TRANSFORM_IDS = (
    "manifest_attribute_alpha",
    "manifest_attribute_beta",
    "manifest_attribute_gamma",
    "manifest_attribute_delta",
)


@dataclass(frozen=True)
class SkillContractReport:
    status: str
    errors: tuple[str, ...]
    describe_returncode: int
    first_returncode: int
    rerun_returncode: int
    failed_resume_returncode: int
    first_state_sha256: str
    rerun_state_sha256: str
    clean_copy_without_report_state: bool
    completed_step: str = ""
    deliverables_verified: bool = False
    successful_rerun_returncode: int = -1
    step4_api_count: int = 0
    step5_accounted_api_count: int = 0
    current_artifact_sha256: str = ""


def audit_public_contract(root: Path) -> tuple[str, ...]:
    root = Path(root)
    skill = root / "SKILL.md"
    if not skill.is_file():
        return ("missing_skill_md",)
    text = skill.read_text(encoding="utf-8")
    errors = []
    scripts = sorted(set(PUBLIC_SCRIPT_RE.findall(text)))
    if "scripts/run_step.py" not in scripts:
        errors.append("missing_public_run_step_entrypoint")
    for relative in scripts:
        if not (root / relative).is_file():
            errors.append(f"stale_public_script:{relative}")
    for match in REPORT_ARG_RE.finditer(text):
        value = match.group(1).strip('"\'')
        if "$" not in value and ".upgrade-report" not in value:
            errors.append("public_report_path_must_be_upgrade_report")
            break
    for required in (
        ".upgrade-report/.runtime/state/main_state.json",
        ".upgrade-report/.runtime/state/interaction.json",
        "--describe-step1-contract",
        "--response-json",
    ):
        if required not in text:
            errors.append(f"missing_public_contract:{required}")
    manifest_path = root / "scripts" / "step_manifest.json"
    if manifest_path.is_file():
        try:
            manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_steps = {
                str(item.get("id") or ""): item
                for item in manifest_payload.get("steps") or ()
                if isinstance(item, dict)
            }
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            errors.append("invalid_step_manifest")
            manifest_steps = {}
        headings = list(PHASE_HEADING_RE.finditer(text))
        for index, heading in enumerate(headings):
            if heading.group("mode") != "CHECKPOINT":
                continue
            section_end = (
                headings[index + 1].start()
                if index + 1 < len(headings)
                else len(text)
            )
            step_match = PHASE_STEP_RE.search(text, heading.end(), section_end)
            if not step_match:
                continue
            step_id = step_match.group("step")
            step_meta = manifest_steps.get(step_id) or {}
            if not step_meta.get("interaction"):
                errors.append(
                    f"skill_checkpoint_missing_manifest_interaction:{step_id}"
                )
    return tuple(errors)


def _semantic_state_sha(path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))

    def normalize(value):
        if isinstance(value, dict):
            return {
                key: normalize(item)
                for key, item in sorted(value.items())
                if key not in {"generated_at", "updated_at", "timestamp"}
            }
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, str) and Path(value).is_absolute():
            return "<ABSOLUTE_PATH>"
        return value

    encoded = json.dumps(normalize(payload), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _run(command, cwd):
    return subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        **subprocess_platform_kwargs(),
    )


def _compile_java(source: Path, output: Path, *, classpath: Path | None = None):
    output.mkdir(parents=True, exist_ok=True)
    command = ["javac", "-encoding", "UTF-8", "-d", str(output)]
    if classpath is not None:
        command.extend(["-classpath", str(classpath)])
    command.append(str(source))
    completed = _run(command, source.parent)
    if completed.returncode != 0:
        raise RuntimeError(f"javac fixture failed: {completed.stderr}")


def _write_library_jar(
    path: Path, classes: Path, version: str, artifact_variant: str = ""
):
    properties = (
        "groupId=contract\nartifactId=demo-lib\n"
        f"version={version}\n"
    ).encode("utf-8")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        manifest = "Manifest-Version: 1.0\n"
        if artifact_variant:
            manifest += f"X-Contract-Variant: {artifact_variant}\n"
        archive.writestr("META-INF/MANIFEST.MF", manifest + "\n")
        for class_file in sorted(classes.rglob("*.class")):
            archive.write(class_file, class_file.relative_to(classes).as_posix())
        archive.writestr(
            "META-INF/maven/contract/demo-lib/pom.properties", properties
        )


def _write_fat_jar(
    path: Path, app_classes: Path, library: Path, artifact_variant: str = ""
):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        manifest = "Manifest-Version: 1.0\nMain-Class: contract.App\n"
        if artifact_variant:
            manifest += f"X-Contract-Variant: {artifact_variant}\n"
        archive.writestr("META-INF/MANIFEST.MF", manifest + "\n")
        for class_file in sorted(app_classes.rglob("*.class")):
            archive.write(
                class_file,
                "BOOT-INF/classes/" + class_file.relative_to(app_classes).as_posix(),
            )
        archive.write(library, f"BOOT-INF/lib/{library.name}")


def _write_classes_jar(path: Path, classes: Path):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for class_file in sorted(classes.rglob("*.class")):
            archive.write(class_file, class_file.relative_to(classes).as_posix())


def _current_jdk_home(cwd: Path) -> Path:
    stdout, stderr, returncode = run_cmd(
        ["java", "-XshowSettings:properties", "-version"],
        cwd=str(cwd),
        timeout=30,
    )
    if returncode != 0:
        raise RuntimeError(f"java_home_probe_failed:{stderr or stdout}")
    match = re.search(r"(?m)^\s*java\.home\s*=\s*(.+?)\s*$", f"{stdout}\n{stderr}")
    if not match:
        raise RuntimeError("java_home_probe_missing")
    return Path(match.group(1)).resolve()


def _materialize_complete_fixture(
    fixture: Path, artifact_variant: str = ""
) -> tuple[Path, Path, Path, Path]:
    build = fixture / "contract-build"
    old_source = build / "old-src" / "contract" / "Target.java"
    new_source = build / "new-src" / "contract" / "Target.java"
    app_source = fixture / "src" / "main" / "java" / "contract" / "App.java"
    for path, content in (
        (old_source, "package contract; public class Target { public String removed() { return \"old\"; } }\n"),
        (new_source, "package contract; public class Target { }\n"),
        (app_source, "package contract; public class App { public String run(Target target) { return target.removed(); } }\n"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    old_classes = build / "old-classes"
    new_classes = build / "new-classes"
    app_classes = build / "app-classes"
    _compile_java(old_source, old_classes)
    _compile_java(new_source, new_classes)
    _compile_java(app_source, app_classes, classpath=old_classes)
    old_library = build / "demo-lib-1.0.jar"
    new_library = build / "demo-lib-2.0.jar"
    _write_library_jar(old_library, old_classes, "1.0", artifact_variant)
    _write_library_jar(new_library, new_classes, "2.0", artifact_variant)
    base_artifact = build / "app-base.jar"
    current_artifact = build / "app-current.jar"
    _write_fat_jar(base_artifact, app_classes, old_library, artifact_variant)
    _write_fat_jar(current_artifact, app_classes, new_library, artifact_variant)
    business_jar = build / "business-classes.jar"
    _write_classes_jar(business_jar, app_classes)
    jdk_home = _current_jdk_home(fixture)
    loader_topology = {
        "coverage_status": "complete",
        "entrypoint_realms": ["application-loader"],
        "realms": [
            {
                "identity": "platform-loader",
                "kind": "platform",
                "delegation": "parent_first",
                "module_mode": "named-platform",
            },
            {
                "identity": "application-loader",
                "kind": "application",
                "parent": "platform-loader",
                "delegation": "parent_first",
                "module_mode": "unnamed",
            },
        ],
    }
    entrypoints = {
        "coverage_status": "complete",
        "methods": [{
            "initiating_loader_realm_identity": "application-loader",
            "class_name": "contract/App",
            "member_name": "run",
            "descriptor": "(Lcontract/Target;)Ljava/lang/String;",
        }],
    }

    def side(outer: Path, library: Path, version: str):
        return {
            "jdk_home": str(jdk_home),
            "artifacts": [
                {
                    "path": str(business_jar),
                    "outer_artifact_path": str(outer),
                    "container_entry": "BOOT-INF/classes/",
                    "logical_location": "app/business-classes",
                    "loader_realm": "application-loader",
                    "path_kind": "business_classes",
                    "slot": 0,
                    "coord": "contract:fixture:1",
                    "lineage": "contract:fixture",
                    "runtime_code_source_origin_identity": "fixture-application",
                },
                {
                    "path": str(library),
                    "outer_artifact_path": str(outer),
                    "container_entry": f"BOOT-INF/lib/{library.name}",
                    "logical_location": "lib/demo-lib.jar",
                    "loader_realm": "application-loader",
                    "path_kind": "nested_runtime",
                    "slot": 1,
                    "coord": f"contract:demo-lib:{version}",
                    "lineage": "contract:demo-lib",
                    "runtime_code_source_origin_identity": "fixture-demo-lib",
                },
            ],
            "runtime_profile": {
                "container_and_launcher_kind": "spring-boot-fat-jar",
                "loader_topology": loader_topology,
                "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
                "active_profile_identities": [],
                "external_config_snapshot_identities": [],
                "agent_transformer_plugin_profile_identities": [],
                "business_entrypoint_profile": entrypoints,
                "runtime_class_closure_coverage_status": "complete",
                "resource_selection_coverage_status": "complete",
            },
        }

    config_path = build / "binary-pipeline.json"
    config_path.write_text(json.dumps({
        "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
        "base": side(base_artifact, old_library, "1.0"),
        "current": side(current_artifact, new_library, "2.0"),
        "runtime_comparison": {
            "comparison_intent": "same_deployment_profile",
            "profile_correspondence_policy_version": "v1",
            "controlled_profile_fields": ["loader_topology"],
            "declared_upgrade_payload_scope": ["artifact-bytes"],
            "changed_or_unknown_profile_fields": [],
        },
        "source_overlay": {
            "source_sets": [{
                "source_root": str(fixture),
                "source_dirs": [str(app_source.parents[2])],
                "owner_type": "business",
                "owner_coord": "contract:fixture:1",
                "module": ".",
            }],
        },
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return base_artifact, current_artifact, app_source.parents[2], config_path


def _initialize_fixture_remote(fixture: Path, remote: Path) -> str:
    """Give the workflow fixture the same reachable-remote contract as users."""
    fixture = Path(fixture).resolve()
    remote = Path(remote).resolve()

    def git(cwd, *args):
        stdout, stderr, rc = run_cmd(
            git_cmd() + [*args],
            cwd=str(cwd),
            timeout=60,
        )
        if rc != 0:
            raise RuntimeError(
                "skill contract Git fixture failed:"
                f" {' '.join(args)}: {stderr or stdout or f'rc={rc}'}"
            )
        return str(stdout or "").strip()

    git(fixture, "init", "-q")
    git(fixture, "add", "pom.xml", "src")
    git(
        fixture,
        "-c", "user.name=Skill Contract",
        "-c", "user.email=skill-contract@example.invalid",
        "commit", "-qm", "contract fixture base source",
    )
    base_commit = git(fixture, "rev-parse", "HEAD")
    current_marker = fixture / "src" / "main" / "java" / "contract" / "Current.java"
    current_marker.write_text(
        "package contract; final class Current {}\n",
        encoding="utf-8",
    )
    git(fixture, "add", str(current_marker.relative_to(fixture)))
    git(
        fixture,
        "-c", "user.name=Skill Contract",
        "-c", "user.email=skill-contract@example.invalid",
        "commit", "-qm", "contract fixture current source",
    )
    git(remote.parent, "init", "--bare", "-q", str(remote))
    git(fixture, "remote", "add", "origin", str(remote))
    git(
        fixture,
        "push", "-q", "origin",
        f"{base_commit}:refs/heads/base-artifact",
        "HEAD:refs/heads/current-artifact",
    )
    return git(fixture, "rev-parse", "HEAD")


def _state_completed_step(state_path: Path) -> str:
    if not state_path.is_file():
        return ""
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    return str((payload.get("state") or {}).get("completed_step") or "")


def run_skill_contract(
    repo_root: Path,
    workspace: Path,
    *,
    complete_workflow: bool = False,
    artifact_variant: str = "",
) -> SkillContractReport:
    repo_root = Path(repo_root)
    workspace = Path(workspace)
    skill_root = workspace / "clean-skill"
    fixture = workspace / "fixture-project"
    report_dir = fixture / ".upgrade-report"
    shutil.copytree(
        repo_root,
        skill_root,
        ignore=shutil.ignore_patterns(".git", ".upgrade-report", "__pycache__", "*.pyc"),
    )
    fixture.mkdir(parents=True)
    (fixture / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>contract</groupId><artifactId>fixture</artifactId>"
        "<version>1</version></project>\n",
        encoding="utf-8",
    )
    base_artifact = current_artifact = source_root = binary_config = None
    if complete_workflow:
        base_artifact, current_artifact, source_root, binary_config = _materialize_complete_fixture(
            fixture, artifact_variant
        )
        _initialize_fixture_remote(
            fixture,
            workspace / "fixture-origin.git",
        )
    clean = not report_dir.exists() and not (skill_root / ".upgrade-report").exists()
    errors = list(audit_public_contract(skill_root))
    describe = _run(
        [sys.executable, "scripts/run_step.py", "--describe-step1-contract"], skill_root
    )
    try:
        json.loads(describe.stdout)
    except json.JSONDecodeError:
        errors.append("describe_contract_not_json")
    command = [
        sys.executable, str(skill_root / "scripts" / "run_step.py"),
        "--step", "step1",
        "--project-dir", str(fixture),
        "--report-dir", str(report_dir),
    ]
    if complete_workflow:
        command.extend([
            "--base-artifact-path", str(base_artifact),
            "--current-artifact-path", str(current_artifact),
            "--base-branch", "base-artifact",
            "--current-branch", "current-artifact",
            "--source-dirs", str(source_root),
            "--target-module", ".",
            "--binary-pipeline-config", str(binary_config),
        ])
    first = _run(command, fixture)
    state = report_dir / ".runtime" / "state" / "main_state.json"
    interaction = report_dir / ".runtime" / "state" / "interaction.json"
    if first.returncode != 4:
        errors.append(f"first_checkpoint_returncode:{first.returncode}")
    if not state.is_file() or not interaction.is_file():
        errors.append("checkpoint_state_missing")
        first_sha = ""
    else:
        first_sha = _semantic_state_sha(state)
    rerun = _run(command, fixture)
    if rerun.returncode != 4:
        errors.append(f"rerun_checkpoint_returncode:{rerun.returncode}")
    rerun_sha = _semantic_state_sha(state) if state.is_file() else ""
    if first_sha and rerun_sha and first_sha != rerun_sha:
        errors.append("checkpoint_rerun_not_idempotent")
    invalid_report_dir = fixture / ".upgrade-report-invalid-resume"
    if report_dir.is_dir():
        shutil.copytree(report_dir, invalid_report_dir)
    failed_resume = _run(
        [
            sys.executable, str(skill_root / "scripts" / "run_step.py"),
            "--step", "auto",
            "--project-dir", str(fixture),
            "--report-dir", str(invalid_report_dir),
            "--response-json",
            '{"intent_patch":{"action":"continue","set":"not-an-object"}}',
        ],
        fixture,
    )
    if failed_resume.returncode != 1:
        errors.append(f"invalid_resume_returncode:{failed_resume.returncode}")
    if "intent_patch.set 必须是 JSON 对象" not in failed_resume.stderr:
        errors.append("invalid_resume_rejection_reason_mismatch")
    completed_step = _state_completed_step(state)
    deliverables_verified = False
    successful_rerun_returncode = -1
    step4_api_count = 0
    step5_accounted_api_count = 0
    current_artifact_sha256 = ""
    if complete_workflow:
        javac_probe = _run(["javac", "-version"], fixture)
        javac_match = re.search(r"(?:javac\s+)?(\d+)(?:\.|\s|$)", f"{javac_probe.stdout}\n{javac_probe.stderr}")
        fixture_jdk = javac_match.group(1) if javac_match else "17"
        for _ in range(10):
            if completed_step == "step6":
                break
            interaction_payload = {}
            if interaction.is_file():
                interaction_payload = json.loads(interaction.read_text(encoding="utf-8"))
            step_id = str(interaction_payload.get("step_id") or "")
            response = {"action": "continue", "notes": "contract workflow"}
            response_properties = dict(
                (interaction_payload.get("response_schema") or {}).get("properties")
                or {}
            )
            required_fields = list(interaction_payload.get("required_fields") or [])
            known_fixture_values = {
                "target_module": ".",
                "primary_module": ".",
                "base_branch": "base-artifact",
                "current_branch": "current-artifact",
                "jdk_base": fixture_jdk,
                "jdk_current": fixture_jdk,
                "source_dirs": [str(source_root)],
                "accept_suggested_mappings": True,
            }
            for field in required_fields:
                if field in response_properties and field in known_fixture_values:
                    response[field] = known_fixture_values[field]
            if step_id == "step2" and "source_dirs" in response_properties:
                response["source_dirs"] = [str(source_root)]
            if step_id == "step4":
                response["scope_mode"] = "full"
            resume_command = [
                sys.executable, str(skill_root / "scripts" / "run_step.py"),
                "--step", "auto",
                "--project-dir", str(fixture),
                "--report-dir", str(report_dir),
            ]
            if step_id:
                resume_command.extend(["--response-json", json.dumps(response)])
            resumed = _run(resume_command, fixture)
            if resumed.returncode not in (0, 4):
                errors.append(
                    f"workflow_resume_failed:{step_id}:{resumed.returncode}:"
                    f"{resumed.stderr[-500:]}"
                )
                break
            completed_step = _state_completed_step(state)
        if completed_step != "step6":
            errors.append(f"workflow_incomplete:{completed_step or 'none'}")
        deliverables_verified = all(
            path.is_file()
            for path in (
                report_dir / "deliverables" / "report.md",
                report_dir / ".runtime" / "state" / "main_state.json",
            )
        )
        if not deliverables_verified:
            errors.append("workflow_deliverables_missing")
        successful_rerun = _run(
            [
                sys.executable, str(skill_root / "scripts" / "run_step.py"),
                "--step", "step6",
                "--project-dir", str(fixture),
                "--report-dir", str(report_dir),
            ],
            fixture,
        )
        successful_rerun_returncode = successful_rerun.returncode
        if successful_rerun.returncode != 0:
            errors.append(f"successful_rerun_failed:{successful_rerun.returncode}")
        step4_apis = report_dir / "evidence" / "api_changes" / "all_changed_apis.csv"
        if step4_apis.is_file():
            with step4_apis.open(encoding="utf-8-sig", newline="") as handle:
                step4_api_count = sum(1 for _row in csv.DictReader(handle))
        step5_summary = report_dir / "evidence" / "call_chain" / "summary.json"
        if step5_summary.is_file():
            summary_payload = json.loads(step5_summary.read_text(encoding="utf-8"))
            step5_accounted_api_count = int(summary_payload.get("total_apis") or 0)
        if step4_api_count <= 0:
            errors.append("workflow_step4_api_population_empty")
        if step5_accounted_api_count != step4_api_count:
            errors.append(
                f"workflow_step4_step5_scope_mismatch:{step4_api_count}:"
                f"{step5_accounted_api_count}"
            )
        current_artifact_sha256 = hashlib.sha256(
            Path(current_artifact).read_bytes()
        ).hexdigest()
    return SkillContractReport(
        "failed" if errors else "passed",
        tuple(errors),
        describe.returncode,
        first.returncode,
        rerun.returncode,
        failed_resume.returncode,
        first_sha,
        rerun_sha,
        clean,
        completed_step,
        deliverables_verified,
        successful_rerun_returncode,
        step4_api_count,
        step5_accounted_api_count,
        current_artifact_sha256,
    )


def run_skill_contract_metamorphic_matrix(
    repo_root: Path, workspace: Path, variants
) -> dict[str, SkillContractReport]:
    workspace = Path(workspace)
    variant_ids = [str(variant) for variant in variants]

    def run_variant(variant):
        return variant, run_skill_contract(
            repo_root,
            workspace / variant,
            complete_workflow=True,
            artifact_variant=variant,
        )

    # Every variant owns an isolated checkout, remote and report directory.
    # A small bounded pool keeps the public contract test practical without
    # creating a burst of Git/JVM subprocesses on constrained CI workers.
    with ThreadPoolExecutor(max_workers=min(2, len(variant_ids) or 1)) as executor:
        return dict(executor.map(run_variant, variant_ids))
