#!/usr/bin/env python3
"""Validate the public Claude Code skill from a clean copied checkout."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


PUBLIC_SCRIPT_RE = re.compile(r"\$\{CLAUDE_SKILL_DIR\}/(scripts/[A-Za-z0-9_./-]+\.py)")
REPORT_ARG_RE = re.compile(r"--report-dir\s+([^\s\\]+)")


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
    )


def run_skill_contract(repo_root: Path, workspace: Path) -> SkillContractReport:
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
    failed_resume = _run(
        [
            sys.executable, str(skill_root / "scripts" / "run_step.py"),
            "--step", "auto",
            "--project-dir", str(fixture),
            "--report-dir", str(report_dir),
            "--response-json", '{"intent_patch":{"action":"continue"}}',
        ],
        fixture,
    )
    if failed_resume.returncode == 0:
        errors.append("invalid_resume_was_accepted")
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
    )
