#!/usr/bin/env python3
"""Bind a deployable artifact to verifiable source and build provenance."""

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import subprocess


@dataclass(frozen=True)
class AlignmentRecord:
    status: str
    project_root: str
    artifact_path: str
    artifact_sha256: str
    git_revision: str
    dirty_paths: tuple[str, ...]
    target_module: str
    build_command: tuple[str, ...]
    build_profile: str
    internally_built: bool
    expected_revision: str
    expected_sha256: str
    reasons: tuple[str, ...]

    def to_dict(self):
        return asdict(self)


def _git(project, *args):
    completed = subprocess.run(
        ["git", "-C", str(project), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_artifact_alignment(
    project_root,
    artifact_path,
    *,
    target_module="",
    build_command=(),
    build_profile="",
    expected_revision="",
    expected_sha256="",
    internally_built=False,
):
    project = Path(project_root).resolve()
    artifact = Path(artifact_path).resolve()
    revision = _git(project, "rev-parse", "HEAD")
    status_text = _git(project, "status", "--porcelain=v1", "--untracked-files=all")
    dirty_paths = tuple(
        sorted(line[3:] for line in status_text.splitlines() if len(line) > 3)
    )
    reasons = []

    if not artifact.is_file():
        reasons.append("artifact_missing")
        artifact_sha = ""
    else:
        artifact_sha = _sha256(artifact)

    if not revision:
        reasons.append("source_revision_unavailable")
    if dirty_paths:
        reasons.append("source_worktree_dirty")
    if expected_revision and revision != expected_revision:
        reasons.append("source_revision_mismatch")
    if expected_sha256 and artifact_sha != expected_sha256:
        reasons.append("artifact_sha256_mismatch")
    if not expected_sha256:
        reasons.append("artifact_sha256_unpinned")

    module = str(target_module or "").strip().strip("/")
    if module and module != ".":
        module_root = (project / module).resolve()
        try:
            artifact.relative_to(module_root)
        except ValueError:
            reasons.append("target_module_mismatch")

    pinned_external = bool(expected_revision and expected_sha256)
    if not internally_built and not pinned_external:
        reasons.append("external_artifact_manifest_missing")

    if "artifact_missing" in reasons or "source_revision_unavailable" in reasons:
        status = "invalid"
    elif reasons:
        status = "unverified"
    else:
        status = "aligned"

    return AlignmentRecord(
        status=status,
        project_root=str(project),
        artifact_path=str(artifact),
        artifact_sha256=artifact_sha,
        git_revision=revision,
        dirty_paths=dirty_paths,
        target_module=module,
        build_command=tuple(str(item) for item in (build_command or ())),
        build_profile=str(build_profile or ""),
        internally_built=bool(internally_built),
        expected_revision=str(expected_revision or ""),
        expected_sha256=str(expected_sha256 or ""),
        reasons=tuple(sorted(set(reasons))),
    )
