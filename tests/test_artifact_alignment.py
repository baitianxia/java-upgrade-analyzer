import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import artifact_alignment  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402


class ArtifactAlignmentTest(unittest.TestCase):
    def make_project(self, root):
        project = Path(root) / "project"
        artifact = project / "app" / "target" / "app.jar"
        artifact.parent.mkdir(parents=True)
        (project / "app" / "pom.xml").write_text("<project/>", encoding="utf-8")
        artifact.write_bytes(b"current artifact")
        subprocess.run(["git", "init", "-q", str(project)], check=True)
        subprocess.run(["git", "-C", str(project), "add", "."], check=True)
        subprocess.run(
            [
                "git", "-C", str(project), "-c", "user.name=Test",
                "-c", "user.email=test@example.com", "commit", "-qm", "fixture",
            ],
            check=True,
        )
        revision = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
        return project, artifact, revision, sha

    def test_internal_clean_build_is_aligned(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, artifact, revision, sha = self.make_project(tmp)
            record = artifact_alignment.build_artifact_alignment(
                project,
                artifact,
                target_module="app",
                build_command=("mvn", "-pl", "app", "package"),
                build_profile="prod",
                expected_revision=revision,
                expected_sha256=sha,
                internally_built=True,
            )

        self.assertEqual(record.status, "aligned")
        self.assertEqual(record.git_revision, revision)
        self.assertEqual(record.artifact_sha256, sha)
        self.assertEqual(record.dirty_paths, ())

    def test_external_artifact_without_manifest_is_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, artifact, _revision, _sha = self.make_project(tmp)
            record = artifact_alignment.build_artifact_alignment(
                project, artifact, target_module="app", internally_built=False
            )

        self.assertEqual(record.status, "unverified")
        self.assertIn("external_artifact_manifest_missing", record.reasons)

    def test_dirty_tree_cannot_be_aligned(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, artifact, revision, sha = self.make_project(tmp)
            (project / "app" / "pom.xml").write_text("dirty", encoding="utf-8")
            record = artifact_alignment.build_artifact_alignment(
                project, artifact, target_module="app", expected_revision=revision,
                expected_sha256=sha, internally_built=True,
            )

        self.assertEqual(record.status, "unverified")
        self.assertIn("source_worktree_dirty", record.reasons)

    def test_revision_sha_and_module_mismatches_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, artifact, _revision, _sha = self.make_project(tmp)
            record = artifact_alignment.build_artifact_alignment(
                project,
                artifact,
                target_module="wrong-module",
                expected_revision="f" * 40,
                expected_sha256="0" * 64,
                internally_built=True,
            )

        self.assertEqual(record.status, "unverified")
        self.assertEqual(
            set(record.reasons),
            {"source_revision_mismatch", "artifact_sha256_mismatch", "target_module_mismatch"},
        )

    def test_missing_artifact_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, _artifact, revision, _sha = self.make_project(tmp)
            record = artifact_alignment.build_artifact_alignment(
                project, project / "app/target/missing.jar", target_module="app",
                expected_revision=revision, internally_built=True,
            )

        self.assertEqual(record.status, "invalid")
        self.assertIn("artifact_missing", record.reasons)

    def test_step5_accepts_sha_and_revision_pinned_external_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, artifact, revision, sha = self.make_project(tmp)
            report = Path(tmp) / "report"
            dependencies = report / "evidence" / "dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.build-provenance.v1",
                    "sides": [{
                        "side": "current",
                        "source_mode": "provided_artifact",
                        "revision": revision,
                        "target_module": "app",
                        "artifact_path": str(artifact),
                        "artifact_sha256": sha,
                    }],
                }),
                encoding="utf-8",
            )

            result = step5.assess_source_artifact_alignment(
                report, [str(project / "app")]
            )

        self.assertEqual(result["status"], "aligned")
        self.assertEqual(result["reason_codes"], [])
        self.assertEqual(result["expected_revision"], revision)


if __name__ == "__main__":
    unittest.main()
