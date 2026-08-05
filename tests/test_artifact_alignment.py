import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


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

    def test_internal_artifact_without_pinned_sha_is_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, artifact, revision, _sha = self.make_project(tmp)
            artifact.write_bytes(b"unrelated artifact")
            record = artifact_alignment.build_artifact_alignment(
                project,
                artifact,
                target_module="app",
                expected_revision=revision,
                internally_built=True,
            )

        self.assertEqual(record.status, "unverified")
        self.assertIn("artifact_sha256_unpinned", record.reasons)

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

    def test_step5_alignment_skips_dirty_check_for_compile_modified_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, artifact, revision, sha = self.make_project(tmp)
            generated_source = project / "app" / "src" / "main" / "java"
            generated_source.mkdir(parents=True)
            (generated_source / "GeneratedDao.java").write_text(
                "interface GeneratedDao {}\n", encoding="utf-8"
            )
            (project / "app" / "pom.xml").write_text(
                "<project><properties/></project>\n", encoding="utf-8"
            )
            report = Path(tmp) / "report"
            dependencies = report / "evidence" / "dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.build-provenance.v1",
                    "sides": [{
                        "side": "current",
                        "source_mode": "checkout_build",
                        "revision": revision,
                        "target_module": "app",
                        "artifact_path": str(artifact),
                        "artifact_sha256": sha,
                    }],
                }),
                encoding="utf-8",
            )

            result = step5.assess_source_artifact_alignment(
                report, [str(generated_source)]
            )

        self.assertEqual(result["status"], "aligned")
        self.assertEqual(result["reason_codes"], [])
        self.assertIsNone(result["worktree_dirty"])
        self.assertFalse(result["worktree_dirty_checked"])
        self.assertEqual(result["alignment_record"]["dirty_paths"], ())

    def test_step5_alignment_hashes_retained_artifact_not_deleted_worktree_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, artifact, revision, sha = self.make_project(tmp)
            report = Path(tmp) / "report"
            dependencies = report / "evidence" / "dependencies"
            retained = dependencies / "s1_artifacts" / "current.jar"
            retained.parent.mkdir(parents=True)
            retained.write_bytes(artifact.read_bytes())
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.build-provenance.v1",
                    "sides": [{
                        "side": "current",
                        "source_mode": "checkout_build",
                        "revision": revision,
                        "target_module": "app",
                        "artifact_path": str(retained),
                        "original_artifact_path": str(
                            Path(tmp) / "deleted-worktree/app/target/app.jar"
                        ),
                        "artifact_relative_path": "app/target/app.jar",
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
        self.assertEqual(
            result["alignment_record"]["artifact_path"],
            str(retained.resolve()),
        )
        self.assertEqual(
            result["alignment_record"]["artifact_relative_path"],
            "app/target/app.jar",
        )


class Step5BusinessSourceWorkspaceTest(unittest.TestCase):
    def make_project_history(self, root):
        project = Path(root) / "project"
        source = project / "app" / "src" / "main" / "java"
        source.mkdir(parents=True)
        java_file = source / "Demo.java"
        java_file.write_text("class Demo { int value = 1; }\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(project)], check=True)
        subprocess.run(["git", "-C", str(project), "add", "."], check=True)
        subprocess.run(
            [
                "git", "-C", str(project), "-c", "user.name=Test",
                "-c", "user.email=test@example.com", "commit", "-qm", "base",
            ],
            check=True,
        )
        base_revision = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        java_file.write_text("class Demo { int value = 2; }\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(project), "add", "."], check=True)
        subprocess.run(
            [
                "git", "-C", str(project), "-c", "user.name=Test",
                "-c", "user.email=test@example.com", "commit", "-qm", "current",
            ],
            check=True,
        )
        current_revision = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        return project, source, java_file, base_revision, current_revision

    def write_current_provenance(self, report, revision):
        dependencies = Path(report) / "evidence" / "dependencies"
        dependencies.mkdir(parents=True)
        (dependencies / "build_provenance.json").write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.build-provenance.v1",
                "sides": [{
                    "side": "current",
                    "source_mode": "checkout_build",
                    "revision": revision,
                }],
            }),
            encoding="utf-8",
        )

    def test_clean_matching_checkout_is_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, source, _java_file, _base, current = self.make_project_history(tmp)
            report = Path(tmp) / "report"
            self.write_current_provenance(report, current)

            with step5.materialize_step5_business_source_workspace(
                report, [str(source)]
            ) as workspace:
                self.assertEqual(workspace["mode"], "existing_matching_checkout")
                self.assertEqual(workspace["source_dirs"], [str(source.resolve())])
                self.assertEqual(workspace["temporary_worktree"], "")

            worktrees = subprocess.run(
                ["git", "-C", str(project), "worktree", "list", "--porcelain"],
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertEqual(worktrees.count("worktree "), 1)

    def test_matching_checkout_reuses_untracked_generated_mybatis_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            (project / "pom.xml").write_text("<project/>\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(project)], check=True)
            subprocess.run(["git", "-C", str(project), "add", "."], check=True)
            subprocess.run(
                [
                    "git", "-C", str(project), "-c", "user.name=Test",
                    "-c", "user.email=test@example.com", "commit", "-qm", "current",
                ],
                check=True,
            )
            current = subprocess.run(
                ["git", "-C", str(project), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            generated_source = (
                project / "rcitcs-dao" / "src" / "main" / "java"
            )
            generated_source.mkdir(parents=True)
            generated_dao = generated_source / "GeneratedDao.java"
            generated_dao.write_text(
                "interface GeneratedDao {}\n", encoding="utf-8"
            )
            (project / "pom.xml").write_text(
                "<project><properties/></project>\n", encoding="utf-8"
            )
            report = Path(tmp) / "report"
            self.write_current_provenance(report, current)

            untracked = subprocess.run(
                [
                    "git", "-C", str(project), "status", "--porcelain=v1",
                    "--untracked-files=all",
                ],
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertIn("GeneratedDao.java", untracked)
            self.assertIn("pom.xml", untracked)

            with step5.materialize_step5_business_source_workspace(
                report, [str(generated_source)]
            ) as workspace:
                self.assertEqual(workspace["mode"], "existing_matching_checkout")
                self.assertEqual(
                    workspace["source_dirs"], [str(generated_source.resolve())]
                )
                self.assertTrue(generated_dao.is_file())
                self.assertEqual(workspace["temporary_worktree"], "")

            worktrees = subprocess.run(
                ["git", "-C", str(project), "worktree", "list", "--porcelain"],
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertEqual(worktrees.count("worktree "), 1)

    def test_detached_maven_compile_inherits_side_jdks_wrapper_settings_and_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            worktree = root / "worktree"
            project.mkdir()
            worktree.mkdir()
            wrapper = project / ("mvnw.cmd" if step5.IS_WINDOWS else "mvnw")
            wrapper.write_text(
                "@exit /b 0\r\n" if step5.IS_WINDOWS else "#!/bin/sh\nexit 0\n",
                encoding="utf-8",
            )
            if not step5.IS_WINDOWS:
                wrapper.chmod(0o755)
            settings = project / ".mvn" / "settings.xml"
            settings.parent.mkdir()
            settings.write_text("<settings/>\n", encoding="utf-8")
            (worktree / "pom.xml").write_text("<project/>\n", encoding="utf-8")
            base_jdk = root / "base-jdk"
            current_jdk = root / "current-jdk"
            for jdk in (base_jdk, current_jdk):
                java = jdk / "bin" / ("java.exe" if step5.IS_WINDOWS else "java")
                java.parent.mkdir(parents=True)
                java.write_text("", encoding="utf-8")
            report = root / "report"
            dependencies = report / "evidence" / "dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "sides": [
                        {
                            "side": "base",
                            "jdk_home": str(root / "stale-base-jdk"),
                            "target_module": "app",
                            "active_maven_profiles": ["base-profile"],
                        },
                        {
                            "side": "current",
                            "jdk_home": str(root / "stale-current-jdk"),
                            "target_module": "app",
                            "active_maven_profiles": ["current-profile"],
                        },
                    ],
                }),
                encoding="utf-8",
            )
            state_path = report / ".runtime" / "state" / "main_state.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps({
                    "step5": {
                        "input": {
                            "base_jdk_home": str(base_jdk),
                            "current_jdk_home": str(current_jdk),
                            "step5_timeout": 73,
                        },
                    },
                }),
                encoding="utf-8",
            )
            calls = []

            def fake_runner(command, **kwargs):
                calls.append((list(command), dict(kwargs)))
                return "", "", 0

            with patch.dict(
                os.environ,
                {
                    "JUA_ORCHESTRATED": "1",
                    "HOME": str(root / "home"),
                    "MAVEN_ARGS": "",
                    "MAVEN_USER_HOME": str(root / "maven-home"),
                },
                clear=False,
            ):
                base_result = step5.run_step5_detached_maven_compile(
                    report, project, worktree, side="base", runner=fake_runner
                )
                current_result = step5.run_step5_detached_maven_compile(
                    report, project, worktree, side="current", runner=fake_runner
                )

        self.assertEqual(len(calls), 2)
        for command, kwargs in calls:
            self.assertEqual(command[0], str(wrapper.resolve()))
            self.assertEqual(
                command[command.index("--settings") + 1], str(settings.resolve())
            )
            self.assertEqual(command[-2:], ["-DskipTests", "compile"])
            self.assertEqual(kwargs["timeout"], 73)
            self.assertEqual(kwargs["cwd"], str(worktree.resolve()))
            self.assertEqual(
                kwargs["env"]["MAVEN_PROJECTBASEDIR"], str(worktree.resolve())
            )
        self.assertEqual(calls[0][1]["env"]["JAVA_HOME"], str(base_jdk.resolve()))
        self.assertEqual(calls[1][1]["env"]["JAVA_HOME"], str(current_jdk.resolve()))
        self.assertIn("-Pbase-profile", calls[0][0])
        self.assertIn("-Pcurrent-profile", calls[1][0])
        self.assertEqual(base_result["jdk_home"], str(base_jdk.resolve()))
        self.assertEqual(current_result["jdk_home"], str(current_jdk.resolve()))

    def test_detached_maven_compile_has_no_default_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            worktree = root / "worktree"
            project.mkdir()
            worktree.mkdir()
            (worktree / "pom.xml").write_text("<project/>\n", encoding="utf-8")
            report = root / "report"
            dependencies = report / "evidence" / "dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "build_provenance.json").write_text(
                json.dumps({"sides": [{"side": "current"}]}),
                encoding="utf-8",
            )
            captured = {}

            def fake_runner(_command, **kwargs):
                captured.update(kwargs)
                return "", "", 0

            with patch.object(
                step5, "load_orchestrated_step5_input", return_value={}
            ), patch.dict(os.environ, {"JAVA_HOME": ""}, clear=False):
                result = step5.run_step5_detached_maven_compile(
                    report, project, worktree, side="current", runner=fake_runner
                )

        self.assertIsNone(captured["timeout"])
        self.assertIsNone(result["timeout_seconds"])

    def test_missing_detached_maven_sources_are_generated_for_current_side(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            (project / "pom.xml").write_text("<project/>\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(project)], check=True)
            subprocess.run(["git", "-C", str(project), "add", "."], check=True)
            subprocess.run(
                [
                    "git", "-C", str(project), "-c", "user.name=Test",
                    "-c", "user.email=test@example.com", "commit", "-qm", "base",
                ],
                check=True,
            )
            base = subprocess.run(
                ["git", "-C", str(project), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            (project / "marker.txt").write_text("current\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(project), "add", "."], check=True)
            subprocess.run(
                [
                    "git", "-C", str(project), "-c", "user.name=Test",
                    "-c", "user.email=test@example.com", "commit", "-qm", "current",
                ],
                check=True,
            )
            generated_source = project / "app" / "src" / "main" / "java"
            generated_source.mkdir(parents=True)
            (generated_source / "GeneratedDao.java").write_text(
                "interface GeneratedDao {}\n", encoding="utf-8"
            )
            report = Path(tmp) / "report"
            dependencies = report / "evidence" / "dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "sides": [{
                        "side": "current",
                        "source_mode": "checkout_build",
                        "revision": base,
                        "build_tool": "maven",
                    }],
                }),
                encoding="utf-8",
            )
            calls = []

            def fake_compile(_report, root, detached, *, side, runner=step5.run_cmd):
                calls.append((Path(root), Path(detached), side))
                mapped = Path(detached) / generated_source.relative_to(project)
                mapped.mkdir(parents=True)
                (mapped / "GeneratedDao.java").write_text(
                    "interface GeneratedDao {}\n", encoding="utf-8"
                )
                return {"side": side, "build_tool": "maven"}

            with patch.object(
                step5,
                "run_step5_detached_maven_compile",
                side_effect=fake_compile,
            ):
                with step5.materialize_step5_business_source_workspace(
                    report, [str(generated_source)]
                ) as workspace:
                    mapped_source = Path(workspace["source_dirs"][0])
                    self.assertTrue((mapped_source / "GeneratedDao.java").is_file())
                    self.assertEqual(
                        workspace["source_generation"],
                        {"side": "current", "build_tool": "maven"},
                    )

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], project.resolve())
            self.assertEqual(calls[0][2], "current")

    def test_mismatched_checkout_uses_expected_commit_and_cleans_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, source, _java_file, base, _current = self.make_project_history(tmp)
            report = Path(tmp) / "report"
            self.write_current_provenance(report, base)
            temporary_worktree = ""

            with step5.materialize_step5_business_source_workspace(
                report, [str(source)]
            ) as workspace:
                self.assertEqual(workspace["mode"], "detached_commit_workspace")
                mapped_source = Path(workspace["source_dirs"][0])
                temporary_worktree = workspace["temporary_worktree"]
                self.assertIn("value = 1", (mapped_source / "Demo.java").read_text())
                resolved = subprocess.run(
                    ["git", "-C", str(mapped_source), "rev-parse", "HEAD"],
                    check=True, capture_output=True, text=True,
                ).stdout.strip()
                self.assertEqual(resolved, base)

            self.assertFalse(Path(temporary_worktree).exists())
            worktrees = subprocess.run(
                ["git", "-C", str(project), "worktree", "list", "--porcelain"],
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertEqual(worktrees.count("worktree "), 1)

    def test_matching_checkout_preserves_tracked_post_compile_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, source, java_file, _base, current = self.make_project_history(tmp)
            report = Path(tmp) / "report"
            self.write_current_provenance(report, current)
            java_file.write_text("class Demo { int value = 99; }\n", encoding="utf-8")

            with step5.materialize_step5_business_source_workspace(
                report, [str(source)]
            ) as workspace:
                self.assertEqual(workspace["mode"], "existing_matching_checkout")
                mapped_file = Path(workspace["source_dirs"][0]) / "Demo.java"
                self.assertIn("value = 99", mapped_file.read_text())
                self.assertEqual(workspace["worktree_dirty_check"], "skipped")

            self.assertIn("value = 99", java_file.read_text())
            worktrees = subprocess.run(
                ["git", "-C", str(project), "worktree", "list", "--porcelain"],
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertEqual(worktrees.count("worktree "), 1)

    def test_step5_wrapper_keeps_detached_workspace_until_impl_returns(self):
        with tempfile.TemporaryDirectory() as tmp:
            _project, source, _java_file, base, _current = self.make_project_history(tmp)
            report = Path(tmp) / "report"
            self.write_current_provenance(report, base)
            args = SimpleNamespace(
                report_dir=str(report),
                all_changed_apis="",
                output_dir="",
                source_dirs=[str(source)],
                debug_analysis=False,
                debug_break=False,
            )
            captured = {}

            def fake_impl(received_args):
                mapped = Path(received_args._materialized_business_source_dirs[0])
                captured["worktree"] = received_args._business_source_workspace[
                    "temporary_worktree"
                ]
                captured["content"] = (mapped / "Demo.java").read_text()
                self.assertTrue(mapped.is_dir())
                return 7

            with patch.object(
                step5, "_step5_integrated_main_impl", side_effect=fake_impl
            ):
                result = step5.step5_integrated_main(args)

            self.assertEqual(result, 7)
            self.assertIn("value = 1", captured["content"])
            self.assertFalse(Path(captured["worktree"]).exists())
            self.assertFalse(hasattr(args, "_materialized_business_source_dirs"))
            self.assertFalse(hasattr(args, "_business_source_workspace"))

    def test_unavailable_expected_commit_does_not_fall_back_to_current_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            _project, source, _java_file, _base, _current = self.make_project_history(tmp)
            report = Path(tmp) / "report"
            self.write_current_provenance(report, "f" * 40)

            with self.assertRaisesRegex(
                RuntimeError, "STEP5_CURRENT_COMMIT_UNAVAILABLE"
            ):
                with step5.materialize_step5_business_source_workspace(
                    report, [str(source)]
                ):
                    self.fail("unavailable commit must not expose current sources")


if __name__ == "__main__":
    unittest.main()
