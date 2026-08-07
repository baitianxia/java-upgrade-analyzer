import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
import sys

sys.path.insert(0, str(SCRIPTS_DIR))

import run_step
import s2_context_from_deps as step2
import s5_call_chain_engine_integrated as step5


class PinnedSourceDiscoveryTest(unittest.TestCase):
    def _git(self, repo, *args):
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def _write_maven_tree(self, repo, module, marker):
        (repo / "pom.xml").write_text(
            "<project><modelVersion>4.0.0</modelVersion>"
            "<groupId>com.acme</groupId><artifactId>root</artifactId>"
            "<version>1</version><packaging>pom</packaging>"
            f"<modules><module>{module}</module></modules></project>\n",
            encoding="utf-8",
        )
        source = repo / module / "src" / "main" / "java" / "com" / "acme"
        source.mkdir(parents=True)
        (repo / module / "pom.xml").write_text(
            "<project><modelVersion>4.0.0</modelVersion>"
            "<parent><groupId>com.acme</groupId><artifactId>root</artifactId>"
            "<version>1</version></parent>"
            f"<artifactId>{module}</artifactId></project>\n",
            encoding="utf-8",
        )
        (source / f"{marker}.java").write_text(
            f"package com.acme; class {marker} {{}}\n",
            encoding="utf-8",
        )

    def _make_divergent_history(self, root):
        repo = Path(root) / "project"
        repo.mkdir()
        self._git(repo, "init", "-q")
        self._git(repo, "config", "user.name", "Test")
        self._git(repo, "config", "user.email", "test@example.com")

        self._write_maven_tree(repo, "local-module", "LocalOnly")
        self._git(repo, "add", ".")
        self._git(repo, "commit", "-qm", "base-local-layout")
        local_commit = self._git(repo, "rev-parse", "HEAD")

        shutil.rmtree(repo / "local-module")
        self._write_maven_tree(repo, "remote-module", "RemoteOnly")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-qm", "current-remote-layout")
        current_commit = self._git(repo, "rev-parse", "HEAD")

        self._git(repo, "checkout", "-q", "--detach", local_commit)
        (repo / "pom.xml").write_text(
            (repo / "pom.xml").read_text(encoding="utf-8")
            + "<!-- dirty tracked checkout content -->\n",
            encoding="utf-8",
        )
        dirty_source = (
            repo / "dirty-module" / "src" / "main" / "java" / "com" / "acme"
        )
        dirty_source.mkdir(parents=True)
        (repo / "dirty-module" / "pom.xml").write_text(
            "<project><modelVersion>4.0.0</modelVersion>"
            "<artifactId>dirty-module</artifactId></project>\n",
            encoding="utf-8",
        )
        (dirty_source / "DirtyOnly.java").write_text(
            "package com.acme; class DirtyOnly {}\n",
            encoding="utf-8",
        )
        return repo, local_commit, current_commit, dirty_source.parents[1]

    def test_pre_ref_checkpoint_discards_checkout_derived_scope(self):
        stripped = run_step._discard_unpinned_local_source_discovery({
            "current_branch": "release-current",
            "tool": "maven",
            "tool_explicit": False,
            "project_scope": {
                "candidate_modules": ["dirty-local-module"],
                "source_roots": ["/checkout/dirty-local-module/src/main/java"],
            },
            "source_dirs": ["/checkout/dirty-local-module/src/main/java"],
            "source_dirs_status": "auto_detected",
        })

        self.assertEqual(stripped["tool"], "")
        self.assertEqual(stripped["source_dirs"], [])
        self.assertEqual(stripped["source_dirs_status"], "missing")
        self.assertEqual(stripped["project_scope"]["candidate_modules"], [])

    def test_step1_scope_and_source_roots_come_only_from_pinned_current_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _local_commit, current_commit, dirty_source_root = (
                self._make_divergent_history(tmp)
            )
            context = {
                "project_dir": str(repo),
                "analysis_mode": "checkout_build",
                "base_branch": "base-ref",
                "current_branch": "current-ref",
                "current_resolved_commit": current_commit,
                "current_expected_commit": current_commit,
                "active_maven_profiles": [],
                "tool": "maven",
                "modules": [],
                "source_dirs": [
                    str((repo / "local-module" / "src/main/java").resolve()),
                    str(dirty_source_root.resolve()),
                ],
                "source_dirs_status": "auto_detected",
            }

            rebuilt = run_step.rebuild_current_pinned_source_context(
                context, repo,
            )
            snapshot = rebuilt["pinned_source_snapshot"]
            candidates = snapshot["project_scope"]["candidate_modules"]

            self.assertEqual(snapshot["commit"], current_commit)
            self.assertIn("remote-module", candidates)
            self.assertNotIn("local-module", candidates)
            self.assertNotIn("dirty-module", candidates)
            serialized = json.dumps(rebuilt, sort_keys=True)
            self.assertNotIn("s1-scope", serialized)
            self.assertNotIn("jua-s1-scope", serialized)
            self.assertNotIn("temporary_worktree", serialized)
            interaction = run_step.build_step1_preflight_interaction(rebuilt)
            shown_candidates = interaction.get("module_candidates") or []
            self.assertTrue(any(
                (
                    item.get("module") if isinstance(item, dict) else item
                ) == "remote-module"
                for item in shown_candidates
            ))
            self.assertFalse(any(
                (
                    item.get("module") if isinstance(item, dict) else item
                ) in {"local-module", "dirty-module"}
                for item in shown_candidates
            ))

            selected = dict(rebuilt)
            selected["target_module"] = "remote-module"
            selected["primary_module"] = "remote-module"
            selected["modules"] = ["remote-module"]
            selected.pop("pinned_source_snapshot", None)
            selected["source_dirs_status"] = "auto_detected"
            selected = run_step.rebuild_current_pinned_source_context(
                selected, repo,
            )

            self.assertEqual(
                selected["pinned_source_snapshot"]["source_roots"],
                ["remote-module/src/main/java"],
            )
            self.assertEqual(
                selected["source_dirs"],
                [str((repo / "remote-module/src/main/java").resolve())],
            )
            self.assertFalse(Path(selected["source_dirs"][0]).exists())

    def test_explicit_source_dir_is_rejected_when_only_dirty_checkout_has_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _local_commit, current_commit, dirty_source_root = (
                self._make_divergent_history(tmp)
            )
            context = {
                "project_dir": str(repo),
                "current_resolved_commit": current_commit,
                "current_expected_commit": current_commit,
                "active_maven_profiles": [],
                "tool": "maven",
                "target_module": "remote-module",
                "primary_module": "remote-module",
                "modules": ["remote-module"],
                "source_dirs": [str(dirty_source_root.resolve())],
                "source_dirs_status": "explicit",
            }

            with self.assertRaisesRegex(
                run_step.StepError,
                "固定 commit 中不存在",
            ):
                run_step.rebuild_current_pinned_source_context(context, repo)

    def test_auto_build_tool_is_rediscovered_from_pinned_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "project"
            repo.mkdir()
            self._git(repo, "init", "-q")
            self._git(repo, "config", "user.name", "Test")
            self._git(repo, "config", "user.email", "test@example.com")
            self._write_maven_tree(repo, "local-module", "LocalOnly")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-qm", "local-maven")
            local_commit = self._git(repo, "rev-parse", "HEAD")

            shutil.rmtree(repo / "local-module")
            (repo / "pom.xml").unlink()
            (repo / "settings.gradle").write_text(
                "rootProject.name = 'demo'\ninclude ':remote-module'\n",
                encoding="utf-8",
            )
            (repo / "build.gradle").write_text(
                "allprojects { group = 'com.acme'; version = '1' }\n",
                encoding="utf-8",
            )
            source = repo / "remote-module/src/main/java/com/acme"
            source.mkdir(parents=True)
            (repo / "remote-module/build.gradle").write_text(
                "plugins { id 'java' }\n",
                encoding="utf-8",
            )
            (source / "RemoteOnly.java").write_text(
                "package com.acme; class RemoteOnly {}\n",
                encoding="utf-8",
            )
            self._git(repo, "add", "-A")
            self._git(repo, "commit", "-qm", "remote-gradle")
            current_commit = self._git(repo, "rev-parse", "HEAD")
            self._git(repo, "checkout", "-q", "--detach", local_commit)

            rebuilt = run_step.rebuild_current_pinned_source_context(
                {
                    "project_dir": str(repo),
                    "current_resolved_commit": current_commit,
                    "current_expected_commit": current_commit,
                    "active_maven_profiles": [],
                    # This is the old local auto-detection, not a user choice.
                    "tool": "maven",
                    "tool_explicit": False,
                    "target_module": "remote-module",
                    "primary_module": "remote-module",
                    "modules": ["remote-module"],
                    "source_dirs_status": "auto_detected",
                },
                repo,
            )

            self.assertEqual(rebuilt["tool"], "gradle")
            self.assertEqual(
                rebuilt["pinned_source_snapshot"]["build_tool"], "gradle"
            )
            self.assertEqual(
                rebuilt["pinned_source_snapshot"]["source_roots"],
                ["remote-module/src/main/java"],
            )

    def test_step2_maps_logical_roots_into_its_own_detached_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _local_commit, current_commit, _dirty_source_root = (
                self._make_divergent_history(tmp)
            )
            context = {
                "project_dir": str(repo),
                "current_resolved_commit": current_commit,
                "current_expected_commit": current_commit,
                "active_maven_profiles": [],
                "tool": "maven",
                "target_module": "remote-module",
                "primary_module": "remote-module",
                "modules": ["remote-module"],
                "source_dirs_status": "auto_detected",
            }
            rebuilt = run_step.rebuild_current_pinned_source_context(context, repo)
            orchestrated = {
                "pinned_source_snapshot": rebuilt["pinned_source_snapshot"],
                "current_ref_binding": {"repo_dir": str(repo)},
            }

            with step2.materialize_pinned_step2_source_workspace(
                orchestrated, current_commit, repo,
            ) as workspace:
                mapped = Path(workspace["mapped_source_dirs"][0])
                self.assertTrue((mapped / "com/acme/RemoteOnly.java").is_file())
                self.assertFalse((mapped / "com/acme/LocalOnly.java").exists())
                self.assertFalse((mapped / "com/acme/DirtyOnly.java").exists())
                self.assertEqual(
                    workspace["stable_source_dirs"],
                    [str((repo / "remote-module/src/main/java").resolve())],
                )

            worktrees = self._git(repo, "worktree", "list", "--porcelain")
            self.assertEqual(worktrees.count("worktree "), 1)

    def test_step5_uses_pinned_roots_even_when_stable_checkout_path_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _local_commit, current_commit, _dirty_source_root = (
                self._make_divergent_history(tmp)
            )
            context = {
                "project_dir": str(repo),
                "current_resolved_commit": current_commit,
                "current_expected_commit": current_commit,
                "active_maven_profiles": [],
                "tool": "maven",
                "target_module": "remote-module",
                "primary_module": "remote-module",
                "modules": ["remote-module"],
                "source_dirs_status": "auto_detected",
            }
            rebuilt = run_step.rebuild_current_pinned_source_context(context, repo)
            stable_source = str((repo / "remote-module/src/main/java").resolve())
            self.assertFalse(Path(stable_source).exists())

            report = Path(tmp) / "report"
            dependencies = report / "evidence" / "dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "sides": [{
                        "side": "current",
                        "source_mode": "provided_artifact",
                        "revision": current_commit,
                    }],
                }),
                encoding="utf-8",
            )
            state_path = report / ".runtime" / "state" / "main_state.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps({
                    "step5": {
                        "input": {
                            "pinned_source_snapshot": rebuilt[
                                "pinned_source_snapshot"
                            ],
                            "current_ref_binding": {"repo_dir": str(repo)},
                            "source_dirs": [stable_source],
                        },
                    },
                }),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"JUA_ORCHESTRATED": "1"}):
                with step5.materialize_step5_business_source_workspace(
                    report, [stable_source],
                ) as workspace:
                    mapped = Path(workspace["source_dirs"][0])
                    self.assertEqual(
                        workspace.get("source_layout"),
                        "pinned_relative_roots",
                    )
                    self.assertTrue(
                        (mapped / "com/acme/RemoteOnly.java").is_file()
                    )
                    self.assertFalse(
                        (mapped / "com/acme/LocalOnly.java").exists()
                    )

            worktrees = self._git(repo, "worktree", "list", "--porcelain")
            self.assertEqual(worktrees.count("worktree "), 1)


if __name__ == "__main__":
    unittest.main()
