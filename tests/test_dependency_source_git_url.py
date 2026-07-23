import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import run_step  # noqa: E402


class DependencySourceGitUrlTest(unittest.TestCase):
    def _git(self, *args, cwd=None):
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _create_remote(self, root):
        source = root / "dependency-source"
        source.mkdir()
        self._git("init", "-q", cwd=source)
        self._git("config", "user.email", "fixture@example.test", cwd=source)
        self._git("config", "user.name", "Fixture", cwd=source)
        (source / "pom.xml").write_text(
            """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo-lib</artifactId>
  <version>2.0.0</version>
</project>
""",
            encoding="utf-8",
        )
        java_dir = source / "src" / "main" / "java" / "com" / "example"
        java_dir.mkdir(parents=True)
        (java_dir / "Demo.java").write_text(
            "package com.example; public class Demo {}\n",
            encoding="utf-8",
        )
        self._git("add", ".", cwd=source)
        self._git("commit", "-q", "-m", "fixture source", cwd=source)

        remote = root / "demo-lib.git"
        self._git("clone", "-q", "--bare", str(source), str(remote), cwd=root)
        return remote.as_uri()

    def _args(self, project_dir, report_dir):
        return SimpleNamespace(
            project_dir=str(project_dir),
            report_dir=str(report_dir),
            base_branch=None,
            current_branch=None,
            modules=None,
            active_maven_profiles=None,
            source_dirs=None,
            dependency_source_dirs=[],
            dependency_source_mappings=[],
            source_repo_hints=[],
            dependency_repo_mappings=[],
            dependency_git_ref_overrides_json="",
            japicmp_jar="",
            step4_git_diff_timeout=None,
            step4_japicmp_timeout=None,
            step4_fetch_timeout=None,
            step4_tool_install_timeout=None,
            step4_workers=None,
            step5_timeout=None,
            base_artifact_path="",
            current_artifact_path="",
            base_source_project_dir="",
            current_source_project_dir="",
            base_jdk_home="",
            current_jdk_home="",
            primary_module="",
            target_module="",
            manual_coord_overrides=[],
            include_test_scope=False,
            max_depth=None,
            tool="maven",
            allow_degraded=False,
            strict_risk_gate=False,
            allow_unresolved=False,
        )

    def test_build_run_context_clones_git_url_and_derives_dependency_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            report = project / ".upgrade-report"
            project.mkdir()
            report.mkdir()
            git_url = self._create_remote(root)
            run_step.step1_dep_changes_path(report).parent.mkdir(parents=True)
            run_step.step1_dep_changes_path(report).write_text(
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,upgrade,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )

            context = run_step.build_run_context(
                self._args(project, report),
                {},
                {"dependency_source_dirs": [git_url]},
            )

            checkout = Path(context["dependency_source_dirs"][0])
            self.assertTrue((checkout / ".git").is_dir())
            self.assertEqual(context["dependency_source_git_urls"], [git_url])
            self.assertEqual(
                context["dependency_repo_mappings"],
                [f"com.example:demo-lib={checkout}"],
            )
            self.assertIn(
                f"com.example:demo-lib={checkout / 'src' / 'main' / 'java'}",
                context["dependency_source_mappings"],
            )
            metadata = Path(context["dependency_source_git_materializations"][0]["metadata_path"])
            self.assertEqual(json.loads(metadata.read_text(encoding="utf-8"))["git_url"], git_url)

    def test_materialized_git_url_is_reused_without_recloning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            git_url = self._create_remote(root)

            first = run_step.materialize_dependency_source_git_url(git_url, report)
            marker = Path(first["repo_path"]) / "reuse-marker"
            marker.write_text("keep", encoding="utf-8")
            second = run_step.materialize_dependency_source_git_url(git_url, report)

            self.assertEqual(first["repo_path"], second["repo_path"])
            self.assertTrue(marker.is_file())
            self.assertTrue(second["reused"])

    def test_user_response_accepts_git_url_as_dependency_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            git_url = "https://git.example.test/team/demo-lib.git"

            updated = run_step.merge_user_response_into_run_context(
                {
                    "dependency_source_dirs": [str(project / "old-source")],
                    "dependency_source_git_urls": ["https://git.example.test/old.git"],
                    "dependency_repo_mappings": ["com.example:old=/old-source"],
                },
                {"dependency_source_dirs": [git_url]},
                project,
            )

            self.assertEqual(updated["dependency_source_dirs"], [git_url])
            self.assertEqual(updated["dependency_source_git_urls"], [git_url])
            self.assertNotIn("dependency_repo_mappings", updated)

    def test_dependency_source_object_accepts_git_url_key(self):
        git_url = "ssh://git@git.example.test/team/demo-lib.git"

        normalized = run_step.normalize_dependency_source_dirs(
            [{"git_url": git_url}],
            Path("/project"),
        )

        self.assertEqual(normalized, [git_url])

    def test_clone_failure_is_reported_as_input_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_remote = (Path(tmp) / "missing.git").as_uri()

            with self.assertRaisesRegex(run_step.StepError, "无法克隆依赖源码 Git 地址"):
                run_step.materialize_dependency_source_git_url(
                    missing_remote,
                    Path(tmp) / ".upgrade-report",
                    clone_timeout=5,
                )


if __name__ == "__main__":
    unittest.main()
