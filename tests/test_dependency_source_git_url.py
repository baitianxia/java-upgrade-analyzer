import json
import hashlib
from contextlib import contextmanager
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


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

    def test_token_rotation_reuses_credential_free_cache_and_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            endpoint = self._create_remote(root)
            first_url = f"{endpoint}?token=first-low-entropy-token"
            second_url = f"{endpoint}?access_token=rotated-low-entropy-token"
            real_run_cmd = run_step.run_cmd
            clone_commands = []

            def routed_run_cmd(command, *args, **kwargs):
                command = list(command)
                if "clone" in command:
                    clone_commands.append(list(command))
                    for raw_url in (first_url, second_url):
                        if raw_url in command:
                            command[command.index(raw_url)] = endpoint
                return real_run_cmd(command, *args, **kwargs)

            with patch.object(run_step, "run_cmd", side_effect=routed_run_cmd):
                first = run_step.materialize_dependency_source_git_url(
                    first_url,
                    report,
                    clone_timeout=10,
                )
                second = run_step.materialize_dependency_source_git_url(
                    second_url,
                    report,
                    clone_timeout=10,
                )

            self.assertEqual(len(clone_commands), 1)
            self.assertIn(first_url, clone_commands[0])
            self.assertNotIn("--recurse-submodules", clone_commands[0])
            self.assertEqual(first["repo_path"], second["repo_path"])
            self.assertTrue(second["reused"])
            endpoint_hash = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
            self.assertEqual(first["git_url"], endpoint)
            self.assertEqual(first["git_endpoint"], endpoint)
            self.assertEqual(first["git_url_sha256"], endpoint_hash)
            self.assertEqual(second["git_endpoint_sha256"], endpoint_hash)
            origin = self._git(
                "remote", "get-url", "origin", cwd=first["repo_path"]
            )
            self.assertEqual(origin, endpoint)
            self._git("ls-remote", "origin", "HEAD", cwd=first["repo_path"])

    def test_materialization_exposes_only_redacted_url_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            safe_url = self._create_remote(root)
            raw_url = (
                "https://unique-user:unique-password@git.example.test/"
                "team/demo-lib.git?z=2&access_token=unique-token&a=1"
            )
            expected_display = (
                "https://git.example.test/team/demo-lib.git?a=1&z=2"
            )
            real_run_cmd = run_step.run_cmd
            clone_commands = []

            def routed_run_cmd(command, *args, **kwargs):
                command = list(command)
                if "clone" in command:
                    clone_commands.append(list(command))
                    command[command.index(raw_url)] = safe_url
                return real_run_cmd(command, *args, **kwargs)

            def valid_local_repo(repo_path, _git_url, **_kwargs):
                return (Path(repo_path) / ".git").is_dir()

            with patch.object(
                run_step,
                "run_cmd",
                side_effect=routed_run_cmd,
            ), patch.object(
                run_step,
                "_is_materialized_dependency_source_repo",
                side_effect=valid_local_repo,
            ):
                materialized = run_step.materialize_dependency_source_inputs(
                    [raw_url],
                    root,
                    report,
                    clone_timeout=10,
                )

            self.assertIn(raw_url, clone_commands[0])
            self.assertEqual(
                materialized["dependency_source_git_urls"],
                [expected_display],
            )
            item = materialized["dependency_source_git_materializations"][0]
            self.assertEqual(item["git_url"], expected_display)
            self.assertEqual(item["git_endpoint"], expected_display)
            self.assertEqual(
                item["git_url_sha256"],
                hashlib.sha256(expected_display.encode("utf-8")).hexdigest(),
            )
            self.assertEqual(item["git_endpoint_sha256"], item["git_url_sha256"])
            self.assertNotIn("--recurse-submodules", clone_commands[0])
            serialized = json.dumps(materialized, ensure_ascii=False)
            metadata_text = Path(item["metadata_path"]).read_text(encoding="utf-8")
            git_config_text = (Path(item["repo_path"]) / ".git" / "config").read_text(
                encoding="utf-8"
            )
            for secret in ("unique-user", "unique-password", "unique-token"):
                self.assertNotIn(secret, serialized)
                self.assertNotIn(secret, metadata_text)
                self.assertNotIn(secret, git_config_text)

    def test_redacted_checkpoint_url_is_not_cloned_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            report = project / ".upgrade-report"
            local_repo = root / "already-materialized"
            project.mkdir()
            local_repo.mkdir()
            (local_repo / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.example</groupId><artifactId>demo-lib</artifactId>"
                "<version>1</version></project>",
                encoding="utf-8",
            )
            previous = {
                "dependency_source_dirs": [str(local_repo)],
                "dependency_source_git_urls": [
                    "https://***@git.example.test/team/demo-lib.git"
                ],
            }

            with patch.object(
                run_step,
                "materialize_dependency_source_git_url",
            ) as clone:
                context = run_step.build_run_context(
                    self._args(project, report),
                    previous,
                    {},
                )

            clone.assert_not_called()
            self.assertEqual(
                context["dependency_source_dirs"],
                [str(local_repo.resolve())],
            )
            self.assertEqual(
                context["dependency_source_git_urls"],
                ["https://git.example.test/team/demo-lib.git"],
            )

    def test_legacy_raw_url_is_consumed_once_then_checkpoint_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            report = project / ".upgrade-report"
            local_repo = root / "legacy-materialized"
            project.mkdir()
            local_repo.mkdir()
            (local_repo / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.example</groupId><artifactId>demo-lib</artifactId>"
                "<version>1</version></project>",
                encoding="utf-8",
            )
            raw_url = (
                "https://legacy-user:legacy-password@git.example.test/"
                "team/demo-lib.git?token=legacy-token"
            )
            display_url = (
                "https://git.example.test/team/demo-lib.git"
            )
            endpoint_hash = hashlib.sha256(display_url.encode("utf-8")).hexdigest()
            materialized = {
                "git_url": display_url,
                "git_url_sha256": endpoint_hash,
                "git_endpoint_sha256": endpoint_hash,
                "repo_path": str(local_repo.resolve()),
                "metadata_path": str((report / "metadata.json").resolve()),
                "reused": False,
                "clone_attempts": 1,
            }

            with patch.object(
                run_step,
                "materialize_dependency_source_git_url",
                return_value=materialized,
            ) as clone:
                context = run_step.build_run_context(
                    self._args(project, report),
                    {
                        "dependency_source_dirs": [],
                        "dependency_source_git_urls": [raw_url],
                    },
                    {},
                )

            clone.assert_called_once()
            self.assertEqual(clone.call_args.args[0], raw_url)
            self.assertEqual(clone.call_args.kwargs["clone_timeout"], 300)
            state = run_step.new_main_state(report)
            run_step.store_step_input(state, "step1", context)
            run_step.save_main_state(report, state)
            checkpoint_text = run_step.main_state_path(report).read_text(
                encoding="utf-8"
            )
            for secret in ("legacy-user", "legacy-password", "legacy-token"):
                self.assertNotIn(secret, checkpoint_text)

            with patch.object(
                run_step,
                "materialize_dependency_source_git_url",
            ) as resumed_clone:
                resumed = run_step.build_run_context(
                    self._args(project, report),
                    context,
                    {},
                )

            resumed_clone.assert_not_called()
            self.assertEqual(resumed["dependency_source_git_urls"], [display_url])

    def test_clone_retries_transient_transport_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            git_url = self._create_remote(root)
            real_run_cmd = run_step.run_cmd
            clone_calls = []

            def flaky_run_cmd(command, *args, **kwargs):
                if "clone" in command:
                    clone_calls.append(list(command))
                    if len(clone_calls) < 3:
                        return "", "TLS connection was non-properly terminated", 1
                return real_run_cmd(command, *args, **kwargs)

            with patch.object(
                run_step,
                "run_cmd",
                side_effect=flaky_run_cmd,
            ):
                result = run_step.materialize_dependency_source_git_url(
                    git_url,
                    report,
                    clone_timeout=10,
                )

            self.assertEqual(result["clone_attempts"], 3)
            self.assertTrue(Path(result["repo_path"]).is_dir())
            metadata = json.loads(
                Path(result["metadata_path"]).read_text(encoding="utf-8")
            )
            self.assertEqual(len(metadata["attempts"]), 3)
            self.assertEqual(metadata["attempts"][-1]["status"], "success")

    def test_dead_clone_cache_owner_is_recovered_without_waiting_for_age(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_entry = Path(tmp) / "cache"
            lock_dir = cache_entry / ".materialize.lock"
            lock_dir.mkdir(parents=True)
            (lock_dir / "owner.json").write_text(
                json.dumps({"pid": 999_999_999}),
                encoding="utf-8",
            )

            with run_step._dependency_source_cache_lock(cache_entry, timeout=1):
                owner = json.loads(
                    (lock_dir / "owner.json").read_text(encoding="utf-8")
                )
                self.assertEqual(owner["pid"], os.getpid())

            self.assertFalse(lock_dir.exists())

    def test_clone_rejects_a_symlinked_cache_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            cache_parent = run_step.runtime_cache_dir(report)
            cache_parent.mkdir(parents=True, exist_ok=True)
            outside = root / "outside"
            outside.mkdir()
            (cache_parent / "dependency_source_git").symlink_to(
                outside,
                target_is_directory=True,
            )

            with self.assertRaisesRegex(
                run_step.StepError,
                "缓存根目录不能是符号链接",
            ):
                run_step.materialize_dependency_source_git_url(
                    "https://git.example.test/team/demo.git",
                    report,
                    clone_timeout=1,
                )

            self.assertEqual(list(outside.iterdir()), [])

    def test_clone_does_not_start_an_attempt_after_total_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            git_url = "https://git.example.test/team/demo.git"

            @contextmanager
            def acquired_lock(*_args, **_kwargs):
                yield

            with patch.object(
                run_step,
                "_dependency_source_cache_lock",
                side_effect=acquired_lock,
            ), patch.object(
                run_step,
                "_is_materialized_dependency_source_repo",
                return_value=False,
            ), patch.object(
                run_step.time,
                "monotonic",
                side_effect=[100.0, 100.0, 102.0],
            ), patch.object(run_step, "run_cmd") as git_call:
                with self.assertRaisesRegex(
                    run_step.StepError,
                    "超过总时限",
                ):
                    run_step.materialize_dependency_source_git_url(
                        git_url,
                        report,
                        clone_timeout=1,
                    )

            git_call.assert_not_called()

    def test_scp_alias_without_at_or_dot_git_is_recognized(self):
        self.assertTrue(
            run_step.is_dependency_source_git_url("corp-git:team/demo-lib")
        )

    def test_git_url_redaction_covers_https_and_ssh_userinfo(self):
        self.assertEqual(
            run_step._redact_git_url(
                "https://token:secret@git.example.test/team/demo.git"
            ),
            "https://***@git.example.test/team/demo.git",
        )
        self.assertEqual(
            run_step._redact_git_url(
                "ssh://user:secret@git.example.test/team/demo.git"
            ),
            "ssh://***@git.example.test/team/demo.git",
        )

    def test_canonical_endpoint_removes_credentials_and_normalizes_query(self):
        self.assertEqual(
            run_step._canonical_git_endpoint(
                "HTTPS://User:Password@Git.Example.Test/team/demo.git?"
                "z=last&token=secret&a=first&X-Amz-Signature=signature"
                "#access_token=fragment-secret"
            ),
            "https://git.example.test/team/demo.git?a=first&z=last",
        )
        self.assertEqual(
            run_step._canonical_git_endpoint(
                "deploy-user@Git.Example.Test:team/demo.git"
            ),
            "git.example.test:team/demo.git",
        )

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

    def test_failure_and_state_persistence_deeply_redact_git_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            raw_url = "https://state-user:state-password@git.example.test/repo.git"
            interaction = {
                "step_id": "step1",
                "reason_code": "STEP1_REMOTE_OPERATION_FAILED",
                "ref_resolution_requests": [{
                    "requested_ref": "release",
                    "candidates": [{
                        "remote_url": raw_url,
                        "failure": (
                            f"fetch {raw_url} Authorization: Bearer state-token "
                            "http.extraHeader=Proxy-Authorization: Basic proxy-token"
                        ),
                    }],
                }],
                "authorization": "Bearer dict-token",
            }
            state = run_step.new_main_state(report)
            state["step1"]["input"] = {
                "base_ref_binding": interaction,
                "token": "field-token",
            }
            state["state"]["pending_interaction"] = interaction

            run_step.save_main_state(report, state)
            run_step.save_interaction_file(report, interaction)

            persisted = (
                run_step.main_state_path(report).read_text(encoding="utf-8")
                + (run_step.runtime_state_dir(report) / "interaction.json").read_text(
                    encoding="utf-8"
                )
            )
            for secret in (
                "state-user",
                "state-password",
                "state-token",
                "proxy-token",
                "dict-token",
                "field-token",
            ):
                self.assertNotIn(secret, persisted)
            self.assertIn("https://***@git.example.test/repo.git", persisted)

    def test_clone_failure_metadata_and_error_do_not_persist_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            raw_url = (
                "https://failure-user:failure-password@git.example.test/"
                "repo.git?token=failure-query-token"
            )
            failure = (
                f"fatal: Authentication failed for {raw_url}\n"
                "Authorization: Bearer failure-auth-token\n"
                "Proxy-Authorization: Basic failure-proxy-token"
            )
            clone_commands = []

            def failed_run_cmd(command, *args, **kwargs):
                if "clone" in command:
                    clone_commands.append(list(command))
                return "", failure, 1

            with patch.object(
                run_step,
                "_is_materialized_dependency_source_repo",
                return_value=False,
            ), patch.object(
                run_step,
                "run_cmd",
                side_effect=failed_run_cmd,
            ):
                with self.assertRaises(run_step.StepError) as raised:
                    run_step.materialize_dependency_source_git_url(
                        raw_url,
                        report,
                        clone_timeout=5,
                    )

            self.assertIn(raw_url, clone_commands[0])
            cache_key = hashlib.sha256(
                run_step._canonical_git_endpoint(raw_url).encode("utf-8")
            ).hexdigest()[:24]
            metadata_path = (
                run_step.runtime_cache_dir(report)
                / "dependency_source_git"
                / cache_key
                / "metadata.json"
            )
            state = run_step.new_main_state(report)
            run_step.persist_step_error(
                state,
                "step1",
                report,
                raised.exception,
            )
            persisted = "\n".join([
                str(raised.exception),
                metadata_path.read_text(encoding="utf-8"),
                run_step.main_state_path(report).read_text(encoding="utf-8"),
                run_step.last_step_summary_path(report).read_text(encoding="utf-8"),
            ])
            for secret in (
                "failure-user",
                "failure-password",
                "failure-query-token",
                "failure-auth-token",
                "failure-proxy-token",
            ):
                self.assertNotIn(secret, persisted)


if __name__ == "__main__":
    unittest.main()
