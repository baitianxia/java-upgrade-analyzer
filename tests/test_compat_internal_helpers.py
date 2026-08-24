from __future__ import annotations

import io
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import compat


class CompatMavenConfigurationTest(unittest.TestCase):
    def test_maven_option_parser_accepts_quoted_and_unquoted_values(self):
        self.assertEqual(
            compat._extract_maven_repo_local_from_opts(
                '-Xmx1g -Dmaven.repo.local="/tmp/repo with spaces" -Dfoo=bar'
            ),
            "/tmp/repo with spaces",
        )
        self.assertEqual(
            compat._extract_maven_repo_local_from_opts(
                "-Dmaven.repo.local=/tmp/repository"
            ),
            "/tmp/repository",
        )
        self.assertEqual(compat._extract_maven_repo_local_from_opts("-Xmx1g"), "")

    def test_settings_parser_handles_namespace_and_malformed_xml_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            settings = home / ".m2" / "settings.xml"
            settings.parent.mkdir()
            settings.write_text(
                '<settings xmlns="urn:maven"><localRepository>'
                "${user.home}/repo</localRepository></settings>",
                encoding="utf-8",
            )
            with patch.object(compat.Path, "home", return_value=home):
                self.assertEqual(
                    compat._read_maven_settings_local_repo(),
                    "${user.home}/repo",
                )

            settings.write_text(
                "<settings><broken><localRepository>/fallback/repo"
                "</localRepository>",
                encoding="utf-8",
            )
            with patch.object(compat.Path, "home", return_value=home):
                self.assertEqual(
                    compat._read_maven_settings_local_repo(),
                    "/fallback/repo",
                )

    def test_maven_repository_precedence_is_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            keys = (
                "MAVEN_REPO_LOCAL", "MAVEN_OPTS", "JAVA_TOOL_OPTIONS",
                "MAVEN_USER_HOME",
            )
            cleared = {key: "" for key in keys}
            with patch.object(compat.Path, "home", return_value=home), patch.dict(
                compat.os.environ,
                {**cleared, "MAVEN_REPO_LOCAL": str(home / "direct")},
                clear=False,
            ):
                self.assertEqual(compat.maven_repo_dir(), home / "direct")

            with patch.object(compat.Path, "home", return_value=home), patch.dict(
                compat.os.environ,
                {
                    **cleared,
                    "MAVEN_OPTS": (
                        f"-Dmaven.repo.local={home / 'options'}"
                    ),
                },
                clear=False,
            ):
                self.assertEqual(compat.maven_repo_dir(), home / "options")

            with patch.object(compat.Path, "home", return_value=home), patch.dict(
                compat.os.environ,
                {**cleared, "MAVEN_USER_HOME": str(home / "maven-home")},
                clear=False,
            ), patch.object(
                compat, "_read_maven_settings_local_repo", return_value=None,
            ):
                self.assertEqual(
                    compat.maven_repo_dir(), home / "maven-home" / "repository",
                )


class CompatGradleCoordinateTest(unittest.TestCase):
    def test_gradle_text_extractors_reject_ambiguous_group_and_read_artifact(self):
        self.assertEqual(
            compat._extract_gradle_group_from_text("group = 'com.acme.demo'"),
            "com.acme.demo",
        )
        self.assertEqual(
            compat._extract_gradle_group_from_text("group = 'Com.Acme'"), "",
        )
        self.assertEqual(
            compat._extract_gradle_artifact_from_text(
                'archivesName = "runtime-artifact"'
            ),
            "runtime-artifact",
        )
        self.assertEqual(compat._extract_gradle_artifact_from_text("plugins {}"), "")

    def test_gradle_coordinate_uses_nearest_repository_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            module = repository / "services" / "billing"
            module.mkdir(parents=True)
            (repository / "gradle.properties").write_text(
                "group=com.example.platform\n", encoding="utf-8",
            )
            (repository / "settings.gradle.kts").write_text(
                'rootProject.name = "platform-root"\n', encoding="utf-8",
            )
            named_build = module / "billing-api.gradle.kts"
            named_build.write_text("plugins {}\n", encoding="utf-8")

            self.assertEqual(
                compat._read_text_if_exists(named_build), "plugins {}\n",
            )
            self.assertEqual(
                compat._extract_group_from_gradle_properties(module),
                "com.example.platform",
            )
            self.assertEqual(
                compat._extract_artifact_from_settings(module), "platform-root",
            )
            self.assertEqual(
                compat._artifact_id_from_gradle_build_file(named_build),
                "billing-api",
            )
            self.assertEqual(
                compat._artifact_id_from_gradle_build_file(
                    module / "build.gradle.kts"
                ),
                "",
            )
            self.assertEqual(
                compat._extract_gradle_group_from_file(
                    repository / "gradle.properties"
                ),
                "com.example.platform",
            )
            self.assertEqual(
                compat._infer_gradle_group_from_ancestors(module, repository),
                "com.example.platform",
            )
            self.assertEqual(
                compat._parse_gradle_coord_with_repo_context(
                    named_build, repository,
                ),
                "com.example.platform:billing-api",
            )

            default_build = module / "build.gradle"
            default_build.write_text(
                "group = 'com.example.billing'\n"
                "archivesBaseName = 'billing-runtime'\n",
                encoding="utf-8",
            )
            self.assertEqual(
                compat._parse_gradle_coord(default_build),
                "com.example.billing:billing-runtime",
            )

    def test_root_gradle_coordinate_uses_declared_name_not_checkout_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary) / "random-checkout-token"
            checkout.mkdir()
            (checkout / "settings.gradle").write_text(
                "rootProject.name = 'declared-root'\n", encoding="utf-8",
            )
            build = checkout / "build.gradle"
            build.write_text(
                "group = 'com.example.platform'\n", encoding="utf-8",
            )

            self.assertEqual(
                compat._parse_gradle_coord(build),
                "com.example.platform:declared-root",
            )

    def test_named_gradle_module_inherits_group_from_ancestor_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "build.gradle").write_text(
                "group = 'com.example.ancestor'\n", encoding="utf-8",
            )
            module = repository / "services" / "billing"
            module.mkdir(parents=True)
            named_build = module / "billing-api.gradle"
            named_build.write_text("plugins {}\n", encoding="utf-8")

            self.assertEqual(
                compat._parse_gradle_coord_with_repo_context(
                    named_build, repository,
                ),
                "com.example.ancestor:billing-api",
            )

    def test_source_module_and_coordinate_list_projection_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary)
            self.assertFalse(compat._looks_like_source_module(module))
            (module / "src" / "main" / "java").mkdir(parents=True)
            self.assertTrue(compat._looks_like_source_module(module))

        with patch.object(
            compat,
            "infer_maven_coord_locations",
            return_value=[
                {"coord": "g:a"}, {"coord": ""}, {"module_dir": "/tmp"},
            ],
        ) as locations:
            self.assertEqual(compat.infer_maven_coords("project", 3), ["g:a"])
        locations.assert_called_once_with("project", max_poms=3)

    def test_location_scan_keeps_source_root_and_gradle_context_coordinates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src" / "main" / "java").mkdir(parents=True)
            (root / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.example</groupId><artifactId>root-app</artifactId>"
                "<version>1</version><modules><module>child</module></modules>"
                "</project>",
                encoding="utf-8",
            )
            child = root / "child"
            child.mkdir()
            (child / "child-api.gradle").write_text(
                "plugins {}\n", encoding="utf-8",
            )
            (root / "build.gradle").write_text(
                "group = 'com.example.gradle'\n", encoding="utf-8",
            )

            locations = compat.infer_maven_coord_locations(root)

        self.assertIn("com.example:root-app", {
            row["coord"] for row in locations
        })
        self.assertIn("com.example.gradle:child-api", {
            row["coord"] for row in locations
        })


class CompatInteractionAndLifecycleTest(unittest.TestCase):
    def test_windows_encoding_probe_uses_platform_subprocess_options(self):
        completed = MagicMock()
        completed.stdout.decode.return_value = "Active code page: 65001"
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat.subprocess, "run", return_value=completed,
        ), patch.object(
            compat, "subprocess_platform_kwargs", return_value={"creationflags": 7},
        ) as platform_kwargs:
            self.assertEqual(compat._detect_subprocess_encoding(), "utf-8")

        platform_kwargs.assert_called_once_with()

    def test_git_file_capture_timeout_terminates_and_closes_owned_process(self):
        process = MagicMock()
        process.communicate.side_effect = compat.subprocess.TimeoutExpired(
            ["git", "rev-parse"], 1,
        )
        with patch.object(
            compat, "managed_popen", return_value=process,
        ), patch.object(compat, "_terminate_subprocess") as terminate, patch.object(
            compat, "_close_subprocess_pipes",
        ) as close:
            result = compat._run_git_file_capture(
                ["git", "rev-parse", "HEAD"],
                cwd=None,
                timeout=1,
                input_bytes=None,
                env=None,
                process_group_kwargs={},
            )

        self.assertEqual(result, ("", "Git 文件捕获重试超时（1秒）", -1))
        terminate.assert_called_once_with(process, process_group=True)
        close.assert_called_once_with(process)

    def test_windows_tree_termination_uses_platform_flags_only_for_live_root(self):
        process = MagicMock(pid=321)
        setattr(process, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE, None)
        process.poll.return_value = None
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "_claim_managed_process_tree", return_value=True,
        ), patch.object(
            compat, "subprocess_platform_kwargs", return_value={"creationflags": 9},
        ) as platform_kwargs, patch.object(
            compat.subprocess, "run",
        ) as taskkill:
            compat._terminate_subprocess(process, process_group=True)

        platform_kwargs.assert_called_once_with()
        self.assertEqual(taskkill.call_args.args[0][:2], ["taskkill", "/PID"])
        self.assertEqual(taskkill.call_args.kwargs["creationflags"], 9)

    def test_managed_subprocess_pipe_failure_reaps_tree_and_closes_pipes(self):
        process = MagicMock()
        process.communicate.side_effect = OSError("pipe failed")
        with patch.object(
            compat, "managed_popen", return_value=process,
        ), patch.object(compat, "terminate_process_tree") as terminate, patch.object(
            compat, "_close_subprocess_pipes",
        ) as close:
            with self.assertRaisesRegex(OSError, "pipe failed"):
                compat.run_managed_subprocess(
                    ["tool"], capture_output=True,
                )

        terminate.assert_called_once_with(process)
        close.assert_called_once_with(process)

    def test_process_observer_installation_returns_previous_owner(self):
        original = compat._PROCESS_OBSERVER
        first = object()
        second = object()
        try:
            self.assertIs(compat.set_process_observer(first), original)
            self.assertIs(compat.set_process_observer(second), first)
            self.assertIs(compat._PROCESS_OBSERVER, second)
        finally:
            compat.set_process_observer(original)

    def test_human_confirmation_modes_are_fail_closed_without_tty(self):
        stderr = io.StringIO()
        stdin = MagicMock()
        stdin.isatty.return_value = False
        with patch.object(compat.sys, "stderr", stderr), patch.object(
            compat.sys, "stdin", stdin,
        ), patch.dict(compat.os.environ, {"JUA_CONFIRM_MODE": "emit"}):
            self.assertTrue(compat.require_human_confirm("Review", ["one", None]))
        self.assertIn("【人工确认】Review", stderr.getvalue())
        self.assertIn("- one", stderr.getvalue())

        with patch.object(compat.sys, "stderr", io.StringIO()), patch.object(
            compat.sys, "stdin", stdin,
        ), patch.dict(compat.os.environ, {"JUA_CONFIRM_MODE": "prompt"}):
            self.assertFalse(compat.require_human_confirm("Review"))

        self.assertEqual(compat.normalize_path(Path("a") / "b"), str(Path("a") / "b"))

    def test_sigterm_handler_reaps_registered_groups_and_delegates_previous(self):
        token = object()
        process = MagicMock()
        setattr(process, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE, token)
        delegated = []

        def previous(signum, frame):
            delegated.append((signum, frame))

        with patch.object(
            compat, "_POSIX_MANAGED_PROCESS_GROUPS", {1234},
        ), patch.object(
            compat, "_MANAGED_PROCESS_TREES", {token: (process, 99, True)},
        ), patch.object(
            compat, "_PREVIOUS_SIGTERM_HANDLER", previous,
        ), patch.object(
            compat, "_MANAGED_SIGTERM_HANDLER_INSTALLED", True,
        ), patch.object(compat.os, "killpg") as kill_group, patch.object(
            compat.signal, "signal",
        ) as install_signal:
            compat._managed_sigterm_handler(signal.SIGTERM, "frame")

        kill_group.assert_called_once_with(1234, signal.SIGKILL)
        install_signal.assert_called_once_with(signal.SIGTERM, previous)
        self.assertEqual(delegated, [(signal.SIGTERM, "frame")])
        self.assertFalse(hasattr(
            process, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE,
        ))


if __name__ == "__main__":
    unittest.main()
