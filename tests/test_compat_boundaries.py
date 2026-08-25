from __future__ import annotations

import io
import os
from pathlib import Path
import signal
import subprocess
import ctypes
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from tests import test_compat_internal_helpers as existing


compat = existing.compat


class CompatBoundaryTest(unittest.TestCase):
    def tearDown(self):
        compat._GIT_EXECUTABLE_CACHE.clear()
        compat._MANAGED_PROCESS_TREES.clear()
        compat._POSIX_MANAGED_PROCESS_GROUPS.clear()

    def test_setup_utf8_io_stream_capability_matrix(self):
        utf8 = SimpleNamespace(encoding="UTF-8")
        reconfigurable = MagicMock(encoding="latin-1")
        with patch.object(compat.sys, "stdout", utf8), patch.object(
            compat.sys, "stderr", reconfigurable,
        ):
            compat.setup_utf8_io()
        reconfigurable.reconfigure.assert_called_once_with(
            encoding="utf-8", errors="replace", line_buffering=True,
        )

        stdout_buffer = io.BytesIO()
        buffered = SimpleNamespace(encoding="ascii", buffer=stdout_buffer)
        plain = SimpleNamespace(encoding="ascii")
        with patch.object(compat.sys, "stdout", buffered), patch.object(
            compat.sys, "stderr", plain,
        ):
            compat.setup_utf8_io()
            self.assertIsInstance(compat.sys.stdout, io.TextIOWrapper)
            compat.sys.stdout.write("中文")
            compat.sys.stdout.flush()
            self.assertEqual(stdout_buffer.getvalue(), "中文".encode("utf-8"))
            compat.sys.stdout.detach()

    def test_subprocess_encoding_precedence_and_platform_matrix(self):
        with patch.dict(
            compat.os.environ,
            {"JAVA_TOOL_OPTIONS": "-Dfile.encoding=UTF-8"},
            clear=True,
        ):
            self.assertEqual(compat._detect_subprocess_encoding(), "utf-8")
        with patch.dict(
            compat.os.environ,
            {"MAVEN_OPTS": "-Dfile.encoding=utf-8"},
            clear=True,
        ):
            self.assertEqual(compat._detect_subprocess_encoding(), "utf-8")
        with patch.dict(
            compat.os.environ,
            {"PYTHONIOENCODING": "GB18030:replace"},
            clear=True,
        ):
            self.assertEqual(compat._detect_subprocess_encoding(), "gb18030")

        for output, expected in (
            ("Active code page: 936", "gbk"),
            ("Active code page: 54936", "gbk"),
            ("Active code page: 950", "big5"),
            ("Active code page: 437", "mbcs"),
        ):
            completed = SimpleNamespace(stdout=MagicMock())
            completed.stdout.decode.return_value = output
            with self.subTest(output=output), patch.dict(
                compat.os.environ, {}, clear=True,
            ), patch.object(compat, "IS_WINDOWS", True), patch.object(
                compat.subprocess, "run", return_value=completed,
            ):
                self.assertEqual(compat._detect_subprocess_encoding(), expected)
        with patch.dict(compat.os.environ, {}, clear=True), patch.object(
            compat, "IS_WINDOWS", True,
        ), patch.object(compat.subprocess, "run", side_effect=OSError("chcp")):
            self.assertEqual(compat._detect_subprocess_encoding(), "mbcs")
        for preferred, expected in (("UTF-16", "UTF-16"), ("", "utf-8")):
            with self.subTest(preferred=preferred), patch.dict(
                compat.os.environ, {}, clear=True,
            ), patch.object(compat, "IS_WINDOWS", False), patch.object(
                compat.locale, "getpreferredencoding", return_value=preferred,
            ):
                self.assertEqual(compat._detect_subprocess_encoding(), expected)

    def test_output_decoding_and_executable_normalization_matrix(self):
        self.assertEqual(compat._decode_subprocess_output(b""), "")
        self.assertEqual(compat._decode_subprocess_output("中文".encode()), "中文")
        with patch.object(compat, "_SUBPROCESS_ENCODING", "ascii"):
            self.assertEqual(compat._decode_subprocess_output(b"\xff"), "ÿ")
        with patch.object(compat, "_SUBPROCESS_ENCODING", "not-an-encoding"):
            self.assertEqual(compat._decode_subprocess_output(b"\xfe"), "þ")

        self.assertEqual(compat._normalized_executable_path(""), "")
        absolute = str(Path("/opt/tools/git"))
        self.assertEqual(compat._normalized_executable_path(absolute), absolute)
        with patch.object(compat.shutil, "which", return_value="/usr/bin/tool"):
            self.assertEqual(
                compat._normalized_executable_path("tool"), "/usr/bin/tool",
            )
        with patch.object(compat.shutil, "which", return_value=None):
            self.assertEqual(
                compat._normalized_executable_path("tool"),
                os.path.abspath("tool"),
            )
        self.assertEqual(
            compat._normalized_executable_path("bin/tool"),
            os.path.abspath("bin/tool"),
        )

    def test_git_command_identification_all_candidate_sources(self):
        for command in (None, "git", [], (), [""], [None]):
            with self.subTest(command=command):
                self.assertFalse(compat._command_uses_git(command))
        self.assertTrue(compat._command_uses_git(["git", "status"]))
        self.assertTrue(compat._command_uses_git(["/tools/GIT.EXE"]))

        with patch.dict(
            compat.os.environ, {"JUA_GIT_EXECUTABLE": "/custom/git-tool"},
            clear=False,
        ), patch.object(
            compat, "_normalized_executable_path", side_effect=lambda value: str(value),
        ):
            self.assertTrue(compat._command_uses_git(["/custom/git-tool"]))
            self.assertFalse(compat._command_uses_git(["/other/tool"]))

        with patch.dict(
            compat.os.environ, {"JUA_GIT_EXECUTABLE": ""}, clear=False,
        ), patch.object(
            compat, "_GIT_EXECUTABLE_CACHE", {"one": "", "two": "/cached/git"},
        ), patch.object(
            compat, "_normalized_executable_path", side_effect=lambda value: str(value),
        ):
            self.assertTrue(compat._command_uses_git(["/cached/git"]))
            self.assertFalse(compat._command_uses_git(["/different/git-tool"]))

    def test_git_config_allowlist_parsing_deduplication_and_limits(self):
        safe = (
            "http.https://example.test.extraHeader",
            "credential.helper",
            "core.sshCommand",
            "ssh.variant",
            "url.ssh://git@example.test/.insteadOf",
            "url.ssh://git@example.test/.pushInsteadOf",
            "remote.origin.proxy",
            "remote.origin.proxyAuthMethod",
            "protocol.https.allow",
        )
        for key in safe:
            with self.subTest(key=key):
                self.assertTrue(compat._git_config_key_is_transport_safe(key))
        for key in (None, "", "core.hooksPath", "protocol.file.allow"):
            with self.subTest(key=key):
                self.assertFalse(compat._git_config_key_is_transport_safe(key))

        self.assertEqual(
            compat._case_insensitive_env_items({"key": "first", "KEY": "last"}),
            {"KEY": "last"},
        )
        environment = {
            "git_config_count": "5",
            "git_config_key_0": "http.proxy",
            "git_config_value_0": "proxy",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_VALUE_1": "/unsafe",
            "GIT_CONFIG_KEY_2": "credential.helper",
            # Missing VALUE_2 proves incomplete indexed entries are ignored.
            "GIT_CONFIG_VALUE_3": "orphan",
            # Empty KEY_3 proves incomplete indexed entries are ignored.
            "GIT_CONFIG_KEY_4": "protocol.ssh.allow",
            "GIT_CONFIG_VALUE_4": "always",
            "GIT_CONFIG_PARAMETERS": (
                "'http.proxy=proxy' 'credential.useHttpPath=true' "
                "'core.hooksPath=/unsafe' 'separatorless'"
            ),
        }
        self.assertEqual(compat._parse_inherited_git_config(environment), [
            ("http.proxy", "proxy"),
            ("protocol.ssh.allow", "always"),
            ("credential.useHttpPath", "true"),
        ])
        for raw_count in ("invalid", "-1", str(compat._MAX_INHERITED_GIT_CONFIG_ITEMS + 1)):
            with self.subTest(raw_count=raw_count):
                self.assertEqual(compat._parse_inherited_git_config({
                    "GIT_CONFIG_COUNT": raw_count,
                    "GIT_CONFIG_PARAMETERS": "'unterminated",
                }), [])

    def test_git_environment_sanitization_redaction_and_observer_failures(self):
        environment = {
            "git_dir": "/wrong",
            "Git_Config_Count": "2",
            "GIT_CONFIG_KEY_0": "http.proxy",
            "GIT_CONFIG_VALUE_0": "proxy",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_VALUE_1": "/unsafe",
            "GIT_TRACE_PACKET": "1",
            "KEEP": "value",
        }
        result = compat._sanitize_git_environment(environment)
        self.assertIs(result, environment)
        self.assertNotIn("git_dir", result)
        self.assertNotIn("GIT_TRACE_PACKET", result)
        self.assertEqual(result["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(result["GIT_CONFIG_KEY_0"], "http.proxy")
        self.assertEqual(result["KEEP"], "value")
        self.assertEqual(result["GIT_TERMINAL_PROMPT"], "0")

        secret = (
            "http.https://host.extraHeader=Authorization: Bearer abc\n"
            "proxy-authorization: Basic xyz\n"
            "https://user:pass@example.test/repo?access_token=secret "
            "git@example.test:private/repo.git"
        )
        redacted = compat._redact_git_text(secret)
        for value in ("abc", "xyz", "user:pass", "secret"):
            self.assertNotIn(value, redacted)
        self.assertEqual(
            compat._redact_git_command([secret, "plain"]),
            [redacted, "plain"],
        )

        observer = MagicMock()
        self.assertEqual(
            compat._finish_observed_command(observer, "token", ("", "", 0)),
            ("", "", 0),
        )
        observer.command_finished.assert_called_once_with("token")
        for candidate, token in ((None, "token"), (observer, None)):
            compat._finish_observed_command(candidate, token, "result")
        observer.command_finished.side_effect = AttributeError("observer")
        self.assertEqual(
            compat._finish_observed_command(observer, "token", "result"),
            "result",
        )

    def test_maven_settings_options_and_repository_fallback_matrix(self):
        self.assertEqual(compat._extract_maven_repo_local_from_opts(""), "")
        self.assertEqual(
            compat._extract_maven_repo_local_from_opts("-Xmx2g"), "",
        )
        self.assertEqual(
            compat._extract_maven_repo_local_from_opts(
                '-Dmaven.repo.local="/quoted repo"'
            ),
            "/quoted repo",
        )
        self.assertEqual(
            compat._extract_maven_repo_local_from_opts(
                '-Dmaven.repo.local="unterminated'
            ),
            '"unterminated',
        )

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            with patch.object(compat.Path, "home", return_value=home):
                self.assertIsNone(compat._read_maven_settings_local_repo())
            settings = home / ".m2" / "settings.xml"
            settings.parent.mkdir()
            settings.write_text("<settings><mirror/></settings>", encoding="utf-8")
            with patch.object(compat.Path, "home", return_value=home):
                self.assertIsNone(compat._read_maven_settings_local_repo())
            settings.write_text("<settings><broken>", encoding="utf-8")
            with patch.object(compat.Path, "home", return_value=home):
                self.assertIsNone(compat._read_maven_settings_local_repo())
            with patch.object(compat.Path, "home", return_value=home), patch.object(
                compat.Path, "read_text", side_effect=OSError("unreadable"),
            ):
                self.assertIsNone(compat._read_maven_settings_local_repo())

            empty_environment = {
                "MAVEN_REPO_LOCAL": "",
                "MAVEN_OPTS": "",
                "JAVA_TOOL_OPTIONS": "",
                "MAVEN_USER_HOME": "",
            }
            with patch.object(compat.Path, "home", return_value=home), patch.dict(
                compat.os.environ,
                {**empty_environment, "JAVA_TOOL_OPTIONS": "-Dmaven.repo.local=/java/repo"},
                clear=True,
            ), patch.object(compat, "_read_maven_settings_local_repo", return_value=None):
                self.assertEqual(compat.maven_repo_dir(), Path("/java/repo"))
            with patch.object(compat.Path, "home", return_value=home), patch.dict(
                compat.os.environ, empty_environment, clear=True,
            ), patch.object(
                compat, "_read_maven_settings_local_repo",
                return_value="${user.home}/settings-repo",
            ):
                self.assertEqual(
                    compat.maven_repo_dir(), home / "settings-repo",
                )
            with patch.object(compat.Path, "home", return_value=home), patch.dict(
                compat.os.environ, empty_environment, clear=True,
            ), patch.object(compat, "_read_maven_settings_local_repo", return_value=None):
                self.assertEqual(
                    compat.maven_repo_dir(), home / ".m2" / "repository",
                )

    def test_text_io_and_human_confirmation_complete_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "nested" / "text.txt"
            compat.write_text(path, "a\nb")
            self.assertEqual(path.read_bytes(), b"a\nb")
            with compat.open_text(path) as stream:
                self.assertEqual(stream.read(), "a\nb")
            with compat.open_text(path, "w") as stream:
                stream.write("replacement")
            self.assertEqual(path.read_text(encoding="utf-8"), "replacement")

        class BrokenTty:
            def isatty(self):
                raise OSError("stdin")

        with patch.object(compat.sys, "stdin", BrokenTty()), patch.object(
            compat.sys, "stderr", io.StringIO(),
        ), patch.dict(compat.os.environ, {}, clear=True):
            self.assertTrue(compat.require_human_confirm("", []))

        tty = MagicMock()
        tty.isatty.return_value = True
        for mode in ("report", "log"):
            with self.subTest(mode=mode), patch.object(
                compat.sys, "stdin", tty,
            ), patch.object(compat.sys, "stderr", io.StringIO()), patch.dict(
                compat.os.environ, {"JUA_CONFIRM_MODE": mode}, clear=True,
            ):
                self.assertTrue(compat.require_human_confirm("Review"))
        for mode in ("block", "strict"):
            with self.subTest(mode=mode), patch.object(
                compat.sys, "stdin", tty,
            ), patch.object(compat.sys, "stderr", io.StringIO()), patch.dict(
                compat.os.environ, {"JUA_CONFIRM_MODE": mode}, clear=True,
            ):
                self.assertFalse(compat.require_human_confirm("Review"))
        for mode, answer, expected in (
            ("prompt", "YES", True),
            ("interactive", "no", False),
            ("custom", "yes", True),
        ):
            with self.subTest(mode=mode), patch.object(
                compat.sys, "stdin", tty,
            ), patch.object(compat.sys, "stderr", io.StringIO()), patch.dict(
                compat.os.environ, {"JUA_CONFIRM_MODE": mode}, clear=True,
            ), patch("builtins.input", return_value=answer):
                self.assertEqual(compat.require_human_confirm("Review"), expected)
        with patch.object(compat.sys, "stdin", tty), patch.object(
            compat.sys, "stderr", io.StringIO(),
        ), patch.dict(
            compat.os.environ, {"JUA_CONFIRM_MODE": "custom"}, clear=True,
        ), patch("builtins.input", side_effect=EOFError):
            self.assertFalse(compat.require_human_confirm("Review"))

    def test_executable_resolution_and_build_tool_command_matrix(self):
        with patch.object(compat, "_find_working_git", return_value="/git") as find_git:
            self.assertEqual(compat.find_executable("GIT.EXE"), "/git")
        find_git.assert_called_once_with()
        with patch.object(compat.shutil, "which", return_value="/tool"):
            self.assertEqual(compat.find_executable("tool"), "/tool")
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat.shutil, "which", return_value=None,
        ):
            self.assertIsNone(compat.find_executable("tool"))
        calls = []

        def windows_which(name):
            calls.append(name)
            return "C:/tool.exe" if name == "tool.exe" else None

        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat.shutil, "which", side_effect=windows_which,
        ):
            self.assertEqual(compat.find_executable("tool"), "C:/tool.exe")
        self.assertEqual(calls, ["tool", "tool.cmd", "tool.bat", "tool.exe"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            mvnw = root / "mvnw"
            gradlew = root / "gradlew"
            mvnw.write_text("wrapper", encoding="utf-8")
            gradlew.write_text("wrapper", encoding="utf-8")
            with patch.object(compat, "IS_WINDOWS", False), patch.object(
                compat.os, "access", return_value=False,
            ), patch.object(compat, "find_executable", return_value=None):
                self.assertEqual(compat.mvn_cmd(root), ["sh", str(mvnw)])
                self.assertEqual(compat.gradle_cmd(root), ["sh", str(gradlew)])
            with patch.object(compat, "IS_WINDOWS", False), patch.object(
                compat.os, "access", return_value=True,
            ):
                self.assertEqual(compat.mvn_cmd(root), [str(mvnw)])
                self.assertEqual(compat.gradle_cmd(root), [str(gradlew)])

            windows_mvnw = root / "mvnw.cmd"
            windows_gradlew = root / "gradlew.bat"
            windows_mvnw.write_text("wrapper", encoding="utf-8")
            windows_gradlew.write_text("wrapper", encoding="utf-8")
            with patch.object(compat, "IS_WINDOWS", True):
                self.assertEqual(compat.mvn_cmd(root), [str(windows_mvnw)])
                self.assertEqual(compat.gradle_cmd(root), [str(windows_gradlew)])

        with patch.object(compat, "find_executable", side_effect=lambda name: {
            "mvn": "/mvn", "gradle": "/gradle",
        }.get(name)):
            self.assertEqual(compat.mvn_cmd(), ["/mvn"])
            self.assertEqual(compat.gradle_cmd("/missing"), ["/gradle"])
        with patch.object(compat, "find_executable", return_value=None):
            self.assertEqual(compat.mvn_cmd(), ["mvn"])
            self.assertEqual(compat.gradle_cmd("/missing"), ["gradle"])

        with patch.object(compat, "find_executable", return_value=None), patch.object(
            compat, "IS_WINDOWS", False,
        ):
            self.assertEqual(compat.git_cmd(), ["git"])
        with patch.object(compat, "find_executable", return_value="C:/git.exe"), patch.object(
            compat, "IS_WINDOWS", True,
        ):
            self.assertEqual(
                compat.git_cmd(),
                ["C:/git.exe", "-c", "core.longpaths=true"],
            )
        for command in (None, [], (), "git"):
            self.assertIs(compat.resolve_command(command), command)
        command = ["tool", "arg"]
        self.assertIs(compat.resolve_command(command), command)
        with patch.object(compat, "find_executable", return_value="/git"):
            self.assertEqual(compat.resolve_command(["GIT", "status"]), ["/git", "status"])
        with patch.object(compat, "find_executable", return_value=None):
            self.assertEqual(compat.resolve_command(["git", "status"]), ["git", "status"])

    def test_xml_and_gradle_parser_boundaries(self):
        empty = compat.ET.fromstring("<project><empty/><x> </x></project>")
        self.assertEqual(compat._xml_first_text(empty, "artifactId"), "")
        populated = compat.ET.fromstring(
            "<project><ignored>v</ignored><artifactId> demo </artifactId></project>"
        )
        self.assertEqual(compat._xml_first_text(populated, "artifactId"), "demo")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invalid = root / "invalid.xml"
            invalid.write_text("<broken>", encoding="utf-8")
            self.assertIsNone(compat._parse_pom_coord(invalid))
            direct = root / "direct.xml"
            direct.write_text(
                "<project><groupId>g</groupId><artifactId>a</artifactId></project>",
                encoding="utf-8",
            )
            self.assertEqual(compat._parse_pom_coord(direct), "g:a")
            inherited = root / "inherited.xml"
            inherited.write_text(
                "<project><parent><groupId>parent.g</groupId></parent>"
                "<artifactId>child</artifactId></project>",
                encoding="utf-8",
            )
            self.assertEqual(compat._parse_pom_coord(inherited), "parent.g:child")
            incomplete = root / "incomplete.xml"
            incomplete.write_text("<project><artifactId>a</artifactId></project>", encoding="utf-8")
            self.assertIsNone(compat._parse_pom_coord(incomplete))

            self.assertEqual(compat._read_text_if_exists(root / "missing"), "")
            self.assertEqual(compat._read_text_if_exists(root), "")
            text = root / "text"
            text.write_text("value", encoding="utf-8")
            self.assertEqual(compat._read_text_if_exists(text), "value")

        for source, expected in (
            ("", ""),
            ("group 'com.example.one'", "com.example.one"),
            ("group = com.example.two", "com.example.two"),
            ("group = 'UPPER.group'", ""),
            ("group = '   '", ""),
            ("group = ''", ""),
            ("group = 'bad/group'", ""),
        ):
            with self.subTest(source=source):
                self.assertEqual(
                    compat._extract_gradle_group_from_text(source), expected,
                )
        for source, expected in (
            ("", ""),
            ("archivesBaseName = 'base'", "base"),
            ("archivesName = 'archive'", "archive"),
            ("artifactId = 'artifact'", "artifact"),
            ("rootProject.name = 'root'", "root"),
            ("archivesName = ''", ""),
        ):
            with self.subTest(source=source):
                self.assertEqual(
                    compat._extract_gradle_artifact_from_text(source), expected,
                )

    def test_gradle_file_iteration_coordinate_and_ancestor_fallbacks(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            module = repo / "services" / "api"
            module.mkdir(parents=True)
            (repo / "gradle.properties").write_text("ignored=true\n", encoding="utf-8")
            (repo / "settings.gradle").write_text(
                "rootProject.name = 'repository'\n", encoding="utf-8",
            )
            (repo / "build.gradle").write_text(
                "group = 'com.example.root'\n", encoding="utf-8",
            )
            (module / "build.gradle").write_text("plugins {}\n", encoding="utf-8")
            (module / "build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")
            (module / "settings.gradle").write_text("plugins {}\n", encoding="utf-8")
            (module / "api-extra.gradle").write_text("plugins {}\n", encoding="utf-8")
            (module / "api-more.gradle.kts").write_text("plugins {}\n", encoding="utf-8")

            files = [path.name for path in compat._iter_gradle_build_files(module)]
            self.assertEqual(files, [
                "build.gradle", "build.gradle.kts",
                "api-extra.gradle", "api-more.gradle.kts",
            ])
            self.assertEqual(compat._extract_gradle_group_from_file(repo / "missing"), "")
            self.assertEqual(
                compat._infer_gradle_group_from_ancestors(module, repo),
                "com.example.root",
            )
            self.assertEqual(
                compat._parse_gradle_coord(module / "api-extra.gradle"),
                None,
            )
            self.assertEqual(
                compat._parse_gradle_coord_with_repo_context(
                    module / "api-extra.gradle", repo,
                ),
                "com.example.root:api-extra",
            )
            (module / "gradle.properties").write_text(
                "group=com.example.module\n", encoding="utf-8",
            )
            self.assertEqual(
                compat._extract_group_from_gradle_properties(module),
                "com.example.module",
            )
            self.assertEqual(
                compat._extract_artifact_from_settings(module), "repository",
            )
            self.assertEqual(
                compat._artifact_id_from_gradle_build_file(module / "custom.gradle"),
                "custom",
            )
            self.assertEqual(
                compat._artifact_id_from_gradle_build_file(module / "custom.txt"),
                "",
            )
            empty = module / "empty.gradle"
            empty.write_text("", encoding="utf-8")
            self.assertIsNone(compat._parse_gradle_coord(empty))

            isolated = repo / "isolated"
            isolated.mkdir()
            build = isolated / "build.gradle"
            build.write_text("group = 'com.example.isolated'\n", encoding="utf-8")
            self.assertEqual(
                compat._parse_gradle_coord(build),
                "com.example.isolated:isolated",
            )
            no_group = isolated / "named.gradle"
            no_group.write_text("plugins {}\n", encoding="utf-8")
            with patch.object(
                compat, "_infer_gradle_group_from_ancestors", return_value="",
            ):
                self.assertIsNone(
                    compat._parse_gradle_coord_with_repo_context(no_group, isolated),
                )

    def test_sigterm_install_restore_and_handler_semantics(self):
        process = SimpleNamespace()
        token = object()
        setattr(process, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE, object())
        with patch.object(
            compat, "_POSIX_MANAGED_PROCESS_GROUPS", {123},
        ), patch.object(
            compat, "_MANAGED_PROCESS_TREES", {token: (process, 123, True)},
        ), patch.object(
            compat, "_PREVIOUS_SIGTERM_HANDLER", signal.SIG_IGN,
        ), patch.object(
            compat, "_MANAGED_SIGTERM_HANDLER_INSTALLED", True,
        ), patch.object(compat.os, "killpg", side_effect=OSError), patch.object(
            compat.signal, "signal",
        ) as install, patch.object(compat.os, "kill") as kill:
            compat._managed_sigterm_handler(signal.SIGTERM, None)
        install.assert_called_once_with(signal.SIGTERM, signal.SIG_IGN)
        kill.assert_not_called()

        with patch.object(
            compat, "_POSIX_MANAGED_PROCESS_GROUPS", set(),
        ), patch.object(
            compat, "_MANAGED_PROCESS_TREES", {},
        ), patch.object(
            compat, "_PREVIOUS_SIGTERM_HANDLER", signal.SIG_DFL,
        ), patch.object(
            compat, "_MANAGED_SIGTERM_HANDLER_INSTALLED", True,
        ), patch.object(compat.signal, "signal") as install, patch.object(
            compat.os, "getpid", return_value=77,
        ), patch.object(compat.os, "kill") as kill:
            compat._managed_sigterm_handler(signal.SIGTERM, "frame")
        install.assert_called_once_with(signal.SIGTERM, signal.SIG_DFL)
        kill.assert_called_once_with(77, signal.SIGTERM)

        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat.signal, "getsignal",
        ) as getsignal:
            compat._ensure_managed_sigterm_handler()
        getsignal.assert_not_called()
        worker = MagicMock()
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat.threading, "current_thread", return_value=worker,
        ), patch.object(
            compat.threading, "main_thread", return_value=object(),
        ), patch.object(compat.signal, "getsignal") as getsignal:
            compat._ensure_managed_sigterm_handler()
        getsignal.assert_not_called()

        for current, signal_error, expected_installed in (
            (compat._managed_sigterm_handler, None, True),
            (signal.SIG_DFL, OSError("install"), False),
            (signal.SIG_DFL, None, True),
        ):
            with self.subTest(current=current, signal_error=signal_error), patch.object(
                compat, "IS_WINDOWS", False,
            ), patch.object(
                compat.threading, "current_thread", return_value=threading.main_thread(),
            ), patch.object(
                compat, "_MANAGED_SIGTERM_HANDLER_INSTALLED", False,
            ), patch.object(
                compat, "_PREVIOUS_SIGTERM_HANDLER", None,
            ), patch.object(
                compat.signal, "getsignal", return_value=current,
            ), patch.object(
                compat.signal, "signal", side_effect=signal_error,
            ):
                compat._ensure_managed_sigterm_handler()
                self.assertEqual(
                    compat._MANAGED_SIGTERM_HANDLER_INSTALLED,
                    expected_installed,
                )

        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat.signal, "getsignal",
        ) as getsignal:
            compat._restore_managed_sigterm_handler()
        getsignal.assert_not_called()
        for groups, installed in (({1}, True), (set(), False)):
            with self.subTest(groups=groups, installed=installed), patch.object(
                compat, "IS_WINDOWS", False,
            ), patch.object(
                compat, "_POSIX_MANAGED_PROCESS_GROUPS", groups,
            ), patch.object(
                compat, "_MANAGED_SIGTERM_HANDLER_INSTALLED", installed,
            ), patch.object(compat.signal, "getsignal") as getsignal:
                compat._restore_managed_sigterm_handler()
            getsignal.assert_not_called()
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat, "_POSIX_MANAGED_PROCESS_GROUPS", set(),
        ), patch.object(
            compat, "_MANAGED_SIGTERM_HANDLER_INSTALLED", True,
        ), patch.object(
            compat, "_PREVIOUS_SIGTERM_HANDLER", signal.SIG_IGN,
        ), patch.object(
            compat.signal, "getsignal", return_value=signal.SIG_DFL,
        ), patch.object(compat.signal, "signal") as install:
            compat._restore_managed_sigterm_handler()
        install.assert_not_called()
        self.assertFalse(compat._MANAGED_SIGTERM_HANDLER_INSTALLED)

    def test_process_tree_registration_take_and_duplicate_ownership(self):
        invalid = SimpleNamespace(pid="invalid")
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat, "_ensure_managed_sigterm_handler",
        ):
            with self.assertRaisesRegex(ValueError, "valid pid"):
                compat._register_managed_process_tree(invalid)

        windows_invalid = SimpleNamespace(pid="invalid")
        with patch.object(compat, "IS_WINDOWS", True):
            compat._register_managed_process_tree(windows_invalid)
        token = getattr(
            windows_invalid, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE,
        )
        self.assertIsNone(compat._MANAGED_PROCESS_TREES[token][1])
        self.assertTrue(compat._unregister_managed_process_tree(windows_invalid))
        self.assertFalse(compat._unregister_managed_process_tree(windows_invalid))

        process = SimpleNamespace(pid=50)
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat, "_ensure_managed_sigterm_handler",
        ), patch.object(compat, "_restore_managed_sigterm_handler"):
            compat._register_managed_process_tree(process)
            with self.assertRaisesRegex(RuntimeError, "already managed"):
                compat._register_managed_process_tree(process)
            wrong = SimpleNamespace(pid=50)
            setattr(
                wrong,
                compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE,
                getattr(process, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE),
            )
            self.assertIsNone(compat._take_managed_process_tree(wrong))
            self.assertTrue(compat._claim_managed_process_tree(process))
            self.assertFalse(compat._claim_managed_process_tree(process))

        first = SimpleNamespace(pid=60)
        second = SimpleNamespace(pid=60)
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat, "_ensure_managed_sigterm_handler",
        ), patch.object(compat, "_restore_managed_sigterm_handler"):
            compat._register_managed_process_tree(first)
            compat._register_managed_process_tree(second)
            self.assertIsNotNone(compat._take_managed_process_tree(first))
            self.assertIn(60, compat._POSIX_MANAGED_PROCESS_GROUPS)
            self.assertIsNotNone(compat._take_managed_process_tree(second))
            self.assertNotIn(60, compat._POSIX_MANAGED_PROCESS_GROUPS)

    @staticmethod
    def _windows_kernel(*, create=101, assign=True, terminate=True):
        kernel = SimpleNamespace(
            CreateJobObjectW=MagicMock(return_value=create),
            AssignProcessToJobObject=MagicMock(return_value=assign),
            CloseHandle=MagicMock(return_value=True),
            TerminateJobObject=MagicMock(return_value=terminate),
        )
        return kernel

    def test_windows_job_attach_creation_assignment_and_release_matrix(self):
        process = SimpleNamespace(_handle=88)
        for is_windows, os_name in ((False, "posix"), (True, "posix")):
            with self.subTest(is_windows=is_windows, os_name=os_name), patch.object(
                compat, "IS_WINDOWS", is_windows,
            ), patch.object(compat.os, "name", os_name):
                self.assertIsNone(compat._attach_windows_managed_job(process))

        def windows_context(kernel):
            return (
                patch.object(compat, "IS_WINDOWS", True),
                patch.object(compat.os, "name", "nt"),
                patch.object(ctypes, "WinDLL", return_value=kernel, create=True),
                patch.object(ctypes, "get_last_error", return_value=5, create=True),
                patch.object(
                    ctypes, "WinError", side_effect=lambda code: OSError(code),
                    create=True,
                ),
            )

        kernel = self._windows_kernel()
        contexts = windows_context(kernel)
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
            compat._attach_windows_managed_job(process)
        self.assertEqual(
            getattr(process, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE), 101,
        )

        missing = self._windows_kernel(create=0)
        contexts = windows_context(missing)
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
            with self.assertRaises(OSError):
                compat._attach_windows_managed_job(SimpleNamespace(_handle=1))
        missing.CloseHandle.assert_not_called()

        rejected = self._windows_kernel(assign=False)
        contexts = windows_context(rejected)
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
            with self.assertRaises(OSError):
                compat._attach_windows_managed_job(SimpleNamespace(_handle=1))
        rejected.CloseHandle.assert_called_once_with(101)

        self.assertFalse(compat._release_windows_managed_job(SimpleNamespace()))
        outside = SimpleNamespace()
        setattr(outside, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE, 9)
        with patch.object(compat, "IS_WINDOWS", False):
            self.assertFalse(compat._release_windows_managed_job(outside))

        release_kernel = self._windows_kernel(terminate=True)
        contexts = windows_context(release_kernel)
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
            self.assertTrue(
                compat._release_windows_managed_job(process, terminate=True),
            )
        release_kernel.TerminateJobObject.assert_called_once()
        release_kernel.CloseHandle.assert_called_once()
        self.assertFalse(hasattr(process, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE))

        process = SimpleNamespace()
        setattr(process, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE, 202)
        release_kernel = self._windows_kernel(terminate=False)
        contexts = windows_context(release_kernel)
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
            self.assertFalse(
                compat._release_windows_managed_job(process, terminate=False),
            )
        release_kernel.TerminateJobObject.assert_not_called()

    def test_windows_job_assignment_retries_only_access_denied(self):
        def attach(kernel, error_codes):
            process = SimpleNamespace(_handle=88)
            with patch.object(compat, "IS_WINDOWS", True), patch.object(
                compat.os, "name", "nt",
            ), patch.object(
                ctypes, "WinDLL", return_value=kernel, create=True,
            ), patch.object(
                ctypes, "get_last_error", side_effect=error_codes, create=True,
            ), patch.object(
                ctypes,
                "WinError",
                side_effect=lambda code: OSError(code),
                create=True,
            ), patch.object(compat.time, "sleep") as sleep:
                compat._attach_windows_managed_job(process)
            return process, sleep

        transient = self._windows_kernel()
        transient.AssignProcessToJobObject.side_effect = [False, False, True]
        process, sleep = attach(transient, [5, 5])
        self.assertEqual(transient.AssignProcessToJobObject.call_count, 3)
        self.assertEqual(
            [item.args[0] for item in sleep.call_args_list],
            [
                compat._WINDOWS_JOB_ASSIGNMENT_RETRY_DELAY_SECONDS,
                compat._WINDOWS_JOB_ASSIGNMENT_RETRY_DELAY_SECONDS * 2,
            ],
        )
        self.assertEqual(
            getattr(process, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE), 101,
        )
        transient.CloseHandle.assert_not_called()

        persistent = self._windows_kernel(assign=False)
        with self.assertRaises(OSError):
            attach(persistent, [5, 5, 5])
        self.assertEqual(persistent.AssignProcessToJobObject.call_count, 3)
        persistent.CloseHandle.assert_called_once_with(101)

        deterministic = self._windows_kernel(assign=False)
        with self.assertRaises(OSError):
            attach(deterministic, [87])
        deterministic.AssignProcessToJobObject.assert_called_once()
        deterministic.CloseHandle.assert_called_once_with(101)

    def test_managed_popen_option_conflicts_spawn_and_assignment_failures(self):
        process = SimpleNamespace(pid=1)
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "managed_foreground_process_kwargs",
            return_value={"creationflags": 8},
        ), patch.object(
            compat.subprocess, "Popen", return_value=process,
        ) as popen, patch.object(
            compat, "_register_managed_process_tree",
        ), patch.object(compat, "_attach_windows_managed_job"):
            self.assertIs(compat.managed_popen(["tool"], creationflags=2), process)
        self.assertEqual(popen.call_args.kwargs["creationflags"], 10)

        for managed, supplied in (
            ({"start_new_session": True}, {"start_new_session": False}),
            ({"custom": "required"}, {"custom": "conflict"}),
        ):
            with self.subTest(managed=managed), patch.object(
                compat, "IS_WINDOWS", True,
            ), patch.object(
                compat, "managed_foreground_process_kwargs", return_value=managed,
            ):
                with self.assertRaises(ValueError):
                    compat.managed_popen(["tool"], **supplied)
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat, "managed_foreground_process_kwargs",
            return_value={"start_new_session": True},
        ), patch.object(compat, "_ensure_managed_sigterm_handler") as ensure, patch.object(
            compat.subprocess, "Popen", side_effect=OSError("spawn"),
        ), patch.object(compat, "_restore_managed_sigterm_handler") as restore:
            with self.assertRaisesRegex(OSError, "spawn"):
                compat.managed_popen(["tool"], start_new_session=True)
        ensure.assert_called_once_with()
        restore.assert_called_once_with()

        process = SimpleNamespace(pid=2)
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "managed_foreground_process_kwargs", return_value={},
        ), patch.object(
            compat.subprocess, "Popen", return_value=process,
        ), patch.object(
            compat, "_register_managed_process_tree",
        ), patch.object(
            compat, "_attach_windows_managed_job", side_effect=KeyboardInterrupt,
        ), patch.object(compat, "_terminate_subprocess") as terminate:
            with self.assertRaises(KeyboardInterrupt):
                compat.managed_popen(["tool"])
        terminate.assert_called_once_with(process, process_group=True)

    def test_git_stdout_requirement_and_file_capture_exception_matrix(self):
        for command, expected in (
            (None, False),
            ([], False),
            (["git", "rev-parse"], True),
            (["git", "symbolic-ref"], True),
            (["git", "worktree"], False),
            (["git", "worktree", "list"], True),
            (["git", "remote", "get-url"], True),
            (["git", "remote", "show"], False),
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    compat._git_command_requires_stdout(command), expected,
                )

        for error in (KeyboardInterrupt(), OSError("communicate")):
            process = MagicMock()
            process.communicate.side_effect = error
            with self.subTest(error=type(error).__name__), patch.object(
                compat, "managed_popen", return_value=process,
            ), patch.object(compat, "_terminate_subprocess") as terminate, patch.object(
                compat, "_close_subprocess_pipes",
            ) as close:
                with self.assertRaises(type(error)):
                    compat._run_git_file_capture(
                        ["git", "rev-parse"], cwd=None, timeout=1,
                        input_bytes=b"input", env={}, process_group_kwargs={},
                    )
            terminate.assert_called_once_with(process, process_group=True)
            close.assert_called_once_with(process)

    def test_terminate_and_close_subprocess_failure_tolerance_matrix(self):
        stale = MagicMock()
        with patch.object(
            compat, "_claim_managed_process_tree", return_value=False,
        ), patch.object(compat.os, "killpg") as kill_group:
            compat._terminate_subprocess(stale, process_group=True)
        kill_group.assert_not_called()

        process = MagicMock(pid=12)
        process.poll.return_value = None
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat, "_claim_managed_process_tree", return_value=True,
        ), patch.object(compat.os, "killpg", side_effect=OSError):
            compat._terminate_subprocess(process, process_group=True)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)

        stopped = MagicMock()
        stopped.poll.return_value = 0
        compat._terminate_subprocess(stopped, process_group=False)
        stopped.kill.assert_not_called()
        stopped.wait.assert_called_once_with(timeout=5)

        broken = MagicMock()
        broken.poll.side_effect = OSError("poll")
        broken.kill.side_effect = OSError("kill")
        broken.wait.side_effect = subprocess.TimeoutExpired(["tool"], 5)
        compat._terminate_subprocess(broken, process_group=False)

        pipes = [None, MagicMock(), MagicMock(), MagicMock()]
        pipes[-1].close.side_effect = OSError("close")
        pipe_process = SimpleNamespace(
            stdin=pipes[0], stdout=pipes[1], stderr=pipes[-1],
        )
        compat._close_subprocess_pipes(pipe_process)
        pipes[1].close.assert_called_once_with()

    def test_run_managed_subprocess_argument_timeout_cleanup_and_check_matrix(self):
        with self.assertRaisesRegex(ValueError, "stdin and input"):
            compat.run_managed_subprocess(
                ["tool"], input=b"x", stdin=subprocess.PIPE,
            )
        for conflict in ({"stdout": subprocess.PIPE}, {"stderr": subprocess.PIPE}):
            with self.subTest(conflict=conflict), self.assertRaisesRegex(
                ValueError, "capture_output",
            ):
                compat.run_managed_subprocess(
                    ["tool"], capture_output=True, **conflict,
                )

        process = SimpleNamespace(returncode=0)
        process.communicate = MagicMock(return_value=(b"out", b"err"))
        with patch.object(compat, "managed_popen", return_value=process) as popen, patch.object(
            compat, "release_process_tree",
        ) as release:
            completed = compat.run_managed_subprocess(
                ["tool"], input=b"input", check=True,
            )
        self.assertEqual((completed.stdout, completed.stderr), (b"out", b"err"))
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.PIPE)
        release.assert_called_once_with(process)

        timeout = subprocess.TimeoutExpired(
            ["tool"], 1, output=b"existing", stderr=b"existing-error",
        )
        process = SimpleNamespace(returncode=None)
        process.communicate = MagicMock(side_effect=[timeout, OSError("cleanup")])
        with patch.object(compat, "managed_popen", return_value=process), patch.object(
            compat, "terminate_process_tree",
        ) as terminate, patch.object(compat, "_close_subprocess_pipes") as close:
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                compat.run_managed_subprocess(["tool"], timeout=1)
        self.assertIs(raised.exception, timeout)
        self.assertEqual(raised.exception.output, b"existing")
        self.assertEqual(raised.exception.stderr, b"existing-error")
        terminate.assert_called_once_with(process)
        close.assert_called_once_with(process)

    def test_repository_probe_root_file_directory_and_marker_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            plain = base / "plain"
            plain.mkdir()
            self.assertEqual(compat._resolve_repo_probe_roots(plain), [plain])

            regular_file = plain / "input.txt"
            regular_file.write_text("input", encoding="utf-8")
            self.assertEqual(
                compat._resolve_repo_probe_roots(regular_file), [plain],
            )
            dot_git_file = plain / ".git"
            dot_git_file.write_text("gitdir: elsewhere", encoding="utf-8")
            self.assertEqual(
                compat._resolve_repo_probe_roots(dot_git_file)[0], plain,
            )
            dot_git_file.unlink()

            repository = base / "repository"
            nested = repository / "services" / "api"
            nested.mkdir(parents=True)
            (repository / ".git").mkdir()
            (nested / "pom.xml").write_text("<project/>", encoding="utf-8")
            roots = compat._resolve_repo_probe_roots(nested)
            self.assertEqual(roots[:2], [nested, repository])
            self.assertEqual(compat._find_git_root(nested), repository)
            self.assertIsNone(compat._find_git_root(base / "plain"))
            self.assertEqual(compat.resolve_repo_input_path(nested), str(nested))

            git_directory = base / "worktree" / ".git"
            git_directory.mkdir(parents=True)
            self.assertEqual(
                compat._resolve_repo_probe_roots(git_directory)[0],
                git_directory.parent,
            )

        with patch.object(compat, "_resolve_repo_probe_roots", return_value=[]):
            expected = str(Path("fallback-input").resolve())
            self.assertEqual(
                compat.resolve_repo_input_path("fallback-input"), expected,
            )
        relative = "relative-probe-without-markers"
        self.assertTrue(
            compat._resolve_repo_probe_roots(relative)[0].is_absolute(),
        )

    def test_embedded_resource_and_child_manifest_walk_boundaries(self):
        base = Path("/repo")
        cases = (
            (base / "src" / "main" / "resources", True),
            (base / "src" / "test" / "resources" / "nested", True),
            (base / "src" / "other" / "resources", False),
            (base / "other" / "main" / "resources", False),
            (base / "src" / "main" / "other", False),
            (base / "src", False),
            (Path("/outside/src/main/resources"), True),
        )
        for path, expected in cases:
            with self.subTest(path=path):
                self.assertEqual(
                    compat._is_embedded_resource_fixture_dir(path, base),
                    expected,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.assertFalse(compat._has_child_module_manifests(root))
            file_path = root / "file"
            file_path.write_text("x", encoding="utf-8")
            self.assertFalse(compat._has_child_module_manifests(file_path))
            missing = root / "missing"
            self.assertFalse(compat._has_child_module_manifests(missing))

            (root / "pom.xml").write_text("<project/>", encoding="utf-8")
            self.assertFalse(compat._has_child_module_manifests(root))
            child = root / "child"
            child.mkdir()
            (child / "pom.xml").write_text("<project/>", encoding="utf-8")
            self.assertTrue(compat._has_child_module_manifests(root))
            (child / "pom.xml").unlink()
            (child / "named.gradle").write_text("plugins {}", encoding="utf-8")
            self.assertTrue(compat._has_child_module_manifests(root))

            embedded = root / "src" / "test" / "resources" / "fixture"
            embedded.mkdir(parents=True)
            (embedded / "pom.xml").write_text("<project/>", encoding="utf-8")
            (child / "named.gradle").unlink()
            self.assertFalse(compat._has_child_module_manifests(root))

            deep = root / "one" / "two" / "three"
            deep.mkdir(parents=True)
            (deep / "pom.xml").write_text("<project/>", encoding="utf-8")
            self.assertFalse(
                compat._has_child_module_manifests(root, max_depth=2),
            )
            self.assertTrue(
                compat._has_child_module_manifests(root, max_depth=4),
            )

        outside = Path("/outside")
        with patch.object(
            compat.os, "walk", return_value=[(str(outside), ["target", "keep"], [])],
        ), patch.object(
            compat, "_is_embedded_resource_fixture_dir", return_value=False,
        ):
            self.assertFalse(compat._has_child_module_manifests(Path("/base")))

    def test_infer_locations_filter_deduplicate_depth_and_break_matrix(self):
        with patch.object(compat, "resolve_repo_input_path", return_value=""):
            self.assertEqual(compat.infer_maven_coord_locations("project"), [])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            missing = root / "missing"
            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(missing),
            ):
                self.assertEqual(
                    compat.infer_maven_coord_locations(missing), [],
                )

            pom = root / "pom.xml"
            build = root / "build.gradle"
            pom.write_text("<project/>", encoding="utf-8")
            build.write_text("plugins {}", encoding="utf-8")
            parse_pom_values = iter(("", "g:a"))
            parse_build_values = iter(("x:y", "g:a"))
            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(root),
            ), patch.object(
                compat, "_find_git_root", return_value=None,
            ), patch.object(
                compat, "_has_child_module_manifests", return_value=False,
            ), patch.object(
                compat, "_looks_like_source_module", return_value=False,
            ), patch.object(
                compat, "_iter_gradle_build_files", return_value=[build],
            ), patch.object(
                compat, "_parse_pom_coord",
                side_effect=lambda *_args: next(parse_pom_values),
            ), patch.object(
                compat, "_parse_gradle_coord_with_repo_context",
                side_effect=lambda *_args: next(parse_build_values),
            ), patch.object(
                compat.os, "walk",
                return_value=[(str(root), ["target", "keep"], ["pom.xml", "build.gradle"])],
            ):
                locations = compat.infer_maven_coord_locations(
                    root,
                    target_coords=(None, "", "g:a"),
                )
            self.assertEqual(
                [item["coord"] for item in locations], ["g:a"],
            )

            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(root),
            ), patch.object(
                compat, "_has_child_module_manifests", return_value=True,
            ), patch.object(
                compat, "_looks_like_source_module", return_value=False,
            ), patch.object(
                compat, "_iter_gradle_build_files", return_value=[build],
            ), patch.object(
                compat.os, "walk",
                return_value=[(str(root), ["child"], ["pom.xml", "build.gradle"])],
            ), patch.object(compat, "_parse_pom_coord") as parse_pom, patch.object(
                compat, "_parse_gradle_coord_with_repo_context",
            ) as parse_build:
                self.assertEqual(
                    compat.infer_maven_coord_locations(root, max_depth=0), [],
                )
            parse_pom.assert_not_called()
            parse_build.assert_not_called()

            child = root / "child"
            child.mkdir()
            child_pom = child / "pom.xml"
            child_pom.write_text("<project/>", encoding="utf-8")
            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(root),
            ), patch.object(
                compat, "_has_child_module_manifests", return_value=True,
            ), patch.object(
                compat, "_looks_like_source_module", return_value=False,
            ), patch.object(
                compat, "_iter_gradle_build_files", return_value=[],
            ), patch.object(
                compat, "_parse_pom_coord", return_value="g:child",
            ), patch.object(
                compat.os, "walk", return_value=[
                    (str(root), ["child"], ["pom.xml"]),
                    (str(child), [], ["pom.xml"]),
                ],
            ):
                locations = compat.infer_maven_coord_locations(
                    root, max_poms=1,
                )
            self.assertEqual(
                [item["coord"] for item in locations], ["g:child"],
            )

            outside = root.parent / "outside-walk"
            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(root),
            ), patch.object(
                compat, "_has_child_module_manifests", return_value=False,
            ), patch.object(
                compat, "_iter_gradle_build_files", return_value=[],
            ), patch.object(
                compat.os, "walk", return_value=[(str(outside), [], [])],
            ):
                self.assertEqual(
                    compat.infer_maven_coord_locations(root), [],
                )

    def test_ancestor_group_search_empty_and_repository_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            module = root / "one" / "two"
            module.mkdir(parents=True)
            self.assertEqual(
                compat._infer_gradle_group_from_ancestors(module, root), "",
            )

    def test_run_cmd_streaming_input_deadline_relay_and_drain_failure(self):
        class Pipe:
            def __init__(self, lines=(), error=None):
                self.lines = list(lines)
                self.error = error
                self.closed = False

            def readline(self):
                if self.error is not None:
                    error, self.error = self.error, None
                    raise error
                return self.lines.pop(0) if self.lines else b""

            def close(self):
                self.closed = True

        class SyncThread:
            def __init__(self, *, target, args, daemon):
                self.target = target
                self.args = args
                self.daemon = daemon
                self.started = False

            def start(self):
                self.started = True
                self.target(*self.args)

            def join(self, timeout=None):
                return None

            def is_alive(self):
                return False

        stdin = MagicMock()
        process = SimpleNamespace(
            stdout=Pipe((b"stdout\n",)),
            stderr=Pipe((b"stderr\n",)),
            stdin=stdin,
            returncode=0,
            wait=MagicMock(return_value=0),
        )
        observer = MagicMock()
        observer.command_started.return_value = "token"
        relayed = io.StringIO()
        with patch.object(compat, "_PROCESS_OBSERVER", observer), patch.object(
            compat, "managed_popen", return_value=process,
        ) as popen, patch.object(
            compat.threading, "Thread", SyncThread,
        ), patch.object(compat, "release_process_tree") as release, patch.object(
            compat.sys, "stderr", relayed,
        ), patch.dict(
            compat.os.environ, {"JAVA_TOOL_OPTIONS": "-Dfile.encoding=ISO-8859-1"},
            clear=True,
        ):
            result = compat.run_cmd(
                ["tool"], timeout=None, input_text="输入",
                env={"EXTRA": "value"}, stream_output=True,
                stream_stdout=False,
            )
        self.assertEqual(result, ("stdout\n", "stderr\n", 0))
        self.assertEqual(relayed.getvalue(), "stderr\n")
        stdin.write.assert_called_once_with("输入".encode("utf-8"))
        stdin.close.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=None)
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.PIPE)
        self.assertEqual(popen.call_args.kwargs["env"]["EXTRA"], "value")
        self.assertEqual(
            popen.call_args.kwargs["env"]["JAVA_TOOL_OPTIONS"],
            "-Dfile.encoding=ISO-8859-1",
        )
        release.assert_called_once_with(process)
        observer.command_started.assert_called_once_with(["tool"])
        observer.command_finished.assert_called_once_with("token")

        failing = SimpleNamespace(
            stdout=Pipe(error=OSError("drain")), stderr=Pipe(), stdin=None,
            returncode=None,
            wait=MagicMock(side_effect=subprocess.TimeoutExpired(["tool"], 1)),
        )
        with patch.object(compat, "managed_popen", return_value=failing), patch.object(
            compat.threading, "Thread", SyncThread,
        ), patch.object(compat, "_terminate_subprocess") as terminate, patch.object(
            compat, "_close_subprocess_pipes",
        ):
            result = compat.run_cmd(
                ["tool"], timeout=1, stream_output=True,
            )
        self.assertEqual(result[2], -1)
        terminate.assert_called_once_with(failing, process_group=True)

    def test_run_cmd_streaming_lingering_pipe_or_operands(self):
        class StaticThread:
            def __init__(self, alive):
                self.alive = alive
                self.is_alive_calls = 0

            def start(self):
                return None

            def join(self, timeout=None):
                return None

            def is_alive(self):
                self.is_alive_calls += 1
                return self.alive

        for stdout_alive, stderr_alive in ((True, False), (False, True)):
            threads = [StaticThread(stdout_alive), StaticThread(stderr_alive)]

            def thread_factory(**_kwargs):
                return threads.pop(0)

            process = SimpleNamespace(
                stdout=MagicMock(), stderr=MagicMock(), stdin=None,
                returncode=0, wait=MagicMock(return_value=0),
            )
            with self.subTest(
                stdout_alive=stdout_alive, stderr_alive=stderr_alive,
            ), patch.object(
                compat, "managed_popen", return_value=process,
            ), patch.object(
                compat.threading, "Thread", side_effect=thread_factory,
            ), patch.object(compat, "_terminate_subprocess") as terminate, patch.object(
                compat, "_close_subprocess_pipes",
            ) as close:
                result = compat.run_cmd(
                    ["tool"], timeout=0, stream_output=True,
                )
            self.assertEqual(result[2], -1)
            terminate.assert_called_once_with(process, process_group=True)
            close.assert_called_once_with(process)

    def test_run_cmd_nonstream_git_retry_observer_and_stdin_matrix(self):
        process = SimpleNamespace(returncode=0)
        process.communicate = MagicMock(return_value=(b"", b"primary-error"))
        observer = MagicMock()
        observer.command_started.side_effect = AttributeError("start")
        with patch.object(compat, "_PROCESS_OBSERVER", observer), patch.object(
            compat, "resolve_command", return_value=["/git", "rev-parse"],
        ), patch.object(
            compat, "_command_uses_git", side_effect=[False, True],
        ), patch.object(
            compat, "managed_popen", return_value=process,
        ) as popen, patch.object(
            compat, "release_process_tree",
        ), patch.object(
            compat, "_git_command_requires_stdout", return_value=True,
        ), patch.object(
            compat, "_run_git_file_capture", return_value=("", "", 0),
        ):
            result = compat.run_cmd(
                ["alias-git"], input_text="input", timeout=2,
            )
        self.assertEqual(result[2], -1)
        self.assertIn("primary-error", result[1])
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.PIPE)
        process.communicate.assert_called_once_with(input=b"input", timeout=2)

        for retry, expected in (
            (("", "retry-error", 2), ("", "retry-error", 2)),
            (("", "", 2), ("", "primary", 2)),
            (("value", "retry", 0), ("value", "retry", 0)),
            (("", "retry-detail", 0), (
                "", "GIT_REQUIRED_STDOUT_EMPTY: Git 两种捕获方式均返回成功但没有必要输出；stderr=retry-detail", -1,
            )),
        ):
            process = SimpleNamespace(returncode=0)
            process.communicate = MagicMock(return_value=(b"", b"primary"))
            with self.subTest(retry=retry), patch.object(
                compat, "_command_uses_git", return_value=True,
            ), patch.object(
                compat, "resolve_command", return_value=["git", "rev-parse"],
            ), patch.object(
                compat, "managed_popen", return_value=process,
            ), patch.object(compat, "release_process_tree"), patch.object(
                compat, "_git_command_requires_stdout", return_value=True,
            ), patch.object(
                compat, "_run_git_file_capture", return_value=retry,
            ):
                self.assertEqual(
                    compat.run_cmd(["git", "rev-parse"]), expected,
                )

        process = SimpleNamespace(returncode=0)
        process.communicate = MagicMock(return_value=(b"", b""))
        with patch.object(
            compat, "_command_uses_git", return_value=True,
        ), patch.object(
            compat, "resolve_command", return_value=["git", "rev-parse"],
        ), patch.object(
            compat, "managed_popen", return_value=process,
        ), patch.object(compat, "release_process_tree"), patch.object(
            compat, "_git_command_requires_stdout", return_value=True,
        ), patch.object(
            compat, "_run_git_file_capture", return_value=("", "retry-only", 0),
        ):
            self.assertEqual(
                compat.run_cmd(["git", "rev-parse"]),
                (
                    "",
                    "GIT_REQUIRED_STDOUT_EMPTY: Git 两种捕获方式均返回成功但没有必要输出；stderr=retry-only",
                    -1,
                ),
            )

        process = SimpleNamespace(returncode=0)
        process.communicate = MagicMock(return_value=(b"", b""))
        with patch.object(
            compat, "_command_uses_git", return_value=True,
        ), patch.object(
            compat, "resolve_command", return_value=["git", "rev-parse"],
        ), patch.object(
            compat, "managed_popen", return_value=process,
        ), patch.object(compat, "release_process_tree"), patch.object(
            compat, "_git_command_requires_stdout", return_value=True,
        ), patch.object(
            compat, "_run_git_file_capture", return_value=("", "", 0),
        ):
            self.assertEqual(
                compat.run_cmd(["git", "rev-parse"]),
                (
                    "",
                    "GIT_REQUIRED_STDOUT_EMPTY: Git 两种捕获方式均返回成功但没有必要输出",
                    -1,
                ),
            )

    def test_run_cmd_outer_exception_mapping_empty_and_nonempty_commands(self):
        observer = MagicMock()
        observer.command_started.return_value = "token"
        cases = (
            ([], FileNotFoundError(), "命令未找到：(空命令)"),
            (["missing"], FileNotFoundError(), "命令未找到：missing"),
            (["denied"], PermissionError(), "权限不足"),
            (["slow"], subprocess.TimeoutExpired(["slow"], 1), "命令超时"),
            (["broken"], OSError("failure"), "执行异常：OSError: failure"),
        )
        for command, error, expected in cases:
            with self.subTest(command=command, error=type(error).__name__), patch.object(
                compat, "_PROCESS_OBSERVER", observer,
            ), patch.object(
                compat, "managed_popen", side_effect=error,
            ):
                result = compat.run_cmd(command, timeout=1)
            self.assertEqual(result[2], -1)
            self.assertIn(expected, result[1])

        with patch.object(compat, "_PROCESS_OBSERVER", observer), patch.object(
            compat, "managed_popen", side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                compat.run_cmd(["interrupt"])

    def test_git_candidate_platform_probe_cache_and_exhaustion_matrix(self):
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat.sys, "platform", "darwin",
        ), patch.object(compat.Path, "home", return_value=Path("/home/user")):
            candidates = compat._git_platform_fallback_candidates()
        self.assertIn("/opt/homebrew/bin/git", candidates)
        self.assertIn("/home/user/.local/bin/git", candidates)
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat.sys, "platform", "linux",
        ), patch.object(compat.Path, "home", return_value=Path("/home/user")):
            self.assertIn(
                "/usr/bin/git", compat._git_platform_fallback_candidates(),
            )

        windows_environment = {
            "ProgramFiles": "C:/Program Files",
            "ProgramFiles(x86)": "",
            "LOCALAPPDATA": "C:/Users/user/AppData/Local",
        }
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat.sys, "platform", "win32",
        ), patch.object(
            compat.Path, "home", return_value=Path("C:/Users/user"),
        ), patch.dict(compat.os.environ, windows_environment, clear=True):
            candidates = compat._git_platform_fallback_candidates()
        self.assertIn("C:/Program Files/Git/cmd/git.exe", candidates)
        self.assertIn(
            "C:/Users/user/AppData/Local/Programs/Git/cmd/git.exe",
            candidates,
        )
        self.assertFalse(any("ProgramFiles(x86)" in item for item in candidates))

        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "git"
            self.assertFalse(compat._git_executable_works(""))
            self.assertFalse(compat._git_executable_works(candidate))
            candidate.write_text("git", encoding="utf-8")
            for outcome, expected in ((0, True), (1, False)):
                completed = SimpleNamespace(returncode=outcome)
                with self.subTest(outcome=outcome), patch.object(
                    compat, "run_managed_subprocess", return_value=completed,
                ):
                    self.assertEqual(
                        compat._git_executable_works(candidate), expected,
                    )
            with patch.object(
                compat, "run_managed_subprocess", side_effect=OSError("probe"),
            ):
                self.assertFalse(compat._git_executable_works(candidate))

        environment = {
            "JUA_GIT_EXECUTABLE": "/explicit/git",
            "PATH": "/bin",
            "ProgramFiles": "",
            "ProgramFiles(x86)": "",
            "LOCALAPPDATA": "",
        }
        with patch.dict(compat.os.environ, environment, clear=True), patch.object(
            compat.Path, "home", return_value=Path("/home/user"),
        ), patch.object(
            compat.sys, "platform", "linux",
        ), patch.object(
            compat.shutil, "which", return_value="/path/git",
        ), patch.object(
            compat, "_git_platform_fallback_candidates",
            return_value=["", "/explicit/git", "/fallback/git"],
        ), patch.object(
            compat, "_git_executable_works",
            side_effect=lambda value: value == "/fallback/git",
        ) as works:
            self.assertEqual(compat._find_working_git(), "/fallback/git")
            first_call_count = works.call_count
            self.assertEqual(compat._find_working_git(), "/fallback/git")
        self.assertEqual(works.call_count, first_call_count)

        compat._GIT_EXECUTABLE_CACHE.clear()
        with patch.dict(compat.os.environ, environment, clear=True), patch.object(
            compat.Path, "home", return_value=Path("/home/user"),
        ), patch.object(compat.sys, "platform", "linux"), patch.object(
            compat.shutil, "which", return_value=None,
        ), patch.object(
            compat, "_git_platform_fallback_candidates", return_value=["", ""],
        ), patch.object(
            compat, "_git_executable_works", return_value=False,
        ) as works:
            self.assertIsNone(compat._find_working_git())
        works.assert_called_once_with("/explicit/git")

    def test_remaining_small_helper_false_and_fallback_operands(self):
        self.assertEqual(
            compat._case_insensitive_env_items({None: "none", "": "empty"}),
            {"": "empty"},
        )
        empty_encoding = SimpleNamespace(encoding=None)
        empty_encoding.reconfigure = MagicMock()
        with patch.object(compat.sys, "stdout", empty_encoding), patch.object(
            compat.sys, "stderr", SimpleNamespace(encoding="utf8"),
        ):
            compat.setup_utf8_io()
        empty_encoding.reconfigure.assert_called_once()

        self.assertFalse(compat._git_command_requires_stdout([None, "status"]))
        with patch.object(compat, "_find_working_git", return_value=None):
            self.assertIsNone(compat.find_executable(None))
        calls = []
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat.shutil, "which",
            side_effect=lambda name: calls.append(name) or None,
        ):
            self.assertIsNone(compat.find_executable("missing"))
        self.assertEqual(calls[-1], "missing")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            wrapper = root / "gradlew"
            wrapper.write_text("wrapper", encoding="utf-8")
            with patch.object(compat, "IS_WINDOWS", False), patch.object(
                compat.os, "access", return_value=False,
            ), patch.object(compat, "find_executable", return_value="/bin/sh"):
                self.assertEqual(
                    compat.gradle_cmd(root), ["/bin/sh", str(wrapper)],
                )
        with patch.object(compat, "find_executable", return_value=None):
            self.assertEqual(compat.gradle_cmd(None), ["gradle"])
        self.assertEqual(compat.resolve_command([None, "arg"]), [None, "arg"])

        stdin = MagicMock()
        stdin.isatty.return_value = False
        with patch.object(compat.sys, "stdin", stdin), patch.object(
            compat.sys, "stderr", io.StringIO(),
        ), patch.dict(
            compat.os.environ, {"JUA_CONFIRM_MODE": "interactive"}, clear=True,
        ):
            self.assertFalse(compat.require_human_confirm("Review"))

    def test_maven_xml_and_gradle_empty_tag_text_capture_matrix(self):
        elements = [
            SimpleNamespace(tag=None, text="value"),
            SimpleNamespace(tag="localRepository", text=None),
            SimpleNamespace(tag="localRepository", text="  "),
            SimpleNamespace(tag="other", text="value"),
        ]
        root = SimpleNamespace(iter=lambda: iter(elements))
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            settings = home / ".m2" / "settings.xml"
            settings.parent.mkdir()
            settings.write_text("<settings/>", encoding="utf-8")
            with patch.object(compat.Path, "home", return_value=home), patch.object(
                compat.ET, "fromstring", return_value=root,
            ):
                self.assertIsNone(compat._read_maven_settings_local_repo())

        xml_children = [
            SimpleNamespace(tag=None, text="value"),
            SimpleNamespace(tag="artifactId", text=None),
            SimpleNamespace(tag="artifactId", text="  "),
            SimpleNamespace(tag="other", text="value"),
        ]
        self.assertEqual(
            compat._xml_first_text(xml_children, "artifactId"), "",
        )

        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary).resolve()
            child = root_path / "child"
            child.mkdir()
            (root_path / "gradle.properties").write_text(
                "group=\n", encoding="utf-8",
            )
            (root_path / "settings.gradle.kts").write_text(
                "rootProject.name = ''\n", encoding="utf-8",
            )
            self.assertEqual(
                compat._extract_group_from_gradle_properties(child), "",
            )
            self.assertEqual(compat._extract_artifact_from_settings(child), "")
            self.assertEqual(
                compat._extract_gradle_group_from_text("group = '-'"), "-",
            )
            self.assertEqual(
                compat._extract_gradle_artifact_from_text(
                    "rootProject.name = ''"
                ),
                "",
            )

    def test_remaining_signal_process_and_windows_false_operands(self):
        real_hasattr = __builtins__["hasattr"] if isinstance(__builtins__, dict) else __builtins__.hasattr

        def without_sigterm(value, name):
            if value is compat.signal and name == "SIGTERM":
                return False
            return real_hasattr(value, name)

        with patch.object(compat, "IS_WINDOWS", False), patch(
            "builtins.hasattr", side_effect=without_sigterm,
        ), patch.object(compat.signal, "getsignal") as getsignal:
            compat._ensure_managed_sigterm_handler()
        getsignal.assert_not_called()

        worker = object()
        with patch.object(compat, "IS_WINDOWS", False), patch.object(
            compat.threading, "current_thread", return_value=worker,
        ), patch.object(
            compat.threading, "main_thread", return_value=object(),
        ), patch.object(compat.signal, "getsignal") as getsignal:
            compat._restore_managed_sigterm_handler()
        getsignal.assert_not_called()

        outside = SimpleNamespace()
        setattr(outside, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE, 9)
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat.os, "name", "posix",
        ):
            self.assertFalse(compat._release_windows_managed_job(outside))

        process = SimpleNamespace(pid=70)
        token = object()
        setattr(process, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE, token)
        other_token = object()
        other = SimpleNamespace(pid=71)
        compat._MANAGED_PROCESS_TREES.update({
            token: (process, 70, True),
            other_token: (other, 71, False),
        })
        compat._POSIX_MANAGED_PROCESS_GROUPS.add(70)
        self.assertIsNotNone(compat._take_managed_process_tree(process))
        self.assertNotIn(70, compat._POSIX_MANAGED_PROCESS_GROUPS)

        stopped = MagicMock(pid=80)
        stopped.poll.return_value = 0
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "_claim_managed_process_tree", return_value=True,
        ), patch.object(compat.subprocess, "run") as taskkill:
            compat._terminate_subprocess(stopped, process_group=True)
        taskkill.assert_not_called()
        stopped = SimpleNamespace(
            pid=81,
            poll=lambda: 0,
            kill=lambda: None,
            wait=lambda timeout=None: 0,
        )
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "_claim_managed_process_tree", return_value=True,
        ), patch.object(compat.subprocess, "run") as taskkill:
            compat._terminate_subprocess(stopped, process_group=True)
        taskkill.assert_not_called()

        proc = SimpleNamespace(pid=90)
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "managed_foreground_process_kwargs",
            return_value={"custom": "value"},
        ), patch.object(
            compat.subprocess, "Popen", return_value=proc,
        ) as popen, patch.object(
            compat, "_register_managed_process_tree",
        ), patch.object(compat, "_attach_windows_managed_job"):
            self.assertIs(compat.managed_popen(["tool"]), proc)
            self.assertIs(
                compat.managed_popen(["tool"], custom="value"), proc,
            )
        self.assertEqual(popen.call_count, 2)
        with patch.object(
            compat, "_unregister_managed_process_tree", return_value=False,
        ), patch.object(compat, "_release_windows_managed_job") as release:
            self.assertIsNone(compat.release_process_tree(proc))
        release.assert_not_called()

        with patch.object(compat.sys, "stdin", None), patch.object(
            compat.sys, "stderr", io.StringIO(),
        ), patch.dict(
            compat.os.environ, {"JUA_CONFIRM_MODE": "prompt"}, clear=True,
        ):
            self.assertFalse(compat.require_human_confirm("Review"))

    def test_run_cmd_stream_input_without_pipe_and_completed_drain_error(self):
        class Pipe:
            def __init__(self, error=None):
                self.error = error

            def readline(self):
                if self.error:
                    error, self.error = self.error, None
                    raise error
                return b""

            def close(self):
                return None

        class SyncThread:
            def __init__(self, *, target, args, daemon):
                self.target = target
                self.args = args

            def start(self):
                self.target(*self.args)

            def join(self, timeout=None):
                return None

            def is_alive(self):
                return False

        no_stdin = SimpleNamespace(
            stdout=Pipe(), stderr=Pipe(), stdin=None, returncode=0,
            wait=MagicMock(return_value=0),
        )
        with patch.object(compat, "managed_popen", return_value=no_stdin), patch.object(
            compat.threading, "Thread", SyncThread,
        ), patch.object(compat, "release_process_tree"):
            self.assertEqual(
                compat.run_cmd(
                    ["tool"], input_text="value", stream_output=True,
                ),
                ("", "", 0),
            )

        broken = SimpleNamespace(
            stdout=Pipe(OSError("drain completed")), stderr=Pipe(), stdin=None,
            returncode=0, wait=MagicMock(return_value=0),
        )
        with patch.object(compat, "managed_popen", return_value=broken), patch.object(
            compat.threading, "Thread", SyncThread,
        ), patch.object(compat, "_terminate_subprocess") as terminate:
            result = compat.run_cmd(["tool"], stream_output=True)
        self.assertEqual(result[2], -1)
        self.assertIn("drain completed", result[1])
        terminate.assert_called_once_with(broken, process_group=True)

    def test_remaining_pom_gradle_and_context_combinations(self):
        parent_without_artifact = SimpleNamespace(
            tag="project",
            __iter__=lambda self: iter(()),
        )
        # ``list(root)`` uses the type slot, so use a tiny explicit container.
        class Container:
            def __init__(self, children):
                self.children = children

            def __iter__(self):
                return iter(self.children)

        parent = Container([SimpleNamespace(tag="groupId", text="g")])
        root = Container([
            SimpleNamespace(tag=None, text=None),
            SimpleNamespace(tag="parent", text=None, __iter__=lambda: iter(())),
        ])
        # Supply the actual parent container after exercising the empty tag.
        root.children[-1] = parent
        parent.tag = "parent"
        parent.text = None
        with patch.object(
            compat.ET, "parse", return_value=SimpleNamespace(getroot=lambda: root),
        ):
            self.assertIsNone(compat._parse_pom_coord("virtual-pom"))

        with patch.object(compat, "_read_text_if_exists", return_value="group='g'"), patch.object(
            compat, "_extract_gradle_group_from_text", return_value="g",
        ), patch.object(
            compat, "_extract_gradle_artifact_from_text", return_value="",
        ), patch.object(
            compat, "_artifact_id_from_gradle_build_file", return_value="",
        ), patch.object(
            compat, "_extract_artifact_from_settings", return_value="",
        ):
            self.assertIsNone(compat._parse_gradle_coord(Path("/build.gradle")))
        with patch.object(compat, "_parse_gradle_coord", return_value=None), patch.object(
            compat, "_infer_gradle_group_from_ancestors", return_value="g",
        ), patch.object(
            compat, "_artifact_id_from_gradle_build_file", return_value="",
        ):
            self.assertIsNone(
                compat._parse_gradle_coord_with_repo_context(
                    Path("/build.gradle"), Path("/"),
                )
            )
        with patch.object(
            compat, "_parse_gradle_coord", return_value="g:a",
        ):
            self.assertEqual(
                compat._parse_gradle_coord_with_repo_context("build.gradle", "."),
                "g:a",
            )

        with patch.object(
            compat, "_extract_group_from_gradle_properties", return_value="",
        ), patch.object(
            compat, "_iter_gradle_build_files", return_value=[],
        ):
            self.assertEqual(
                compat._infer_gradle_group_from_ancestors(
                    Path("/tmp/module"), Path("/unrelated/repository"),
                ),
                "",
            )

        self.assertEqual(
            compat._parse_inherited_git_config({
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": None,
                "GIT_CONFIG_VALUE_0": None,
            }),
            [],
        )
        environment = {None: "value", "ordinary": "keep"}
        compat._sanitize_git_environment(environment)
        self.assertIn(None, environment)

    def test_remaining_manifest_and_inference_walk_combinations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            embedded = root / "src" / "main" / "resources"
            embedded.mkdir(parents=True)
            with patch.object(
                compat.os, "walk",
                return_value=[(str(embedded), ["child"], ["pom.xml"])],
            ):
                self.assertFalse(compat._has_child_module_manifests(root))

            child = root / "child"
            child.mkdir()
            with patch.object(
                compat.os, "walk", return_value=[
                    (str(root), ["child", "target"], []),
                    (str(child), ["keep"], []),
                ],
            ), patch.object(
                compat, "_iter_gradle_build_files", return_value=[],
            ):
                self.assertFalse(compat._has_child_module_manifests(root))
            with patch.object(
                compat.os, "walk", return_value=[
                    (str(root), ["child"], []),
                    (str(child), [], []),
                ],
            ), patch.object(
                compat, "_iter_gradle_build_files",
                return_value=[child / "ghost.gradle"],
            ):
                self.assertFalse(compat._has_child_module_manifests(root))

            repo = root / "repo"
            module = root / "outside"
            repo.mkdir()
            module.mkdir()
            self.assertEqual(
                compat._infer_gradle_group_from_ancestors(module, repo), "",
            )

            build = root / "build.gradle"
            build.write_text("plugins {}", encoding="utf-8")
            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(root),
            ), patch.object(
                compat, "_find_git_root", return_value=root,
            ), patch.object(
                compat, "_has_child_module_manifests", return_value=False,
            ), patch.object(
                compat, "_iter_gradle_build_files", return_value=[build],
            ), patch.object(
                compat, "_parse_gradle_coord_with_repo_context", return_value="g:a",
            ), patch.object(
                compat.os, "walk", return_value=[
                    (str(root), ["child", "target"], []),
                    (str(child), [], []),
                ],
            ):
                locations = compat.infer_maven_coord_locations(
                    root, max_depth=1, target_coords=("unmatched",),
                )
            self.assertEqual(locations, [])

            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(root),
            ), patch.object(
                compat, "_has_child_module_manifests", return_value=False,
            ), patch.object(
                compat, "_iter_gradle_build_files", return_value=[build],
            ), patch.object(
                compat.os, "walk", return_value=[
                    (str(root), [], ["different.gradle"]),
                ],
            ):
                compat.infer_maven_coord_locations(root)

            ignored = root / "target"
            included = root / "ordinary"
            ignored.mkdir(exist_ok=True)
            included.mkdir(exist_ok=True)
            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(root),
            ), patch.object(
                compat, "_has_child_module_manifests", return_value=False,
            ), patch.object(
                compat, "_iter_gradle_build_files", return_value=[],
            ):
                self.assertEqual(compat.infer_maven_coord_locations(root), [])

            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(root),
            ), patch.object(
                compat, "_has_child_module_manifests", return_value=False,
            ), patch.object(
                compat, "_iter_gradle_build_files", return_value=[],
            ), patch.object(
                compat, "_is_embedded_resource_fixture_dir",
                side_effect=lambda current, _base: Path(current) == embedded,
            ), patch.object(
                compat.os, "walk", return_value=[(str(embedded), ["x"], [])],
            ):
                self.assertEqual(compat.infer_maven_coord_locations(root), [])

            child_build = child / "child.gradle"
            child_build.write_text("plugins {}", encoding="utf-8")
            with patch.object(
                compat, "resolve_repo_input_path", return_value=str(root),
            ), patch.object(
                compat, "_has_child_module_manifests", return_value=True,
            ), patch.object(
                compat, "_looks_like_source_module", return_value=False,
            ), patch.object(
                compat, "_iter_gradle_build_files",
                side_effect=lambda directory: (
                    [build] if Path(directory) == root else [child_build]
                ),
            ), patch.object(
                compat, "_parse_gradle_coord_with_repo_context",
                return_value="g:child",
            ), patch.object(
                compat.os, "walk", return_value=[
                    (str(root), ["child", "target"], ["build.gradle"]),
                    (str(child), [], ["child.gradle"]),
                ],
            ):
                locations = compat.infer_maven_coord_locations(
                    root, max_poms=2,
                )
            self.assertEqual(
                [item["coord"] for item in locations], ["g:child"],
            )


if __name__ == "__main__":
    unittest.main()
