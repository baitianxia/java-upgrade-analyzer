from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_step


class RunStepStep0BoundaryTest(unittest.TestCase):
    def assert_step_error(self, action):
        with self.assertRaises(run_step.StepError) as captured:
            action()
        return captured.exception

    @staticmethod
    def make_source_tree(module: Path, *, java=True, kotlin=True):
        if java:
            (module / "src" / "main" / "java").mkdir(parents=True)
        if kotlin:
            (module / "src" / "main" / "kotlin").mkdir(parents=True)

    def test_module_and_analysis_mode_normalization_matrix(self):
        self.assertIsNone(run_step.normalize_modules_value(None))
        self.assertIsNone(run_step.normalize_modules_value(""))
        self.assertEqual(run_step.normalize_modules_value(" app "), ["app"])
        self.assertEqual(
            run_step.normalize_modules_value(
                [None, 1, "", "  ", " app ", "lib"]
            ),
            ["app", "lib"],
        )
        for invalid in (1, {}, ("app",)):
            with self.subTest(invalid_modules=invalid):
                self.assert_step_error(
                    lambda invalid=invalid: run_step.normalize_modules_value(invalid)
                )

        self.assertEqual(
            run_step.normalize_analysis_mode(None, allow_empty=True), ""
        )
        self.assertEqual(
            run_step.normalize_analysis_mode(" artifact_inputs "),
            "artifact_inputs",
        )
        self.assertEqual(
            run_step.normalize_analysis_mode("checkout_build"),
            "checkout_build",
        )
        self.assert_step_error(lambda: run_step.normalize_analysis_mode(None))
        self.assert_step_error(
            lambda: run_step.normalize_analysis_mode("unsupported")
        )

    def test_source_directory_discovery_root_nested_and_dedupe_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.assertEqual(run_step.detect_source_dirs(project), [])

            self.make_source_tree(project)
            module = project / "module-a"
            self.make_source_tree(module)
            non_directory = project / "plain.txt"
            non_directory.touch()
            discovered = run_step.detect_source_dirs(project)
            self.assertEqual(len(discovered), 4)
            self.assertEqual(len(discovered), len(set(discovered)))

            # Repeating a directory in the enumeration exercises path-identity
            # deduplication without relying on platform-specific symlinks.
            with patch.object(
                Path, "iterdir", return_value=iter([module, module, non_directory])
            ):
                repeated = run_step.detect_source_dirs(project)
            self.assertEqual(len(repeated), 4)
            self.assertEqual(len(repeated), len(set(repeated)))

    def test_module_scoped_source_detection_alias_fallback_and_error_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.make_source_tree(project)
            module = project / "module-a"
            self.make_source_tree(module)
            duplicate_fallback = project / "duplicate"
            self.make_source_tree(duplicate_fallback, kotlin=False)
            unknown = project / "unknown"
            self.make_source_tree(unknown, java=False)
            file_module = project / "file-module"
            file_module.touch()
            records = [
                {
                    "module": "module-a", "gradle_path": ":app",
                    "artifact_id": "artifact-a", "coord": "g:a",
                    "module_dir": str(module),
                },
                {
                    "module": "duplicate", "gradle_path": "",
                    "artifact_id": "", "coord": "",
                    "module_dir": str(module),
                },
                {
                    "module": "duplicate", "gradle_path": None,
                    "artifact_id": None, "coord": None,
                    "module_dir": str(project),
                },
                {
                    "module": None, "gradle_path": None,
                    "artifact_id": None, "coord": None,
                    "module_dir": None,
                },
            ]

            self.assertEqual(
                run_step.detect_source_dirs_by_modules(project, None), []
            )
            with patch.object(
                run_step, "discover_project_modules",
                return_value={"modules": records},
            ):
                detected = run_step.detect_source_dirs_by_modules(
                    project,
                    [
                        ".", "./", "__root__", "root",
                        "module-a", ":app", "artifact-a", "g:a",
                        module.name, "duplicate", "unknown", "module-a",
                    ],
                )
            self.assertEqual(len(detected), len(set(detected)))
            self.assertIn(str((project / "src/main/java").resolve()), detected)
            self.assertIn(str((module / "src/main/kotlin").resolve()), detected)
            self.assertIn(
                str((duplicate_fallback / "src/main/java").resolve()), detected
            )
            self.assertIn(str((unknown / "src/main/kotlin").resolve()), detected)

            with patch.object(
                run_step, "discover_project_modules", return_value={}
            ):
                self.assert_step_error(
                    lambda: run_step.detect_source_dirs_by_modules(
                        project, ["missing"]
                    )
                )
                self.assert_step_error(
                    lambda: run_step.detect_source_dirs_by_modules(
                        project, ["file-module"]
                    )
                )

            with patch.object(
                run_step, "normalize_modules_value", return_value=[None]
            ), patch.object(
                run_step, "discover_project_modules", return_value={"modules": []}
            ):
                self.assertEqual(
                    run_step.detect_source_dirs_by_modules(project, ["x"]),
                    [
                        str((project / "src/main/java").resolve()),
                        str((project / "src/main/kotlin").resolve()),
                    ],
                )

    def test_module_root_guess_known_build_and_fallback_matrix(self):
        self.assertEqual(run_step._guess_module_root_from_source_dir(None), "")
        self.assertEqual(run_step._guess_module_root_from_source_dir("/src"), "/src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            maven = root / "maven-module"
            source = maven / "custom" / "nested"
            source.mkdir(parents=True)
            (maven / "pom.xml").touch()
            self.assertEqual(
                run_step._guess_module_root_from_source_dir(source), str(maven)
            )

            gradle = root / "gradle-module"
            nested = gradle / "custom" / "nested"
            nested.mkdir(parents=True)
            (gradle / "build.gradle").touch()
            self.assertEqual(
                run_step._guess_module_root_from_source_dir(nested), str(gradle)
            )

            gradle_kts = root / "gradle-kts-module"
            nested_kts = gradle_kts / "custom" / "nested"
            nested_kts.mkdir(parents=True)
            (gradle_kts / "build.gradle.kts").touch()
            self.assertEqual(
                run_step._guess_module_root_from_source_dir(nested_kts),
                str(gradle_kts),
            )

            plain = root / "plain" / "leaf"
            plain.mkdir(parents=True)
            self.assertEqual(
                run_step._guess_module_root_from_source_dir(plain),
                str(plain.parent),
            )

            for suffix in (
                "src/main/java", "src/main/kotlin", "src/test/java",
                "src/test/kotlin", "src/java", "java/src", "src",
            ):
                value = root / "known" / suffix
                with self.subTest(suffix=suffix):
                    self.assertEqual(
                        run_step._guess_module_root_from_source_dir(value),
                        str(root / "known"),
                    )

        with patch.object(
            Path, "resolve", side_effect=OSError("unresolvable")
        ):
            self.assertEqual(
                run_step._guess_module_root_from_source_dir(
                    "relative\\src\\main\\java"
                ),
                "relative",
            )

    def test_source_and_dependency_directory_normalization_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            repo = project / "repo"
            repo.mkdir()

            self.assertIsNone(run_step.normalize_source_dirs(None, project))
            self.assertIsNone(run_step.normalize_source_dirs("", project))
            self.assertEqual(
                run_step.normalize_source_dirs(
                    [None, 3, "", " repo "], project
                ),
                [str(repo)],
            )
            self.assertEqual(
                run_step.normalize_source_dirs("repo", project), [str(repo)]
            )
            self.assert_step_error(
                lambda: run_step.normalize_source_dirs({}, project)
            )

            def is_remote(value, _project):
                return str(value).startswith(("https://", "ssh://"))

            aliases = (
                "url", "git_url", "clone_url", "path", "root",
                "repo_path", "git_path", "repo", "local_path",
            )
            items = ["", " repo ", "repo", "https://example/repo.git"]
            items.extend({alias: "repo"} for alias in aliases)
            with patch.object(
                run_step, "is_dependency_source_git_url",
                side_effect=is_remote,
            ), patch.object(
                run_step, "resolve_repo_input_path", side_effect=lambda value: value,
            ):
                normalized = run_step.normalize_dependency_source_dirs(
                    items, project
                )
                self.assertEqual(
                    normalized,
                    [str(repo), "https://example/repo.git"],
                )
                self.assertEqual(
                    run_step.normalize_dependency_source_dirs(
                        {"path": "repo"}, project
                    ),
                    [str(repo)],
                )
                self.assertEqual(
                    run_step.normalize_dependency_source_dirs(
                        "repo", project
                    ),
                    [str(repo)],
                )
                self.assert_step_error(
                    lambda: run_step.normalize_dependency_source_dirs(
                        [{}], project
                    )
                )
                self.assert_step_error(
                    lambda: run_step.normalize_dependency_source_dirs(
                        [1], project
                    )
                )
            for empty in (None, ""):
                self.assertIsNone(
                    run_step.normalize_dependency_source_dirs(empty, project)
                )
            self.assert_step_error(
                lambda: run_step.normalize_dependency_source_dirs(1, project)
            )

    def test_dependency_repo_and_source_mapping_alias_error_dedupe_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            repo = project / "repo"
            repo.mkdir()

            def looks_remote(value):
                return str(value).startswith("https://")

            coord_aliases = ("coord", "coord_hint", "group")
            repo_path_aliases = (
                "path", "root", "repo_path", "git_path", "repo", "local_path",
            )
            repo_items = ["", "repo", "g:a=repo", "g:a=repo"]
            for index, alias in enumerate(repo_path_aliases):
                item = {alias: "repo"}
                if index < len(coord_aliases):
                    item[coord_aliases[index]] = f"g:{index}"
                repo_items.append(item)
            with patch.object(
                run_step, "looks_like_remote_repo", side_effect=looks_remote,
            ), patch.object(
                run_step, "resolve_repo_input_path", side_effect=lambda value: value,
            ):
                normalized = run_step.normalize_dependency_repo_mappings(
                    repo_items, project
                )
                self.assertEqual(len(normalized), len(set(normalized)))
                self.assertIn(str(repo), normalized)
                self.assertIn(f"g:a={repo}", normalized)
                self.assertEqual(
                    run_step.normalize_dependency_repo_mappings(
                        {"path": "repo"}, project
                    ),
                    [str(repo)],
                )
                for invalid in (
                    ["g:a="], [{}], [1], ["https://example/repo.git"],
                ):
                    with self.subTest(invalid_repo_mapping=invalid):
                        self.assert_step_error(
                            lambda invalid=invalid:
                            run_step.normalize_dependency_repo_mappings(
                                invalid, project
                            )
                        )
            for empty in (None, ""):
                self.assertIsNone(
                    run_step.normalize_dependency_repo_mappings(empty, project)
                )
            self.assert_step_error(
                lambda: run_step.normalize_dependency_repo_mappings(1, project)
            )
            with patch.object(
                run_step, "looks_like_remote_repo", return_value=True,
            ), patch.object(
                run_step, "resolve_repo_input_path", side_effect=lambda value: value,
            ):
                self.assertEqual(
                    run_step.normalize_dependency_repo_mappings(str(repo), project),
                    [str(repo)],
                )

            source_path_aliases = (
                "path", "root", "source_dir", "src_dir", "repo_path",
                "git_path", "repo", "local_path",
            )
            source_items = ["", "repo", "g:a=repo", "g:a=repo"]
            for index, alias in enumerate(source_path_aliases):
                item = {alias: "repo"}
                if index < len(coord_aliases):
                    item[coord_aliases[index]] = f"g:{index}"
                source_items.append(item)
            with patch.object(
                run_step, "looks_like_remote_repo", side_effect=looks_remote,
            ):
                normalized = run_step.normalize_dependency_source_mappings(
                    source_items, project
                )
                self.assertEqual(len(normalized), len(set(normalized)))
                self.assertIn(str(repo), normalized)
                self.assertIn(f"g:a={repo}", normalized)
                self.assertEqual(
                    run_step.normalize_dependency_source_mappings(
                        {"source_dir": "repo"}, project
                    ),
                    [str(repo)],
                )
                for invalid in (
                    ["g:a="], [{}], [1], ["https://example/repo.git"],
                ):
                    with self.subTest(invalid_source_mapping=invalid):
                        self.assert_step_error(
                            lambda invalid=invalid:
                            run_step.normalize_dependency_source_mappings(
                                invalid, project
                            )
                        )
            for empty in (None, ""):
                self.assertIsNone(
                    run_step.normalize_dependency_source_mappings(empty, project)
                )
            self.assert_step_error(
                lambda: run_step.normalize_dependency_source_mappings(1, project)
            )
            with patch.object(
                run_step, "looks_like_remote_repo", return_value=True,
            ):
                self.assertEqual(
                    run_step.normalize_dependency_source_mappings(str(repo), project),
                    [str(repo)],
                )

    def test_manual_artifact_identity_validation_fallback_and_dedupe_matrix(self):
        self.assertIsNone(
            run_step.normalize_manual_artifact_identities(None, "identities")
        )
        base = {
            "side": "base", "entry_id": "entry-a", "lib_entry": "lib-a.jar",
            "group_id": "g", "artifact_id": "a", "version": "1",
            "classifier": " tests ",
        }
        normalized = run_step.normalize_manual_artifact_identities(
            [base, dict(base)], "identities"
        )
        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0]["classifier"], "tests")
        self.assertEqual(
            run_step.normalize_manual_artifact_identities(
                {
                    "side": "current", "lib_entry": "lib-b.jar",
                    "group_id": "g", "artifact_id": "b", "version": "2",
                },
                "identities",
            )[0]["entry_id"],
            "lib-b.jar",
        )
        self.assertEqual(
            run_step.normalize_manual_artifact_identities(
                {
                    "side": "current", "entry_id": "entry-c",
                    "group_id": "g", "artifact_id": "c", "version": "3",
                },
                "identities",
            )[0]["lib_entry"],
            "entry-c",
        )
        invalid = (
            "text", ["text"],
            [{**base, "side": "other"}],
            [{**base, "side": None}],
            [{**base, "entry_id": "", "lib_entry": ""}],
            [{**base, "group_id": ""}],
            [{**base, "artifact_id": ""}],
            [{**base, "version": ""}],
        )
        for value in invalid:
            with self.subTest(invalid_identity=value):
                self.assert_step_error(
                    lambda value=value:
                    run_step.normalize_manual_artifact_identities(
                        value, "identities"
                    )
                )

    def test_build_tool_marker_precedence_and_variant_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(run_step.detect_build_tool(root), "")
            markers = (
                ("build.gradle", "gradle"),
                ("build.gradle.kts", "gradle"),
                ("settings.gradle", "gradle"),
                ("settings.gradle.kts", "gradle"),
                ("gradlew", "gradle"),
                ("gradlew.bat", "gradle"),
            )
            for index, (marker, expected) in enumerate(markers):
                candidate = root / f"case-{index}"
                candidate.mkdir()
                (candidate / marker).touch()
                with self.subTest(marker=marker):
                    self.assertEqual(
                        run_step.detect_build_tool(candidate), expected
                    )
            mixed = root / "mixed"
            mixed.mkdir()
            (mixed / "pom.xml").touch()
            (mixed / "build.gradle").touch()
            self.assertEqual(run_step.detect_build_tool(mixed), "maven")

    def test_artifact_application_version_archive_and_metadata_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = run_step.detect_artifact_application_version(
                root / "missing.jar"
            )
            self.assertEqual(missing["status"], "artifact_missing")
            self.assertEqual(
                run_step.detect_artifact_application_version(None)["status"],
                "artifact_missing",
            )

            invalid = root / "invalid.jar"
            invalid.write_bytes(b"not-a-zip")
            self.assertEqual(
                run_step.detect_artifact_application_version(invalid)["status"],
                "invalid_archive",
            )

            def write_archive(name, entries):
                path = root / name
                with zipfile.ZipFile(path, "w") as archive:
                    for entry, content in entries.items():
                        archive.writestr(entry, content)
                return path

            empty = write_archive(
                "empty.jar",
                {
                    "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
                    "META-INF/maven/g/a/pom.properties": (
                        "\n# comment\n ! second comment\ninvalid\n"
                        "groupId=g\nartifactId=a\nversion=\n"
                    ),
                },
            )
            self.assertEqual(
                run_step.detect_artifact_application_version(empty)["status"],
                "not_found",
            )

            detected = write_archive(
                "detected.jar",
                {
                    "META-INF/maven/g/a/pom.properties": (
                        "groupId = g\nartifactId=a\nversion = 1.2.3\n"
                    ),
                    "META-INF/maven/duplicate/a/pom.properties": (
                        "groupId=g\nartifactId=a\nversion=1.2.3\n"
                    ),
                },
            )
            result = run_step.detect_artifact_application_version(detected)
            self.assertEqual(result["status"], "detected")
            self.assertEqual(result["version"], "1.2.3")
            self.assertEqual(len(result["identities"]), 1)

            version_only = write_archive(
                "version-only.jar",
                {
                    "META-INF/maven/unknown/app/pom.properties": (
                        "version=3.0\n"
                    ),
                },
            )
            result = run_step.detect_artifact_application_version(version_only)
            self.assertEqual(result["status"], "detected")
            self.assertEqual(result["identities"][0]["group_id"], "")
            self.assertEqual(result["identities"][0]["artifact_id"], "")

            ambiguous = write_archive(
                "ambiguous.jar",
                {
                    "META-INF/maven/g/a/pom.properties": (
                        "groupId=g\nartifactId=a\nversion=1\n"
                    ),
                    "META-INF/maven/g/b/pom.properties": (
                        "groupId=g\nartifactId=b\nversion=2\n"
                    ),
                },
            )
            self.assertEqual(
                run_step.detect_artifact_application_version(ambiguous)["status"],
                "ambiguous",
            )

            class ReadFailureArchive:
                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def namelist(self):
                    return ["META-INF/maven/g/a/pom.properties"]

                def read(self, _name):
                    raise KeyError("vanished")

            with patch.object(
                run_step.zipfile, "ZipFile", return_value=ReadFailureArchive()
            ):
                self.assertEqual(
                    run_step.detect_artifact_application_version(detected)[
                        "status"
                    ],
                    "not_found",
                )

    def test_jdk_release_and_java_home_resolution_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing"
            self.assertEqual(run_step._jdk_major_from_home(None), "")
            self.assertEqual(run_step._jdk_major_from_home(missing), "")

            unreadable = root / "unreadable"
            unreadable.mkdir()
            (unreadable / "release").touch()
            with patch.object(Path, "read_text", side_effect=OSError("denied")):
                self.assertEqual(run_step._jdk_major_from_home(unreadable), "")

            cases = (
                ("no-version", "IMPLEMENTOR=Vendor\n", ""),
                ("legacy", 'JAVA_VERSION="1.8.0_402"\n', "8"),
                ("modern", 'JAVA_VERSION="17.0.10"\n', "17"),
                ("invalid", 'JAVA_VERSION="future"\n', ""),
            )
            for name, content, expected in cases:
                home = root / name
                home.mkdir()
                (home / "release").write_text(content, encoding="utf-8")
                with self.subTest(release=name):
                    self.assertEqual(
                        run_step._jdk_major_from_home(home), expected
                    )

            release_less = root / "release-less"
            (release_less / "bin").mkdir(parents=True)
            (release_less / "bin" / "java").touch()
            runtime_cases = (
                (("", "failed", 1), ""),
                (("java.version = 1.8.0_504\n", None, 0), "8"),
                (("", 'openjdk version "17.0.12"\n', 0), "17"),
                ((None, None, 0), ""),
                (("java.version = future\n", "", 0), ""),
            )
            for command_result, expected in runtime_cases:
                with self.subTest(runtime=command_result), patch.object(
                    run_step, "run_cmd", return_value=command_result
                ):
                    self.assertEqual(
                        run_step._jdk_major_from_home(release_less), expected
                    )

            (release_less / "bin" / "java").unlink()
            (release_less / "bin" / "java.exe").touch()
            with patch.object(
                run_step,
                "run_cmd",
                return_value=("java.version = 21.0.4\n", "", 0),
            ) as probe:
                self.assertEqual(
                    run_step._jdk_major_from_home(release_less), "21"
                )
            self.assertTrue(str(probe.call_args.args[0][0]).endswith("java.exe"))

            self.assertIsNone(run_step._java_home_from_executable(None))
            with patch.object(
                run_step, "run_cmd", return_value=("", "failed", 1)
            ):
                self.assertIsNone(
                    run_step._java_home_from_executable("/bin/java")
                )
            with patch.object(
                run_step, "run_cmd", return_value=(None, None, 0)
            ):
                self.assertIsNone(
                    run_step._java_home_from_executable("/bin/java")
                )
            with patch.object(
                run_step, "run_cmd",
                return_value=("", "java.home = /missing/home\n", 0),
            ):
                self.assertIsNone(
                    run_step._java_home_from_executable("/bin/java")
                )

            modern_home = root / "modern-home"
            modern_home.mkdir()
            with patch.object(
                run_step, "run_cmd",
                return_value=(
                    f"java.home = {modern_home}\n", "version output", 0
                ),
            ):
                self.assertEqual(
                    run_step._java_home_from_executable("/bin/java"),
                    modern_home,
                )

            jdk8 = root / "jdk8"
            jre = jdk8 / "jre"
            (jdk8 / "bin").mkdir(parents=True)
            jre.mkdir()
            (jdk8 / "release").touch()
            (jdk8 / "bin" / "javac").touch()
            with patch.object(
                run_step, "run_cmd",
                return_value=("", f"  java.home = {jre}  \n", 0),
            ):
                self.assertEqual(
                    run_step._java_home_from_executable("/bin/java"), jdk8
                )

            jdk8_exe = root / "jdk8-exe"
            jre_exe = jdk8_exe / "jre"
            (jdk8_exe / "bin").mkdir(parents=True)
            jre_exe.mkdir()
            (jdk8_exe / "release").touch()
            (jdk8_exe / "bin" / "javac.exe").touch()
            with patch.object(
                run_step, "run_cmd",
                return_value=("", f"java.home={jre_exe}\n", 0),
            ):
                self.assertEqual(
                    run_step._java_home_from_executable("/bin/java"),
                    jdk8_exe,
                )

            incomplete = root / "incomplete" / "jre"
            incomplete.mkdir(parents=True)
            with patch.object(
                run_step, "run_cmd",
                return_value=("", f"java.home = {incomplete}\n", 0),
            ):
                self.assertEqual(
                    run_step._java_home_from_executable("/bin/java"),
                    incomplete,
                )

            no_compiler_home = root / "no-compiler"
            no_compiler_jre = no_compiler_home / "jre"
            no_compiler_jre.mkdir(parents=True)
            (no_compiler_home / "release").touch()
            with patch.object(
                run_step, "run_cmd",
                return_value=("", f"java.home = {no_compiler_jre}\n", 0),
            ):
                self.assertEqual(
                    run_step._java_home_from_executable("/bin/java"),
                    no_compiler_jre,
                )

    def test_jdk_home_discovery_preference_dedupe_and_invalid_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preferred = root / "jdk8"
            reported = root / "jdk17"
            for home, version, java in (
                (preferred, "1.8.0_402", True),
                (reported, "17.0.10", True),
            ):
                (home / "bin").mkdir(parents=True)
                if version:
                    (home / "release").write_text(
                        f'JAVA_VERSION="{version}"\n', encoding="utf-8"
                    )
                if java:
                    (home / "bin" / ("java.exe" if os.name == "nt" else "java")).touch()

            user_home = root / "user"
            pkgx_root = user_home / ".pkgx" / "openjdk.org"
            local_root = user_home / ".local" / "pkgs" / "openjdk.org"
            pkgx_root.mkdir(parents=True)
            local_root.mkdir(parents=True)
            # Enumerated candidates include invalid major and a valid-major home
            # without java, while JAVA_HOME/which repeat the preferred home.
            pkgx_bad = pkgx_root / "bad"
            (pkgx_bad / "bin").mkdir(parents=True)
            (pkgx_bad / "bin" / (
                "java.exe" if os.name == "nt" else "java"
            )).touch()
            local_no_java = local_root / "no-java"
            (local_no_java / "bin").mkdir(parents=True)
            (local_no_java / "release").write_text(
                'JAVA_VERSION="21"\n', encoding="utf-8"
            )

            with patch.dict(
                run_step.os.environ, {"JAVA_HOME": str(preferred)}, clear=True,
            ), patch.object(
                run_step.shutil, "which", return_value=str(preferred / "bin/java"),
            ), patch.object(
                run_step, "_java_home_from_executable", return_value=reported,
            ), patch.object(
                Path, "home", return_value=user_home,
            ):
                homes = run_step.discover_jdk_homes()
            self.assertEqual(homes["8"], str(preferred.resolve()))
            self.assertEqual(homes["17"], str(reported.resolve()))
            self.assertNotIn("21", homes)

            with patch.dict(run_step.os.environ, {}, clear=True), patch.object(
                run_step.shutil, "which", return_value=str(root / "launcher"),
            ), patch.object(
                run_step, "_java_home_from_executable", return_value=None,
            ), patch.object(Path, "home", return_value=root / "empty-home"):
                self.assertIsInstance(run_step.discover_jdk_homes(), dict)

            with patch.dict(run_step.os.environ, {}, clear=True), patch.object(
                run_step.shutil, "which", return_value=None,
            ), patch.object(Path, "home", return_value=root / "empty-home"):
                self.assertIsInstance(run_step.discover_jdk_homes(), dict)

            mac_root = Path("/Library/Java/JavaVirtualMachines")
            original_is_dir = Path.is_dir
            original_iterdir = Path.iterdir

            def is_dir(path):
                if path == mac_root:
                    return True
                return original_is_dir(path)

            def iterdir(path):
                if path == mac_root:
                    return iter([path / "Synthetic.jdk"])
                return original_iterdir(path)

            with patch.dict(run_step.os.environ, {}, clear=True), patch.object(
                run_step.shutil, "which", return_value=None,
            ), patch.object(
                Path, "home", return_value=root / "empty-home",
            ), patch.object(
                Path, "is_dir", new=is_dir,
            ), patch.object(
                Path, "iterdir", new=iterdir,
            ):
                self.assertIsInstance(run_step.discover_jdk_homes(), dict)

    def test_step1_mode_inference_explicit_implicit_and_enrichment_matrix(self):
        cases = (
            ({}, "", "", "none"),
            (
                {"analysis_mode": "artifact_inputs"},
                "artifact_inputs", "provided_artifacts", "none",
            ),
            (
                {"analysis_mode": "checkout_build"},
                "checkout_build", "built_artifacts", "none",
            ),
            (
                {"base_artifact_path": "base.jar"},
                "artifact_inputs", "provided_artifacts", "none",
            ),
            (
                {
                    "base_artifact_path": "base.jar",
                    "current_artifact_path": "current.jar",
                    "base_branch": "main", "current_branch": "upgrade",
                },
                "artifact_inputs", "provided_artifacts", "branch_checkout",
            ),
            (
                {"base_branch": "main"},
                "checkout_build", "built_artifacts", "none",
            ),
            (
                {"base_branch": "main", "current_branch": "upgrade"},
                "checkout_build", "built_artifacts", "none",
            ),
            (
                {
                    "analysis_mode": "artifact_inputs",
                    "base_source_project_dir": "/base",
                },
                "artifact_inputs", "provided_artifacts", "source_project_dir",
            ),
            (
                {
                    "analysis_mode": "artifact_inputs",
                    "current_source_project_dir": "/current",
                },
                "artifact_inputs", "provided_artifacts", "source_project_dir",
            ),
        )
        for context, mode, source, enrichment in cases:
            with self.subTest(context=context):
                result = run_step.infer_step1_mode_fields(context)
                self.assertEqual(result["analysis_mode"], mode)
                self.assertEqual(result["result_source"], source)
                self.assertEqual(result["enrichment_strategy"], enrichment)

    def test_revision_build_tool_detection_git_prefix_target_and_marker_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            git_root = Path(directory).resolve()
            repo = git_root / "project"
            outside = git_root.parent / "outside-project"

            def detect(context, output="", rc=0, *, root=git_root, repo_dir=repo):
                with patch.object(
                    run_step, "_step1_ref_repository", return_value=repo_dir,
                ), patch.object(
                    run_step, "_git_repository_root", return_value=root,
                ), patch.object(
                    run_step, "git_cmd", return_value=["git"],
                ), patch.object(
                    run_step, "run_cmd", return_value=(output, "", rc),
                ):
                    return run_step._detect_build_tool_for_revision(
                        context, "base"
                    )

            self.assertEqual(detect({}, "pom.xml"), "")
            with patch.object(
                run_step, "_step1_ref_repository", return_value=repo,
            ), patch.object(
                run_step, "_git_repository_root", return_value=None,
            ):
                self.assertEqual(
                    run_step._detect_build_tool_for_revision(
                        {"base_resolved_commit": "a" * 40}, "base"
                    ),
                    "",
                )
            self.assertEqual(
                detect({"base_resolved_commit": "a" * 40}, "pom.xml", rc=1),
                "",
            )

            base_context = {
                "base_resolved_commit": "a" * 40,
                "project_dir": str(repo),
            }
            self.assertEqual(
                detect(base_context, "project/pom.xml\n"), "maven"
            )
            for marker in (
                "build.gradle", "build.gradle.kts", "settings.gradle",
                "settings.gradle.kts", "gradlew", "gradlew.bat",
            ):
                with self.subTest(marker=marker):
                    self.assertEqual(
                        detect(base_context, f"project/{marker}\n"), "gradle"
                    )
            self.assertEqual(
                detect(
                    base_context,
                    "project/pom.xml\nproject/build.gradle\n",
                ),
                "",
            )
            self.assertEqual(detect(base_context, "README.md\n"), "")
            self.assertEqual(detect(base_context, None), "")
            self.assertEqual(detect(base_context, "  \n"), "")

            module_context = {
                **base_context,
                "target_module": "module\\app",
            }
            self.assertEqual(
                detect(module_context, "project/module/app/pom.xml\n"),
                "maven",
            )
            colon_context = {**base_context, "target_module": ":module:app"}
            self.assertEqual(
                detect(colon_context, "project/build.gradle\n"), "gradle"
            )
            self.assertEqual(
                detect(
                    {**base_context, "target_module": "module"},
                    "pom.xml\n",
                    root=git_root,
                    repo_dir=outside,
                ),
                "maven",
            )

    def test_step0_jdk_version_detection_artifact_manifest_and_failure_matrix(self):
        with patch.object(
            run_step, "infer_step1_mode_fields",
            return_value={"analysis_mode": "artifact_inputs"},
        ), patch(
            "s2_context_from_deps.detect_jdk_from_artifact",
            side_effect=(
                {"status": "detected", "version": "8"},
                {"status": "not_found", "version": None},
            ),
        ) as detect_artifact:
            versions = run_step._detect_step0_jdk_versions({
                "base_artifact_path": "base.jar",
                "current_artifact_path": "current.jar",
            })
        self.assertEqual(versions, {"base": "8", "current": ""})
        self.assertEqual(detect_artifact.call_count, 2)

        with patch.object(
            run_step, "infer_step1_mode_fields",
            return_value={"analysis_mode": "artifact_inputs"},
        ), patch(
            "s2_context_from_deps.detect_jdk_from_artifact",
            return_value={"status": "detected", "version": None},
        ):
            self.assertEqual(
                run_step._detect_step0_jdk_versions({}),
                {"base": "", "current": ""},
            )

        with patch.object(
            run_step, "infer_step1_mode_fields",
            return_value={"analysis_mode": "artifact_inputs"},
        ), patch(
            "s2_context_from_deps.detect_jdk_from_artifact",
        ) as detect_artifact:
            versions = run_step._detect_step0_jdk_versions({
                "jdk_base": "11", "jdk_current": "17",
            })
        self.assertEqual(versions, {"base": "11", "current": "17"})
        detect_artifact.assert_not_called()

        checkout_context = {
            "project_dir": "/project",
            "base_resolved_commit": "a" * 40,
            "current_resolved_commit": "b" * 40,
            "base_tool": "maven", "current_tool": "gradle",
        }
        with patch.object(
            run_step, "infer_step1_mode_fields",
            return_value={"analysis_mode": "checkout_build"},
        ), patch.object(
            run_step, "_step1_ref_repository", return_value=Path("/repo"),
        ), patch(
            "s2_context_from_deps.detect_jdk_versions_from_manifests",
            side_effect=(("1.8", "ignored", {}), ("17", "ignored", {})),
        ) as detect_manifest:
            versions = run_step._detect_step0_jdk_versions(checkout_context)
        self.assertEqual(versions, {"base": "8", "current": "17"})
        self.assertEqual(detect_manifest.call_count, 2)

        with patch.object(
            run_step, "infer_step1_mode_fields",
            return_value={"analysis_mode": "checkout_build"},
        ), patch.object(
            run_step, "_step1_ref_repository", return_value=Path("/repo"),
        ), patch(
            "s2_context_from_deps.detect_jdk_versions_from_manifests",
            side_effect=OSError("unavailable"),
        ) as detect_manifest:
            versions = run_step._detect_step0_jdk_versions({
                "base_resolved_commit": "",
                "current_resolved_commit": "b" * 40,
                "base_tool": "maven", "current_tool": "unknown",
            })
        self.assertEqual(versions, {"base": "", "current": ""})
        detect_manifest.assert_not_called()

        with patch.object(
            run_step, "infer_step1_mode_fields",
            return_value={"analysis_mode": "checkout_build"},
        ), patch.object(
            run_step, "_step1_ref_repository", return_value=Path("/repo"),
        ), patch(
            "s2_context_from_deps.detect_jdk_versions_from_manifests",
        ) as detect_manifest:
            versions = run_step._detect_step0_jdk_versions({
                "jdk_base": "8",
                "current_resolved_commit": "b" * 40,
                "current_tool": None,
            })
        self.assertEqual(versions, {"base": "8", "current": ""})
        detect_manifest.assert_not_called()

        for error in (OSError("io"), RuntimeError("runtime"), ValueError("bad")):
            with self.subTest(manifest_error=type(error).__name__), patch.object(
                run_step, "infer_step1_mode_fields",
                return_value={"analysis_mode": "checkout_build"},
            ), patch.object(
                run_step, "_step1_ref_repository", return_value=Path("/repo"),
            ), patch(
                "s2_context_from_deps.detect_jdk_versions_from_manifests",
                side_effect=error,
            ):
                versions = run_step._detect_step0_jdk_versions({
                    "base_resolved_commit": "a" * 40,
                    "base_tool": "maven", "jdk_current": "21",
                })
                self.assertEqual(versions, {"base": "", "current": "21"})

    def test_prepare_step0_context_detection_resolution_scope_tool_and_home_matrix(self):
        def invoke(
            context, *, mode="", artifact_evidence=None, matches=None,
            current_branch="", resolved=None, ref_interaction=None,
            rebuilt=None, detected_tools=None, jdk_versions=None, homes=None,
            mode_side_effect=None,
        ):
            artifact_values = iter(artifact_evidence or (
                {"status": "not_found", "version": ""},
                {"status": "not_found", "version": ""},
            ))
            match_values = iter(matches or ())
            rebuild_values = iter(rebuilt or ())
            tool_values = dict(detected_tools or {})
            calls = {"rebuild": 0}

            def artifact(_path):
                return dict(next(artifact_values))

            def match(_repo, _version):
                return dict(next(match_values))

            def resolve(updated, *_args, **_kwargs):
                overrides = dict(resolved or {})
                return {**updated, **overrides}, ref_interaction

            def rebuild(updated, _project):
                calls["rebuild"] += 1
                value = dict(next(rebuild_values))
                return {**updated, **value}

            def tool(_updated, side):
                return tool_values.get(side, "")

            with patch.object(
                run_step, "infer_step1_mode_fields",
                side_effect=mode_side_effect,
                return_value={"analysis_mode": mode},
            ), patch.object(
                run_step, "detect_artifact_application_version",
                side_effect=artifact,
            ) as detect_artifact, patch.object(
                run_step, "_step1_ref_repository", return_value=Path("/repo"),
            ), patch.object(
                run_step, "match_remote_refs_by_version", side_effect=match,
            ) as match_refs, patch.object(
                run_step, "_version_ref_request",
                side_effect=lambda side, version, match, _updated: {
                    "side": side, "version": version, "match": match,
                },
            ), patch.object(
                run_step, "detect_current_git_branch", return_value=current_branch,
            ), patch.object(
                run_step, "resolve_step1_refs_for_execution",
                side_effect=resolve,
            ), patch.object(
                run_step, "build_step1_ref_confirmation_interaction",
                side_effect=lambda _updated, requests: {
                    "ref_resolution_requests": list(requests),
                },
            ) as build_ref, patch.object(
                run_step, "rebuild_current_pinned_source_context",
                side_effect=rebuild,
            ), patch.object(
                run_step, "_detect_build_tool_for_revision", side_effect=tool,
            ) as detect_tool, patch.object(
                run_step, "_detect_step0_jdk_versions",
                return_value=dict(jdk_versions or {"base": "", "current": ""}),
            ), patch.object(
                run_step, "discover_jdk_homes", return_value=dict(homes or {}),
            ):
                result = run_step.prepare_step0_context(
                    context, "/project", on_side_resolved=lambda *_args: None,
                )
            return result, calls, {
                "artifact": detect_artifact,
                "match": match_refs,
                "build_ref": build_ref,
                "tool": detect_tool,
            }

        (updated, interaction), calls, mocks = invoke(None)
        self.assertEqual(updated["tool"], "")
        self.assertIsNone(interaction)
        self.assertEqual(calls["rebuild"], 0)
        mocks["artifact"].assert_not_called()

        mode_values = iter((
            {"analysis_mode": ""},
            {"analysis_mode": "checkout_build"},
            {"analysis_mode": "checkout_build"},
        ))
        (updated, interaction), _calls, _mocks = invoke(
            {"application_source": "/repo"},
            current_branch="main",
            mode_side_effect=lambda *_args, **_kwargs: next(mode_values),
        )
        self.assertEqual(updated["analysis_mode"], "checkout_build")
        self.assertEqual(updated["current_branch"], "main")
        self.assertEqual(updated["input_origins"]["current_branch"], "detected")
        self.assertIsNone(interaction)

        commit = "c" * 40
        artifact_context = {
            "analysis_mode": "artifact_inputs",
            "base_artifact_path": "base.jar",
            "current_artifact_path": "current.jar",
            "current_tool": "stale",
            "input_origins": {"current_tool": "detected"},
        }
        resolved = {**artifact_context, "current_resolved_commit": commit}
        (updated, interaction), calls, mocks = invoke(
            artifact_context,
            mode="artifact_inputs",
            artifact_evidence=(
                {"status": "detected", "version": "1.0"},
                {"status": "detected", "version": "2.0"},
            ),
            matches=(
                {
                    "status": "resolved",
                    "candidates": [{"ref": "origin/v1"}],
                },
                {"status": "ambiguous", "candidates": [{"ref": "v2"}]},
            ),
            resolved=resolved,
            ref_interaction={"ref_resolution_requests": [{"side": "existing"}]},
            rebuilt=(
                {"project_scope": {"candidate_modules": ["app"]}},
                {"project_scope": {"candidate_modules": ["app"]}},
            ),
            detected_tools={"base": "maven", "current": ""},
            jdk_versions={"base": "8", "current": "17"},
            homes={"8": "/jdk8", "17": "/jdk17"},
        )
        self.assertEqual(updated["base_branch"], "origin/v1")
        self.assertEqual(updated["base_artifact_version"], "1.0")
        self.assertEqual(updated["target_module"], "app")
        self.assertEqual(updated["base_tool"], "maven")
        self.assertEqual(updated["current_tool"], "")
        self.assertEqual(updated["tool"], "maven")
        self.assertEqual(updated["base_jdk_home"], "/jdk8")
        self.assertEqual(updated["current_jdk_home"], "/jdk17")
        self.assertEqual(calls["rebuild"], 2)
        self.assertEqual(interaction["step_id"], "step0")
        self.assertEqual(len(interaction["ref_resolution_requests"]), 2)
        self.assertEqual(mocks["match"].call_count, 2)

        (updated, interaction), calls, mocks = invoke(
            {
                "analysis_mode": "artifact_inputs",
                "base_branch": "given", "target_module": "app",
                "base_tool": "maven", "current_tool": "gradle",
                "base_jdk_home": "/given-jdk",
                "input_origins": {
                    "base_tool": "user", "current_tool": "user",
                },
            },
            mode="artifact_inputs",
            artifact_evidence=(
                {"status": "detected", "version": "1"},
                {"status": "not_found", "version": ""},
            ),
            resolved={
                "analysis_mode": "artifact_inputs",
                "base_branch": "given", "target_module": "app",
                "base_tool": "maven", "current_tool": "gradle",
                "base_jdk_home": "/given-jdk",
                "current_resolved_commit": commit,
                "input_origins": {
                    "base_tool": "user", "current_tool": "user",
                },
            },
            rebuilt=({"project_scope": {"candidate_modules": []}},),
            jdk_versions={"base": "", "current": "21"},
            homes={},
        )
        self.assertEqual(updated["tool"], "gradle")
        self.assertEqual(updated["base_jdk_home"], "/given-jdk")
        self.assertNotIn("current_jdk_home", updated)
        self.assertEqual(calls["rebuild"], 1)
        self.assertIsNone(interaction)
        mocks["match"].assert_not_called()
        mocks["tool"].assert_not_called()

        for candidates in ([], ["a", "b"]):
            with self.subTest(scope_candidates=candidates):
                (updated, _interaction), calls, _mocks = invoke(
                    {}, mode="checkout_build",
                    resolved={
                        "current_resolved_commit": commit,
                        "input_origins": {},
                    },
                    rebuilt=({
                        "project_scope": {"candidate_modules": candidates},
                    },),
                )
                self.assertNotIn("target_module", updated)
                self.assertEqual(calls["rebuild"], 1)

        (updated, _interaction), _calls, _mocks = invoke(
            {
                "analysis_mode": "artifact_inputs",
                "base_artifact_path": "base.jar",
                "current_artifact_path": "current.jar",
            },
            mode="artifact_inputs",
            artifact_evidence=(
                {"status": "detected", "version": "1"},
                {"status": "detected", "version": "2"},
            ),
            matches=(
                {"status": "resolved", "candidates": []},
                {"status": "not_found", "candidates": []},
            ),
        )
        self.assertNotIn("base_branch", updated)
        self.assertIsNone(_interaction)

        (updated, _interaction), _calls, _mocks = invoke(
            {"current_branch": "given"}, mode="checkout_build",
        )
        self.assertEqual(updated["current_branch"], "given")

        for existing_interaction in (None, {"kind": "existing"}):
            with self.subTest(existing_ref_interaction=existing_interaction):
                (updated, interaction), _calls, _mocks = invoke(
                    {
                        "analysis_mode": "artifact_inputs",
                        "base_artifact_path": "base.jar",
                        "current_artifact_path": "current.jar",
                    },
                    mode="artifact_inputs",
                    artifact_evidence=(
                        {"status": "detected", "version": "1"},
                        {"status": "not_found", "version": ""},
                    ),
                    matches=({"status": "ambiguous", "candidates": []},),
                    ref_interaction=existing_interaction,
                )
                self.assertEqual(interaction["step_id"], "step0")

        (updated, _interaction), calls, _mocks = invoke(
            {}, mode="checkout_build",
            resolved={
                "current_resolved_commit": commit,
                "input_origins": {},
            },
            rebuilt=({},),
        )
        self.assertNotIn("target_module", updated)
        self.assertEqual(calls["rebuild"], 1)

    def test_validate_step0_missing_artifact_commit_full_jdk_and_version_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_artifact = root / "base.jar"
            current_artifact = root / "current.jar"
            base_artifact.touch()
            current_artifact.touch()

            def make_jdk(name, major, *, executables=("java", "javac", "javap"), platform=True):
                home = root / name
                (home / "bin").mkdir(parents=True)
                (home / "release").write_text(
                    f'JAVA_VERSION="{major}"\n', encoding="utf-8"
                )
                for executable in executables:
                    (home / "bin" / executable).touch()
                normalized_major = "8" if str(major).startswith("1.8") else str(major).split(".", 1)[0]
                if platform and normalized_major == "8":
                    (home / "jre" / "lib").mkdir(parents=True)
                    (home / "jre" / "lib" / "rt.jar").touch()
                elif platform:
                    (home / "lib").mkdir(parents=True)
                    (home / "lib" / "modules").touch()
                    (home / "jmods").mkdir()
                return home

            jdk8 = make_jdk("jdk8", "1.8.0_402")
            jdk17 = make_jdk("jdk17", "17.0.10")
            jdk17_exe = make_jdk(
                "jdk17-exe", "17", executables=(
                    "java.exe", "javac.exe", "javap.exe",
                ),
            )
            context = {
                "base_artifact_path": str(base_artifact),
                "current_artifact_path": str(current_artifact),
                "base_resolved_commit": "a" * 40,
                "current_resolved_commit": "B" * 64,
                "base_jdk_home": str(jdk8),
                "current_jdk_home": str(jdk17),
                "jdk_base": "1.8", "jdk_current": "17",
            }

            with patch.object(
                run_step, "build_step0_confirmation_interaction",
                return_value={"missing_inputs": [
                    {"label": "应用源码"}, {"field": "target_module"},
                ]},
            ):
                error = self.assert_step_error(
                    lambda: run_step.validate_step0_context(context)
                )
            self.assertIn("应用源码", str(error))
            self.assertIn("target_module", str(error))

            def validate(value, mode="checkout_build"):
                with patch.object(
                    run_step, "build_step0_confirmation_interaction",
                    return_value={"missing_inputs": []},
                ), patch.object(
                    run_step, "infer_step1_mode_fields",
                    return_value={"analysis_mode": mode},
                ):
                    return run_step.validate_step0_context(value)

            self.assertIsNone(validate(dict(context), "artifact_inputs"))
            exe_context = {
                **context,
                "current_jdk_home": str(jdk17_exe),
            }
            self.assertIsNone(validate(exe_context, "checkout_build"))

            for field in ("base_artifact_path", "current_artifact_path"):
                invalid = dict(context)
                invalid[field] = str(root / f"missing-{field}.jar")
                with self.subTest(missing_artifact=field):
                    self.assert_step_error(
                        lambda invalid=invalid: validate(
                            invalid, "artifact_inputs"
                        )
                    )
            missing_artifact_field = dict(context)
            missing_artifact_field["base_artifact_path"] = None
            self.assert_step_error(
                lambda: validate(missing_artifact_field, "artifact_inputs")
            )

            for side in ("base", "current"):
                invalid = dict(context)
                invalid[f"{side}_resolved_commit"] = "mutable"
                with self.subTest(invalid_commit=side):
                    self.assert_step_error(
                        lambda invalid=invalid: validate(invalid)
                    )
            missing_commit = dict(context)
            missing_commit["base_resolved_commit"] = None
            self.assert_step_error(lambda: validate(missing_commit))

            missing_home = dict(context)
            missing_home["base_jdk_home"] = None
            self.assert_step_error(lambda: validate(missing_home))

            no_release = root / "no-release"
            (no_release / "bin").mkdir(parents=True)
            invalid = {**context, "base_jdk_home": str(no_release)}
            self.assert_step_error(lambda: validate(invalid))

            missing_tools = make_jdk(
                "missing-tools", "8", executables=("java",), platform=True
            )
            invalid = {**context, "base_jdk_home": str(missing_tools)}
            error = self.assert_step_error(lambda: validate(invalid))
            self.assertIn("javac", str(error))
            self.assertIn("javap", str(error))

            jdk8_no_platform = make_jdk("jdk8-no-platform", "8", platform=False)
            invalid = {**context, "base_jdk_home": str(jdk8_no_platform)}
            self.assert_step_error(lambda: validate(invalid))

            jdk17_no_modules = make_jdk("jdk17-no-modules", "17", platform=False)
            (jdk17_no_modules / "jmods").mkdir()
            invalid = {
                **context, "current_jdk_home": str(jdk17_no_modules),
            }
            self.assert_step_error(lambda: validate(invalid))

            jdk17_no_jmods = make_jdk("jdk17-no-jmods", "17", platform=False)
            (jdk17_no_jmods / "lib").mkdir()
            (jdk17_no_jmods / "lib" / "modules").touch()
            invalid = {
                **context, "current_jdk_home": str(jdk17_no_jmods),
            }
            self.assert_step_error(lambda: validate(invalid))

            mismatch = {**context, "jdk_current": "21"}
            self.assert_step_error(lambda: validate(mismatch))
            no_expected = {**context, "jdk_base": "", "jdk_current": ""}
            self.assertIsNone(validate(no_expected))

    def test_step0_confirmation_record_complete_and_empty_projection_matrix(self):
        captured = []

        def write(_path, payload):
            captured.append(dict(payload))

        full = {
            "base_artifact_path": "/artifacts/base.jar",
            "current_artifact_path": "/artifacts/current.jar",
            "base_artifact_version": "1", "current_artifact_version": "2",
            "application_source_display": "origin/app",
            "application_source": "/repo",
            "target_module": "app",
            "base_branch": "main", "current_branch": "upgrade",
            "base_resolved_ref": "refs/heads/main",
            "current_resolved_ref": "refs/heads/upgrade",
            "base_resolved_commit": "a" * 40,
            "current_resolved_commit": "b" * 40,
            "base_tool": "maven", "current_tool": "gradle",
            "base_jdk_home": "/jdk8", "current_jdk_home": "/jdk17",
            "jdk_base": "8", "jdk_current": "17",
            "input_origins": {"target_module": "user"},
            "step0_preflight": {"status": "passed"},
        }
        with patch.object(
            run_step, "infer_step1_mode_fields",
            return_value={"analysis_mode": "artifact_inputs"},
        ), patch.object(
            run_step, "_step0_dependency_source_values",
            return_value=["/dep"],
        ), patch.object(
            run_step, "_sanitize_git_persistence_payload",
            side_effect=lambda payload: payload,
        ), patch.object(
            run_step, "write_json", side_effect=write,
        ):
            payload = run_step.write_step0_confirmation_record(
                "/report", full
            )
        self.assertEqual(payload["artifacts"]["base"]["user_filename"], "base.jar")
        self.assertEqual(payload["application_source"], "origin/app")
        self.assertEqual(payload["dependency_sources"], ["/dep"])
        self.assertEqual(captured[-1], payload)

        empty = {"application_source": "/fallback"}
        with patch.object(
            run_step, "infer_step1_mode_fields",
            return_value={"analysis_mode": "checkout_build"},
        ), patch.object(
            run_step, "_step0_dependency_source_values", return_value=[],
        ), patch.object(
            run_step, "_sanitize_git_persistence_payload",
            side_effect=lambda payload: payload,
        ), patch.object(run_step, "write_json", side_effect=write):
            payload = run_step.write_step0_confirmation_record(
                "/report", empty
            )
        self.assertEqual(payload["application_source"], "/fallback")
        self.assertEqual(payload["artifacts"]["base"]["path"], "")
        self.assertEqual(payload["artifacts"]["base"]["user_filename"], "")
        self.assertEqual(payload["input_origins"], {})
        self.assertEqual(payload["preflight"], {})

        with patch.object(
            run_step, "infer_step1_mode_fields",
            return_value={"analysis_mode": ""},
        ), patch.object(
            run_step, "_step0_dependency_source_values", return_value=[],
        ), patch.object(
            run_step, "_sanitize_git_persistence_payload",
            side_effect=lambda payload: payload,
        ), patch.object(run_step, "write_json", side_effect=write):
            payload = run_step.write_step0_confirmation_record("/report", {})
        self.assertEqual(payload["application_source"], "")

    def test_rebuild_pinned_source_context_revision_scope_explicit_and_failure_matrix(self):
        stale = {
            "current_resolved_commit": "mutable",
            "pinned_source_snapshot": {"stale": True},
        }
        self.assertNotIn(
            "pinned_source_snapshot",
            run_step.rebuild_current_pinned_source_context(stale, "/project"),
        )
        self.assertEqual(
            run_step.rebuild_current_pinned_source_context(None, "/project"),
            {},
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            git_root = root / "git"
            repo = git_root / "project"
            worktree = root / "worktree"
            repo.mkdir(parents=True)
            worktree.mkdir()
            (worktree / "src" / "main" / "java").mkdir(parents=True)

            def invoke(
                context, *, project_path=".", detected_tool="gradle",
                scope=None, discovery=None, source_plan=None,
                logical_scope=None, apply_result="context",
                create_error=None, source_relative=None,
            ):
                captured = {}

                def relative(_root, path, *, label):
                    if label == "current source project":
                        return project_path
                    if label == "source_dirs":
                        return (source_relative or {}).get(str(path), "src/main/java")
                    if label == "source root":
                        path = Path(path)
                        if path == (worktree if project_path == "." else worktree / project_path):
                            return "."
                        return "src/main/java"
                    raise AssertionError(label)

                def apply_snapshot(updated, _project):
                    captured["snapshot"] = dict(updated["pinned_source_snapshot"])
                    if apply_result == "context":
                        return dict(updated)
                    return apply_result

                with ExitStack() as stack:
                    stack.enter_context(patch.object(
                        run_step, "_step1_ref_repository", return_value=repo,
                    ))
                    stack.enter_context(patch.object(
                        run_step, "_pinned_source_git_root", return_value=git_root,
                    ))
                    stack.enter_context(patch.object(
                        run_step, "_relative_path_inside", side_effect=relative,
                    ))
                    create = stack.enter_context(patch.object(
                        run_step, "create_detached_worktree",
                        side_effect=create_error,
                        return_value=worktree,
                    ))
                    remove = stack.enter_context(patch.object(
                        run_step, "remove_detached_worktree",
                    ))
                    stack.enter_context(patch.object(
                        run_step, "detect_build_tool", return_value=detected_tool,
                    ))
                    build_scope = stack.enter_context(patch.object(
                        run_step, "build_project_scope",
                        return_value=dict(scope or {
                            "status": "complete", "source_roots": [],
                        }),
                    ))
                    discover = stack.enter_context(patch.object(
                        run_step, "discover_project_modules",
                        return_value=dict(discovery or {"modules": []}),
                    ))
                    stack.enter_context(patch.object(
                        run_step, "_semantic_source_project_root", return_value=repo,
                    ))
                    resolve_plan = stack.enter_context(patch.object(
                        run_step, "_resolve_source_dirs_plan",
                        return_value=dict(source_plan or {
                            "source_dirs": [], "status": "missing",
                        }),
                    ))
                    stack.enter_context(patch.object(
                        run_step, "_logicalize_project_scope_paths",
                        return_value=dict(logical_scope or {}),
                    ))
                    stack.enter_context(patch.object(
                        run_step, "_apply_pinned_source_snapshot",
                        side_effect=apply_snapshot,
                    ))
                    result = run_step.rebuild_current_pinned_source_context(
                        context, repo
                    )
                return result, captured, {
                    "create": create, "remove": remove,
                    "build_scope": build_scope, "discover": discover,
                    "resolve_plan": resolve_plan,
                }

            commit = "a" * 40
            explicit_context = {
                "current_resolved_commit": commit,
                "current_tool": "maven",
                "target_module": "app",
                "active_maven_profiles": ["prod"],
                "source_dirs_status": "explicit",
                "source_dirs": [str(repo), str(repo / "src/main/java")],
                "modules": ["app"],
                "input_origins": {"current_tool": "user"},
            }
            result, captured, mocks = invoke(
                explicit_context,
                detected_tool="gradle",
                scope={
                    "status": "complete",
                    "source_roots": [str(worktree / "src/main/java")],
                },
                source_plan={
                    "source_dirs": [str(worktree), str(worktree / "src/main/java")],
                    "status": "explicit",
                },
                logical_scope={"resource_roots": ["src/main/resources"]},
                source_relative={
                    str(repo): ".",
                    str(repo / "src/main/java"): "src/main/java",
                },
            )
            self.assertEqual(result["current_tool"], "maven")
            self.assertEqual(captured["snapshot"]["source_roots"], [
                ".", "src/main/java",
            ])
            self.assertEqual(
                captured["snapshot"]["resource_roots"],
                ["src/main/resources"],
            )
            mocks["build_scope"].assert_called_once()
            mocks["discover"].assert_not_called()
            self.assertIsNotNone(
                mocks["resolve_plan"].call_args.kwargs["source_dirs"]
            )
            mocks["remove"].assert_called_once()

            subproject = worktree / "subproject"
            subproject.mkdir()
            result, captured, mocks = invoke(
                {
                    "current_resolved_commit": commit,
                    "current_tool": "stale",
                    "input_origins": {"current_tool": "detected"},
                },
                project_path="subproject", detected_tool="gradle",
                discovery={
                    "modules": [{"module": "app"}, {"module": None}],
                },
                source_plan={"source_dirs": [], "status": "missing"},
                logical_scope={"candidate_modules": ["app", None]},
            )
            self.assertEqual(result["current_tool"], "gradle")
            self.assertEqual(
                captured["snapshot"]["project_path"], "subproject"
            )
            self.assertEqual(
                captured["snapshot"]["project_scope"]["candidate_modules"],
                ["app", None],
            )
            mocks["build_scope"].assert_not_called()
            mocks["discover"].assert_called_once()
            self.assertIsNone(
                mocks["resolve_plan"].call_args.kwargs["source_dirs"]
            )

            result, captured, _mocks = invoke(
                {
                    "current_resolved_commit": commit,
                    "current_tool": None,
                    "input_origins": {"current_tool": "user"},
                    "source_dirs_status": "explicit",
                    "source_dirs": None,
                },
                detected_tool="gradle",
                source_plan={"source_dirs": [], "status": None},
            )
            self.assertEqual(result["current_tool"], "gradle")
            self.assertEqual(
                captured["snapshot"]["source_dirs_status"], "missing"
            )

            missing_project = worktree / "missing-project"
            self.assertFalse(missing_project.exists())
            with self.assertRaises(run_step.StepError):
                invoke(
                    {"current_resolved_commit": commit},
                    project_path="missing-project",
                )

            missing_source = repo / "missing-source"
            with self.assertRaises(run_step.StepError):
                invoke(
                    {
                        "current_resolved_commit": commit,
                        "source_dirs_status": "explicit",
                        "source_dirs": [str(missing_source)],
                    },
                    source_relative={str(missing_source): "missing-source"},
                )

            with self.assertRaises(run_step.StepError):
                invoke(
                    {"current_resolved_commit": commit},
                    apply_result=None,
                )

            with self.assertRaises(run_step.StepError) as captured_error:
                invoke(
                    {"current_resolved_commit": commit},
                    create_error=RuntimeError("worktree failed"),
                )
            self.assertIn("worktree failed", str(captured_error.exception))

    def test_step0_java_environment_and_artifact_preflight_matrix(self):
        with patch.dict(
            run_step.os.environ, {"PATH": "/usr/bin"}, clear=True,
        ):
            environment = run_step._step0_java_environment("/jdk")
        self.assertEqual(environment["JAVA_HOME"], str(Path("/jdk").resolve()))
        self.assertTrue(environment["PATH"].endswith(os.pathsep + "/usr/bin"))

        with patch.dict(run_step.os.environ, {}, clear=True), patch.object(
            run_step.os, "defpath", "",
        ):
            environment = run_step._step0_java_environment(None)
        self.assertEqual(environment["PATH"], str(Path("bin").resolve()))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assert_step_error(
                lambda: run_step._preflight_artifact_input(
                    None, side="base"
                )
            )
            invalid = root / "invalid.jar"
            invalid.write_bytes(b"invalid")
            self.assert_step_error(
                lambda: run_step._preflight_artifact_input(
                    invalid, side="base"
                )
            )
            valid = root / "valid.jar"
            with zipfile.ZipFile(valid, "w") as archive:
                archive.writestr("entry.txt", "content")
            result = run_step._preflight_artifact_input(valid, side="current")
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["archive_entry_count"], 1)
            self.assertEqual(len(result["sha256"]), 64)

            class CorruptArchive:
                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def infolist(self):
                    return [object()]

                def testzip(self):
                    return "bad.class"

            with patch.object(
                run_step.zipfile, "ZipFile", return_value=CorruptArchive()
            ):
                error = self.assert_step_error(
                    lambda: run_step._preflight_artifact_input(
                        valid, side="current"
                    )
                )
            self.assertIn("bad.class", str(error))

    def test_output_storage_write_read_cleanup_and_failure_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            result = run_step._preflight_output_storage(report)
            self.assertEqual(result["status"], "passed")
            self.assertGreaterEqual(result["total_bytes"], result["free_bytes"])

            with patch.object(Path, "mkdir", side_effect=OSError("denied")):
                self.assert_step_error(
                    lambda: run_step._preflight_output_storage(report)
                )

            with patch.object(Path, "unlink", side_effect=OSError("locked")):
                self.assert_step_error(
                    lambda: run_step._preflight_output_storage(report)
                )

            with patch.object(
                run_step, "fsync_directory",
                side_effect=(None, OSError("directory fsync failed")),
            ):
                self.assert_step_error(
                    lambda: run_step._preflight_output_storage(report)
                )

            writer = MagicMock()
            writer.fileno.return_value = 1
            writer_context = MagicMock()
            writer_context.__enter__.return_value = writer
            reader = MagicMock()
            reader.read.return_value = b"wrong"
            reader_context = MagicMock()
            reader_context.__enter__.return_value = reader

            def open_probe(_path, mode, *_args, **_kwargs):
                return writer_context if mode == "xb" else reader_context

            with patch.object(
                Path, "open", new=open_probe,
            ), patch.object(
                run_step.os, "fsync",
            ), patch.object(
                run_step, "fsync_directory",
            ), patch.object(
                Path, "unlink", side_effect=FileNotFoundError,
            ):
                self.assert_step_error(
                    lambda: run_step._preflight_output_storage(report)
                )

            with patch.object(
                Path, "mkdir", side_effect=OSError("primary"),
            ), patch.object(
                Path, "unlink", side_effect=OSError("cleanup"),
            ):
                error = self.assert_step_error(
                    lambda: run_step._preflight_output_storage(report)
                )
            self.assertTrue(
                any("cleanup" in note for note in getattr(error, "__notes__", []))
            )

            class NoAddNoteError(Exception):
                add_note = None
                with_existing_note = False

                def __init__(self, message, **_kwargs):
                    super().__init__(message)
                    if self.with_existing_note:
                        self.__notes__ = ["existing"]

            for existing in (False, True):
                with self.subTest(preexisting_notes=existing):
                    NoAddNoteError.with_existing_note = existing
                    with patch.object(
                        Path, "mkdir", side_effect=OSError("primary"),
                    ), patch.object(
                        Path, "unlink", side_effect=OSError("cleanup"),
                    ), patch.object(
                        run_step, "StepError", NoAddNoteError,
                    ):
                        with self.assertRaises(NoAddNoteError) as captured:
                            run_step._preflight_output_storage(report)
                    notes = getattr(captured.exception, "__notes__", [])
                    self.assertIn("cleanup", notes[-1])

    def test_pinned_build_tool_preflight_maven_gradle_command_and_cleanup_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            git_root = root / "git"
            repo = git_root / "project"
            worktree = root / "worktree"
            subproject = worktree / "project"
            repo.mkdir(parents=True)
            worktree.mkdir()
            subproject.mkdir()

            def invoke(
                context, *, project_path=".", command_results=None,
                create_error=None, remove_error=None, detail="detail",
            ):
                results = iter(command_results or ())
                with ExitStack() as stack:
                    stack.enter_context(patch.object(
                        run_step, "_step1_ref_repository", return_value=repo,
                    ))
                    stack.enter_context(patch.object(
                        run_step, "_pinned_source_git_root", return_value=git_root,
                    ))
                    stack.enter_context(patch.object(
                        run_step, "_relative_path_inside", return_value=project_path,
                    ))
                    stack.enter_context(patch.object(
                        run_step, "create_detached_worktree",
                        side_effect=create_error, return_value=worktree,
                    ))
                    remove = stack.enter_context(patch.object(
                        run_step, "remove_detached_worktree",
                        side_effect=remove_error,
                    ))
                    stack.enter_context(patch.object(
                        run_step, "git_cmd", return_value=["git"],
                    ))
                    stack.enter_context(patch.object(
                        run_step, "mvn_cmd", return_value=["mvn"],
                    ))
                    stack.enter_context(patch.object(
                        run_step, "gradle_cmd", return_value=["gradle"],
                    ))
                    run = stack.enter_context(patch.object(
                        run_step, "run_cmd", side_effect=lambda *_a, **_k: next(results),
                    ))
                    stack.enter_context(patch.object(
                        run_step, "_step0_java_environment",
                        return_value={"JAVA_HOME": "/jdk", "PATH": "/jdk/bin"},
                    ))
                    stack.enter_context(patch.object(
                        run_step, "_subprocess_failure_detail", return_value=detail,
                    ))
                    result = run_step._preflight_pinned_build_tool(
                        context, repo, "base"
                    )
                return result, run, remove

            base = {
                "base_resolved_commit": "A" * 40,
                "base_tool": "maven", "base_jdk_home": "/jdk8",
            }
            result, run, remove = invoke(
                base,
                command_results=(("maven out", "", 0), ("", "maven err", 0)),
            )
            self.assertEqual(result["build_tool"], "maven")
            self.assertEqual(result["commit"], "a" * 40)
            self.assertEqual(len(result["commands"]), 2)
            self.assertEqual(run.call_count, 2)
            remove.assert_called_once()

            no_commit = {**base, "base_resolved_commit": None}
            result, _run, _remove = invoke(
                no_commit,
                command_results=(("", "", 0), ("", "", 0)),
            )
            self.assertEqual(result["commit"], "")

            gradle = {**base, "base_tool": "gradle"}
            result, run, _remove = invoke(
                gradle, project_path="project",
                command_results=((None, None, 0), ("out", "err", 0)),
            )
            self.assertEqual(result["project_path"], "project")
            self.assertEqual(result["build_tool"], "gradle")
            self.assertEqual(run.call_count, 2)

            missing_project = root / "missing-worktree"
            with patch.object(
                run_step, "create_detached_worktree",
                return_value=missing_project,
            ), patch.object(
                run_step, "_step1_ref_repository", return_value=repo,
            ), patch.object(
                run_step, "_pinned_source_git_root", return_value=git_root,
            ), patch.object(
                run_step, "_relative_path_inside", return_value=".",
            ), patch.object(
                run_step, "git_cmd", return_value=["git"],
            ), patch.object(run_step, "remove_detached_worktree"):
                self.assert_step_error(
                    lambda: run_step._preflight_pinned_build_tool(
                        base, repo, "base"
                    )
                )

            for tool in (None, "ant"):
                with self.subTest(unsupported_tool=tool):
                    invalid = {**base, "base_tool": tool}
                    error = self.assert_step_error(
                        lambda invalid=invalid: invoke(invalid)
                    )
                    self.assertIn("不受支持", str(error))

            for detail, streams in (
                ("detail", ("stdout", "stderr", 9)),
                ("", (None, None, 7)),
            ):
                with self.subTest(command_failure_detail=detail):
                    error = self.assert_step_error(
                        lambda detail=detail, streams=streams: invoke(
                            base, command_results=(streams,), detail=detail,
                        )
                    )
                    self.assertIn(
                        "detail" if detail else "exit=7", str(error)
                    )

            error = self.assert_step_error(
                lambda: invoke(
                    base, create_error=RuntimeError("create failed")
                )
            )
            self.assertIn("create failed", str(error))

            error = self.assert_step_error(
                lambda: invoke(
                    base,
                    command_results=(("", "", 0), ("", "", 0)),
                    remove_error=RuntimeError("remove failed"),
                )
            )
            self.assertIn("清理失败", str(error))

            error = self.assert_step_error(
                lambda: invoke(
                    base,
                    command_results=(("", "", 5),),
                    remove_error=RuntimeError("suppressed cleanup"),
                )
            )
            self.assertIn("前置命令失败", str(error))

    def test_run_step0_preflight_cache_modes_asm_and_error_matrix(self):
        def invoke(
            context, *, mode="checkout_build", jdk_error=None,
            explicit=({}, None), asm_error=None,
        ):
            captured = {}

            def write(_path, payload):
                captured.update(payload)

            with ExitStack() as stack:
                preflight_jdk = stack.enter_context(patch.object(
                    run_step, "preflight_jdk_home",
                    side_effect=jdk_error,
                    return_value={"status": "passed"},
                ))
                build = stack.enter_context(patch.object(
                    run_step, "_preflight_pinned_build_tool",
                    side_effect=lambda _ctx, _project, side: {"side": side},
                ))
                stack.enter_context(patch.object(
                    run_step, "infer_step1_mode_fields",
                    return_value={"analysis_mode": mode},
                ))
                artifacts = stack.enter_context(patch.object(
                    run_step, "_preflight_artifact_input",
                    side_effect=lambda path, *, side: {
                        "side": side, "path": str(path),
                    },
                ))
                stack.enter_context(patch.object(
                    run_step, "_preflight_explicit_binary_config",
                    return_value=explicit,
                ))
                resolve_asm = stack.enter_context(patch.object(
                    run_step, "resolve_asm_jar",
                    side_effect=asm_error,
                    return_value=Path("/asm.jar"),
                ))
                stack.enter_context(patch.object(
                    run_step, "_preflight_sha256", return_value="a" * 64,
                ))
                stack.enter_context(patch.object(
                    run_step, "_preflight_output_storage",
                    return_value={"status": "passed"},
                ))
                stack.enter_context(patch.object(
                    run_step, "_sanitize_git_persistence_payload",
                    side_effect=lambda payload: payload,
                ))
                stack.enter_context(patch.object(
                    run_step, "step0_preflight_path", return_value=Path("/result.json"),
                ))
                stack.enter_context(patch.object(
                    run_step, "write_json", side_effect=write,
                ))
                result = run_step.run_step0_preflight(
                    context, "/project", "/report"
                )
            return result, captured, {
                "jdk": preflight_jdk, "build": build,
                "artifacts": artifacts, "resolve_asm": resolve_asm,
            }

        shared = {
            "base_jdk_home": "/jdk", "current_jdk_home": "/jdk",
        }
        result, captured, mocks = invoke(shared)
        self.assertEqual(mocks["jdk"].call_count, 1)
        self.assertEqual(mocks["build"].call_count, 2)
        mocks["artifacts"].assert_not_called()
        mocks["resolve_asm"].assert_called_once()
        self.assertEqual(result, captured)
        self.assertEqual(len(result["step0_preflight_identity"]), 64)

        artifact_context = {
            "base_jdk_home": None, "current_jdk_home": "/jdk17",
            "base_artifact_path": "base.jar",
            "current_artifact_path": "current.jar",
        }
        explicit_asm = Path("/explicit-asm.jar")
        result, _captured, mocks = invoke(
            artifact_context, mode="artifact_inputs",
            explicit=({"status": "passed"}, explicit_asm),
        )
        self.assertEqual(mocks["jdk"].call_count, 2)
        self.assertEqual(mocks["artifacts"].call_count, 2)
        mocks["resolve_asm"].assert_not_called()
        self.assertEqual(result["asm"]["path"], str(explicit_asm))

        jdk_error = run_step.JdkPreflightError(
            "JDK_BAD", "bad jdk", diagnostic={"detail": 1}
        )
        error = self.assert_step_error(
            lambda: invoke(shared, jdk_error=jdk_error)
        )
        self.assertIn("JDK_BAD", error.reason_codes)

        asm_error = run_step.BinaryAsmError("ASM_BAD", "bad asm")
        error = self.assert_step_error(
            lambda: invoke(shared, asm_error=asm_error)
        )
        self.assertIn("ASM_BAD", error.reason_codes)


if __name__ == "__main__":
    unittest.main()
