from __future__ import annotations

import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s1_dep_diff


class Step1DependencyDiffRemainingBoundaryTest(unittest.TestCase):
    @staticmethod
    def _inventory_row(**overrides):
        row = {
            "entry_id": "BOOT-INF/lib/a.jar",
            "lib_entry": "BOOT-INF/lib/a.jar",
            "lib_name": "a.jar",
            "coord": "g:a",
            "group_id": "g",
            "artifact_id": "a",
            "version": "1",
            "classifier": "",
            "filename_stem": "a",
            "match_source": "pom_properties",
            "resolution_status": "resolved",
            "read_error": "",
            "content_sha256": "a" * 64,
            "metadata_anomalies": [],
        }
        row.update(overrides)
        return row

    def test_error_identity_hash_filename_and_unresolved_normalization_matrix(self):
        required = s1_dep_diff.ArtifactCoordinateInputRequiredError(
            Path("artifact.jar"), [{"label": "a"}],
        )
        self.assertEqual(required.artifact_path, "artifact.jar")
        self.assertEqual(required.unresolved_items, [{"label": "a"}])
        self.assertEqual(str(required), "artifact.jar")
        self.assertEqual(
            s1_dep_diff.ArtifactCoordinateInputRequiredError("a.jar").unresolved_items,
            [],
        )

        unresolved = s1_dep_diff.UnresolvedPackagedCoordinatesError(
            ["a:1", "", {"artifact_id": "b", "version": "2"}],
            {"g:a": {"version": "1"}},
        )
        self.assertEqual(unresolved.resolved_deps["g:a"]["version"], "1")
        self.assertIn("a:1", str(unresolved))
        self.assertEqual(
            s1_dep_diff.UnresolvedPackagedCoordinatesError([]).resolved_deps, {},
        )

        self.assertEqual(
            s1_dep_diff._entry_content_sha256({"content_sha256": " A" * 0 + "A" * 64}),
            "a" * 64,
        )
        self.assertEqual(s1_dep_diff._entry_content_sha256({"content_sha256": "bad"}), "")
        self.assertEqual(s1_dep_diff._entry_content_sha256(None), "")

        self.assertEqual(
            s1_dep_diff._normalize_unresolved_label({
                "artifact_id": "a", "version": "1", "classifier": "tests",
                "source": "BOOT-INF/lib/a.jar",
            }),
            "a:1:tests [BOOT-INF/lib/a.jar]",
        )
        self.assertEqual(
            s1_dep_diff._normalize_unresolved_label({}),
            "<unknown-artifact>:<unknown-version>",
        )
        self.assertEqual(s1_dep_diff._normalize_unresolved_label(" a:1 "), "a:1")

        self.assertEqual(
            s1_dep_diff._parse_artifact_version_from_filename("/tmp/demo-1.2.3.jar"),
            ("demo", "1.2.3"),
        )
        self.assertEqual(
            s1_dep_diff._parse_artifact_version_from_filename("demo-2.0-RC1"),
            ("demo", "2.0-RC1"),
        )
        self.assertEqual(s1_dep_diff._parse_artifact_version_from_filename("demo.jar"), ("", ""))

        self.assertEqual(
            s1_dep_diff._split_maven_dependency_artifact_path(
                "g:a:jar:1:/repo/a.jar",
            ),
            ("g:a:jar:1", "/repo/a.jar"),
        )
        self.assertEqual(
            s1_dep_diff._split_maven_dependency_artifact_path(
                r"g:a:jar:1:C:\repo\a.jar",
            ),
            ("g:a:jar:1", r"C:\repo\a.jar"),
        )
        self.assertEqual(
            s1_dep_diff._split_maven_dependency_artifact_path("g:a:jar:1"),
            ("g:a:jar:1", ""),
        )
        self.assertEqual(
            s1_dep_diff._split_maven_dependency_artifact_path(None),
            ("", ""),
        )

        normalized = s1_dep_diff.normalize_unresolved_items([
            "a:1", "a:1", "plain", None,
            {"artifact_id": "b", "version": "2", "side": "base"},
            {"artifact_id": "b", "version": "2", "side": "current"},
        ])
        self.assertEqual(len(normalized), 5)
        self.assertEqual(normalized[0]["artifact_id"], "a")
        self.assertEqual(normalized[1]["label"], "plain")
        self.assertEqual(
            [item["side"] for item in s1_dep_diff.attach_unresolved_side(normalized[:2], " current ")],
            ["current", "current"],
        )
        self.assertEqual(s1_dep_diff.attach_unresolved_side(None, None), [])
        self.assertEqual(
            s1_dep_diff.attach_unresolved_side(["a:1"], None)[0]["side"],
            "",
        )
        fully_populated = s1_dep_diff.normalize_unresolved_items([{
            "artifact_id": "a", "version": "1", "classifier": "tests",
            "entry_id": "entry", "lib_entry": "lib/a.jar", "lib_name": "a.jar",
            "side": "base", "source": "archive", "reason_code": "MISSING",
        }])[0]
        self.assertEqual(fully_populated["classifier"], "tests")
        self.assertEqual(fully_populated["entry_id"], "entry")

    def test_runtime_record_merge_sort_and_text_parser_matrix(self):
        deps = {}
        self.assertIsNone(s1_dep_diff._merge_runtime_artifact_record(deps, {}))
        self.assertEqual(deps, {})
        first = {
            "key": " g:a ", "version": "1", "observed_versions": ["1", ""],
            "artifact_file_name": "a-1.jar",
            "artifact_file_names": ["a-1.jar"],
            "artifact_file_path": "/repo/a-1.jar",
        }
        s1_dep_diff._merge_runtime_artifact_record(deps, first)
        self.assertEqual(deps["g:a"]["observed_versions"], ["1"])
        self.assertFalse(deps["g:a"]["runtime_version_conflict"])
        second = {
            "key": "g:a", "version": "2", "observed_versions": ("2", "1"),
            "artifact_file_names": ["a-2.jar", "a-1.jar"],
            "artifact_file_paths": ["/repo/a-2.jar"],
        }
        s1_dep_diff._merge_runtime_artifact_record(deps, second)
        self.assertEqual(deps["g:a"]["observed_versions"], ["1", "2"])
        self.assertTrue(deps["g:a"]["runtime_version_conflict"])
        self.assertEqual(deps["g:a"]["artifact_file_names"], ["a-1.jar", "a-2.jar"])

        self.assertEqual(
            s1_dep_diff._entry_sort_key({"coord": " g:a ", "version": " 1 ", "lib_entry": " b "}),
            ("g:a", "1", "b"),
        )
        self.assertEqual(s1_dep_diff._entry_sort_key({}), ("", "", ""))
        self.assertEqual(s1_dep_diff._filename_stem(r"C:\repo\demo-1.JAR"), "demo-1")
        self.assertEqual(s1_dep_diff._filename_stem(None), "")
        self.assertEqual(s1_dep_diff._gradle_task({"gradle_path": ":app:"}, "build"), ":app:build")
        self.assertEqual(s1_dep_diff._gradle_task({}, "build"), "build")

        with patch.object(
            s1_dep_diff, "_parse_maven_dependency_list_line",
            side_effect=[None, {"key": "g:a", "version": "1"}, {"key": "g:a", "version": "2"}],
        ):
            parsed = s1_dep_diff.parse_maven_dependency_list("one\ntwo\nthree")
        self.assertEqual(parsed["g:a"]["observed_versions"], ["1", "2"])
        self.assertEqual(s1_dep_diff.parse_maven_dependency_list(""), {})

        self.assertEqual(
            s1_dep_diff._parse_properties_text(
                "# comment\n groupId = g \ninvalid\nartifactId=a=extra\n\n",
            ),
            {"groupId": "g", "artifactId": "a=extra"},
        )
        self.assertEqual(s1_dep_diff._parse_properties_text(None), {})

    def test_build_command_failure_detection_and_cleanup_matrix(self):
        self.assertTrue(s1_dep_diff._is_gradle_lock_contention("Timeout waiting to lock cache"))
        self.assertTrue(s1_dep_diff._is_gradle_lock_contention("another Gradle instance owns it"))
        self.assertFalse(s1_dep_diff._is_gradle_lock_contention(None))
        causes = s1_dep_diff._infer_maven_failure_causes(
            "invalid target release; unsupported class file major version; "
            "JAVA_HOME is not defined correctly; could not resolve dependencies; "
            "the goal you specified requires a project",
        )
        self.assertEqual(len(causes), 5)
        self.assertIn("Maven 命令执行失败", s1_dep_diff._infer_maven_failure_causes("")[0])
        self.assertEqual(
            len(s1_dep_diff._infer_maven_failure_causes("java_home is wrong")),
            1,
        )

        with patch.object(s1_dep_diff, "_gradle_target_model", return_value={"gradle_path": ":app"}), patch.object(
            s1_dep_diff, "_gradle_task", return_value=":app:build",
        ), patch.object(s1_dep_diff, "gradle_cmd", return_value=["gradlew"]):
            self.assertEqual(
                s1_dep_diff._manual_package_command("gradle", "/repo", "app"),
                "gradlew :app:build -x test",
            )
        with patch.object(s1_dep_diff, "_gradle_target_model", side_effect=ValueError("ambiguous")), patch.object(
            s1_dep_diff, "gradle_cmd", return_value=["gradlew"],
        ), patch("sys.stderr", new=io.StringIO()) as stderr:
            self.assertEqual(
                s1_dep_diff._manual_package_command("gradle", "/repo", "app"),
                "gradlew build -x test",
            )
            self.assertIn("回落到根工程 build", stderr.getvalue())
        with patch.object(s1_dep_diff, "_normalize_maven_pl_with_workdir", return_value="app"):
            self.assertIn("-pl app -am", s1_dep_diff._manual_package_command("maven", "/repo", "app"))
        with patch.object(s1_dep_diff, "_normalize_maven_pl_with_workdir", return_value=""):
            self.assertNotIn("-pl", s1_dep_diff._manual_package_command("maven", "/repo", None))

        blocked = s1_dep_diff.Step1CommandExecutionBlockedError(
            stage="build", command="mvn", stderr_excerpt="failure",
        )
        result = s1_dep_diff.append_cleanup_failure_to_blocked_error(
            blocked, OSError("busy"),
        )
        self.assertIs(result, blocked)
        self.assertIn("此外", blocked.stderr_excerpt)
        self.assertEqual(len(blocked.suspected_causes), 1)
        s1_dep_diff.append_cleanup_failure_to_blocked_error(blocked, OSError("again"))
        self.assertEqual(len(blocked.suspected_causes), 1)
        empty_blocked = s1_dep_diff.Step1CommandExecutionBlockedError(
            stage="build", command="mvn", stderr_excerpt="",
        )
        s1_dep_diff.append_cleanup_failure_to_blocked_error(empty_blocked, OSError("busy"))
        self.assertIn("清理失败", empty_blocked.stderr_excerpt)
        fallback = s1_dep_diff.append_cleanup_failure_to_blocked_error(
            RuntimeError("primary"), OSError("cleanup"),
        )
        self.assertIn("primary", str(fallback))
        self.assertIn("cleanup", str(fallback))
        fully_bound = s1_dep_diff.Step1CommandExecutionBlockedError(
            stage="dependency", command="mvn list", stderr_excerpt="failure",
            side="base", branch="main", jdk_field="base_jdk_home",
            jdk_home="/jdk", source_mode="checkout",
            source_project_dir="/repo", artifact_path="/app.jar",
            suspected_causes=["cause"],
        )
        self.assertIn("branch=main", str(fully_bound))
        self.assertEqual(fully_bound.suspected_causes, ["cause"])
        entirely_defaulted = s1_dep_diff.Step1CommandExecutionBlockedError(
            stage=None, command=None, stderr_excerpt=None,
        )
        self.assertIn("build_command", str(entirely_defaulted))
        self.assertEqual(entirely_defaulted.suspected_causes, [])

    def test_packaged_entry_inventory_cacheability_and_archive_type_matrix(self):
        self.assertEqual(
            s1_dep_diff._build_packaged_entry(None)["resolution_status"],
            "resolved",
        )
        built = s1_dep_diff._build_packaged_entry("BOOT-INF/lib/demo-1.jar")
        self.assertEqual(built["lib_name"], "demo-1.jar")
        self.assertEqual(built["filename_stem"], "demo-1")

        valid = self._inventory_row()
        self.assertFalse(s1_dep_diff._packaged_inventory_rows_are_valid(None))
        self.assertFalse(s1_dep_diff._packaged_inventory_rows_are_valid([None]))
        self.assertFalse(s1_dep_diff._packaged_inventory_rows_are_valid([{}]))
        self.assertTrue(s1_dep_diff._packaged_inventory_rows_are_valid([]))
        self.assertTrue(s1_dep_diff._packaged_inventory_rows_are_valid([valid]))
        self.assertFalse(s1_dep_diff._packaged_inventory_rows_are_cacheable(None))
        self.assertFalse(s1_dep_diff._packaged_inventory_rows_are_cacheable([
            self._inventory_row(read_error="broken"),
        ]))
        self.assertTrue(s1_dep_diff._packaged_inventory_rows_are_cacheable([valid]))

        for item, expected in (
            ({}, ""),
            ({"metadata_anomalies": [" z ", "", "a", "a"]}, ";metadata_anomalies=a|z"),
        ):
            self.assertEqual(s1_dep_diff._packaged_metadata_anomaly_suffix(item), expected)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                ("boot.jar", ["BOOT-INF/lib/a.jar"], "boot_jar"),
                ("web.war", ["WEB-INF/lib/a.jar"], "war"),
                ("packaged.jar", ["lib/a.jar"], "packaged_jar"),
                ("thin.jar", ["A.class"], "thin_jar"),
            )
            for name, entries, expected in cases:
                path = root / name
                with zipfile.ZipFile(path, "w") as archive:
                    for entry in entries:
                        archive.writestr(entry, b"x")
                with self.subTest(archive=name):
                    self.assertEqual(s1_dep_diff._detect_archive_packaging_type(path), expected)
            broken = root / "broken.jar"
            broken.write_text("not a zip", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                s1_dep_diff._detect_archive_packaging_type(broken)

    def test_artifact_candidate_discovery_gradle_fallback_and_support_dep_matrix(self):
        for name, expected in (
            ("app.jar", True), ("app.war", True), ("app.zip", False),
            ("app-sources.jar", False), ("app-tests.jar", False),
            ("app-plain.jar", False), ("app.original.jar", False),
        ):
            with self.subTest(candidate=name):
                self.assertIs(s1_dep_diff._looks_like_artifact_candidate(Path(name)), expected)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            libs = root / "build" / "libs"
            target.mkdir()
            libs.mkdir(parents=True)
            (target / "small.jar").write_bytes(b"x")
            (target / "skip-sources.jar").write_bytes(b"large-but-skipped")
            (libs / "large.war").write_bytes(b"12345")
            (libs / "directory.jar").mkdir()
            (target / "small-alias.jar").symlink_to(target / "small.jar")
            archives = s1_dep_diff._discover_packaged_archives(root)
            self.assertEqual([path.name for path in archives], ["large.war", "small.jar"])
            self.assertEqual(s1_dep_diff._discover_packaged_archives(root / "missing"), [])
            file_root = root / "file-root"
            file_root.mkdir()
            (file_root / "target").write_text("not a directory", encoding="utf-8")
            self.assertEqual(s1_dep_diff._discover_packaged_archives(file_root), [])

        for stdout, stderr, expected in (
            ("Task 'juaRuntimeArtifactInventory' not found", "", True),
            ("artifactView", "could not find method", True),
            ("", "unable to resolve class org.gradle.api.artifacts.component", True),
            ("artifactView", "compilation failed", False),
            ("", "ordinary failure", False),
        ):
            with self.subTest(stdout=stdout, stderr=stderr):
                self.assertIs(
                    s1_dep_diff._gradle_inventory_fallback_allowed(stdout, stderr),
                    expected,
                )

        self.assertTrue(s1_dep_diff._is_ignorable_packaging_support_dep({
            "artifact_id": "spring-boot-jarmode-layertools",
        }))
        self.assertTrue(s1_dep_diff._is_ignorable_packaging_support_dep({
            "filename_stem": "spring-boot-jarmode-tools",
        }))
        self.assertTrue(s1_dep_diff._is_ignorable_packaging_support_dep({
            "lib_name": "spring-boot-jarmode-extra.jar",
        }))
        self.assertFalse(s1_dep_diff._is_ignorable_packaging_support_dep({}))

    def test_module_version_environment_and_interaction_matrix(self):
        self.assertEqual(s1_dep_diff._normalize_version_text(None), "")
        self.assertEqual(s1_dep_diff._normalize_version_text("v1.2.3.RELEASE+build"), "1.2.3")
        self.assertEqual(s1_dep_diff._normalize_version_text("V2-android"), "2")
        self.assertEqual(
            s1_dep_diff._runtime_artifact_versions({
                "observed_versions": ["1", "", "2", "1"], "version": "3",
            }),
            ["1", "2", "3"],
        )
        self.assertEqual(s1_dep_diff._runtime_artifact_versions(None), [])

        for value, expected in (
            (None, None), ("", None), (":app", "app"),
            ("group/sub", "sub"), (r"group\sub", "sub"),
            (":group:app", "app"), (":", None),
        ):
            with self.subTest(module=value):
                self.assertEqual(s1_dep_diff.normalize_primary_module(value), expected)

        env = {"EXISTING": "1"}
        self.assertEqual(
            s1_dep_diff.add_branch_hint_to_env(env, " feature "),
            {"EXISTING": "1", "JUA_GIT_BRANCH_HINT": "feature"},
        )
        self.assertEqual(s1_dep_diff.add_branch_hint_to_env(None, None), {})
        self.assertEqual(env, {"EXISTING": "1"})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(s1_dep_diff, "resolve_primary_module_id", side_effect=lambda value, _root: "resolved" if value == "alias" else None):
                self.assertEqual(
                    s1_dep_diff.resolve_module_ids(
                        [".", "./", "root", "__root__", "alias", "group/app", ":", "", 7],
                        root,
                    ),
                    ["__root__", "__root__", "__root__", "__root__", "resolved", "app"],
                )
                self.assertEqual(
                    s1_dep_diff.resolve_module_ids("alias", root),
                    ["resolved"],
                )
            self.assertEqual(s1_dep_diff.resolve_module_ids(None, root), [])
            self.assertEqual(s1_dep_diff.resolve_module_ids("", root), [])
            self.assertEqual(s1_dep_diff.resolve_module_ids(7, root), [])

        base_item = {
            "artifact_id": "a", "version": "1", "side": "base",
            "lib_entry": "BOOT-INF/lib/a.jar", "reason_code": "MISSING",
        }
        interaction = s1_dep_diff.build_step1_coordinate_ambiguity_interaction([
            base_item,
            {**base_item, "artifact_id": "b", "side": "current", "lib_entry": "", "reason_code": ""},
            {**base_item, "artifact_id": "c", "lib_entry": "", "entry_id": "entry-c"},
        ])
        self.assertEqual(interaction["step_id"], "step1")
        self.assertIn("Base", interaction["checklist_lines"][0])
        self.assertIn("Current", interaction["checklist_lines"][1])
        many = s1_dep_diff.build_step1_coordinate_ambiguity_interaction([
            {**base_item, "artifact_id": f"a{index}"} for index in range(51)
        ])
        self.assertEqual(len(many["checklist_lines"]), 51)
        self.assertIn("其余 1 项", many["checklist_lines"][-1])

        with patch.dict(s1_dep_diff.os.environ, {"JAVA_HOME": "/env/jdk"}, clear=True):
            self.assertEqual(s1_dep_diff.resolve_effective_jdk_home(""), str(Path("/env/jdk").resolve()))
        with patch.dict(s1_dep_diff.os.environ, {}, clear=True):
            self.assertEqual(s1_dep_diff.resolve_effective_jdk_home(None), "")
        self.assertEqual(
            s1_dep_diff.resolve_effective_jdk_home(" ~/jdk "),
            str(Path("~/jdk").expanduser().resolve()),
        )

    def test_maven_reactor_module_xml_matrix(self):
        self.assertEqual(s1_dep_diff._pom_module_values(ET.fromstring("<project/>")), ())
        self.assertEqual(
            s1_dep_diff._pom_module_values(ET.fromstring("<project><name>x</name></project>")),
            (),
        )
        namespaced = ET.fromstring(
            '<project xmlns="urn:test"><modules><module> app </module>'
            '<ignored>x</ignored><module/><module> </module>'
            '<module>core</module></modules></project>'
        )
        self.assertEqual(s1_dep_diff._pom_module_values(namespaced), ("app", "core"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(s1_dep_diff._maven_reactor_has_modules(root))
            (root / "pom.xml").write_text("<broken", encoding="utf-8")
            self.assertFalse(s1_dep_diff._maven_reactor_has_modules(root))
            (root / "pom.xml").write_text("<project><modules/></project>", encoding="utf-8")
            self.assertFalse(s1_dep_diff._maven_reactor_has_modules(root))
            (root / "pom.xml").write_text(
                "<project><modules><module></module><ignored>x</ignored>"
                "<module>app</module></modules></project>",
                encoding="utf-8",
            )
            self.assertTrue(s1_dep_diff._maven_reactor_has_modules(root))

    def test_formal_failure_exception_payload_and_fallback_matrix(self):
        gradle = s1_dep_diff.GradleCommandFailure(
            stage=" inventory ", command=" gradle task ", stdout="stdout",
            stderr="stderr", return_code="7", attempts=0,
        )
        self.assertEqual(gradle.stage, "inventory")
        self.assertEqual(gradle.attempts, 1)
        self.assertIn("stderr", str(gradle))
        stdout_only = s1_dep_diff.GradleCommandFailure(
            stage=None, command=None, stdout=" output ", stderr=None,
            return_code=1, attempts=3,
        )
        self.assertIn("output", str(stdout_only))
        empty_output = s1_dep_diff.GradleCommandFailure(
            stage="task", command="gradle", stdout=None, stderr=None,
            return_code=1,
        )
        self.assertTrue(str(empty_output).endswith("："))

        pinned = s1_dep_diff.PinnedCommitMaterializationError(
            "base", {"expected_commit": " abc "},
        )
        self.assertEqual(pinned.side, "base")
        self.assertIn("abc", str(pinned))
        self.assertIn(
            "(unknown)",
            str(s1_dep_diff.PinnedCommitMaterializationError(None, None)),
        )
        source_only = s1_dep_diff.SourceRevisionConfirmationRequiredError(
            "current", "/repo", "/app.jar", {"status": "local"},
        )
        self.assertEqual(source_only.artifact_path, "/app.jar")
        self.assertIn("current", str(source_only))
        self.assertIn(
            "该侧",
            str(s1_dep_diff.SourceRevisionConfirmationRequiredError(None, None)),
        )
        ref = s1_dep_diff.Step1RefResolutionRequiredError(
            "base", "/repo", "/app.jar", {"status": "ambiguous"},
        )
        self.assertIn("ambiguous", str(ref))
        self.assertIn(
            "not_found",
            str(s1_dep_diff.Step1RefResolutionRequiredError(None, None, None, None)),
        )

        remote = s1_dep_diff.Step1RemoteOperationError(
            "base", "/repo", {"failures": [{"reason": "denied"}]},
        )
        self.assertIn("denied", str(remote))
        remote_fallback = s1_dep_diff.Step1RemoteOperationError(
            None, None, {"remote_failures": [{}], "reason": "timeout"},
        )
        self.assertIn("timeout", str(remote_fallback))
        source_fallback = s1_dep_diff.Step1RemoteOperationError(
            "current", "/repo", {"source_status": "offline"},
        )
        self.assertIn("offline", str(source_fallback))
        self.assertIn(
            "未知 Git 远端错误",
            str(s1_dep_diff.Step1RemoteOperationError(None, None, None)),
        )

    def test_version_parse_compare_and_physical_filename_matrix(self):
        self.assertIsNone(s1_dep_diff.parse_version_info(None))
        self.assertIsNone(s1_dep_diff.parse_version_info("qualifier"))
        self.assertEqual(s1_dep_diff.parse_version_info("1.2.3")["base"], [1, 2, 3])
        self.assertEqual(s1_dep_diff.parse_version_info("1.2-RC3")["stage_rank"], -1)
        self.assertEqual(s1_dep_diff.parse_version_info("1.2-RC3")["stage_num"], 3)
        self.assertEqual(s1_dep_diff.parse_version_info("1.2-custom")["stage_rank"], -6)
        self.assertEqual(s1_dep_diff.parse_version_info("1.2-sp")["stage_rank"], 1)
        self.assertIsNone(s1_dep_diff.parse_version_info("💥"))
        self.assertEqual(s1_dep_diff.parse_version_info("1-RC")["stage_num"], 0)
        self.assertEqual(s1_dep_diff.parse_version_info("1-RC-beta")["stage_num"], 0)

        for old, new, expected in (
            (None, "1", 0), ("1", None, 0), ("2", "1", 1), ("1", "2", -1),
            ("1.0", "1", 0), ("1-RC1", "1", -1),
            ("1", "1-RC1", 1), ("1-RC2", "1-RC1", 1),
            ("1-RC1", "1-RC2", -1), ("1.0", "1.0", 0),
        ):
            with self.subTest(old=old, new=new):
                self.assertEqual(s1_dep_diff.compare_versions(old, new), expected)

        for args, expected in (
            ((None, "a"), ""), (("other-1.jar", "a"), ""),
            (("a-1.jar", None), ""),
            (("a-.jar", "a"), ""), (("a-1.jar", "a"), "1"),
            (("a-latest.jar", "a"), ""),
            (("a-tests-1.jar", "a", "tests"), "1"),
            (("a-1-tests.jar", "a", "tests"), "1"),
            (("a-tests-latest.jar", "a", "tests"), ""),
            (("a-latest-tests.jar", "a", "tests"), ""),
            (("a-1-other.jar", "a", "tests"), ""),
        ):
            with self.subTest(physical=args):
                self.assertEqual(
                    s1_dep_diff._physical_version_from_filename_coordinate(*args),
                    expected,
                )

    def test_runtime_filename_classifier_and_candidate_stem_matrix(self):
        item = {
            "group_id": "g", "artifact_id": "a", "classifier": "tests",
            "observed_versions": ["1", "2"],
        }
        stems = s1_dep_diff._runtime_candidate_filename_stems(item)
        self.assertIn("a-1", stems)
        self.assertIn("g-a-1", stems)
        self.assertIn("a-tests-1", stems)
        self.assertIn("a-1-tests", stems)
        self.assertEqual(s1_dep_diff._runtime_candidate_filename_stems({}), set())
        self.assertEqual(
            s1_dep_diff._runtime_candidate_filename_stems({"artifact_id": "a"}),
            set(),
        )
        self.assertEqual(
            s1_dep_diff._runtime_candidate_filename_stems({
                "artifact_id": "a", "version": "1",
            }),
            {"a-1"},
        )
        self.assertEqual(
            s1_dep_diff._runtime_candidate_filename_stems({
                "group_id": "g", "artifact_id": "a", "version": "1",
            }),
            {"a-1", "g-a-1"},
        )

        for name, artifact, version, expected in (
            (None, "a", "1", ""), ("a-1.jar", "a", "1", ""),
            ("a-1.jar", None, "1", ""), ("a-1.jar", "a", None, ""),
            ("a-1-tests.jar", "a", "1", "tests"),
            ("a-tests-1.jar", "a", "1", "tests"),
            ("other-1.jar", "a", "1", ""),
            ("a-tests-2.jar", "a", "1", ""),
        ):
            with self.subTest(classifier=name):
                self.assertEqual(
                    s1_dep_diff._classifier_from_filename(name, artifact, version),
                    expected,
                )

        for name, artifact, version, expected in (
            (None, "a", "1", (False, "", "")),
            ("a-1.jar", None, "1", (False, "", "")),
            ("a-1.jar", "a", None, (False, "", "")),
            ("a-1.jar", "a", "1", (True, "", "artifact-version")),
            ("a-1-tests.jar", "a", "1", (True, "tests", "artifact-version-classifier")),
            ("a-tests-1.jar", "a", "1", (True, "tests", "artifact-classifier-version")),
            ("a-1-.jar", "a", "1", (False, "", "")),
            ("a--1.jar", "a", "1", (False, "", "")),
            ("other-1.jar", "a", "1", (False, "", "")),
        ):
            with self.subTest(match=name):
                self.assertEqual(
                    s1_dep_diff._match_runtime_artifact_filename(
                        name, artifact, version,
                    ),
                    expected,
                )

    def test_step1_blocked_cause_and_module_selector_matrix(self):
        with patch.object(s1_dep_diff, "_infer_maven_failure_causes", return_value=["maven"]):
            self.assertEqual(
                s1_dep_diff._infer_step1_blocked_causes("mvn_package", "x"),
                ["maven"],
            )
        with patch.object(s1_dep_diff, "_infer_gradle_failure_causes", return_value=["gradle"]):
            self.assertEqual(
                s1_dep_diff._infer_step1_blocked_causes("gradle_build", "x"),
                ["gradle"],
            )
        self.assertIn("JDK Home", s1_dep_diff._infer_step1_blocked_causes("prepare_java_env", "")[0])
        causes = s1_dep_diff._infer_step1_blocked_causes(
            "prepare_branch_worktree",
            "already checked out; not a git repository; permission denied; filename too long",
        )
        self.assertEqual(len(causes), 4)
        self.assertIn(
            "同名 worktree",
            s1_dep_diff._infer_step1_blocked_causes(
                "prepare_branch_worktree", "already registered",
            )[0],
        )
        self.assertIn(
            "worktree 初始化",
            s1_dep_diff._infer_step1_blocked_causes("cleanup_branch_worktree", "unknown")[0],
        )
        self.assertIn(
            "准备阶段失败",
            s1_dep_diff._infer_step1_blocked_causes(None, None)[0],
        )

        root = Path("/repo")
        self.assertFalse(s1_dep_diff._module_selector_matches(None, "app", root))
        self.assertFalse(s1_dep_diff._module_selector_matches("app", None, root))
        self.assertTrue(s1_dep_diff._module_selector_matches("group/app", "group/app", root))
        self.assertTrue(s1_dep_diff._module_selector_matches("group/app", ":app", root))
        with patch.object(s1_dep_diff, "_read_pom_identity", return_value=("g", "artifact")):
            self.assertTrue(s1_dep_diff._module_selector_matches("module", "artifact", root))
        with patch.object(s1_dep_diff, "_read_pom_identity", return_value=("", "")):
            self.assertFalse(s1_dep_diff._module_selector_matches("module", "artifact", root))
        with patch.object(s1_dep_diff, "_read_pom_identity", return_value=("g", "other")):
            self.assertFalse(s1_dep_diff._module_selector_matches("module", "artifact", root))
        with patch.object(s1_dep_diff, "_read_pom_identity", return_value=("g", "a:")):
            self.assertTrue(s1_dep_diff._module_selector_matches("module", "a:", root))

    def test_manual_override_confirmation_and_artifact_identity_matrix(self):
        overrides, invalid = s1_dep_diff.parse_manual_coord_overrides([
            None, "", "bad", "a:1 -> invalid", "a -> g:a",
            ":1 -> g:a", "a: -> g:a", "a:1 -> :a", "a:1 -> g:",
            "a:1 -> g:a", "a:1:tests -> g:a-tests",
        ])
        self.assertEqual(overrides[("a", "1")]["coord"], "g:a")
        self.assertEqual(overrides[("a", "1", "tests")]["classifier"], "tests")
        self.assertEqual(len(invalid), 7)
        self.assertEqual(s1_dep_diff.parse_manual_coord_overrides(None), ({}, []))

        confirmed, invalid_json = s1_dep_diff.parse_confirmed_unresolved_items([
            None, "", "not-json", "[]", '{"artifact_id":"a","version":"1"}',
        ])
        self.assertEqual(confirmed[0]["artifact_id"], "a")
        self.assertEqual(invalid_json, ["not-json", "[]"])
        self.assertEqual(s1_dep_diff.parse_confirmed_unresolved_items(None), ([], []))

        packaged = {
            "entry_id": "entry", "lib_entry": "BOOT-INF/lib/a.jar", "side": "base",
        }
        identities = [
            {"side": "current", "entry_id": "entry", "coord": "g:wrong", "version": "1"},
            {"side": "base", "entry_id": "other", "coord": "g:other", "version": "1"},
            {"side": "base", "entry_id": "entry", "coord": "g:a", "version": "1"},
            {"side": "base", "lib_entry": "BOOT-INF/lib/a.jar", "coord": "g:a", "version": "1"},
        ]
        selected, candidates = s1_dep_diff._manual_artifact_identity_for_entry(
            packaged, identities,
        )
        self.assertEqual(selected["coord"], "g:a")
        self.assertEqual(len(candidates), 1)
        ambiguous, candidates = s1_dep_diff._manual_artifact_identity_for_entry(
            packaged,
            identities + [{
                "side": "base", "entry_id": "entry", "coord": "g:a", "version": "2",
            }],
        )
        self.assertIsNone(ambiguous)
        self.assertEqual(len(candidates), 2)
        self.assertEqual(
            s1_dep_diff._manual_artifact_identity_for_entry({}, None),
            (None, []),
        )

    def test_gradle_target_pom_identity_and_java_environment_matrix(self):
        modules = [
            {
                "module": "app", "gradle_path": ":app", "artifact_id": "app-artifact",
                "coord": "g:app", "module_dir": "/repo/app",
            },
            {
                "module": "other", "gradle_path": ":other", "artifact_id": "other",
                "coord": "g:other", "module_dir": "/repo/other",
            },
        ]
        with patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": modules}):
            for selector in ("app", ":app", "app-artifact", "g:app"):
                self.assertEqual(
                    s1_dep_diff._gradle_target_model("/repo", selector)["module"],
                    "app",
                )
            with self.assertRaises(RuntimeError):
                s1_dep_diff._gradle_target_model("/repo", "missing")
        with patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": [
            {**modules[0], "module": "first"}, {**modules[0], "module": "second"},
        ]}):
            with self.assertRaises(RuntimeError):
                s1_dep_diff._gradle_target_model("/repo", ":app")
        with patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": [{
            "module": ".", "gradle_path": ":", "artifact_id": "root",
            "coord": "g:root", "module_dir": "/repo",
        }]}):
            self.assertEqual(s1_dep_diff._gradle_target_model("/repo", None)["module"], ".")
        with patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": [{
            "module": ".", "gradle_path": None, "artifact_id": None,
            "coord": None, "module_dir": "",
        }]}):
            self.assertEqual(s1_dep_diff._gradle_target_model("/repo", "./")["module"], ".")
        with patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": [{
            "module": None, "gradle_path": None, "artifact_id": "only",
            "coord": None, "module_dir": None,
        }]}):
            self.assertEqual(
                s1_dep_diff._gradle_target_model("/repo", "only")["artifact_id"],
                "only",
            )
        with patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": [{
            "module": ".", "gradle_path": ":", "artifact_id": "root",
            "coord": "g:root", "module_dir": "/repo",
        }]}):
            self.assertEqual(s1_dep_diff._gradle_target_model("/repo", "root")["module"], ".")
        with patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": None}):
            with self.assertRaises(RuntimeError):
                s1_dep_diff._gradle_target_model("/repo", "missing")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.xml"
            self.assertEqual(s1_dep_diff._read_pom_identity(missing), ("", ""))
            malformed = root / "malformed.xml"
            malformed.write_text("<broken", encoding="utf-8")
            self.assertEqual(s1_dep_diff._read_pom_identity(malformed), ("", ""))
            direct = root / "direct.xml"
            direct.write_text(
                "<project><groupId>g</groupId><artifactId>a</artifactId>"
                "<groupId>ignored</groupId><artifactId>ignored</artifactId></project>",
                encoding="utf-8",
            )
            self.assertEqual(s1_dep_diff._read_pom_identity(direct), ("g", "a"))
            inherited = root / "inherited.xml"
            inherited.write_text(
                "<project><parent><groupId>parent.g</groupId></parent>"
                "<artifactId>a</artifactId></project>",
                encoding="utf-8",
            )
            self.assertEqual(s1_dep_diff._read_pom_identity(inherited), ("parent.g", "a"))
            parent_without_group = root / "parent-without-group.xml"
            parent_without_group.write_text(
                "<project><parent><name>x</name></parent><artifactId>a</artifactId></project>",
                encoding="utf-8",
            )
            self.assertEqual(
                s1_dep_diff._read_pom_identity(parent_without_group),
                ("", "a"),
            )
            sparse = root / "sparse.xml"
            sparse.write_text(
                "<project><name>x</name><groupId></groupId><artifactId></artifactId>"
                "<parent><name>x</name><groupId></groupId>"
                "<groupId>fallback.g</groupId></parent>"
                "<artifactId>actual</artifactId></project>",
                encoding="utf-8",
            )
            self.assertEqual(
                s1_dep_diff._read_pom_identity(sparse),
                ("fallback.g", "actual"),
            )

            jdk = root / "jdk"
            java = jdk / "bin" / ("java.exe" if s1_dep_diff.IS_WINDOWS else "java")
            java.parent.mkdir(parents=True)
            java.write_text("java", encoding="utf-8")
            with patch.object(s1_dep_diff, "resolve_effective_jdk_home", return_value=""):
                self.assertEqual(s1_dep_diff.build_java_env(None), {})
            with patch.object(s1_dep_diff, "resolve_effective_jdk_home", return_value=str(jdk)), patch.dict(
                s1_dep_diff.os.environ, {"PATH": "/existing"}, clear=True,
            ):
                env = s1_dep_diff.build_java_env(str(jdk))
                self.assertEqual(env["JAVA_HOME"], str(jdk))
                self.assertTrue(env["PATH"].endswith(s1_dep_diff.os.pathsep + "/existing"))
            with patch.object(s1_dep_diff, "resolve_effective_jdk_home", return_value=str(jdk)), patch.dict(
                s1_dep_diff.os.environ, {}, clear=True,
            ):
                self.assertEqual(s1_dep_diff.build_java_env(str(jdk))["PATH"], str(jdk / "bin"))
            with patch.object(s1_dep_diff, "resolve_effective_jdk_home", return_value=str(root / "bad")):
                with self.assertRaises(RuntimeError):
                    s1_dep_diff.build_java_env("bad")
            empty_jdk = root / "empty-jdk"
            empty_jdk.mkdir()
            with patch.object(
                s1_dep_diff,
                "resolve_effective_jdk_home",
                return_value=str(empty_jdk),
            ):
                with self.assertRaises(RuntimeError):
                    s1_dep_diff.build_java_env(str(empty_jdk))
            windows_jdk = root / "windows-jdk"
            windows_java = windows_jdk / "bin" / "java.exe"
            windows_java.parent.mkdir(parents=True)
            windows_java.write_text("java", encoding="utf-8")
            with patch.object(s1_dep_diff, "IS_WINDOWS", True), patch.object(
                s1_dep_diff,
                "resolve_effective_jdk_home",
                return_value=str(windows_jdk),
            ):
                self.assertEqual(
                    s1_dep_diff.build_java_env(str(windows_jdk))["JAVA_HOME"],
                    str(windows_jdk),
                )

    def test_spring_boot_classpath_index_validation_matrix(self):
        class Archive:
            def __init__(self, raw=None, names=(), error=None):
                self.raw = raw
                self.names = list(names)
                self.error = error

            def read(self, _name):
                if self.error:
                    raise self.error
                return self.raw

            def namelist(self):
                return self.names

        self.assertEqual(s1_dep_diff._spring_boot_classpath_order(Archive(error=KeyError("missing"))), {})
        self.assertEqual(s1_dep_diff._spring_boot_classpath_order(Archive(raw=b"\xff")), {})
        self.assertEqual(s1_dep_diff._spring_boot_classpath_order(Archive(raw=b"# comment\n\n")), {})
        self.assertEqual(s1_dep_diff._spring_boot_classpath_order(Archive(raw=b"# comment\n\ninvalid")), {})
        duplicate = b'- "BOOT-INF/lib/a.jar"\n- "BOOT-INF/lib/a.jar"'
        self.assertEqual(s1_dep_diff._spring_boot_classpath_order(Archive(raw=duplicate)), {})
        missing = b'- "BOOT-INF/lib/a.jar"'
        self.assertEqual(s1_dep_diff._spring_boot_classpath_order(Archive(raw=missing, names=[])), {})
        valid = b'# comment\n- "BOOT-INF/lib/a.jar"\n- "BOOT-INF/lib/b.jar"'
        self.assertEqual(
            s1_dep_diff._spring_boot_classpath_order(Archive(
                raw=valid, names=["BOOT-INF/lib/a.jar", "BOOT-INF/lib/b.jar"],
            )),
            {"BOOT-INF/lib/a.jar": 0, "BOOT-INF/lib/b.jar": 1},
        )

    def test_entry_compare_key_variants(self):
        self.assertEqual(s1_dep_diff._entry_compare_key(None), "")
        self.assertEqual(s1_dep_diff._entry_compare_key({"artifact_id": "a"}), "a")
        self.assertEqual(
            s1_dep_diff._entry_compare_key({"artifact_id": "a", "classifier": "tests"}),
            "a:tests",
        )
        self.assertEqual(s1_dep_diff._entry_compare_key({"lib_entry": " lib/a.jar "}), "lib/a.jar")
        self.assertEqual(s1_dep_diff._entry_compare_key({"lib_name": " a.jar "}), "a.jar")


if __name__ == "__main__":
    unittest.main()
