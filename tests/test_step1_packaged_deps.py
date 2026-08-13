import io
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s1_dep_diff  # noqa: E402
import path_runtime  # noqa: E402
from pipeline_constants import (  # noqa: E402
    STEP1_ARTIFACTS_DIRNAME,
    STEP1_DEPENDENCY_JARS_MANIFEST_FILE,
)


class Step1PackagedDepsTest(unittest.TestCase):
    def test_windows_step1_git_command_enables_long_paths_without_global_config(self):
        with patch.object(path_runtime, "IS_WINDOWS", True), \
                patch.object(path_runtime, "git_cmd", return_value=[r"C:\Git\git.exe"]):
            command = path_runtime.git_with_long_paths()

        self.assertEqual(
            [r"C:\Git\git.exe", "-c", "core.longpaths=true"],
            command,
        )

    def test_create_branch_worktree_uses_short_name_and_retries_another_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_root = root / "first"
            second_root = root / "second"
            branch = "a" * 40
            calls = []

            def fake_run_cmd(command, cwd=None, timeout=None, **_kwargs):
                calls.append((list(command), cwd, timeout))
                if "rev-parse" in command:
                    return branch, "", 0
                if "ls-tree" in command:
                    return "src/" + ("nested/" * 20) + "Demo.java\0", "", 0
                if "add" in command and "worktree" in command:
                    target = Path(command[-2])
                    if target.parent == first_root:
                        return "", "error: unable to create file: Filename too long", 1
                    return "", "", 0
                if "remove" in command and "worktree" in command:
                    return "", "", 0
                raise AssertionError(f"unexpected command: {command}")

            with patch.object(path_runtime, "IS_WINDOWS", True), \
                    patch.object(path_runtime, "git_cmd", return_value=["git"]), \
                    patch.object(
                        path_runtime,
                        "short_temp_root_candidates",
                        return_value=[first_root, second_root],
                    ), \
                    patch.object(path_runtime, "run_cmd", side_effect=fake_run_cmd):
                worktree = path_runtime.create_detached_worktree(
                    branch,
                    root,
                    label="s1-b",
                )

            self.assertEqual(second_root, worktree.parent)
            self.assertTrue(worktree.name.startswith("s1-b-"))
            self.assertNotIn(branch, worktree.name)
            self.assertLess(len(worktree.name), 32)
            self.assertTrue(any(
                "remove" in command and str(first_root) in command[-1]
                for command, _cwd, _timeout in calls
            ))
            self.assertTrue(all(
                command[1:3] == ["-c", "core.longpaths=true"]
                for command, _cwd, _timeout in calls
            ))

    def test_worktree_blocked_interaction_is_not_mislabeled_as_maven(self):
        error = s1_dep_diff.build_step1_command_blocked_error(
            stage="prepare_branch_worktree",
            command="git worktree add --detach <temp> abc123",
            exc=RuntimeError("Filename too long"),
            side="current",
            branch="abc123",
        )

        interaction = s1_dep_diff.build_step1_command_blocked_interaction(error)

        self.assertEqual(
            "step1_git_worktree_command_blocked",
            interaction["reason_code"],
        )
        self.assertIn("Git worktree", interaction["summary"])
        self.assertNotIn(
            "current_jdk_home",
            interaction["response_schema"]["properties"],
        )
        self.assertTrue(any(
            "路径超过" in cause for cause in interaction["suspected_causes"]
        ))

    def test_coordinate_followup_uses_cross_step_diagnostic_contract(self):
        interaction = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="current",
            side_cn="当前侧",
            artifact_path="/tmp/app.jar",
            unresolved_items=[{"label": "unknown-lib.jar"}],
        )

        self.assertEqual(
            "DEPENDENCY_COORDINATES_UNRESOLVED",
            interaction["reason_code"],
        )
        self.assertEqual("step1", interaction["origin_step"])
        self.assertIn(
            "unresolved_dependency_coordinates_after_enrichment",
            interaction["reason_code_aliases"],
        )
        self.assertEqual(
            "DEPENDENCY_COORDINATES_UNRESOLVED",
            interaction["diagnostic_guidance"]["reason_code"],
        )

    def test_unconfirmed_packaged_version_requires_entry_identity_confirmation(self):
        interaction = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="current",
            side_cn="当前侧",
            artifact_path="/tmp/app.jar",
            unresolved_items=[{
                "artifact_id": "renamed",
                "version": "<unknown-version>",
                "entry_id": "BOOT-INF/lib/renamed.jar",
                "lib_entry": "BOOT-INF/lib/renamed.jar",
                "side": "current",
                "reason_code": "PACKAGED_VERSION_UNCONFIRMED",
            }],
        )

        self.assertIn(
            "manual_artifact_identities",
            interaction["required_fields"],
        )
        self.assertIn(
            "manual_artifact_identities",
            interaction["response_schema"]["properties"],
        )
        self.assertNotIn("primary_module", interaction["required_fields"])

    def test_spring_boot_classpath_index_is_parsed_as_runtime_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/lib/second.jar", b"second")
                archive.writestr("BOOT-INF/lib/first.jar", b"first")
                archive.writestr(
                    "BOOT-INF/classpath.idx",
                    '- "BOOT-INF/lib/first.jar"\n'
                    '- "BOOT-INF/lib/second.jar"\n',
                )
            with zipfile.ZipFile(artifact) as archive:
                order = s1_dep_diff._spring_boot_classpath_order(archive)

        self.assertEqual({
            "BOOT-INF/lib/first.jar": 0,
            "BOOT-INF/lib/second.jar": 1,
        }, order)

    def test_malformed_spring_boot_classpath_index_is_not_authoritative(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/lib/demo.jar", b"demo")
                archive.writestr(
                    "BOOT-INF/classpath.idx",
                    "BOOT-INF/lib/demo.jar\n",
                )
            with zipfile.ZipFile(artifact) as archive:
                order = s1_dep_diff._spring_boot_classpath_order(archive)

        self.assertFalse(order)

    def test_retained_runtime_jar_carries_explicit_classpath_order(self):
        nested_bytes = self._nested_jar_bytes([
            ("demo/Support.class", b"class"),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "app.jar"
            lib_entry = "BOOT-INF/lib/support.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(lib_entry, nested_bytes)
                archive.writestr(
                    "BOOT-INF/classpath.idx",
                    f'- "{lib_entry}"\n',
                )
            _manifest, items = s1_dep_diff.materialize_changed_dependency_jars(
                [],
                {"current": {
                    "artifact_path": str(artifact),
                    "artifact_sha256": hashlib.sha256(
                        artifact.read_bytes()
                    ).hexdigest(),
                }},
                root / "dependencies",
                current_entries=[{
                    "coord": "com.acme:support",
                    "version": "1",
                    "scope": "runtime",
                    "lib_entry": lib_entry,
                    "resolution_status": "resolved",
                }],
            )

        self.assertEqual(1, len(items))
        self.assertEqual(0, items[0]["runtime_classpath_index"])
        self.assertEqual(
            "spring_boot_classpath_index",
            items[0]["runtime_classpath_authority"],
        )

    def test_materialization_keeps_complete_base_and_current_runtime_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            side_meta = {}
            side_entries = {}
            for side, version in (("base", "1"), ("current", "2")):
                nested = self._nested_jar_bytes([
                    ("demo/Dependency.class", f"dependency-{version}".encode()),
                ])
                artifact = root / f"{side}.jar"
                lib_entry = f"BOOT-INF/lib/dependency-{version}.jar"
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr(
                        "BOOT-INF/classes/biz/Application.class",
                        f"business-{version}".encode(),
                    )
                    archive.writestr(lib_entry, nested)
                side_meta[side] = {
                    "artifact_path": str(artifact),
                    "artifact_sha256": hashlib.sha256(
                        artifact.read_bytes()
                    ).hexdigest(),
                }
                side_entries[side] = [{
                    "coord": "com.acme:dependency",
                    "version": version,
                    "scope": "runtime",
                    "lib_entry": lib_entry,
                    "resolution_status": "resolved",
                }]

            manifest_path, items = s1_dep_diff.materialize_changed_dependency_jars(
                [],
                side_meta,
                root / "dependencies",
                base_entries=side_entries["base"],
                current_entries=side_entries["current"],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual({item["side"] for item in items}, {"base", "current"})
        self.assertTrue(all("binary_runtime" in item["purposes"] for item in items))
        self.assertEqual(
            {item["side"] for item in manifest["business_artifacts"]},
            {"base", "current"},
        )
        self.assertTrue(all(
            item["container_and_launcher_kind"] == "spring-boot-executable-jar"
            for item in manifest["business_artifacts"]
        ))

    def test_thin_business_jar_retains_runtime_meta_inf_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("biz/Application.class", b"class")
                archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
                archive.writestr("META-INF/services/demo.Service", b"biz.Provider\n")
                archive.writestr(
                    "META-INF/persistence.xml",
                    b"<persistence><persistence-unit><class>biz.Entity</class>"
                    b"</persistence-unit></persistence>",
                )
                archive.writestr(
                    "META-INF/maven/acme/app/pom.properties",
                    b"groupId=acme\nartifactId=app\nversion=1\n",
                )

            manifest_path, _items = s1_dep_diff.materialize_changed_dependency_jars(
                [],
                {"current": {
                    "artifact_path": str(artifact),
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }},
                root / "dependencies",
                current_entries=[],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            business = next(
                item for item in manifest["business_artifacts"]
                if item["side"] == "current"
            )
            with zipfile.ZipFile(business["retained_path"]) as retained:
                names = set(retained.namelist())

        self.assertIn("META-INF/services/demo.Service", names)
        self.assertIn("META-INF/persistence.xml", names)
        self.assertNotIn("META-INF/MANIFEST.MF", names)
        self.assertNotIn("META-INF/maven/acme/app/pom.properties", names)

    def test_packaging_detection_distinguishes_thin_from_corrupt_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            thin = root / "thin.jar"
            corrupt = root / "corrupt.jar"
            with zipfile.ZipFile(thin, "w") as archive:
                archive.writestr("example/Application.class", b"class")
            corrupt.write_bytes(b"not-a-zip-archive")

            self.assertEqual(
                s1_dep_diff._detect_archive_packaging_type(thin), "thin_jar"
            )
            with self.assertRaisesRegex(
                RuntimeError, "最终制品扫描不完整.*archive_open:BadZipFile"
            ):
                s1_dep_diff._detect_archive_packaging_type(corrupt)

    def test_parse_gradle_dependency_report_uses_selected_runtime_version(self):
        deps = s1_dep_diff.parse_gradle_dependency_report(
            """runtimeClasspath - Runtime classpath of source set 'main'.
            +--- org.example:direct:1.0 -> 1.2
            |    \\--- org.example:transitive:3.4 (*)
            +--- project :internal
            \\--- org.example:broken:9 FAILED
            """,
            project_modules=[{
                "gradle_path": ":internal",
                "group_id": "com.acme",
                "artifact_id": "internal-core",
                "version": "2.1.0",
            }],
        )

        self.assertEqual(deps["org.example:direct"]["version"], "1.2")
        self.assertEqual(deps["org.example:transitive"]["version"], "3.4")
        self.assertEqual(deps["com.acme:internal-core"]["version"], "2.1.0")
        self.assertEqual(
            deps["com.acme:internal-core"]["gradle_project_path"],
            ":internal",
        )
        self.assertNotIn("org.example:broken", deps)

    def test_parse_gradle_artifact_inventory_preserves_physical_artifacts(self):
        prefix = s1_dep_diff.GRADLE_ARTIFACT_INVENTORY_PREFIX
        rows = [
            {
                "group_id": "com.github.jnr",
                "artifact_id": "jffi",
                "version": "1.2.23",
                "file_name": "jffi-1.2.23.jar",
                "file_path": "/cache/jffi-1.2.23.jar",
            },
            {
                "group_id": "com.github.jnr",
                "artifact_id": "jffi",
                "version": "1.2.23",
                "file_name": "jffi-1.2.23-native.jar",
                "file_path": "/cache/jffi-1.2.23-native.jar",
            },
            {
                "project_path": ":internal",
                "file_name": "internal-core-2.1.0.jar",
                "file_path": "/workspace/internal-core-2.1.0.jar",
            },
        ]
        report = "\n".join(
            prefix + json.dumps(row)
            for row in rows
        )

        deps = s1_dep_diff.parse_gradle_artifact_inventory(
            report,
            project_modules=[{
                "gradle_path": ":internal",
                "group_id": "com.acme",
                "artifact_id": "internal-core",
                "version": "2.1.0",
            }],
        )

        self.assertEqual(
            set(deps),
            {
                "com.github.jnr:jffi",
                "com.github.jnr:jffi:native",
                "com.acme:internal-core",
            },
        )
        self.assertEqual(
            deps["com.github.jnr:jffi:native"]["artifact_file_name"],
            "jffi-1.2.23-native.jar",
        )
        self.assertEqual(
            deps["com.acme:internal-core"]["gradle_project_path"],
            ":internal",
        )

    def test_gradle_inventory_uses_effective_project_component_coordinates(self):
        report = (
            s1_dep_diff.GRADLE_ARTIFACT_INVENTORY_PREFIX
            + json.dumps({
                "project_path": ":internal",
                "group_id": "com.effective",
                "artifact_id": "internal-runtime",
                "version": "3.4.5",
                "file_name": "custom-internal.jar",
                "file_path": "/workspace/custom-internal.jar",
            })
        )

        deps = s1_dep_diff.parse_gradle_artifact_inventory(
            report,
            project_modules=[{
                "gradle_path": ":internal",
                "group_id": "",
                "artifact_id": "static-name",
                "version": "unspecified",
            }],
        )

        self.assertEqual(set(deps), {"com.effective:internal-runtime"})
        self.assertEqual(
            deps["com.effective:internal-runtime"]["artifact_file_name"],
            "custom-internal.jar",
        )
        self.assertEqual(
            deps["com.effective:internal-runtime"]["gradle_project_path"],
            ":internal",
        )

    def test_collect_gradle_runtime_deps_prefers_artifact_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.gradle").write_text(
                "include ':app'\n",
                encoding="utf-8",
            )
            (root / "build.gradle").write_text(
                "group = 'com.acme'\nversion = '1.0'\n",
                encoding="utf-8",
            )
            (root / "app").mkdir()
            (root / "app/build.gradle").write_text(
                "plugins { id 'java' }\n",
                encoding="utf-8",
            )
            row = {
                "group_id": "org.example",
                "artifact_id": "native-lib",
                "version": "3.2.1",
                "file_name": "native-lib-3.2.1-linux.jar",
                "file_path": "/cache/native-lib-3.2.1-linux.jar",
            }
            report = (
                s1_dep_diff.GRADLE_ARTIFACT_INVENTORY_PREFIX
                + json.dumps(row)
            )
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                return report, "", 0

            with patch.object(s1_dep_diff, "run_cmd", side_effect=fake_run):
                deps, command_text = (
                    s1_dep_diff.collect_runtime_deps_for_workspace(
                        root,
                        primary_module=":app",
                        build_tool="gradle",
                    )
                )

        self.assertEqual(len(commands), 1)
        self.assertTrue(any(
            value.endswith(s1_dep_diff.GRADLE_ARTIFACT_INVENTORY_TASK)
            for value in commands[0]
        ))
        self.assertNotIn("dependencies", commands[0])
        self.assertIn("<generated-init-script>", command_text)
        self.assertEqual(
            set(deps),
            {"org.example:native-lib:linux"},
        )

    def test_gradle_lock_contention_retries_only_the_same_command(self):
        command = ["gradlew", "--no-daemon", ":app:dependencies"]
        results = [
            ("", "Timeout waiting to lock dependency cache", 1),
            ("", "Could not lock file hash cache", 1),
            ("resolved", "", 0),
        ]

        with patch.object(
            s1_dep_diff,
            "run_cmd",
            side_effect=results,
        ) as runner, patch.object(
            s1_dep_diff.time,
            "sleep",
        ) as sleeper:
            stdout, stderr, return_code, attempts = (
                s1_dep_diff._run_gradle_command_with_lock_retry(
                    command,
                    cwd="/workspace",
                )
            )

        self.assertEqual((stdout, stderr, return_code), ("resolved", "", 0))
        self.assertEqual(attempts, 3)
        self.assertEqual(
            [call.args[0] for call in runner.call_args_list],
            [command, command, command],
        )
        self.assertEqual(
            [call.args[0] for call in sleeper.call_args_list],
            [1, 3],
        )
        self.assertTrue(s1_dep_diff._is_gradle_lock_contention(
            "Timeout of 120000 reached waiting for exclusive access to file: "
            "/home/user/.gradle/wrapper/dists/gradle.zip"
        ))

    def test_gradle_inventory_lock_failure_never_starts_component_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.gradle").write_text(
                "include ':app'\n",
                encoding="utf-8",
            )
            (root / "build.gradle").write_text(
                "group = 'com.acme'\nversion = '1.0'\n",
                encoding="utf-8",
            )
            (root / "app").mkdir()
            (root / "app/build.gradle").write_text(
                "plugins { id 'java' }\n",
                encoding="utf-8",
            )
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                return "", "Timeout waiting to lock dependency cache", 1

            with patch.object(
                s1_dep_diff,
                "run_cmd",
                side_effect=fake_run,
            ), patch.object(
                s1_dep_diff.time,
                "sleep",
            ):
                with self.assertRaises(
                    s1_dep_diff.GradleCommandFailure
                ) as raised:
                    s1_dep_diff.collect_runtime_deps_for_workspace(
                        root,
                        primary_module=":app",
                        build_tool="gradle",
                    )

        self.assertEqual(len(commands), 3)
        self.assertTrue(all(
            any(
                value.endswith(
                    s1_dep_diff.GRADLE_ARTIFACT_INVENTORY_TASK
                )
                for value in command
            )
            for command in commands
        ))
        self.assertEqual(
            raised.exception.stage,
            "gradle_artifact_inventory",
        )
        self.assertEqual(raised.exception.attempts, 3)
        self.assertNotIn("dependencies --configuration", str(
            raised.exception.command
        ))

    def test_gradle_inventory_api_incompatibility_allows_component_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.gradle").write_text(
                "include ':app', ':internal'\n",
                encoding="utf-8",
            )
            (root / "build.gradle").write_text(
                "allprojects {\n"
                "  group = 'com.acme'\n"
                "  version = '2.1.0'\n"
                "}\n",
                encoding="utf-8",
            )
            for module in ("app", "internal"):
                (root / module).mkdir()
                (root / module / "build.gradle").write_text(
                    "plugins { id 'java' }\n",
                    encoding="utf-8",
                )
            fallback_report = (
                "+--- project :internal\n"
                "\\--- org.example:external:1.0\n"
            )
            results = [
                ("", "Could not find method artifactView()", 1),
                (fallback_report, "", 0),
            ]

            with patch.object(
                s1_dep_diff,
                "run_cmd",
                side_effect=results,
            ) as runner:
                deps, command_text = (
                    s1_dep_diff.collect_runtime_deps_for_workspace(
                        root,
                        primary_module=":app",
                        build_tool="gradle",
                    )
                )

        self.assertEqual(runner.call_count, 2)
        self.assertIn("fallback=", command_text)
        self.assertEqual(
            set(deps),
            {"com.acme:internal", "org.example:external"},
        )
        self.assertFalse(
            s1_dep_diff._gradle_inventory_fallback_allowed(
                "",
                "MissingMethodException in the user's build.gradle",
            )
        )

    def test_gradle_failure_keeps_actual_stage_and_command(self):
        failure = s1_dep_diff.GradleCommandFailure(
            stage="gradle_artifact_inventory",
            command="gradlew --init-script <generated> :app:juaRuntimeArtifactInventory",
            stdout="",
            stderr="Timeout waiting to lock dependency cache",
            return_code=1,
            attempts=3,
        )

        blocked = s1_dep_diff.build_step1_command_blocked_from_exception(
            failure,
            default_stage="gradle_dependencies",
            default_command=(
                "gradlew dependencies --configuration runtimeClasspath"
            ),
            side="base",
            branch="abc123",
        )

        self.assertEqual(blocked.stage, "gradle_artifact_inventory")
        self.assertIn("juaRuntimeArtifactInventory", blocked.command)
        self.assertNotIn(
            "dependencies --configuration",
            blocked.command,
        )
        self.assertTrue(any(
            "文件锁" in cause
            for cause in blocked.suspected_causes
        ))

    def test_collect_gradle_runtime_deps_maps_internal_project_coordinates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.gradle").write_text(
                "include ':app', ':internal'\n",
                encoding="utf-8",
            )
            (root / "build.gradle").write_text(
                "allprojects {\n"
                "  group = 'com.acme'\n"
                "  version = '2.1.0'\n"
                "}\n",
                encoding="utf-8",
            )
            for module in ("app", "internal"):
                (root / module).mkdir()
                (root / module / "build.gradle").write_text(
                    "plugins { id 'java' }\n",
                    encoding="utf-8",
                )

            report = (
                "runtimeClasspath - Runtime classpath of source set 'main'.\n"
                "+--- project :internal\n"
                "\\--- org.example:external:1.0\n"
            )
            with patch.object(
                s1_dep_diff,
                "run_cmd",
                return_value=(report, "", 0),
            ):
                deps, _command = s1_dep_diff.collect_runtime_deps_for_workspace(
                    root,
                    primary_module=":app",
                    build_tool="gradle",
                )

        self.assertEqual(deps["com.acme:internal"]["version"], "2.1.0")
        self.assertEqual(
            deps["com.acme:internal"]["remark"],
            "source:gradle_dependencies(runtimeClasspath_project)",
        )
        self.assertEqual(deps["org.example:external"]["version"], "1.0")

    def test_gradle_internal_project_coordinate_resolves_packaged_nested_jar(self):
        runtime_deps = s1_dep_diff.parse_gradle_dependency_report(
            "+--- project :internal\n",
            project_modules=[{
                "gradle_path": ":internal",
                "group_id": "com.acme",
                "artifact_id": "internal-core",
                "version": "2.1.0",
            }],
        )
        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                [{
                    "entry_id": "internal-entry",
                    "lib_entry": "BOOT-INF/lib/internal-core-2.1.0.jar",
                    "lib_name": "internal-core-2.1.0.jar",
                    "artifact_id": "internal-core",
                    "version": "2.1.0",
                    "classifier": "",
                    "coord": "",
                    "match_source": "filename",
                    "filename_stem": "internal-core-2.1.0",
                }],
                runtime_deps,
            )
        )

        self.assertEqual(unresolved, [])
        self.assertIn("com.acme:internal-core", resolved)
        self.assertEqual(entries[0]["coord"], "com.acme:internal-core")
        self.assertEqual(entries[0]["resolution_status"], "resolved")

    def test_gradle_project_module_catalog_is_limited_to_target_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.gradle").write_text(
                "include ':app', ':internal', ':unused'\n",
                encoding="utf-8",
            )
            (root / "build.gradle").write_text(
                "allprojects {\n"
                "  group = 'com.acme'\n"
                "  version = '2.1.0'\n"
                "}\n",
                encoding="utf-8",
            )
            for module in ("app", "internal", "unused"):
                (root / module).mkdir()
                dependency = (
                    "dependencies {\n"
                    "  implementation project(':internal')\n"
                    "}\n"
                    if module == "app"
                    else ""
                )
                (root / module / "build.gradle").write_text(
                    "plugins { id 'java' }\n" + dependency,
                    encoding="utf-8",
                )

            catalog = s1_dep_diff.build_project_module_runtime_catalog(
                root,
                ":app",
                build_tool="gradle",
            )

        self.assertEqual(set(catalog), {"com.acme:internal"})
        self.assertEqual(catalog["com.acme:internal"]["version"], "2.1.0")
        self.assertEqual(
            catalog["com.acme:internal"]["project_module"],
            "internal",
        )

    def test_collect_gradle_deps_uses_wrapper_and_target_module_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            (work_dir / "settings.gradle").write_text("include ':app'\n", encoding="utf-8")
            (work_dir / "build.gradle").write_text("group = 'com.acme'\n", encoding="utf-8")
            (work_dir / "app").mkdir()
            (work_dir / "app/build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
            wrapper = work_dir / ("gradlew.bat" if os.name == "nt" else "gradlew")
            wrapper.write_text(
                "@echo off\r\n" if os.name == "nt" else "#!/bin/sh\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                wrapper.chmod(0o755)
            artifact_path = work_dir / "app/build/libs/app.jar"
            artifact_path.parent.mkdir(parents=True)
            artifact_path.write_text("placeholder", encoding="utf-8")
            commands = []
            call_options = []

            def fake_run(command, **kwargs):
                commands.append(command)
                call_options.append(kwargs)
                return "", "", 0

            packaged_raw = [{
                "entry_id": "1",
                "lib_entry": "BOOT-INF/lib/demo-1.0.jar",
                "lib_name": "demo-1.0.jar",
                "coord": "org.example:demo",
                "group_id": "org.example",
                "artifact_id": "demo",
                "version": "1.0",
                "classifier": "",
                "match_source": "pom.properties",
                "read_error": "",
            }]
            with patch.object(s1_dep_diff, "run_cmd", side_effect=fake_run), \
                    patch.object(
                        s1_dep_diff,
                        "build_project_scope",
                        wraps=s1_dep_diff.build_project_scope,
                    ) as scope_builder, \
                    patch.object(s1_dep_diff, "_discover_packaged_archives", return_value=[artifact_path]), \
                    patch.object(s1_dep_diff, "_detect_archive_packaging_type", return_value="boot_jar"), \
                    patch.object(s1_dep_diff, "_inspect_packaged_archive", return_value=packaged_raw):
                deps, meta = s1_dep_diff.collect_gradle_deps_for_workspace(
                    work_dir, primary_module=":app"
                )

        self.assertIn("org.example:demo", deps)
        self.assertEqual(Path(commands[0][0]), wrapper.resolve())
        self.assertIn(":app:build", commands[0])
        self.assertIsNone(call_options[0]["timeout"])
        self.assertEqual(meta["build_tool"], "gradle")
        self.assertTrue(meta["gradle_model_hash"])
        self.assertEqual(
            scope_builder.call_count,
            1,
            "successful Gradle builds must not be blocked by a post-build scope recheck",
        )

    def test_explicit_profile_is_used_even_when_target_module_is_unprofiled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.acme</groupId><artifactId>parent</artifactId>"
                "<version>1</version><packaging>pom</packaging>"
                "<modules><module>app</module></modules>"
                "<profiles><profile><id>prod</id></profile></profiles></project>",
                encoding="utf-8",
            )
            commands = []
            with patch.object(
                s1_dep_diff, "run_cmd",
                side_effect=lambda cmd, **_kwargs: (
                    commands.append(cmd) or "[INFO] com.acme:common:jar:1:runtime\n",
                    "", 0,
                ),
            ):
                s1_dep_diff.collect_runtime_deps_for_workspace(
                    root,
                    primary_module="app",
                    active_maven_profiles=["prod"],
                )

        self.assertIn("-Pprod", commands[0])

    def test_dependency_enrichment_activates_profile_that_owns_target_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.acme</groupId><artifactId>parent</artifactId>"
                "<version>1</version><packaging>pom</packaging>"
                "<profiles><profile><id>boot</id><modules>"
                "<module>app</module>"
                "</modules></profile></profiles>"
                "</project>",
                encoding="utf-8",
            )
            (root / "app").mkdir()
            (root / "app/pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<artifactId>app</artifactId></project>",
                encoding="utf-8",
            )
            commands = []

            def fake_run(cmd, **_kwargs):
                commands.append(cmd)
                return "[INFO] com.acme:common:jar:1:runtime\n", "", 0

            with patch.object(s1_dep_diff, "run_cmd", side_effect=fake_run):
                s1_dep_diff.collect_runtime_deps_for_workspace(
                    root, primary_module="app"
                )

        self.assertIn("-Pboot", commands[0])
        self.assertIn("-pl", commands[0])
        self.assertEqual(commands[0][commands[0].index("-pl") + 1], "app")

    def test_reactor_dependency_enrichment_packages_modules_before_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.acme</groupId><artifactId>parent</artifactId>"
                "<version>1</version><packaging>pom</packaging>"
                "<modules><module>common</module><module>app</module></modules>"
                "</project>",
                encoding="utf-8",
            )
            commands = []
            call_options = []

            def fake_run(cmd, **kwargs):
                commands.append(cmd)
                call_options.append(kwargs)
                return (
                    "[INFO] com.acme:common:jar:1:compile\n",
                    "",
                    0,
                )

            with patch.object(s1_dep_diff, "run_cmd", side_effect=fake_run):
                deps, _command = s1_dep_diff.collect_runtime_deps_for_workspace(root)

        self.assertIn("package", commands[0])
        self.assertLess(commands[0].index("package"), commands[0].index("dependency:list"))
        self.assertIsNone(call_options[0]["timeout"])
        self.assertIn("com.acme:common", deps)

    def test_reactor_module_catalog_closes_dependency_list_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.acme</groupId><artifactId>parent</artifactId>"
                "<version>${revision}</version><packaging>pom</packaging>"
                "<properties><revision>1.2.3</revision></properties>"
                "<modules><module>common</module><module>app</module>"
                "<module>unused</module></modules>"
                "</project>",
                encoding="utf-8",
            )
            for module in ("common", "app", "unused"):
                module_dir = root / module
                module_dir.mkdir()
                dependencies = (
                    "<dependencies><dependency>"
                    "<groupId>com.acme</groupId><artifactId>common</artifactId>"
                    "<version>${project.version}</version>"
                    "</dependency></dependencies>"
                    if module == "app"
                    else ""
                )
                (module_dir / "pom.xml").write_text(
                    "<project><modelVersion>4.0.0</modelVersion>"
                    "<parent><groupId>com.acme</groupId>"
                    "<artifactId>parent</artifactId>"
                    "<version>${revision}</version></parent>"
                    f"<artifactId>{module}</artifactId>{dependencies}"
                    "</project>",
                    encoding="utf-8",
                )
            internal_artifact = root / "common" / "target" / "custom-internal.jar"
            internal_artifact.parent.mkdir()
            internal_artifact.write_bytes(b"internal")

            with patch.object(
                s1_dep_diff,
                "run_cmd",
                return_value=(
                    "[INFO] org.example:external:jar:9.0:runtime:"
                    "/repo/external-9.0.jar\n",
                    "",
                    0,
                ),
            ):
                runtime_deps, _command = (
                    s1_dep_diff.collect_runtime_deps_for_workspace(
                        root,
                        primary_module="app",
                    )
                )

            entries, resolved, unresolved = (
                s1_dep_diff._enrich_packaged_deps_with_runtime(
                    [{
                        "entry_id": "BOOT-INF/lib/custom-internal.jar",
                        "lib_entry": "BOOT-INF/lib/custom-internal.jar",
                        "lib_name": "custom-internal.jar",
                        "artifact_id": "",
                        "version": "",
                        "classifier": "",
                        "coord": "",
                        "match_source": "filename",
                        "filename_stem": "custom-internal",
                    }],
                    runtime_deps,
                )
            )

        self.assertEqual(
            runtime_deps["com.acme:common"]["version"],
            "1.2.3",
        )
        self.assertNotIn("com.acme:unused", runtime_deps)
        self.assertEqual(
            runtime_deps["com.acme:common"]["artifact_file_name"],
            "custom-internal.jar",
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(
            unresolved[0]["reason_code"],
            "PACKAGED_VERSION_UNCONFIRMED",
        )
        self.assertEqual(entries[0]["coord"], "com.acme:common")
        self.assertEqual(entries[0]["resolution_status"], "unresolved")
        self.assertEqual(
            entries[0]["packaged_match_source"],
            "runtime-artifact-inventory",
        )

    def test_new_project_module_evidence_reopens_confirmed_filename_unresolved(self):
        runtime_deps = {
            "com.acme:common": {
                "key": "com.acme:common",
                "coord": "com.acme:common",
                "group_id": "com.acme",
                "artifact_id": "common",
                "version": "1.2.3",
                "classifier": "",
                "project_module": "common",
            }
        }
        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                [{
                    "entry_id": "BOOT-INF/lib/common-1.2.3.jar",
                    "lib_entry": "BOOT-INF/lib/common-1.2.3.jar",
                    "lib_name": "common-1.2.3.jar",
                    "artifact_id": "common",
                    "version": "1.2.3",
                    "classifier": "",
                    "coord": "",
                    "match_source": "filename",
                    "filename_stem": "common-1.2.3",
                }],
                runtime_deps,
                confirmed_unresolved_items=[{
                    "artifact_id": "common",
                    "version": "1.2.3",
                    "source": "filename",
                }],
            )
        )

        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"com.acme:common"})
        self.assertEqual(entries[0]["resolution_status"], "resolved")

    def test_packaged_archive_rejects_unsafe_entry_before_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "unsafe.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("../escaped.jar", self._nested_jar_bytes([]))

            result = s1_dep_diff._scan_packaged_archive(artifact)

        self.assertFalse(result.complete)
        self.assertTrue(any(
            failure.get("error") == "ARCHIVE_ENTRY_PATH_UNSAFE"
            for failure in result.failures
        ), result.failures)

    def test_packaged_archive_allows_highly_compressible_internal_dependency(self):
        nested_buffer = io.BytesIO()
        with zipfile.ZipFile(
            nested_buffer,
            "w",
            compression=zipfile.ZIP_STORED,
        ) as nested:
            nested.writestr(
                "META-INF/maven/org.example/demo/pom.properties",
                "groupId=org.example\nartifactId=demo\nversion=1.0\n",
            )
            nested.writestr("assets/generated.txt", b"0" * 1024 * 1024)

        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(
                artifact,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as outer:
                outer.writestr(
                    "BOOT-INF/lib/demo-1.0.jar",
                    nested_buffer.getvalue(),
                )
            with zipfile.ZipFile(artifact) as outer:
                info = outer.getinfo("BOOT-INF/lib/demo-1.0.jar")
                self.assertGreater(info.file_size / info.compress_size, 200)

            result = s1_dep_diff._scan_packaged_archive(artifact)

        self.assertTrue(result.complete, result.failures)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.rows[0]["coord"], "org.example:demo")

    def test_dependency_list_parser_preserves_custom_scope_and_classifier(self):
        parsed = s1_dep_diff._parse_maven_dependency_list_line(
            "[INFO] org.example:native-lib:jar:linux-x86_64:1.2.3:company-runtime"
        )

        self.assertEqual(parsed["key"], "org.example:native-lib:linux-x86_64")
        self.assertEqual(parsed["version"], "1.2.3")
        self.assertEqual(parsed["scope"], "company-runtime")
        self.assertEqual(parsed["classifier"], "linux-x86_64")
        optional = s1_dep_diff._parse_maven_dependency_list_line(
            "org.example:helper:jar:2.0:compile (optional)"
        )
        self.assertEqual(optional["scope"], "compile")

    def test_maven_dependency_list_preserves_physical_artifact_path(self):
        unix = s1_dep_diff._parse_maven_dependency_list_line(
            "[INFO] org.example:native-lib:jar:linux:1.2.3:runtime:"
            "/repo/org/example/native-lib/1.2.3/native-lib-1.2.3-linux.jar"
        )
        windows = s1_dep_diff._parse_maven_dependency_list_line(
            "[INFO] org.example:helper:jar:2.0:runtime:"
            r"C:\repo\org\example\helper\2.0\renamed-helper.jar"
        )

        self.assertEqual(
            unix["artifact_file_name"],
            "native-lib-1.2.3-linux.jar",
        )
        self.assertEqual(
            windows["artifact_file_name"],
            "renamed-helper.jar",
        )
        self.assertTrue(windows["artifact_file_path"].startswith("C:"))

    def test_maven_dependency_list_keeps_version_conflict_as_diagnostic_only(self):
        parsed = s1_dep_diff.parse_maven_dependency_list(
            "\n".join((
                "[INFO] org.example:demo:jar:1.0:runtime:"
                "/repo/org/example/demo/1.0/demo-1.0.jar",
                "[INFO] org.example:demo:jar:2.0:runtime:"
                "/repo/org/example/demo/2.0/demo-2.0.jar",
            ))
        )

        self.assertEqual(set(parsed), {"org.example:demo"})
        self.assertEqual(
            parsed["org.example:demo"]["observed_versions"],
            ["1.0", "2.0"],
        )
        self.assertTrue(
            parsed["org.example:demo"]["runtime_version_conflict"]
        )

    def test_merge_runtime_artifact_record_ignores_blank_identity(self):
        deps = {"org.example:kept": {"version": "1.0"}}

        for item in ({}, {"key": ""}, {"key": "   ", "version": "2.0"}):
            with self.subTest(item=item):
                s1_dep_diff._merge_runtime_artifact_record(deps, item)

        self.assertEqual(deps, {"org.example:kept": {"version": "1.0"}})

    def test_merge_runtime_artifact_record_initializes_without_mutating_input(self):
        item = {
            "key": "org.example:demo",
            "version": "1.0",
            "artifact_file_name": "demo-1.0.jar",
            "artifact_file_path": "/repo/demo-1.0.jar",
        }
        original = dict(item)
        deps = {}

        s1_dep_diff._merge_runtime_artifact_record(deps, item)

        self.assertEqual(item, original)
        self.assertEqual(
            deps["org.example:demo"]["observed_versions"],
            ["1.0"],
        )
        self.assertFalse(
            deps["org.example:demo"]["runtime_version_conflict"]
        )
        self.assertEqual(
            deps["org.example:demo"]["artifact_file_names"],
            ["demo-1.0.jar"],
        )
        self.assertEqual(
            deps["org.example:demo"]["artifact_file_paths"],
            ["/repo/demo-1.0.jar"],
        )

    def test_merge_runtime_artifact_record_preserves_and_deduplicates_evidence(self):
        deps = {
            "org.example:demo": {
                "key": "org.example:demo",
                "version": "1.0",
                "observed_versions": ["1.0", " 1.0 ", ""],
                "artifact_file_name": "demo-1.0.jar",
                "artifact_file_path": "/repo/demo-1.0.jar",
            }
        }
        incoming = {
            "key": "org.example:demo",
            "version": "2.0",
            "observed_versions": ["2.0", "3.0", "  "],
            "artifact_file_name": "demo-2.0.jar",
            "artifact_file_names": ["demo-2.0.jar", "demo-3.0.jar"],
            "artifact_file_path": "/repo/demo-2.0.jar",
            "artifact_file_paths": ["/repo/demo-2.0.jar", "/repo/demo-3.0.jar"],
        }
        original = {
            key: list(value) if isinstance(value, list) else value
            for key, value in incoming.items()
        }

        s1_dep_diff._merge_runtime_artifact_record(deps, incoming)
        s1_dep_diff._merge_runtime_artifact_record(deps, incoming)

        merged = deps["org.example:demo"]
        self.assertEqual(incoming, original)
        self.assertEqual(merged["version"], "1.0")
        self.assertEqual(merged["observed_versions"], ["1.0", "2.0", "3.0"])
        self.assertTrue(merged["runtime_version_conflict"])
        self.assertEqual(
            merged["artifact_file_names"],
            ["demo-1.0.jar", "demo-2.0.jar", "demo-3.0.jar"],
        )
        self.assertEqual(
            merged["artifact_file_paths"],
            [
                "/repo/demo-1.0.jar",
                "/repo/demo-2.0.jar",
                "/repo/demo-3.0.jar",
            ],
        )

    def test_dependency_list_parser_ignores_absolute_artifact_filename(self):
        samples = (
            "[INFO] org.ow2.asm:asm-util:jar:7.1:runtime:"
            "/Users/me/.m2/repository/org/ow2/asm/asm-util/7.1/asm-util-7.1.jar",
            "[INFO] org.ow2.asm:asm-util:jar:7.1:runtime:"
            r"C:\Users\me\.m2\repository\org\ow2\asm\asm-util\7.1\asm-util-7.1.jar",
        )

        for line in samples:
            with self.subTest(line=line):
                parsed = s1_dep_diff._parse_maven_dependency_list_line(line)
                self.assertEqual(parsed["key"], "org.ow2.asm:asm-util")
                self.assertEqual(parsed["version"], "7.1")
                self.assertEqual(parsed["scope"], "runtime")
                self.assertEqual(parsed["classifier"], "")

    def test_dependency_list_parser_rejects_log_prose_with_colons(self):
        self.assertIsNone(
            s1_dep_diff._parse_maven_dependency_list_line(
                "[WARNING] Failed to resolve: artifact: because: repository unavailable"
            )
        )

    def _nested_jar_bytes(self, entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as nested:
            for name, content in entries:
                nested.writestr(name, content)
        return buffer.getvalue()

    def test_duplicate_embedded_maven_metadata_with_same_gav_is_collapsed(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            nested_bytes = self._nested_jar_bytes([
                (
                    "META-INF/maven/org.example/demo/pom.properties",
                    "# first\ngroupId=org.example\nartifactId=demo\nversion=1.0\n",
                ),
                (
                    "META-INF/maven/org.example/demo/pom.properties",
                    "# repackaged\ngroupId=org.example\nartifactId=demo\nversion=1.0\n",
                ),
            ])
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/lib/demo-1.0.jar", nested_bytes)

            rows = s1_dep_diff._inspect_packaged_archive(artifact)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["coord"], "org.example:demo")
        self.assertEqual(rows[0]["version"], "1.0")
        self.assertEqual(rows[0]["metadata_anomalies"], [])

    def test_step1_persists_changed_jars_for_step4(self):
        nested_bytes = self._nested_jar_bytes([
            (
                "META-INF/maven/org.example/demo/pom.properties",
                "groupId=org.example\nartifactId=demo\nversion=1.0\n",
            ),
            ("org/example/Demo.class", b"class"),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_artifact = root / "base.jar"
            current_artifact = root / "current.jar"
            base_entry = "BOOT-INF/lib/demo-1.0.jar"
            current_entry = "BOOT-INF/lib/demo-2.0.jar"
            for artifact, entry in (
                (base_artifact, base_entry),
                (current_artifact, current_entry),
            ):
                with zipfile.ZipFile(artifact, "w") as outer:
                    outer.writestr(entry, nested_bytes)
            output_dir = root / "dependencies"
            manifest_path, items = s1_dep_diff.materialize_changed_dependency_jars(
                [{
                    "coord": "org.example:demo",
                    "base_coord": "org.example:demo",
                    "current_coord": "org.example:demo",
                    "old_version": "1.0",
                    "new_version": "2.0",
                    "change_type": "大版本升级",
                    "resolution_status": "resolved",
                    "base_lib_entry": base_entry,
                    "current_lib_entry": current_entry,
                    "base_packaged_match_source": "embedded-pom",
                    "current_packaged_match_source": "embedded-pom",
                }],
                {
                    "base": {
                        "artifact_path": str(base_artifact),
                        "artifact_sha256": hashlib.sha256(
                            base_artifact.read_bytes()
                        ).hexdigest(),
                    },
                    "current": {
                        "artifact_path": str(current_artifact),
                        "artifact_sha256": hashlib.sha256(
                            current_artifact.read_bytes()
                        ).hexdigest(),
                    },
                },
                output_dir,
            )

            payload = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest_path.name, STEP1_DEPENDENCY_JARS_MANIFEST_FILE)
        self.assertEqual(len(items), 2)
        self.assertEqual(len(payload["items"]), 2)
        self.assertTrue(all(item.get("nested_jar_sha256") for item in items))

    def test_conflicting_duplicate_maven_metadata_is_reconciled_by_filename(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            nested_bytes = self._nested_jar_bytes([
                (
                    "META-INF/maven/org.example/demo/pom.properties",
                    "groupId=org.example\nartifactId=demo\nversion=1.0\n",
                ),
                (
                    "META-INF/maven/org.example/demo/pom.properties",
                    "groupId=org.example\nartifactId=demo\nversion=2.0\n",
                ),
            ])

        row = s1_dep_diff._extract_packaged_dep_from_nested_jar(
            nested_bytes, "BOOT-INF/lib/demo-2.0.jar"
        )

        self.assertEqual(row["coord"], "org.example:demo")
        self.assertEqual(row["version"], "2.0")
        self.assertEqual(row["match_source"], "embedded-pom-filename-match")
        self.assertTrue(any(
            item.startswith("maven_metadata_coordinate_conflict:")
            for item in row["metadata_anomalies"]
        ), row["metadata_anomalies"])
        entries, _resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [row], {}
        )
        self.assertEqual(unresolved, [])
        self.assertIn("metadata_anomalies=", entries[0]["remark"])

    def test_identical_duplicate_maven_metadata_resolves_one_gav(self):
        properties = (
            "groupId=com.webank.ims.jmx\n"
            "artifactId=jmxmon\n"
            "version=0.0.1-SNAPSHOT\n"
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            nested_bytes = self._nested_jar_bytes([
                (
                    "META-INF/maven/com.webank.ims.jmx/jmxmon/pom.properties",
                    properties,
                ),
                (
                    "META-INF/maven/com.webank.ims.jmx/jmxmon/pom.properties",
                    properties,
                ),
                (
                    "META-INF/maven/com.webank.ims.jmx/jmxmon/pom.xml",
                    "<project/>",
                ),
                (
                    "META-INF/maven/com.webank.ims.jmx/jmxmon/pom.xml",
                    "<project/>",
                ),
            ])

        row = s1_dep_diff._extract_packaged_dep_from_nested_jar(
            nested_bytes,
            "BOOT-INF/lib/jmxmon-0.0.1-SNAPSHOT.jar",
        )
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [row], {},
        )

        self.assertEqual(row["coord"], "com.webank.ims.jmx:jmxmon")
        self.assertEqual(row["version"], "0.0.1-SNAPSHOT")
        self.assertEqual(row["metadata_anomalies"], [])
        self.assertEqual(len(entries), 1)
        self.assertEqual(list(resolved), ["com.webank.ims.jmx:jmxmon"])
        self.assertEqual(unresolved, [])

    def test_step1_does_not_read_unrelated_nested_class_payloads(self):
        class_payload = b"step1-must-not-read-this-class"
        nested = bytearray(self._nested_jar_bytes([
            (
                "META-INF/maven/org.example/demo/pom.properties",
                "groupId=org.example\nartifactId=demo\nversion=1.0\n",
            ),
            ("org/example/Broken.class", class_payload),
        ]))
        nested[nested.index(class_payload)] ^= 0x01
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/lib/demo-1.0.jar", bytes(nested))

            rows = s1_dep_diff._inspect_packaged_archive(artifact)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["coord"], "org.example:demo")

    def test_step1_dependency_inventory_has_no_nested_entry_count_gate(self):
        nested_buffer = io.BytesIO()
        with zipfile.ZipFile(nested_buffer, "w", compression=zipfile.ZIP_STORED) as nested:
            nested.writestr(
                "META-INF/maven/org.example/demo/pom.properties",
                "groupId=org.example\nartifactId=demo\nversion=1.0\n",
            )
            for index in range(100_001):
                nested.writestr(f"org/example/generated/C{index}.class", b"")
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_STORED) as outer:
                outer.writestr("BOOT-INF/lib/demo-1.0.jar", nested_buffer.getvalue())

            rows = s1_dep_diff._inspect_packaged_archive(artifact)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["coord"], "org.example:demo")

    def test_step1_rejects_duplicate_outer_dependency_paths(self):
        nested = self._nested_jar_bytes([])
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(artifact, "w") as outer:
                    outer.writestr("BOOT-INF/lib/demo-1.0.jar", nested)
                    outer.writestr("BOOT-INF/lib/demo-1.0.jar", nested)

            result = s1_dep_diff._scan_packaged_archive(artifact)

        self.assertFalse(result.complete)
        self.assertTrue(any(
            item.get("error") == "ARCHIVE_DUPLICATE_DEPENDENCY_ENTRY"
            for item in result.failures
        ), result.failures)

    def test_step1_allows_duplicate_outer_maven_metadata(self):
        nested = self._nested_jar_bytes([(
            "META-INF/maven/org.example/demo/pom.properties",
            "groupId=org.example\nartifactId=demo\nversion=1.0\n",
        )])
        metadata_entry = (
            "META-INF/maven/org.example/app/pom.properties"
        )
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(artifact, "w") as outer:
                    outer.writestr(
                        metadata_entry,
                        "groupId=org.example\nartifactId=app\nversion=1.0\n",
                    )
                    outer.writestr(
                        metadata_entry,
                        "groupId=org.example\nartifactId=app\nversion=1.0\n",
                    )
                    outer.writestr("BOOT-INF/lib/demo-1.0.jar", nested)

            result = s1_dep_diff._scan_packaged_archive(artifact)

        self.assertTrue(result.complete, result.failures)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.rows[0]["coord"], "org.example:demo")

    def test_retain_artifact_for_analysis_preserves_exact_bytes_and_updates_meta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = root / "worktree"
            artifact = worktree / "app/build/app.jar"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"exact-artifact")
            meta = {
                "artifact_path": str(artifact),
                "archives": [str(artifact)],
                "worktree_dir": str(worktree),
            }

            s1_dep_diff.retain_artifact_for_analysis(meta, root / "report" / STEP1_ARTIFACTS_DIRNAME, "current")

            retained = Path(meta["artifact_path"])
            self.assertEqual(retained.read_bytes(), b"exact-artifact")
            self.assertEqual(meta["original_artifact_path"], str(artifact))
            self.assertEqual(meta["artifact_relative_path"], "app/build/app.jar")
            self.assertTrue(meta["artifact_retained"])
            self.assertEqual(meta["archives"], [str(retained)])

    def test_collect_packaged_deps_ignores_spring_boot_jarmode_helper_jar(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "app.jar"
            demo_nested = self._nested_jar_bytes(
                [
                    (
                        "META-INF/maven/org.example/demo-lib/pom.properties",
                        "groupId=org.example\nartifactId=demo-lib\nversion=1.2.3\n",
                    )
                ]
            )
            layertools_nested = self._nested_jar_bytes(
                [
                    ("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
                ]
            )
            with zipfile.ZipFile(artifact_path, "w") as outer:
                outer.writestr("BOOT-INF/lib/demo-lib-1.2.3.jar", demo_nested)
                outer.writestr(
                    "BOOT-INF/lib/spring-boot-jarmode-layertools-3.0.0.jar",
                    layertools_nested,
                )

            packaged_deps, meta = s1_dep_diff.collect_packaged_deps_from_artifact_path(
                str(artifact_path),
                runtime_deps={},
            )

        self.assertIn("org.example:demo-lib", packaged_deps)
        self.assertEqual(meta.get("unresolved_items"), [])
        self.assertEqual(
            [item.get("coord") for item in meta.get("dep_entries") or []],
            ["org.example:demo-lib"],
        )

    def test_packaged_archive_streams_nested_jars_without_outer_read_buffer(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "app.jar"
            nested_bytes = self._nested_jar_bytes([
                (
                    "META-INF/maven/org.example/demo-lib/pom.properties",
                    "groupId=org.example\nartifactId=demo-lib\nversion=1.2.3\n",
                ),
                ("payload.bin", b"x" * 4096),
            ])
            with zipfile.ZipFile(artifact_path, "w") as outer:
                outer.writestr("BOOT-INF/lib/demo-lib-1.2.3.jar", nested_bytes)

            original_read = zipfile.ZipFile.read

            def reject_outer_nested_jar_read(zf, name, *args, **kwargs):
                if str(name).startswith("BOOT-INF/lib/"):
                    raise AssertionError("nested jar must be streamed from the outer archive")
                return original_read(zf, name, *args, **kwargs)

            with patch.object(zipfile.ZipFile, "read", new=reject_outer_nested_jar_read):
                rows = s1_dep_diff._inspect_packaged_archive(artifact_path)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["coord"], "org.example:demo-lib")
        self.assertEqual(rows[0]["version"], "1.2.3")
        self.assertEqual(
            rows[0]["content_sha256"],
            s1_dep_diff.hashlib.sha256(nested_bytes).hexdigest(),
        )

    def test_packaged_archive_inventory_cache_reuses_only_valid_content_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_path = root / "app.jar"
            cache_dir = root / "cache"
            nested_bytes = self._nested_jar_bytes([
                (
                    "META-INF/maven/org.example/demo-lib/pom.properties",
                    "groupId=org.example\nartifactId=demo-lib\nversion=1.2.3\n",
                )
            ])
            with zipfile.ZipFile(artifact_path, "w") as outer:
                outer.writestr("BOOT-INF/lib/demo-lib-1.2.3.jar", nested_bytes)

            with patch.object(
                s1_dep_diff,
                "_stream_nested_jar_to_spool",
                wraps=s1_dep_diff._stream_nested_jar_to_spool,
            ) as stream:
                fresh = s1_dep_diff._inspect_packaged_archive(
                    artifact_path, cache_dir=cache_dir
                )
                cached = s1_dep_diff._inspect_packaged_archive(
                    artifact_path, cache_dir=cache_dir
                )

                cache_file = next(cache_dir.glob("*.json"))
                cache_file.write_text("{broken", encoding="utf-8")
                recovered = s1_dep_diff._inspect_packaged_archive(
                    artifact_path, cache_dir=cache_dir
                )

        self.assertEqual(cached, fresh)
        self.assertEqual(recovered, fresh)
        self.assertEqual(stream.call_count, 2)

    def test_packaged_archive_inventory_cache_invalidates_when_artifact_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_path = root / "app.jar"
            cache_dir = root / "cache"

            def write_artifact(version):
                nested = self._nested_jar_bytes([
                    (
                        "META-INF/maven/org.example/demo-lib/pom.properties",
                        f"groupId=org.example\nartifactId=demo-lib\nversion={version}\n",
                    )
                ])
                with zipfile.ZipFile(artifact_path, "w") as outer:
                    outer.writestr(f"BOOT-INF/lib/demo-lib-{version}.jar", nested)

            write_artifact("1.0.0")
            first = s1_dep_diff._inspect_packaged_archive(
                artifact_path, cache_dir=cache_dir
            )
            write_artifact("2.0.0")
            second = s1_dep_diff._inspect_packaged_archive(
                artifact_path, cache_dir=cache_dir
            )
            cache_file_count = len(list(cache_dir.glob("*.json")))

        self.assertEqual(first[0]["version"], "1.0.0")
        self.assertEqual(second[0]["version"], "2.0.0")
        self.assertEqual(cache_file_count, 2)

    def test_packaged_archive_inventory_rejects_artifact_changed_during_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_path = root / "app.jar"
            cache_dir = root / "cache"
            nested = self._nested_jar_bytes([(
                "META-INF/maven/org.example/demo/pom.properties",
                "groupId=org.example\nartifactId=demo\nversion=1.0\n",
            )])
            with zipfile.ZipFile(artifact_path, "w") as archive:
                archive.writestr("BOOT-INF/lib/demo-1.0.jar", nested)
            original_scan = s1_dep_diff._scan_packaged_archive

            def mutating_scan(path):
                result = original_scan(path)
                with zipfile.ZipFile(path, "a") as archive:
                    archive.writestr("mutation-marker", b"changed")
                return result

            with patch.object(
                s1_dep_diff, "_scan_packaged_archive", side_effect=mutating_scan
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "changed during packaged archive scan"
                ):
                    s1_dep_diff._inspect_packaged_archive(
                        artifact_path, cache_dir=cache_dir, cache_stats={}
                    )

            cache_files = list(cache_dir.glob("*.json"))

        self.assertEqual(cache_files, [])

    def test_packaged_archive_inventory_without_cache_rejects_artifact_changed_during_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "app.jar"
            nested = self._nested_jar_bytes([(
                "META-INF/maven/org.example/demo/pom.properties",
                "groupId=org.example\nartifactId=demo\nversion=1.0\n",
            )])
            with zipfile.ZipFile(artifact_path, "w") as archive:
                archive.writestr("BOOT-INF/lib/demo-1.0.jar", nested)
            original_scan = s1_dep_diff._scan_packaged_archive

            def mutating_scan(path):
                result = original_scan(path)
                with zipfile.ZipFile(path, "a") as archive:
                    archive.writestr("mutation-marker", b"changed")
                return result

            with patch.object(
                s1_dep_diff, "_scan_packaged_archive", side_effect=mutating_scan
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "changed during packaged archive scan"
                ):
                    s1_dep_diff._inspect_packaged_archive(
                        artifact_path, cache_dir=None, cache_stats={}
                    )

    def test_packaged_archive_inventory_rejects_artifact_changed_during_cache_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_path = root / "app.jar"
            cache_dir = root / "cache"
            nested = self._nested_jar_bytes([(
                "META-INF/maven/org.example/demo/pom.properties",
                "groupId=org.example\nartifactId=demo\nversion=1.0\n",
            )])
            with zipfile.ZipFile(artifact_path, "w") as archive:
                archive.writestr("BOOT-INF/lib/demo-1.0.jar", nested)
            s1_dep_diff._inspect_packaged_archive(
                artifact_path, cache_dir=cache_dir
            )
            original_load = s1_dep_diff._load_packaged_inventory_cache

            def mutating_load(path, identity):
                cached = original_load(path, identity)
                with zipfile.ZipFile(artifact_path, "a") as archive:
                    archive.writestr("cache-load-mutation", b"changed")
                return cached

            with patch.object(
                s1_dep_diff, "_load_packaged_inventory_cache",
                side_effect=mutating_load,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "changed during packaged archive cache load"
                ):
                    s1_dep_diff._inspect_packaged_archive(
                        artifact_path, cache_dir=cache_dir
                    )

    def test_scan_distinguishes_successful_empty_archive_from_open_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty_artifact = root / "empty.jar"
            with zipfile.ZipFile(empty_artifact, "w") as outer:
                outer.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

            successful = s1_dep_diff._scan_packaged_archive(empty_artifact)
            with patch.object(
                s1_dep_diff.zipfile,
                "ZipFile",
                side_effect=OSError("archive open failed"),
            ):
                failed = s1_dep_diff._scan_packaged_archive(empty_artifact)

        self.assertTrue(successful.complete)
        self.assertEqual(successful.rows, [])
        self.assertEqual(successful.failures, [])
        self.assertFalse(failed.complete)
        self.assertEqual(failed.rows, [])
        self.assertEqual(failed.failures[0]["stage"], "archive_open")
        self.assertIn("archive open failed", failed.failures[0]["error"])

    def test_post_hash_archive_open_failure_is_not_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_path = root / "app.jar"
            cache_dir = root / "cache"
            with zipfile.ZipFile(artifact_path, "w") as outer:
                outer.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

            cache_stats = {}
            with patch.object(
                s1_dep_diff.zipfile,
                "ZipFile",
                side_effect=OSError("post-hash archive open failed"),
            ):
                rows = s1_dep_diff._inspect_packaged_archive(
                    artifact_path,
                    cache_dir=cache_dir,
                    cache_stats=cache_stats,
                )
            cache_files = list(cache_dir.glob("*.json"))

        self.assertIsInstance(rows, list)
        self.assertEqual(rows, [])
        self.assertFalse(cache_stats["scan_complete"])
        self.assertEqual(cache_stats["failures"][0]["stage"], "archive_open")
        self.assertEqual(cache_files, [])

    def test_artifact_collection_rejects_incomplete_packaged_archive_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "app.jar"
            artifact_path.write_bytes(b"placeholder")

            def incomplete_scan(_path, cache_dir=None, cache_stats=None):
                cache_stats.update({
                    "scan_complete": False,
                    "failures": [{
                        "stage": "archive_open",
                        "entry": "",
                        "error": "OSError:transient read failure",
                    }],
                    "archive_bytes": len(b"placeholder"),
                    "nested_entries": 0,
                    "misses": 1,
                })
                return []

            with patch.object(
                s1_dep_diff, "_detect_archive_packaging_type", return_value="boot_jar"
            ), patch.object(
                s1_dep_diff, "_inspect_packaged_archive", side_effect=incomplete_scan
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "最终制品扫描不完整.*transient read failure"
                ):
                    s1_dep_diff.collect_packaged_deps_from_artifact_path(
                        artifact_path,
                    )

    def test_embedded_metadata_read_failure_is_visible_and_not_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_path = root / "app.jar"
            cache_dir = root / "cache"
            nested_bytes = self._nested_jar_bytes([
                (
                    "META-INF/maven/org.example/demo-lib/pom.properties",
                    "groupId=org.example\nartifactId=demo-lib\nversion=1.2.3\n",
                )
            ])
            with zipfile.ZipFile(artifact_path, "w") as outer:
                outer.writestr("BOOT-INF/lib/demo-lib-1.2.3.jar", nested_bytes)

            original_read = zipfile.ZipFile.read

            def fail_embedded_metadata_read(zf, name, *args, **kwargs):
                logical_name = getattr(name, "filename", str(name))
                if logical_name.endswith("/pom.properties"):
                    raise OSError("metadata read failed")
                return original_read(zf, name, *args, **kwargs)

            cache_stats = {}
            with patch.object(zipfile.ZipFile, "read", new=fail_embedded_metadata_read):
                failed_rows = s1_dep_diff._inspect_packaged_archive(
                    artifact_path,
                    cache_dir=cache_dir,
                    cache_stats=cache_stats,
                )
            failed_cache_file_count = len(list(cache_dir.glob("*.json")))

            recovered_rows = s1_dep_diff._inspect_packaged_archive(
                artifact_path,
                cache_dir=cache_dir,
            )
            cache_file_count = len(list(cache_dir.glob("*.json")))

        self.assertEqual(len(failed_rows), 1)
        self.assertEqual(failed_rows[0]["match_source"], "embedded-metadata-read-error")
        self.assertEqual(failed_rows[0]["artifact_id"], "")
        self.assertEqual(failed_rows[0]["version"], "")
        self.assertIn("metadata_read_error", failed_rows[0]["read_error"])
        self.assertFalse(cache_stats["scan_complete"])
        self.assertEqual(len(cache_stats["failures"]), 1)
        self.assertEqual(failed_cache_file_count, 0)
        self.assertEqual(recovered_rows[0]["match_source"], "embedded-pom")
        self.assertEqual(cache_file_count, 1)

    def test_filename_fallback_is_retained_when_metadata_is_absent_without_read_failure(self):
        nested_bytes = self._nested_jar_bytes([
            ("com/example/Demo.class", b"class-bytes"),
        ])

        row = s1_dep_diff._extract_packaged_dep_from_nested_jar(
            nested_bytes,
            "BOOT-INF/lib/demo-lib-1.2.3.jar",
        )

        self.assertEqual(row["match_source"], "filename")
        self.assertEqual(row["artifact_id"], "demo-lib")
        self.assertEqual(row["version"], "1.2.3")
        self.assertEqual(row["read_error"], "")

    def test_embedded_pom_selection_matches_outer_jar_filename(self):
        nested_bytes = self._nested_jar_bytes([
            (
                "META-INF/maven/org.glassfish.jaxb/jaxb-runtime/pom.properties",
                "groupId=org.glassfish.jaxb\n"
                "artifactId=jaxb-runtime\nversion=4.0.6\n",
            ),
            (
                "META-INF/maven/com.sun.xml.bind/jaxb-impl/pom.properties",
                "groupId=com.sun.xml.bind\n"
                "artifactId=jaxb-impl\nversion=4.0.6\n",
            ),
        ])

        row = s1_dep_diff._extract_packaged_dep_from_nested_jar(
            nested_bytes,
            "BOOT-INF/lib/jaxb-impl-4.0.6.jar",
        )

        self.assertEqual(row["coord"], "com.sun.xml.bind:jaxb-impl")
        self.assertEqual(row["artifact_id"], "jaxb-impl")
        self.assertEqual(row["version"], "4.0.6")
        self.assertEqual(row["match_source"], "embedded-pom-filename-match")

    def test_embedded_pom_selection_defers_unmatched_identity_to_runtime_metadata(self):
        nested_bytes = self._nested_jar_bytes([
            (
                "META-INF/maven/org.example/first/pom.properties",
                "groupId=org.example\nartifactId=first\nversion=1.0.0\n",
            ),
            (
                "META-INF/maven/org.example/second/pom.properties",
                "groupId=org.example\nartifactId=second\nversion=1.0.0\n",
            ),
        ])

        row = s1_dep_diff._extract_packaged_dep_from_nested_jar(
            nested_bytes,
            "BOOT-INF/lib/unrelated-name-1.0.0.jar",
        )

        self.assertEqual(row["coord"], "")
        self.assertEqual(row["artifact_id"], "unrelated-name")
        self.assertEqual(row["match_source"], "filename")
        self.assertEqual(row["read_error"], "")

        _, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [row],
            {
                "org.example:first": {
                    "group_id": "org.example", "artifact_id": "first", "version": "1.0.0",
                },
                "org.example:second": {
                    "group_id": "org.example", "artifact_id": "second", "version": "1.0.0",
                },
            },
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0]["artifact_id"], "unrelated-name")

    def test_packaged_archive_reports_archive_bytes_and_nested_entry_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_path = root / "app.jar"
            nested_bytes = self._nested_jar_bytes([
                ("com/example/Demo.class", b"class-bytes"),
            ])
            with zipfile.ZipFile(artifact_path, "w") as outer:
                outer.writestr("BOOT-INF/lib/demo-lib-1.2.3.jar", nested_bytes)
                outer.writestr("BOOT-INF/lib/other-lib-2.0.0.jar", nested_bytes)

            cache_stats = {}
            s1_dep_diff._inspect_packaged_archive(
                artifact_path,
                cache_stats=cache_stats,
            )
            archive_size = artifact_path.stat().st_size

        self.assertEqual(cache_stats["archive_bytes"], archive_size)
        self.assertEqual(cache_stats["nested_entries"], 2)
        self.assertTrue(cache_stats["scan_complete"])

    def test_embedded_pom_preserves_filename_classifier_as_artifact_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "app.jar"
            plain = self._nested_jar_bytes(
                [("META-INF/maven/org.apache.shiro/shiro-core/pom.properties",
                  "groupId=org.apache.shiro\nartifactId=shiro-core\nversion=2.2.0\n")]
            )
            jakarta = self._nested_jar_bytes(
                [("META-INF/maven/org.apache.shiro/shiro-core/pom.properties",
                  "groupId=org.apache.shiro\nartifactId=shiro-core\nversion=2.2.0\n")]
            )
            with zipfile.ZipFile(artifact_path, "w") as outer:
                outer.writestr("BOOT-INF/lib/shiro-core-2.2.0.jar", plain)
                outer.writestr("BOOT-INF/lib/shiro-core-2.2.0-jakarta.jar", jakarta)

            packaged_deps, meta = s1_dep_diff.collect_packaged_deps_from_artifact_path(
                str(artifact_path), runtime_deps={}
            )

        self.assertEqual(
            set(packaged_deps),
            {"org.apache.shiro:shiro-core", "org.apache.shiro:shiro-core:jakarta"},
        )
        self.assertEqual(
            {item.get("coord") for item in meta.get("dep_entries") or []},
            {"org.apache.shiro:shiro-core", "org.apache.shiro:shiro-core:jakarta"},
        )

    def test_filename_only_classifier_does_not_take_version_from_runtime(self):
        nested = self._nested_jar_bytes([
            ("jnr/ffi/Provider.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                f"BOOT-INF/lib/{name}",
            )
            for name in (
                "jffi-1.2.23.jar",
                "jffi-1.2.23-native.jar",
            )
        ]
        runtime = {
            "com.github.jnr:jffi": {
                "group_id": "com.github.jnr",
                "artifact_id": "jffi",
                "version": "1.2.23",
                "classifier": "",
            },
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
            )
        )

        self.assertEqual(set(resolved), {"com.github.jnr:jffi"})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(
            unresolved[0]["reason_code"],
            "PACKAGED_VERSION_UNCONFIRMED",
        )
        native = next(
            item for item in entries
            if item["lib_entry"].endswith("jffi-1.2.23-native.jar")
        )
        self.assertEqual(native["version"], "1.2.23-native")
        self.assertEqual(native["classifier"], "native")
        self.assertEqual(native["resolution_status"], "unresolved")
        self.assertEqual(
            native["packaged_match_source"],
            "runtime-filename-classifier",
        )

    def test_artifact_inventory_does_not_correct_misleading_packaged_version(self):
        nested = self._nested_jar_bytes([
            ("example/Real.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/renamed-9.jar",
            )
        ]
        runtime = s1_dep_diff.parse_maven_dependency_list(
            "[INFO] org.example:real-library:jar:1.4.0:runtime:"
            "/repo/org/example/real-library/1.4.0/renamed-9.jar"
        )

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(
            unresolved[0]["reason_code"],
            "PACKAGED_VERSION_UNCONFIRMED",
        )
        self.assertEqual(entries[0]["version"], "9")
        self.assertEqual(entries[0]["resolution_status"], "unresolved")
        self.assertEqual(
            entries[0]["packaged_match_source"],
            "runtime-artifact-inventory",
        )

    def test_runtime_inventory_cannot_fill_version_absent_from_fat_jar(self):
        nested = self._nested_jar_bytes([("example/Real.class", b"class")])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/renamed.jar",
            )
        ]
        runtime = s1_dep_diff.parse_maven_dependency_list(
            "[INFO] org.example:real-library:jar:1.4.0:runtime:"
            "/repo/org/example/real-library/1.4.0/renamed.jar"
        )

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
                side="current",
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(
            unresolved[0]["reason_code"],
            "PACKAGED_VERSION_UNCONFIRMED",
        )
        self.assertEqual(entries[0]["version"], "")
        self.assertEqual(entries[0]["resolution_status"], "unresolved")

    def test_runtime_version_conflict_does_not_override_fat_jar_version(self):
        nested = self._nested_jar_bytes([("example/Demo.class", b"class")])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/demo-2.0.jar",
            )
        ]
        runtime = s1_dep_diff.parse_maven_dependency_list(
            "\n".join((
                "[INFO] org.example:demo:jar:1.0:runtime:"
                "/repo/org/example/demo/1.0/demo-1.0.jar",
                "[INFO] org.example:demo:jar:2.0:runtime:"
                "/repo/org/example/demo/2.0/demo-2.0.jar",
            ))
        )

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
            )
        )

        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"org.example:demo"})
        self.assertEqual(entries[0]["version"], "2.0")
        self.assertEqual(entries[0]["resolution_status"], "resolved")

    def test_manual_artifact_identity_confirms_version_by_physical_entry(self):
        nested = self._nested_jar_bytes([("example/Demo.class", b"class")])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/renamed.jar",
            )
        ]

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                {},
                manual_artifact_identities=[{
                    "side": "current",
                    "lib_entry": "BOOT-INF/lib/renamed.jar",
                    "group_id": "org.example",
                    "artifact_id": "demo",
                    "version": "2.0",
                    "classifier": "",
                }],
                side="current",
            )
        )

        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"org.example:demo"})
        self.assertEqual(entries[0]["version"], "2.0")
        self.assertEqual(
            entries[0]["packaged_match_source"],
            "manual_artifact_identity",
        )

    def test_manual_artifact_identity_skips_runtime_coordinate_loader(self):
        nested = self._nested_jar_bytes([("example/Demo.class", b"class")])
        runtime_loader = Mock(side_effect=AssertionError("must not run"))
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact_path, "w") as outer:
                outer.writestr("BOOT-INF/lib/renamed.jar", nested)

            packaged, meta = s1_dep_diff.collect_packaged_deps_from_artifact_path(
                artifact_path,
                runtime_deps_loader=runtime_loader,
                manual_artifact_identities=[{
                    "side": "current",
                    "lib_entry": "BOOT-INF/lib/renamed.jar",
                    "group_id": "org.example",
                    "artifact_id": "demo",
                    "version": "2.0",
                    "classifier": "",
                }],
                side="current",
            )

        runtime_loader.assert_not_called()
        self.assertEqual(set(packaged), {"org.example:demo"})
        self.assertEqual(meta["unresolved_items"], [])

    def test_artifact_inventory_precedes_plausible_filename_identity(self):
        nested = self._nested_jar_bytes([
            ("example/Real.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/renamed-9.jar",
            )
        ]
        runtime = {
            "org.example:real-library": {
                "group_id": "org.example",
                "artifact_id": "real-library",
                "version": "1.4.0",
                "classifier": "",
                "artifact_file_name": "renamed-9.jar",
            },
            "org.wrong:renamed": {
                "group_id": "org.wrong",
                "artifact_id": "renamed",
                "version": "9",
                "classifier": "",
            },
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(entries[0]["coord"], "org.example:real-library")
        self.assertEqual(entries[0]["version"], "9")
        self.assertEqual(entries[0]["resolution_status"], "unresolved")
        self.assertEqual(
            entries[0]["packaged_match_source"],
            "runtime-artifact-inventory",
        )

    def test_artifact_inventory_refuses_conflicting_physical_mapping(self):
        nested = self._nested_jar_bytes([
            ("example/Shared.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/shared.jar",
            )
        ]
        runtime = {
            "org.first:shared": {
                "group_id": "org.first",
                "artifact_id": "shared",
                "version": "1.0",
                "classifier": "",
                "artifact_file_name": "shared.jar",
            },
            "org.second:shared": {
                "group_id": "org.second",
                "artifact_id": "shared",
                "version": "1.0",
                "classifier": "",
                "artifact_file_name": "shared.jar",
            },
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(entries[0]["resolution_status"], "unresolved")
        self.assertTrue(any(
            str(item).startswith("runtime_filename_coordinate_ambiguous:")
            for item in entries[0]["metadata_anomalies"]
        ))

    def test_runtime_version_with_hyphen_is_not_misread_as_classifier(self):
        nested = self._nested_jar_bytes([
            ("example/Feature.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/example-1.2.3-native.jar",
            )
        ]
        runtime = {
            "org.example:example": {
                "group_id": "org.example",
                "artifact_id": "example",
                "version": "1.2.3-native",
                "classifier": "",
            },
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
            )
        )

        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"org.example:example"})
        self.assertEqual(entries[0]["version"], "1.2.3-native")
        self.assertEqual(entries[0]["classifier"], "")

    def test_classifier_first_filename_requires_manual_version_confirmation(self):
        nested = self._nested_jar_bytes([
            ("example/Native.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/native-lib-linux-1.0.jar",
            )
        ]
        runtime = {
            "org.example:native-lib": {
                "group_id": "org.example",
                "artifact_id": "native-lib",
                "version": "1.0",
                "classifier": "",
            },
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(
            unresolved[0]["reason_code"],
            "PACKAGED_VERSION_UNCONFIRMED",
        )
        self.assertEqual(entries[0]["version"], "1.0")
        self.assertEqual(entries[0]["classifier"], "linux")
        self.assertEqual(entries[0]["resolution_status"], "unresolved")
        self.assertEqual(
            entries[0]["version_confirmation_status"],
            "unconfirmed",
        )

    def test_runtime_filename_classifier_inference_refuses_ambiguous_ga(self):
        nested = self._nested_jar_bytes([
            ("example/Native.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/native-lib-1.0-linux.jar",
            )
        ]
        runtime = {
            "org.first:native-lib": {
                "group_id": "org.first",
                "artifact_id": "native-lib",
                "version": "1.0",
                "classifier": "",
            },
            "org.second:native-lib": {
                "group_id": "org.second",
                "artifact_id": "native-lib",
                "version": "1.0",
                "classifier": "",
            },
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(entries[0]["resolution_status"], "unresolved")
        self.assertTrue(any(
            str(item).startswith("runtime_filename_coordinate_ambiguous:")
            for item in entries[0]["metadata_anomalies"]
        ))

    def test_source_runtime_evidence_precedes_manual_coordinate_fallback(self):
        nested = self._nested_jar_bytes([
            ("jnr/ffi/Provider.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/jffi-1.2.23-native.jar",
            )
        ]
        runtime = {
            "com.github.jnr:jffi": {
                "group_id": "com.github.jnr",
                "artifact_id": "jffi",
                "version": "1.2.23",
                "classifier": "",
            },
        }
        manual = {
            ("jffi", "1.2.23-native"): {
                "group_id": "wrong.group",
                "artifact_id": "jffi",
                "coord": "wrong.group:jffi",
            },
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
                manual,
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(entries[0]["coord"], "com.github.jnr:jffi:native")
        self.assertEqual(
            entries[0]["packaged_match_source"],
            "runtime-filename-classifier",
        )

    def test_new_runtime_coordinate_evidence_does_not_confirm_version(self):
        nested = self._nested_jar_bytes([
            ("jnr/ffi/Provider.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/jffi-1.2.23-native.jar",
            )
        ]
        runtime = {
            "com.github.jnr:jffi": {
                "group_id": "com.github.jnr",
                "artifact_id": "jffi",
                "version": "1.2.23",
                "classifier": "",
            },
        }
        confirmed_unresolved = [{
            "artifact_id": "jffi",
            "version": "1.2.23-native",
            "source": "filename",
        }]

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
                confirmed_unresolved_items=confirmed_unresolved,
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(
            unresolved[0]["reason_code"],
            "PACKAGED_VERSION_UNCONFIRMED",
        )
        self.assertEqual(entries[0]["resolution_status"], "unresolved")

    def test_artifact_inventory_does_not_supersede_unconfirmed_version(self):
        nested = self._nested_jar_bytes([
            ("example/Real.class", b"class"),
        ])
        packaged = [
            s1_dep_diff._extract_packaged_dep_from_nested_jar(
                nested,
                "BOOT-INF/lib/renamed-9.jar",
            )
        ]
        runtime = s1_dep_diff.parse_maven_dependency_list(
            "[INFO] org.example:real-library:jar:1.4.0:runtime:"
            "/repo/org/example/real-library/1.4.0/renamed-9.jar"
        )

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
                confirmed_unresolved_items=[{
                    "artifact_id": "renamed",
                    "version": "9",
                    "source": "filename",
                }],
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(
            unresolved[0]["reason_code"],
            "PACKAGED_VERSION_UNCONFIRMED",
        )
        self.assertEqual(entries[0]["resolution_status"], "unresolved")

    def test_direct_fat_jar_keeps_classifier_version_ambiguous_after_runtime_catalog(self):
        nested = self._nested_jar_bytes([
            ("jnr/ffi/Provider.class", b"class"),
        ])
        runtime = {
            "com.github.jnr:jffi": {
                "group_id": "com.github.jnr",
                "artifact_id": "jffi",
                "version": "1.2.23",
                "classifier": "",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact_path, "w") as outer:
                outer.writestr(
                    "BOOT-INF/lib/jffi-1.2.23.jar",
                    nested,
                )
                outer.writestr(
                    "BOOT-INF/lib/jffi-1.2.23-native.jar",
                    nested,
                )
            runtime_loader = Mock(return_value=runtime)
            packaged_deps, meta = (
                s1_dep_diff.collect_packaged_deps_from_artifact_path(
                    artifact_path,
                    runtime_deps_loader=runtime_loader,
                    allow_unresolved=True,
                )
            )

        runtime_loader.assert_called_once_with()
        self.assertEqual(
            set(packaged_deps),
            {
                "com.github.jnr:jffi",
            },
        )
        self.assertEqual(len(meta["unresolved_items"]), 1)
        self.assertEqual(
            meta["unresolved_items"][0]["reason_code"],
            "PACKAGED_VERSION_UNCONFIRMED",
        )

    def test_final_artifact_is_authoritative_for_bom_and_exclusion_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "app.jar"
            selected = self._nested_jar_bytes([
                (
                    "META-INF/maven/org.example/selected/pom.properties",
                    "groupId=org.example\nartifactId=selected\nversion=2.0.0\n",
                )
            ])
            with zipfile.ZipFile(artifact_path, "w") as outer:
                # selected:2.0.0 represents the BOM-arbitrated runtime version.
                # An excluded transitive dependency and selected:1.0.0 are not
                # physically packaged and therefore must not enter analysis.
                outer.writestr("BOOT-INF/lib/selected-2.0.0.jar", selected)

            packaged_deps, _meta = s1_dep_diff.collect_packaged_deps_from_artifact_path(
                str(artifact_path),
                runtime_deps={
                    "org.example:selected": {"version": "1.0.0", "scope": "runtime"},
                    "org.example:excluded": {"version": "9.9.9", "scope": "runtime"},
                },
            )

        self.assertEqual(set(packaged_deps), {"org.example:selected"})
        self.assertEqual(packaged_deps["org.example:selected"]["version"], "2.0.0")

    def test_filename_only_nested_jar_ignores_local_m2_and_uses_resolved_build_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repository"
            local_jar = repo / "org" / "example" / "plain-lib" / "1.2.3" / "plain-lib-1.2.3.jar"
            local_jar.parent.mkdir(parents=True)
            nested_bytes = self._nested_jar_bytes([
                ("com/example/Plain.class", b"class-bytes"),
            ])
            local_jar.write_bytes(nested_bytes)
            artifact = root / "app.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/lib/plain-lib-1.2.3.jar", nested_bytes)

            loader_calls = []

            def runtime_loader():
                loader_calls.append(True)
                return {
                    "org.example:plain-lib": {
                        "group_id": "org.example",
                        "artifact_id": "plain-lib",
                        "version": "1.2.3",
                        "scope": "runtime",
                    }
                }

            with patch.dict(os.environ, {"MAVEN_REPO_LOCAL": str(repo)}):
                deps, meta = s1_dep_diff.collect_packaged_deps_from_artifact_path(
                    str(artifact),
                    runtime_deps_loader=runtime_loader,
                )

        self.assertEqual(loader_calls, [True])
        self.assertIn("org.example:plain-lib", deps)
        self.assertEqual(meta["unresolved_items"], [])
        self.assertNotEqual(meta["dep_entries"][0]["match_source"], "local-m2-sha256")

    def test_local_m2_sha_match_stays_unresolved_when_coordinates_are_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repository"
            nested_bytes = self._nested_jar_bytes([("Plain.class", b"same")])
            for group in ("one", "two"):
                jar = repo / "org" / group / "plain-lib" / "1.2.3" / "plain-lib-1.2.3.jar"
                jar.parent.mkdir(parents=True)
                jar.write_bytes(nested_bytes)
            artifact = root / "app.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/lib/plain-lib-1.2.3.jar", nested_bytes)

            with patch.dict(os.environ, {"MAVEN_REPO_LOCAL": str(repo)}):
                _deps, meta = s1_dep_diff.collect_packaged_deps_from_artifact_path(
                    str(artifact),
                    runtime_deps={},
                    allow_unresolved=True,
                )

        self.assertEqual(len(meta["unresolved_items"]), 1)

    def test_classify_change_marks_removed_dependency(self):
        change_type, risk = s1_dep_diff.classify_change("1.2.3", "-")
        self.assertEqual(change_type, "移除")
        self.assertEqual(risk, "待分析")

    def test_build_step1_change_rows_keeps_base_and_current_coords_for_cross_group_upgrade(self):
        rows = s1_dep_diff._build_step1_change_rows(
            [
                {
                    "coord": "com.fasterxml.jackson.core:jackson-core",
                    "group_id": "com.fasterxml.jackson.core",
                    "artifact_id": "jackson-core",
                    "version": "2.14.1",
                    "scope": "packaged",
                    "remark": "source:final_artifact(embedded-pom)",
                    "resolution_status": "resolved",
                }
            ],
            [
                {
                    "coord": "tools.jackson.core:jackson-core",
                    "group_id": "tools.jackson.core",
                    "artifact_id": "jackson-core",
                    "version": "3.0.4",
                    "scope": "packaged",
                    "remark": "source:final_artifact(embedded-pom)",
                    "resolution_status": "resolved",
                }
            ],
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["coord"], "tools.jackson.core:jackson-core")
        self.assertEqual(rows[0]["base_coord"], "com.fasterxml.jackson.core:jackson-core")
        self.assertEqual(rows[0]["current_coord"], "tools.jackson.core:jackson-core")
        self.assertEqual(rows[0]["old_version"], "2.14.1")
        self.assertEqual(rows[0]["new_version"], "3.0.4")
        self.assertEqual(rows[0]["comparison_key"], "jackson-core")
        self.assertEqual(rows[0]["pairing_status"], "unique_artifact_migration")

    def test_build_step1_change_rows_detects_same_version_content_change(self):
        common = {
            "coord": "com.nbs:nbs-bcl-basesvr",
            "artifact_id": "nbs-bcl-basesvr",
            "version": "1.0.0-SNAPSHOT",
            "scope": "runtime",
            "resolution_status": "resolved",
        }

        changed = s1_dep_diff._build_step1_change_rows(
            [{**common, "content_sha256": "a" * 64}],
            [{**common, "content_sha256": "b" * 64}],
        )[0]
        unchanged = s1_dep_diff._build_step1_change_rows(
            [{**common, "content_sha256": "a" * 64}],
            [{**common, "content_sha256": "a" * 64}],
        )[0]

        self.assertEqual(changed["old_version"], changed["new_version"])
        self.assertEqual(changed["change_type"], "已变更")
        self.assertIn(
            "same_version_artifact_content_changed", changed["remark"]
        )
        self.assertEqual(unchanged["change_type"], "未变")

    def test_build_step1_change_rows_matches_exact_coord_before_group_migration(self):
        rows = s1_dep_diff._build_step1_change_rows(
            [
                {"coord": "old.group:shared", "artifact_id": "shared", "version": "1", "resolution_status": "resolved"},
                {"coord": "stable.group:shared", "artifact_id": "shared", "version": "1", "resolution_status": "resolved"},
            ],
            [
                {"coord": "new.group:shared", "artifact_id": "shared", "version": "2", "resolution_status": "resolved"},
                {"coord": "stable.group:shared", "artifact_id": "shared", "version": "2", "resolution_status": "resolved"},
            ],
        )

        exact = next(row for row in rows if row["base_coord"] == "stable.group:shared")
        migrated = next(row for row in rows if row["base_coord"] == "old.group:shared")
        self.assertEqual(exact["current_coord"], "stable.group:shared")
        self.assertEqual(exact["pairing_status"], "exact_coord")
        self.assertEqual(migrated["current_coord"], "new.group:shared")
        self.assertEqual(migrated["pairing_status"], "unique_artifact_migration")

    def test_classifier_compare_key_is_canonical_across_enrichment_shapes(self):
        embedded = {
            "coord": "com.example:native:osx-aarch_64",
            "artifact_id": "native",
            "classifier": "osx-aarch_64",
            "version": "1",
            "resolution_status": "resolved",
        }
        manually_enriched = {
            **embedded,
            "coord": "com.example:native",
            "version": "2",
        }

        self.assertEqual(
            s1_dep_diff._entry_full_compare_key(embedded),
            "com.example:native:osx-aarch_64",
        )
        rows = s1_dep_diff._build_step1_change_rows(
            [embedded], [manually_enriched]
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pairing_status"], "exact_coord")
        self.assertEqual(
            rows[0]["comparison_key"],
            "com.example:native:osx-aarch_64",
        )

    def test_build_step1_change_rows_refuses_ambiguous_cross_group_pairing(self):
        rows = s1_dep_diff._build_step1_change_rows(
            [
                {"coord": "left.one:shared", "artifact_id": "shared", "version": "1", "resolution_status": "resolved"},
                {"coord": "left.two:shared", "artifact_id": "shared", "version": "1", "resolution_status": "resolved"},
            ],
            [
                {"coord": "right.one:shared", "artifact_id": "shared", "version": "2", "resolution_status": "resolved"},
                {"coord": "right.two:shared", "artifact_id": "shared", "version": "2", "resolution_status": "resolved"},
            ],
        )

        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row["resolution_status"] == "unresolved" for row in rows))
        self.assertTrue(all(row["pairing_reason_code"] == "ambiguous_artifact_migration_candidates" for row in rows))
        self.assertTrue(all(not (row["base_coord"] and row["current_coord"]) for row in rows))

    def test_collect_maven_deps_for_workspace_applies_manual_coord_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            artifact_path = work_dir / "target" / "app.jar"
            artifact_path.parent.mkdir(parents=True)
            artifact_path.write_text("placeholder", encoding="utf-8")

            packaged_raw = [
                {
                    "entry_id": "1",
                    "lib_entry": "BOOT-INF/lib/demo-lib-1.2.3.jar",
                    "lib_name": "demo-lib-1.2.3.jar",
                    "coord": "",
                    "group_id": "",
                    "artifact_id": "demo-lib",
                    "version": "1.2.3",
                    "classifier": "",
                    "match_source": "filename",
                    "filename_stem": "demo-lib",
                    "read_error": "",
                }
            ]
            manual_coord_overrides = {
                ("demo-lib", "1.2.3"): {
                    "group_id": "org.example",
                    "artifact_id": "demo-lib",
                    "coord": "org.example:demo-lib",
                }
            }

            with patch.object(s1_dep_diff, "run_cmd", return_value=("", "", 0)), \
                 patch.object(s1_dep_diff, "_resolve_module_dir_for_packaging", return_value=str(work_dir)), \
                 patch.object(s1_dep_diff, "_discover_packaged_archives", return_value=[artifact_path]), \
                 patch.object(s1_dep_diff, "_detect_archive_packaging_type", return_value="boot_jar"), \
                 patch.object(s1_dep_diff, "_inspect_packaged_archive", return_value=packaged_raw), \
                 patch.object(s1_dep_diff, "collect_runtime_deps_for_workspace", return_value=({}, "mvn dependency:list")):
                packaged_deps, meta = s1_dep_diff.collect_maven_deps_for_workspace(
                    str(work_dir),
                    manual_coord_overrides=manual_coord_overrides,
                )

        self.assertIn("org.example:demo-lib", packaged_deps)
        self.assertEqual(meta.get("unresolved_items"), [])
        self.assertEqual(
            [item.get("coord") for item in meta.get("dep_entries") or []],
            ["org.example:demo-lib"],
        )
        self.assertEqual(
            packaged_deps["org.example:demo-lib"]["remark"],
            "source:final_artifact(manual_override)",
        )

    def test_manual_coord_override_preserves_distinct_classifiers(self):
        packaged = [
            {
                "entry_id": classifier,
                "lib_entry": f"BOOT-INF/lib/native-1-{classifier}.jar",
                "lib_name": f"native-1-{classifier}.jar",
                "coord": "",
                "group_id": "",
                "artifact_id": "native",
                "version": "1",
                "classifier": classifier,
                "match_source": "filename",
                "filename_stem": f"native-1-{classifier}",
            }
            for classifier in ("osx-aarch_64", "osx-x86_64")
        ]
        overrides = {
            ("native", "1"): {
                "group_id": "com.example",
                "artifact_id": "native",
                "coord": "com.example:native",
            }
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged, {}, overrides
            )
        )

        self.assertEqual(unresolved, [])
        self.assertEqual(
            set(resolved),
            {
                "com.example:native:osx-aarch_64",
                "com.example:native:osx-x86_64",
            },
        )
        self.assertEqual(
            {item["coord"] for item in entries},
            set(resolved),
        )

    def test_manual_coord_override_parser_accepts_classifier_specific_key(self):
        overrides, invalid = s1_dep_diff.parse_manual_coord_overrides([
            "native:1:osx-aarch_64 -> com.example:native",
            "native:1 -> com.example:native",
        ])

        self.assertEqual(invalid, [])
        self.assertEqual(
            overrides[("native", "1", "osx-aarch_64")]["classifier"],
            "osx-aarch_64",
        )
        self.assertIn(("native", "1"), overrides)

    def test_runtime_enrichment_rejects_different_classifier_candidate(self):
        packaged = [{
            "entry_id": "x86",
            "lib_entry": "BOOT-INF/lib/native-1-osx-x86_64.jar",
            "lib_name": "native-1-osx-x86_64.jar",
            "coord": "",
            "group_id": "",
            "artifact_id": "native",
            "version": "1",
            "classifier": "osx-x86_64",
            "match_source": "filename",
            "filename_stem": "native-1-osx-x86_64",
        }]
        runtime = {
            "com.example:native:osx-aarch_64": {
                "group_id": "com.example",
                "artifact_id": "native",
                "version": "1",
                "classifier": "osx-aarch_64",
            }
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged, runtime
            )
        )

        self.assertEqual(resolved, {})
        self.assertEqual(
            [item["classifier"] for item in unresolved],
            ["osx-x86_64"],
        )
        self.assertEqual(entries[0]["resolution_status"], "unresolved")

    def test_confirmed_unresolved_item_is_scoped_to_classifier(self):
        packaged = [
            {
                "entry_id": classifier,
                "lib_entry": f"BOOT-INF/lib/native-1-{classifier}.jar",
                "lib_name": f"native-1-{classifier}.jar",
                "coord": f"com.example:native:{classifier}",
                "group_id": "com.example",
                "artifact_id": "native",
                "version": "1",
                "classifier": classifier,
                "match_source": "embedded-pom",
            }
            for classifier in ("osx-aarch_64", "osx-x86_64")
        ]
        runtime = {
            item["coord"]: {
                "coord": item["coord"],
                "group_id": item["group_id"],
                "artifact_id": item["artifact_id"],
                "version": item["version"],
                "classifier": item["classifier"],
            }
            for item in packaged
        }

        entries, resolved, unresolved = (
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                packaged,
                runtime,
                confirmed_unresolved_items=[{
                    "artifact_id": "native",
                    "version": "1",
                    "classifier": "osx-aarch_64",
                    "entry_id": "osx-aarch_64",
                    "side": "current",
                }],
                side="current",
            )
        )

        self.assertEqual(
            [item["classifier"] for item in unresolved],
            ["osx-aarch_64"],
        )
        self.assertEqual(
            set(resolved),
            {"com.example:native:osx-x86_64"},
        )
        statuses = {
            item["classifier"]: item["resolution_status"]
            for item in entries
        }
        self.assertEqual(statuses["osx-aarch_64"], "unresolved")
        self.assertEqual(statuses["osx-x86_64"], "resolved")

    def test_get_packaged_deps_by_switching_branch_forwards_manual_coord_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            temp_dir = work_dir / "worktree"
            temp_dir.mkdir(parents=True)
            manual_coord_overrides = {
                ("demo-lib", "1.2.3"): {
                    "group_id": "org.example",
                    "artifact_id": "demo-lib",
                    "coord": "org.example:demo-lib",
                }
            }
            captured = {}

            def fake_collect(*_args, **kwargs):
                captured["manual_coord_overrides"] = kwargs.get("manual_coord_overrides")
                return {"org.example:demo-lib": {"coord": "org.example:demo-lib"}}, {"mode": "final_artifact"}

            with patch.object(s1_dep_diff, "build_java_env", return_value={}), \
                 patch.object(s1_dep_diff, "create_branch_worktree", return_value=temp_dir), \
                 patch.object(s1_dep_diff, "collect_maven_deps_for_workspace", side_effect=fake_collect), \
                 patch.object(s1_dep_diff, "remove_branch_worktree"):
                deps, meta = s1_dep_diff.get_packaged_deps_by_switching_branch(
                    "feature/upgrade",
                    str(work_dir),
                    manual_coord_overrides=manual_coord_overrides,
                )

        self.assertEqual(captured["manual_coord_overrides"], manual_coord_overrides)
        self.assertIn("org.example:demo-lib", deps)
        self.assertEqual(meta["branch"], "feature/upgrade")
        self.assertEqual(meta["worktree_dir"], str(temp_dir))

    def test_get_packaged_deps_by_switching_branch_dispatches_to_gradle(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            temp_dir = work_dir / "worktree"
            temp_dir.mkdir(parents=True)
            artifact = temp_dir / "app/build/libs/app.jar"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"artifact")
            gradle_meta = {
                "mode": "final_artifact",
                "artifact_path": str(artifact),
            }
            with patch.object(s1_dep_diff, "build_java_env", return_value={}), \
                    patch.object(s1_dep_diff, "create_branch_worktree", return_value=temp_dir), \
                    patch.object(
                        s1_dep_diff,
                        "collect_gradle_deps_for_workspace",
                        return_value=({"org.example:demo": {"version": "1"}}, gradle_meta),
                    ) as gradle_collect, \
                    patch.object(s1_dep_diff, "collect_maven_deps_for_workspace") as maven_collect, \
                    patch.object(s1_dep_diff, "remove_branch_worktree"):
                deps, meta = s1_dep_diff.get_packaged_deps_by_switching_branch(
                    "feature/upgrade",
                    work_dir,
                    primary_module=":app",
                    build_tool="gradle",
                )

        gradle_collect.assert_called_once()
        maven_collect.assert_not_called()
        self.assertIn("org.example:demo", deps)
        self.assertEqual(meta["branch"], "feature/upgrade")

    def test_artifact_coordinate_enrichment_prefers_branch_over_source_directory(self):
        branch_deps = {"org.example:branch": {"version": "2.0.0"}}
        branch_meta = {
            "list_command": "mvn branch dependency:list",
        }
        source_deps = {"org.example:source": {"version": "1.0.0"}}

        with patch.object(s1_dep_diff, "build_java_env", return_value={}), \
             patch.object(
                 s1_dep_diff,
                 "resolve_step1_ref",
                 return_value={
                     "status": "resolved",
                     "requested_ref": "current-release",
                     "resolved_ref": "origin/current-release",
                     "resolved_commit": "a" * 40,
                     "resolution_mode": "unique_remote",
                     "candidates": [{"ref": "origin/current-release", "commit": "a" * 40}],
                     "fingerprint": "fixture",
                 },
             ) as ref_call, \
             patch.object(
                 s1_dep_diff,
                 "collect_runtime_deps_for_workspace",
                 return_value=(source_deps, "mvn source dependency:list"),
             ) as source_call, \
             patch.object(
                 s1_dep_diff,
                 "get_runtime_deps_by_switching_branch",
                 return_value=(branch_deps, branch_meta),
             ) as branch_call:
            deps, meta = s1_dep_diff._collect_runtime_deps_for_artifact_input(
                "/same/project",
                "current-release",
                "/analysis/repository",
                primary_module="app",
                side="current",
                artifact_path="/tmp/current.jar",
            )

        self.assertEqual(deps, branch_deps)
        self.assertEqual(meta["source_mode"], "checkout_branch")
        self.assertEqual(meta["branch"], "a" * 40)
        self.assertEqual(meta["requested_ref"], "current-release")
        self.assertEqual(meta["resolved_ref"], "origin/current-release")
        ref_call.assert_called_once_with(
            "/same/project",
            "current-release",
            allow_local_source=False,
            allow_dirty_local_source=False,
        )
        branch_call.assert_called_once()
        self.assertEqual(branch_call.call_args.args[0], "a" * 40)
        self.assertEqual(branch_call.call_args.args[1], "/same/project")
        source_call.assert_not_called()

    def test_artifact_coordinate_enrichment_stops_when_branch_is_ambiguous(self):
        resolution = {
            "status": "ambiguous",
            "requested_ref": "release-2.0.0",
            "resolved_ref": "",
            "resolved_commit": "",
            "resolution_mode": "unresolved",
            "candidates": [
                {"ref": "origin/release-2.0.0", "commit": "a" * 40},
                {"ref": "upstream/release-2.0.0", "commit": "b" * 40},
            ],
            "fingerprint": "ambiguous-fixture",
        }
        with patch.object(s1_dep_diff, "resolve_step1_ref", return_value=resolution), \
             patch.object(s1_dep_diff, "get_runtime_deps_by_switching_branch") as branch_call:
            with self.assertRaises(s1_dep_diff.Step1RefResolutionRequiredError) as caught:
                s1_dep_diff._collect_runtime_deps_for_artifact_input(
                    "/same/project",
                    "release-2.0.0",
                    "/same/project",
                    side="current",
                    artifact_path="/tmp/current.jar",
                )

        self.assertEqual(caught.exception.resolution["status"], "ambiguous")
        branch_call.assert_not_called()
        interaction = s1_dep_diff.build_step1_ref_resolution_interaction(caught.exception)
        self.assertEqual(interaction["reason_code"], "ambiguous_step1_source_ref")
        self.assertEqual(interaction["required_fields"], ["current_branch"])
        self.assertEqual(len(interaction["ref_resolution_requests"][0]["candidates"]), 2)
        self.assertEqual(
            interaction["ref_resolution_scope"]["queried_sides"],
            ["current"],
        )
        self.assertEqual(
            interaction["ref_resolution_scope"]["other_side_status"],
            "not_evaluated_by_this_interaction",
        )
        self.assertIn("不表示基准侧执行过远端查询", interaction["summary"])
        self.assertEqual(
            interaction["ref_resolution_requests"][0]["resolution_trigger"],
            "artifact_coordinate_enrichment",
        )

    def test_artifact_enrichment_does_not_turn_pinned_commit_failure_into_checkpoint(self):
        resolution = {
            "status": "fetch_failed",
            "source_status": "remote_expected_commit_unmaterializable",
            "expected_commit": "a" * 40,
            "observed_commit": "b" * 40,
        }
        with patch.object(
            s1_dep_diff,
            "resolve_step1_ref",
            return_value=resolution,
        ) as resolver, patch.object(
            s1_dep_diff,
            "get_runtime_deps_by_switching_branch",
        ) as branch_call:
            with self.assertRaises(
                s1_dep_diff.PinnedCommitMaterializationError
            ) as raised:
                s1_dep_diff._collect_runtime_deps_for_artifact_input(
                    "/same/project",
                    "release",
                    "/same/project",
                    side="base",
                    artifact_path="/tmp/base.jar",
                    expected_commit="a" * 40,
                    expected_remote="origin",
                    expected_remote_ref="refs/heads/release",
                )

        self.assertIn("不能通过让用户重新选择 ref 解决", str(raised.exception))
        self.assertEqual(resolver.call_args.kwargs["expected_remote"], "origin")
        self.assertEqual(
            resolver.call_args.kwargs["expected_remote_ref"],
            "refs/heads/release",
        )
        branch_call.assert_not_called()

    def test_artifact_enrichment_remote_failure_is_not_a_user_checkpoint(self):
        resolution = {
            "status": "fetch_failed",
            "source_status": "remote_query_failed",
            "failures": [{
                "remote": "origin",
                "stage": "targeted_ls_remote",
                "reason": "connection reset after retries",
                "reason_code": "transient_network_failure",
            }],
        }
        with patch.object(
            s1_dep_diff,
            "resolve_step1_ref",
            return_value=resolution,
        ), patch.object(
            s1_dep_diff,
            "get_runtime_deps_by_switching_branch",
        ) as branch_call:
            with self.assertRaises(
                s1_dep_diff.Step1RemoteOperationError
            ) as raised:
                s1_dep_diff._collect_runtime_deps_for_artifact_input(
                    "/same/project",
                    "release",
                    "/same/project",
                    side="current",
                    artifact_path="/tmp/current.jar",
                )

        self.assertIn("STEP1_REMOTE_OPERATION_FAILED", str(raised.exception))
        self.assertIn("connection reset after retries", str(raised.exception))
        branch_call.assert_not_called()

    def test_source_only_artifact_enrichment_requires_revision_confirmation(self):
        resolution = {
            "status": "resolved",
            "requested_ref": "HEAD",
            "resolved_ref": "HEAD",
            "resolved_commit": "c" * 40,
            "resolution_mode": "exact",
            "candidates": [],
            "fingerprint": "head-fixture",
        }
        with patch.object(s1_dep_diff, "resolve_step1_ref", return_value=resolution):
            with self.assertRaises(s1_dep_diff.SourceRevisionConfirmationRequiredError) as caught:
                s1_dep_diff._collect_runtime_deps_for_artifact_input(
                    "/same/project",
                    "",
                    "/same/project",
                    primary_module="app",
                    side="current",
                    artifact_path="/tmp/current.jar",
                )

        interaction = s1_dep_diff.build_step1_ref_resolution_interaction(caught.exception)
        request = interaction["ref_resolution_requests"][0]
        self.assertEqual(interaction["reason_code"], "step1_source_revision_confirmation_required")
        self.assertEqual(request["detected_commit"], "c" * 40)

    def test_same_repository_path_uses_distinct_confirmed_commits_for_each_side(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "project"
            repo.mkdir()

            def git(*args):
                result = subprocess.run(
                    ["git", *args],
                    cwd=repo,
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                return result.stdout.strip()

            git("init")
            git("config", "user.email", "step1@example.invalid")
            git("config", "user.name", "Step1 Test")
            marker = repo / "runtime-dependency.txt"
            marker.write_text("org.example:base-lib:1.0.0\n", encoding="utf-8")
            git("add", "runtime-dependency.txt")
            git("commit", "-m", "base")
            base_commit = git("rev-parse", "HEAD")
            marker.write_text("org.example:current-lib:2.0.0\n", encoding="utf-8")
            git("commit", "-am", "current")
            current_commit = git("rev-parse", "HEAD")

            observed_worktrees = []

            def fake_collect(worktree_dir, **_kwargs):
                worktree = Path(worktree_dir)
                observed_worktrees.append(worktree)
                coord = (worktree / "runtime-dependency.txt").read_text(
                    encoding="utf-8"
                ).strip()
                group_id, artifact_id, version = coord.split(":")
                return {
                    f"{group_id}:{artifact_id}": {
                        "coord": f"{group_id}:{artifact_id}",
                        "version": version,
                    }
                }, "mvn dependency:list"

            with patch.object(
                s1_dep_diff,
                "collect_runtime_deps_for_workspace",
                side_effect=fake_collect,
            ):
                base_deps, base_meta = s1_dep_diff._collect_runtime_deps_for_artifact_input(
                    str(repo),
                    base_commit,
                    str(repo),
                    side="base",
                    source_resolution={
                        "status": "resolved",
                        "source_status": "remote_source_resolved",
                        "requested_ref": "release-base",
                        "resolved_ref": "origin/release-base",
                        "resolved_commit": base_commit,
                        "resolution_mode": "live_remote",
                    },
                )
                current_deps, current_meta = s1_dep_diff._collect_runtime_deps_for_artifact_input(
                    str(repo),
                    current_commit,
                    str(repo),
                    side="current",
                    source_resolution={
                        "status": "resolved",
                        "source_status": "remote_source_resolved",
                        "requested_ref": "release-current",
                        "resolved_ref": "origin/release-current",
                        "resolved_commit": current_commit,
                        "resolution_mode": "live_remote",
                    },
                )

            self.assertEqual(set(base_deps), {"org.example:base-lib"})
            self.assertEqual(set(current_deps), {"org.example:current-lib"})
            self.assertEqual(base_meta["branch"], base_commit)
            self.assertEqual(current_meta["branch"], current_commit)
            self.assertEqual(git("rev-parse", "HEAD"), current_commit)
            self.assertTrue(all(not path.exists() for path in observed_worktrees))

    def test_main_writes_alerts_csv_with_subset_fields_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            output_path = work_dir / "s1_dep_changes.csv"
            base_entry = {
                "entry_id": "base-1",
                "lib_entry": "BOOT-INF/lib/demo-lib-2.0.0.jar",
                "lib_name": "demo-lib-2.0.0.jar",
                "coord": "org.example:demo-lib",
                "group_id": "org.example",
                "artifact_id": "demo-lib",
                "version": "2.0.0",
                "classifier": "",
                "scope": "packaged",
                "remark": "source:final_artifact(embedded-pom)",
                "packaged_present": "true",
                "packaged_match_source": "embedded-pom",
                "read_error": "",
                "resolution_status": "resolved",
            }
            current_entry = dict(base_entry)
            current_entry.update(
                {
                    "entry_id": "current-1",
                    "lib_entry": "BOOT-INF/lib/demo-lib-1.0.0.jar",
                    "lib_name": "demo-lib-1.0.0.jar",
                    "version": "1.0.0",
                }
            )
            base_deps = {
                "org.example:demo-lib": {
                    "scope": "packaged",
                    "version": "2.0.0",
                }
            }
            curr_deps = {
                "org.example:demo-lib": {
                    "scope": "packaged",
                    "version": "1.0.0",
                }
            }
            nested_jar = self._nested_jar_bytes([
                ("org/example/Demo.class", b"class"),
            ])
            base_artifact = work_dir / "base.jar"
            current_artifact = work_dir / "current.jar"
            with zipfile.ZipFile(base_artifact, "w") as archive:
                archive.writestr(base_entry["lib_entry"], nested_jar)
            with zipfile.ZipFile(current_artifact, "w") as archive:
                archive.writestr(current_entry["lib_entry"], nested_jar)
            base_meta = {
                "mode": "final_artifact",
                "archives": [str(base_artifact)],
                "artifact_path": str(base_artifact),
                "artifact_sha256": hashlib.sha256(base_artifact.read_bytes()).hexdigest(),
                "deps": [base_entry],
                "dep_entries": [base_entry],
                "matched_count": 1,
                "runtime_only_count": 0,
                "runtime_only_coords": [],
                "module_dir": str(work_dir / "base-module"),
            }
            curr_meta = {
                "mode": "final_artifact",
                "archives": [str(current_artifact)],
                "artifact_path": str(current_artifact),
                "artifact_sha256": hashlib.sha256(current_artifact.read_bytes()).hexdigest(),
                "deps": [current_entry],
                "dep_entries": [current_entry],
                "matched_count": 1,
                "runtime_only_count": 0,
                "runtime_only_coords": [],
                "module_dir": str(work_dir / "current-module"),
            }

            with patch.object(
                s1_dep_diff,
                "get_packaged_deps_by_switching_branch",
                side_effect=[(base_deps, base_meta), (curr_deps, curr_meta)],
            ), patch.object(s1_dep_diff, "require_human_confirm", return_value=True), patch.object(
                sys,
                "argv",
                [
                    "s1_dep_diff.py",
                    "--base",
                    "base",
                    "--current",
                    "current",
                    "--base-tool",
                    "maven",
                    "--current-tool",
                    "maven",
                    "--work-dir",
                    str(work_dir),
                    "--output",
                    str(output_path),
                ],
            ):
                s1_dep_diff.main()

            alerts_path = work_dir / "dep_alerts.csv"
            summary_path = work_dir / "dep_summary.txt"
            self.assertTrue(alerts_path.exists())
            self.assertTrue(summary_path.exists())
            summary_text = summary_path.read_text(encoding="utf-8")
            with alerts_path.open("r", encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))

        self.assertIn("一、先看什么", summary_text)
        self.assertIn("先看 dep_alerts.csv", summary_text)
        self.assertIn("二、本次依赖范围是否可信", summary_text)
        self.assertLess(summary_text.index("一、先看什么"), summary_text.index("四、依赖变化统计"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["coord"], "org.example:demo-lib")
        self.assertEqual(rows[0]["old_version"], "2.0.0")
        self.assertEqual(rows[0]["new_version"], "1.0.0")
        self.assertEqual(rows[0]["change_type"], "降级⚠️")
        self.assertEqual(
            ["conclusion", "change_summary", "review_reason"],
            list(rows[0].keys())[:3],
        )
        self.assertEqual(rows[0]["conclusion"], "需要人工复核")
        self.assertIn("org.example:demo-lib: 2.0.0 -> 1.0.0", rows[0]["change_summary"])
        self.assertIn("依赖版本发生降级", rows[0]["review_reason"])
        self.assertTrue(
            {
                "coord",
                "old_version",
                "new_version",
                "change_type",
                "risk",
                "scope",
                "remark",
                "current_packaged",
                "downgrade_confirmed",
                "resolution_status",
            }.issubset(set(rows[0].keys()))
        )


if __name__ == "__main__":
    unittest.main()
