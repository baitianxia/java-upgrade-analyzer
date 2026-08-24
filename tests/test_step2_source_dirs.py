import csv
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s2_context_from_deps as step2  # noqa: E402
import gate  # noqa: E402


class Step2SourceDirsTest(unittest.TestCase):
    def test_strict_git_repository_probe_failure_is_not_not_a_repo(self):
        with patch.object(
            step2,
            "run_cmd",
            return_value=("", "fatal: transient repository read failure", 128),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "STEP2_GIT_REPOSITORY_PROBE_FAILED",
            ):
                step2.is_git_repo("/repo", strict_git=True)

    def test_strict_git_show_distinguishes_absent_path_from_process_failure(self):
        with patch.object(
            step2,
            "run_cmd",
            return_value=(
                "",
                "fatal: path 'pom.xml' does not exist in 'aaaaaaaa'",
                128,
            ),
        ):
            self.assertEqual(
                step2.git_show_file(
                    "a" * 40,
                    "pom.xml",
                    "/repo",
                    strict_git=True,
                ),
                "",
            )

        with patch.object(
            step2,
            "run_cmd",
            return_value=("", "fatal: bad object aaaaaaaa", 128),
        ):
            with self.assertRaisesRegex(RuntimeError, "STEP2_GIT_SHOW_FAILED"):
                step2.git_show_file(
                    "a" * 40,
                    "pom.xml",
                    "/repo",
                    strict_git=True,
                )

    def test_strict_effective_model_worktree_failure_is_blocking(self):
        with patch.object(
            step2,
            "get_git_root",
            return_value="/repo",
        ), patch.object(
            step2,
            "create_detached_worktree",
            side_effect=RuntimeError("git worktree lock unavailable"),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "STEP2_GIT_WORKTREE_CREATE_FAILED",
            ):
                step2.resolve_maven_jdk_from_effective_model(
                    "a" * 40,
                    "/repo",
                    strict_git=True,
                )

    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_fixed_commit_manifest_ignores_checkout_head_and_dirty_files(self):
        real_git = shutil.which("git")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()

            def git(*args):
                completed = subprocess.run(
                    [real_git, *args],
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Step2 Test")
            git("config", "user.email", "step2@example.invalid")
            (repo / "pom.xml").write_text(
                "<project><properties><java.version>11</java.version></properties></project>",
                encoding="utf-8",
            )
            git("add", "pom.xml")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (repo / "pom.xml").write_text(
                "<project><properties><java.version>17</java.version></properties></project>",
                encoding="utf-8",
            )
            git("commit", "-qam", "current")
            current = git("rev-parse", "HEAD")
            # Neither a dirty tracked file nor an untracked manifest may
            # override immutable tree reads.
            (repo / "pom.xml").write_text(
                "<project><properties><java.version>99</java.version></properties></project>",
                encoding="utf-8",
            )
            (repo / "build.gradle").write_text(
                "sourceCompatibility = 99\n",
                encoding="utf-8",
            )

            detected = step2.detect_jdk_versions_from_manifests(
                base,
                current,
                repo,
                "maven",
                strict_git=True,
            )

        self.assertEqual(detected[:2], ("11", "17"))

    @staticmethod
    def _class_bytes(major):
        return b"\xca\xfe\xba\xbe\x00\x00" + int(major).to_bytes(2, "big")

    def test_orchestrated_confirmed_versions_override_auto_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            dep_changes = tmp_path / "s1_dep_changes.csv"
            output_json = tmp_path / "s2_context.json"
            output_dep_graph = tmp_path / "s2_dep_graph.json"
            source_dir = tmp_path / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            dep_changes.write_text(
                "coord,old_version,new_version,change_type,scope\n"
                "org.springframework.boot:spring-boot,2.7.18,3.2.5,升级,compile\n",
                encoding="utf-8",
            )
            argv = [
                "s2_context_from_deps.py",
                "--dep-changes",
                str(dep_changes),
                "--work-dir",
                str(tmp_path),
                "--output",
                str(output_json),
                "--output-dep-graph",
                str(output_dep_graph),
            ]
            confirmed = {
                "base_branch": "main",
                "current_branch": "upgrade",
                "base_resolved_commit": "a" * 40,
                "current_resolved_commit": "b" * 40,
                "source_dirs": [str(source_dir)],
                "jdk_base": "11",
                "jdk_current": "21",
                "springboot_base": "2.6.15",
                "springboot_current": "3.3.2",
            }

            with patch.object(sys, "argv", argv), patch.object(
                step2, "load_orchestrated_step2_input", return_value=confirmed
            ), patch.object(
                step2, "detect_build_tool", return_value="maven"
            ), patch.object(
                step2,
                "require_pinned_git_commit",
                side_effect=lambda revision, *_args, **_kwargs: revision,
            ), patch.object(
                step2,
                "detect_jdk_versions_from_manifests",
                return_value=("8", "17", "pom.xml"),
            ), patch.object(
                step2,
                "detect_jdk_versions",
                side_effect=AssertionError(
                    "Step0 已确认两侧 JDK 后不应在 Step2 启动构建工具探测"
                ),
            ), patch.object(
                step2, "detect_spring_cloud", return_value=(False, None)
            ), patch.object(
                step2, "detect_tech_flags", return_value={}
            ), patch.object(
                step2, "detect_jvm_param_changes", return_value=[]
            ):
                step2.main()

            payload = json.loads(output_json.read_text(encoding="utf-8"))
            graph = json.loads(output_dep_graph.read_text(encoding="utf-8"))

        self.assertEqual(payload["jdk_base"], "11")
        self.assertEqual(payload["jdk_current"], "21")
        self.assertEqual(payload["jdk_source"], "user_confirmed")
        self.assertEqual(payload["springboot_base"], "2.6.15")
        self.assertEqual(payload["springboot_current"], "3.3.2")
        self.assertEqual(payload["springboot_version_source"], "user_confirmed")
        self.assertEqual(graph["total_dependencies"], 1)
        self.assertEqual(
            graph["dependencies"][0]["coord"],
            "org.springframework.boot:spring-boot",
        )
        self.assertEqual(graph["edges"], [])

    def test_load_dep_changes_rejects_duplicate_artifact_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            dep_changes = Path(tmp) / "dep_changes.csv"
            dep_changes.write_text(
                "coord,old_version,new_version,change_type,resolution_status,base_lib_entry,current_lib_entry\n"
                "org.apache.shiro:shiro-core,2.1.0,2.2.0,小版本升级,resolved,BOOT-INF/lib/shiro-core-2.1.0.jar,BOOT-INF/lib/shiro-core-2.2.0.jar\n"
                "org.apache.shiro:shiro-core,2.1.0,2.2.0,小版本升级,resolved,BOOT-INF/lib/shiro-core-2.1.0-jakarta.jar,BOOT-INF/lib/shiro-core-2.2.0-jakarta.jar\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "duplicate dependency identity"):
                step2.load_dep_changes(dep_changes)

    def test_dependency_graph_does_not_infer_edges_from_raw_dependency_poms(self):
        deps = {
            "org.example:parent": {
                "coord": "org.example:parent", "old_version": "1", "new_version": "2",
                "change_type": "升级", "scope": "packaged",
            },
            "org.example:excluded": {
                "coord": "org.example:excluded", "old_version": "1", "new_version": "2",
                "change_type": "升级", "scope": "packaged",
            },
        }

        with patch.object(
            step2,
            "get_pom_deps_from_m2",
            return_value=["org.example:excluded"],
        ) as raw_pom_lookup:
            graph = step2.build_dep_graph(deps)

        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["relationship_status"], "not_inferred_without_resolved_tree")
        raw_pom_lookup.assert_not_called()

    def test_explicit_source_dirs_override_auto_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            dep_changes = tmp_path / "s1_dep_changes.csv"
            output_json = tmp_path / "s2_context.json"
            explicit_a = tmp_path / "module-a" / "src" / "main" / "java"
            explicit_b = tmp_path / "module-b" / "src" / "main" / "java"
            explicit_a.mkdir(parents=True)
            explicit_b.mkdir(parents=True)

            with dep_changes.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["coord", "old_version", "new_version", "change_type", "scope"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "org.springframework.boot:spring-boot",
                        "old_version": "2.7.18",
                        "new_version": "3.2.5",
                        "change_type": "升级",
                        "scope": "compile",
                    }
                )

            argv = [
                "s2_context_from_deps.py",
                "--dep-changes",
                str(dep_changes),
                "--base",
                "origin/main",
                "--current",
                "feature/upgrade",
                "--work-dir",
                str(tmp_path),
                "--source-dirs",
                str(explicit_a),
                str(explicit_b),
                "--output",
                str(output_json),
            ]

            with patch.object(sys, "argv", argv):
                with patch.object(step2, "detect_build_tool", return_value="maven"):
                    with patch.object(step2, "auto_detect_source_dirs") as auto_detect:
                        with patch.object(step2, "detect_spring_boot_version", return_value=("2.7.18", "3.2.5", "step1_scope")):
                            with patch.object(step2, "detect_spring_cloud", return_value=(False, None)):
                                with patch.object(step2, "detect_jdk_versions", return_value=("8", "17")):
                                    with patch.object(step2, "detect_tech_flags", return_value={}):
                                        with patch.object(step2, "detect_jvm_param_changes", return_value=[]):
                                            step2.main()

            payload = json.loads(output_json.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["source_dirs"],
                [str(explicit_a), str(explicit_b)],
            )
            auto_detect.assert_not_called()

    def test_detect_jdk_versions_returns_unknown_without_git_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "pom.xml").write_text(
                "<project><properties><java.version>17</java.version></properties></project>",
                encoding="utf-8",
            )

            with patch.object(step2, "is_git_repo", return_value=False):
                jdk_base, jdk_current = step2.detect_jdk_versions(
                    "origin/main",
                    "feature/upgrade",
                    str(tmp_path),
                    "maven",
                )

        self.assertIsNone(jdk_base)
        self.assertIsNone(jdk_current)

    def test_parse_maven_help_evaluate_jdk_tolerates_noise(self):
        self.assertEqual(step2.parse_maven_help_evaluate_jdk("17"), "17")
        self.assertEqual(step2.parse_maven_help_evaluate_jdk("17%"), "17")
        self.assertEqual(
            step2.parse_maven_help_evaluate_jdk("null object or invalid expression"),
            None,
        )

    def test_detect_jdk_from_pom_resolves_property_chain_and_prefers_release(self):
        pom = """
        <project>
          <properties>
            <java.baseline>17</java.baseline>
            <java.version>${java.baseline}</java.version>
            <maven.compiler.source>11</maven.compiler.source>
            <maven.compiler.release>${java.version}</maven.compiler.release>
          </properties>
        </project>
        """

        self.assertEqual(step2.detect_jdk_from_pom(pom), "17")

    def test_detect_jdk_from_pom_resolves_compiler_plugin_property(self):
        pom = """
        <project>
          <properties>
            <bytecode.level>21</bytecode.level>
            <maven.compiler.source>11</maven.compiler.source>
            <java.version>8</java.version>
          </properties>
          <build><plugins><plugin>
            <artifactId>maven-compiler-plugin</artifactId>
            <configuration>
              <source>17</source>
              <target>${bytecode.level}</target>
            </configuration>
          </plugin></plugins></build>
        </project>
        """

        self.assertEqual(step2.detect_jdk_from_pom(pom), "21")

    def test_detect_jdk_from_pom_uses_highest_java_kotlin_bytecode_target(self):
        pom = """
        <project>
          <build><plugins>
            <plugin>
              <artifactId>maven-compiler-plugin</artifactId>
              <configuration><release>11</release></configuration>
            </plugin>
            <plugin>
              <artifactId>kotlin-maven-plugin</artifactId>
              <configuration><jvmTarget>17</jvmTarget></configuration>
            </plugin>
          </plugins></build>
        </project>
        """

        self.assertEqual(step2.detect_jdk_from_pom(pom), "17")

    def test_detect_jdk_from_malformed_pom_uses_narrow_diagnostic_fragment(self):
        malformed = (
            "<diagnostic><java.version>1.8</java.version>"
            "<unclosed>"
        )

        self.assertEqual(step2.detect_jdk_from_pom(malformed), "8")

    def test_detect_jdk_from_gradle_supports_toolchains_release_and_kotlin_dsl(self):
        self.assertEqual(
            step2.detect_jdk_from_gradle(
                """
                val targetJdk = JavaLanguageVersion.of(21)
                java {
                    toolchain.languageVersion.set(targetJdk)
                }
                """
            ),
            "21",
        )
        self.assertEqual(
            step2.detect_jdk_from_gradle(
                """
                java {
                    sourceCompatibility = JavaVersion.VERSION_1_8
                }
                tasks.withType<JavaCompile> {
                    options.release.set(17)
                }
                """
            ),
            "17",
        )
        self.assertEqual(
            step2.detect_jdk_from_gradle(
                "kotlin { jvmToolchain(21) }\n"
                "compilerOptions.jvmTarget.set(JvmTarget.JVM_17)\n"
            ),
            "17",
        )
        self.assertEqual(
            step2.detect_jdk_from_gradle(
                "targetCompatibility = JavaVersion.VERSION_11\n"
                "compilerOptions.jvmTarget.set(JvmTarget.JVM_17)\n"
            ),
            "17",
        )
        self.assertEqual(
            step2.detect_jdk_from_gradle(
                "tasks.configureEach { println(JvmTarget.JVM_21) }"
            ),
            "21",
        )

    def test_gradle_manifest_detection_reads_both_revisions(self):
        with patch.object(step2, "is_git_repo", return_value=True), patch.object(
            step2, "build_manifest_candidates", return_value=["app/build.gradle.kts"],
        ), patch.object(
            step2,
            "git_show_file",
            side_effect=[
                "java { sourceCompatibility = JavaVersion.VERSION_1_8 }",
                "java { sourceCompatibility = JavaVersion.VERSION_17 }",
            ],
        ) as show:
            base, current, _candidate = step2.detect_jdk_versions_from_manifests(
                "base-sha", "current-sha", ".", "gradle", strict_git=True,
            )

        self.assertEqual((base, current), ("8", "17"))
        self.assertEqual(
            [call.args[:2] for call in show.call_args_list],
            [
                ("base-sha", "app/build.gradle.kts"),
                ("current-sha", "app/build.gradle.kts"),
            ],
        )

    def test_detect_jdk_from_boot_artifact_reads_only_application_bytecode(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/com/example/Legacy.class",
                    self._class_bytes(55),
                )
                archive.writestr(
                    "BOOT-INF/classes/com/example/App.class",
                    self._class_bytes(61),
                )
                archive.writestr(
                    "META-INF/versions/21/com/example/App.class",
                    self._class_bytes(65),
                )
                archive.writestr(
                    "com/foreign/Higher.class",
                    self._class_bytes(65),
                )

            detected = step2.detect_jdk_from_artifact(artifact)

        self.assertEqual(detected["status"], "detected")
        self.assertEqual(detected["version"], "17")
        self.assertEqual(detected["class_count"], 2)
        self.assertEqual(detected["class_versions"], ["11", "17"])

    def test_artifact_jdk_evidence_comes_from_step1_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            dependencies = report_dir / "evidence" / "dependencies"
            context = report_dir / "evidence" / "context"
            dependencies.mkdir(parents=True)
            context.mkdir(parents=True)
            base_artifact = Path(tmp) / "base.jar"
            current_artifact = Path(tmp) / "current.jar"
            for artifact, major in ((base_artifact, 55), (current_artifact, 61)):
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr(
                        "BOOT-INF/classes/com/example/App.class",
                        self._class_bytes(major),
                    )
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "sides": [
                        {
                            "side": "base",
                            "artifact_path": str(base_artifact),
                            "jdk_home": "/jdks/21",
                        },
                        {
                            "side": "current",
                            "artifact_path": str(current_artifact),
                            "jdk_home": "/jdks/21",
                        },
                    ]
                }),
                encoding="utf-8",
            )

            evidence = step2.detect_artifact_jdk_evidence(
                context / "context.json"
            )

        self.assertEqual(evidence["base"]["version"], "11")
        self.assertEqual(evidence["current"]["version"], "17")
        self.assertEqual(evidence["base"]["build_runtime_jdk_home"], "/jdks/21")

    def test_main_uses_complete_artifact_pair_without_build_tool_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            dependencies = report_dir / "evidence" / "dependencies"
            context = report_dir / "evidence" / "context"
            dependencies.mkdir(parents=True)
            context.mkdir(parents=True)
            dep_changes = dependencies / "dep_changes.csv"
            output_json = context / "context.json"
            dep_changes.write_text(
                "coord,old_version,new_version,change_type,scope\n"
                "org.example:demo,1.0,2.0,升级,packaged\n",
                encoding="utf-8",
            )
            sides = []
            for side, major in (("base", 55), ("current", 61)):
                artifact = project_dir / f"{side}.jar"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr(
                        "BOOT-INF/classes/com/example/App.class",
                        self._class_bytes(major),
                    )
                sides.append({"side": side, "artifact_path": str(artifact)})
            (dependencies / "build_provenance.json").write_text(
                json.dumps({"sides": sides}),
                encoding="utf-8",
            )
            argv = [
                "s2_context_from_deps.py",
                "--dep-changes", str(dep_changes),
                "--base", "origin/main",
                "--current", "feature/upgrade",
                "--work-dir", str(project_dir),
                "--output", str(output_json),
            ]

            with patch.object(sys, "argv", argv), patch.object(
                step2, "detect_build_tool", return_value="maven"
            ), patch.object(
                step2,
                "detect_jdk_versions",
                side_effect=AssertionError("完整最终产物不应再启动构建工具探测"),
            ), patch.object(
                step2, "detect_spring_boot_version", return_value=(None, None, "not_found")
            ), patch.object(
                step2, "detect_spring_cloud", return_value=(False, None)
            ), patch.object(
                step2, "detect_tech_flags", return_value={}
            ), patch.object(
                step2, "detect_jvm_param_changes", return_value=[]
            ):
                step2.main()

            payload = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(payload["jdk_base"], "11")
        self.assertEqual(payload["jdk_current"], "17")
        self.assertEqual(payload["jdk_source"], "final_artifact_bytecode")
        self.assertEqual(
            payload["jdk_evidence"]["current"]["artifact"]["class_major_max"],
            61,
        )

    def test_final_artifact_wins_over_conflicting_build_declaration(self):
        selected = step2.select_jdk_evidence(
            {"base": "8", "current": "11"},
            {
                "base": {"version": "11", "status": "detected"},
                "current": {"version": "17", "status": "detected"},
            },
        )

        self.assertEqual(selected["base"]["version"], "11")
        self.assertEqual(selected["current"]["version"], "17")
        self.assertTrue(selected["base"]["evidence_conflict"])
        self.assertEqual(selected["base"]["source"], "final_artifact_bytecode")

    def test_effective_model_probe_uses_shared_worktree_runtime_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp) / "short-worktree"
            worktree.mkdir()
            (worktree / "pom.xml").write_text("<project/>", encoding="utf-8")
            with patch.object(step2, "get_git_root", return_value=tmp), \
                    patch.object(
                        step2, "create_detached_worktree", return_value=worktree,
                    ) as create_worktree, \
                    patch.object(
                        step2, "remove_detached_worktree",
                    ) as remove_worktree, \
                    patch.object(step2, "mvn_cmd", return_value=["mvn"]), \
                    patch.object(step2, "run_cmd", return_value=("17", "", 0)):
                detected = step2.resolve_maven_jdk_from_effective_model(
                    "feature/upgrade", tmp,
                )

        self.assertEqual("17", detected)
        create_worktree.assert_called_once()
        self.assertEqual(
            "s2-jdk", create_worktree.call_args.kwargs["label"],
        )
        remove_worktree.assert_called_once()

    def test_detect_jdk_versions_falls_back_to_effective_maven_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "pom.xml").write_text(
                "<project><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>",
                encoding="utf-8",
            )

            with patch.object(step2, "is_git_repo", return_value=True):
                with patch.object(
                    step2,
                    "git_show_file",
                    side_effect=[
                        "<project><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>",
                        "<project><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>",
                    ],
                ):
                    with patch.object(
                        step2,
                        "resolve_maven_jdk_from_effective_model",
                        side_effect=["11", "17"],
                    ) as resolver:
                        jdk_base, jdk_current = step2.detect_jdk_versions(
                            "origin/main",
                            "feature/upgrade",
                            str(tmp_path),
                            "maven",
                        )

        self.assertEqual(jdk_base, "11")
        self.assertEqual(jdk_current, "17")
        self.assertEqual(resolver.call_count, 2)

    def test_gate_context_allows_unknown_jdk_for_checkpoint_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            context_dir = report_dir / "evidence" / "context"
            context_dir.mkdir(parents=True)
            (context_dir / "context.json").write_text(
                json.dumps(
                    {
                        "build_tool": "maven",
                        "base_branch": "origin/main",
                        "current_branch": "feature/upgrade",
                        "jdk_base": "unknown",
                        "jdk_current": "unknown",
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            gate.gate_context(str(report_dir))

    def test_orchestrated_state_and_pinned_snapshot_boundary_matrix(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report"
            state_dir = report / ".runtime" / "state"
            state_dir.mkdir(parents=True)
            state = state_dir / step2.MAIN_STATE_FILE_NAME

            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(step2.load_orchestrated_step2_input(), {})
            with patch.dict(
                os.environ,
                {"JUA_ORCHESTRATED": "1", "UPGRADE_REPORT_DIR": ""},
                clear=True,
            ):
                self.assertEqual(step2.load_orchestrated_step2_input(), {})
                self.assertEqual(
                    step2.load_orchestrated_step2_input(
                        str(report / "evidence" / "context" / "context.json")
                    ),
                    {},
                )
            state.write_text("not-json", encoding="utf-8")
            with patch.dict(
                os.environ,
                {"JUA_ORCHESTRATED": "1", "UPGRADE_REPORT_DIR": str(report)},
                clear=True,
            ):
                self.assertEqual(step2.load_orchestrated_step2_input(), {})
                for payload, expected in (
                    (None, {}),
                    ({}, {}),
                    ({"step2": {}}, {}),
                    ({"step2": {"input": {"value": 1}}}, {"value": 1}),
                ):
                    state.write_text(json.dumps(payload), encoding="utf-8")
                    self.assertEqual(
                        step2.load_orchestrated_step2_input(), expected,
                    )

            normalize_cases = (
                (None, True, "."), ("./", False, ""),
                ("/absolute", True, ""), ("C:\\absolute", True, ""),
                ("a//./b", True, "a/b"), ("a/../b", True, ""),
                ("///", True, ""),
            )
            for value, allow_root, expected in normalize_cases:
                self.assertEqual(
                    step2._normalize_pinned_relative_path(
                        value, allow_root=allow_root,
                    ),
                    expected,
                )

            valid = {
                "schema": step2.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                "commit": commit.upper(),
                "project_path": ".",
                "source_roots": ["src/main/java", "src/main/java", "."],
            }
            self.assertEqual(
                step2._valid_pinned_source_snapshot(
                    {"pinned_source_snapshot": valid}, commit,
                )["source_roots"],
                ["src/main/java", "."],
            )
            invalid_snapshots = (
                None,
                {},
                {**valid, "schema": "wrong"},
                {**valid, "commit": "bad"},
                {**valid, "commit": 1},
                {**valid, "commit": "b" * 40},
                {key: value for key, value in valid.items() if key != "project_path"},
                {**valid, "project_path": None},
                {**valid, "project_path": "../escape"},
                {**valid, "source_roots": ["../escape"]},
                {**valid, "source_roots": "src/main/java"},
                {**valid, "source_roots": [None]},
                {**valid, "source_roots": [1]},
                {**valid, "source_roots": None},
            )
            for snapshot in invalid_snapshots:
                self.assertEqual(
                    step2._valid_pinned_source_snapshot(
                        {"pinned_source_snapshot": snapshot}, commit,
                    ),
                    {},
                )

            self.assertEqual(
                step2._pinned_source_repository(
                    {"current_ref_binding": {"repo_dir": str(root)}},
                    root / "fallback",
                ),
                root.resolve(),
            )
            self.assertEqual(
                step2._pinned_source_repository(
                    {
                        "current_ref_binding": {"repo_dir": ""},
                        "current_source_project_dir": str(report),
                    },
                    root / "fallback",
                ),
                report.resolve(),
            )
            self.assertEqual(
                step2._pinned_source_repository({}, root / "fallback"),
                (root / "fallback").resolve(),
            )

    def test_dependency_rows_graph_and_source_discovery_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.csv"
            with self.assertRaises(SystemExit):
                step2.load_dep_changes(missing)

            empty = root / "empty.csv"
            empty.write_text("coord,resolution_status\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                step2.load_dep_changes(empty)

            rows = root / "rows.csv"
            rows.write_text(
                "coord,resolution_status,old_version,new_version,change_type,scope\n"
                "# comment,,1,2,升级,compile\n"
                "ignored:unresolved,unresolved,1,2,升级,compile\n"
                "g:a,,1,2,升级,\n"
                "g:stable,,1,1,未变,compile\n",
                encoding="utf-8",
            )
            loaded = step2.load_dep_changes(rows)
            self.assertEqual(set(loaded), {"g:a", "g:stable"})

            duplicate = root / "duplicate.csv"
            duplicate.write_text(
                "coord,old_version,new_version,change_type\n"
                "g:a,1,2,升级\n"
                "g:a,2,3,升级\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "<unknown>"):
                step2.load_dep_changes(duplicate)

            graph = step2.build_dep_graph({
                "g:unchanged": {
                    "change_type": "未变", "old_version": "1",
                    "new_version": "1",
                },
                "g:none": {
                    "change_type": "升级", "old_version": "-",
                    "new_version": "-",
                },
                "invalid": {
                    "change_type": "升级", "old_version": "1",
                    "new_version": "2",
                },
                "g:changed": {
                    "change_type": "升级", "old_version": "1",
                    "new_version": "2",
                },
            })
            self.assertEqual(graph["analysis_order"], ["g:changed"])
            self.assertTrue(graph["dependencies"][0]["is_leaf"])
            self.assertEqual(graph["dependencies"][0]["scope"], "compile")
            self.assertEqual(
                step2.build_dep_graph({"g:a": {"change_type": "未变"}})[
                    "total_dependencies"
                ],
                0,
            )
            self.assertEqual(
                step2.topological_sort(
                    ["a", "b", "c"], [("a", "b"), ("b", "c")],
                ),
                ["a", "b", "c"],
            )
            cycle = step2.topological_sort(
                ["a", "b"], [("a", "b"), ("b", "a")],
            )
            self.assertEqual(set(cycle), {"a", "b"})

            changed = step2.collect_changed_dependencies({
                "": {"change_type": "升级", "old_version": "1", "new_version": "2"},
                "g": {"change_type": "升级", "old_version": "1", "new_version": "2"},
                "g:a": {"change_type": "升级", "old_version": "1", "new_version": "2"},
                "g:none": {"change_type": "升级", "old_version": "-", "new_version": "-"},
                "g:stable": {"change_type": "", "old_version": "1", "new_version": "1"},
            })
            self.assertEqual(
                [(item["group_id"], item["artifact_id"]) for item in changed],
                [("", ""), ("g", ""), ("g", "a")],
            )

            java = root / "module" / "src" / "main" / "java"
            kotlin = root / "module" / "src" / "main" / "kotlin"
            groovy = root / "other" / "src" / "main" / "groovy"
            empty_source = root / "empty" / "src" / "main" / "java"
            skipped = root / "target" / "src" / "main" / "java"
            for directory in (java, kotlin, groovy, empty_source, skipped):
                directory.mkdir(parents=True)
            (java / "A.java").write_text("class A {}", encoding="utf-8")
            (kotlin / "B.kt").write_text("class B", encoding="utf-8")
            (groovy / "C.groovy").write_text("class C {}", encoding="utf-8")
            (skipped / "Ignored.java").write_text(
                "class Ignored {}", encoding="utf-8",
            )
            detected = set(step2.auto_detect_source_dirs(str(root), "maven"))
            self.assertEqual(detected, {str(java), str(kotlin), str(groovy)})
            self.assertEqual(step2.auto_detect_source_dirs("", "maven"), [])

    def test_version_git_and_build_detection_boundary_matrix(self):
        boot = "org.springframework.boot:spring-boot"
        self.assertEqual(
            step2.detect_spring_boot_version({
                boot: {"old_version": "-", "new_version": "-"},
            }),
            (None, None, "step1_scope"),
        )
        self.assertEqual(
            step2.detect_spring_boot_version({}),
            (None, None, "not_found"),
        )
        self.assertEqual(
            step2.detect_spring_cloud({
                "org.springframework.cloud:spring-cloud-context-extra": {
                    "new_version": "", "old_version": "2024.0",
                },
            }),
            (True, "2024.0"),
        )
        self.assertEqual(step2.detect_spring_cloud({}), (False, None))

        for args, expected in (
            ((None, None, None, None), (False, False, False)),
            (("2.7", "3.2", "8", "17"), (True, True, True)),
            (("bad", "still-bad", "unknown", "17"), (True, False, False)),
            (("3", "2", "17", "17"), (True, False, False)),
        ):
            self.assertEqual(step2.compute_version_flags(*args), expected)

        normalize = {
            None: None, "": None, "null": None, "unknown": None,
            '"1_8"': "8", "17.0": "17", "0": None,
            "100": None, "17.1": None,
        }
        for value, expected in normalize.items():
            self.assertEqual(step2.normalize_jdk_version(value), expected)
        for value, expected in ((44, None), (45, "1"), (143, "99"), (144, None), ("bad", None)):
            self.assertEqual(step2.jdk_version_from_class_major(value), expected)

        with patch.object(
            step2, "run_cmd", return_value=("content", "", 0),
        ):
            self.assertEqual(step2.git_show_file("main", "pom.xml"), "content")
        with patch.object(
            step2, "run_cmd", return_value=("", "missing", 1),
        ):
            self.assertEqual(step2.git_show_file("main", "pom.xml"), "")
        with patch.object(
            step2, "run_cmd", return_value=("true\n", "", 0),
        ):
            self.assertTrue(step2.is_git_repo("."))
        with patch.object(
            step2, "run_cmd", return_value=("/repo\n", "", 0),
        ):
            self.assertEqual(step2.get_git_root("."), "/repo")
        with patch.object(
            step2, "run_cmd", return_value=("", "failure", 1),
        ):
            self.assertEqual(step2.get_git_root("."), "")
            with self.assertRaisesRegex(RuntimeError, "ROOT_DISCOVERY"):
                step2.get_git_root(".", strict_git=True)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module = root / "module"
            module.mkdir()
            with patch.object(step2, "get_git_root", return_value=str(root)):
                self.assertEqual(
                    step2.get_repo_relative_prefix(module), "module",
                )
                self.assertEqual(
                    step2.build_manifest_candidates(
                        module, "pom.xml", "pom.xml",
                    ),
                    ["module/pom.xml", "pom.xml"],
                )
            local = module / "bad.txt"
            local.write_text("value", encoding="utf-8")
            with patch.object(
                step2, "open_text", side_effect=[OSError("bad"), io.StringIO("ok")],
            ):
                self.assertEqual(
                    step2.read_local_file(module, "bad.txt", "bad.txt"),
                    "ok",
                )
            self.assertEqual(step2.read_local_file(module, "missing"), "")

            (root / "pom.xml").write_text("<project/>", encoding="utf-8")
            self.assertEqual(step2.detect_build_tool("main", root), "maven")
            (root / "pom.xml").unlink()
            (root / "build.gradle.kts").write_text("", encoding="utf-8")
            self.assertEqual(step2.detect_build_tool("main", root), "gradle")

        command_rows = iter([
            ("", "path does not exist in revision", 1),
            ("build.gradle\n", "", 0),
        ])
        with (
            patch.object(step2, "is_git_repo", return_value=True),
            patch.object(
                step2, "build_manifest_candidates",
                side_effect=[["pom.xml"], ["build.gradle", "build.gradle.kts"]],
            ),
            patch.object(step2, "run_cmd", side_effect=lambda *_a, **_k: next(command_rows)),
        ):
            self.assertEqual(step2.detect_build_tool("a" * 40, "/repo"), "gradle")
        with (
            patch.object(step2, "is_git_repo", return_value=True),
            patch.object(step2, "build_manifest_candidates", return_value=["pom.xml"]),
            patch.object(step2, "run_cmd", return_value=("", "fatal", 2)),
        ):
            with self.assertRaisesRegex(RuntimeError, "GIT_SHOW_FAILED"):
                step2.detect_build_tool("a" * 40, "/repo", strict_git=True)

        with patch.object(step2, "is_git_repo", return_value=False):
            self.assertEqual(step2.detect_jvm_param_changes("a", "b", "."), [])
        diff = (
            "+++ file\n--- file\n+java -XX:+UseG1GC -XX:MaxRAM=1g\n"
            "-java -XX:+UseG1GC\n context"
        )
        with (
            patch.object(step2, "is_git_repo", return_value=True),
            patch.object(step2, "run_cmd", return_value=(diff, "", 0)),
        ):
            self.assertEqual(
                step2.detect_jvm_param_changes("a", "b", "."),
                ["-XX:+UseG1GC", "-XX:MaxRAM=1g"],
            )

    def test_jdk_manifest_artifact_and_selection_boundary_matrix(self):
        self.assertIsNone(step2.detect_jdk_from_pom(""))
        self.assertEqual(
            step2.detect_jdk_from_pom(
                "<project><properties>"
                "<a>${b}</a><b>${a}</b><java.version>${a}</java.version>"
                "</properties></project>"
            ),
            None,
        )
        self.assertEqual(
            step2.detect_jdk_from_pom(
                "<java.version>1_8</java.version>"
            ),
            "8",
        )
        self.assertIsNone(step2.detect_jdk_from_gradle(""))
        self.assertEqual(
            step2.detect_jdk_from_gradle(
                "// sourceCompatibility = 8\n"
                "sourceCompatibility = JavaVersion.toVersion('17')\n"
                "kotlinOptions.jvmTarget = JvmTarget.JVM_21\n"
            ),
            "21",
        )
        self.assertEqual(
            step2.detect_jdk_from_gradle(
                "java { toolchain { languageVersion = "
                "JavaLanguageVersion.of(11) } }"
            ),
            "11",
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = step2.detect_jdk_from_artifact(root / "missing.jar")
            self.assertEqual(missing["status"], "artifact_missing")
            invalid = root / "invalid.jar"
            invalid.write_text("bad", encoding="utf-8")
            self.assertEqual(
                step2.detect_jdk_from_artifact(invalid)["status"],
                "invalid_archive",
            )

            no_classes = root / "no-classes.jar"
            with zipfile.ZipFile(no_classes, "w") as archive:
                archive.writestr("META-INF/value.txt", "x")
                archive.writestr("bad/Short.class", b"short")
                archive.writestr("bad/Magic.class", b"12345678")
            self.assertEqual(
                step2.detect_jdk_from_artifact(no_classes)["status"],
                "no_application_classes",
            )

            war = root / "app.war"
            with zipfile.ZipFile(war, "w") as archive:
                archive.writestr(
                    "WEB-INF/classes/app/Main.class", self._class_bytes(61),
                )
                archive.writestr(
                    "WEB-INF/lib/dep.class", self._class_bytes(65),
                )
                archive.writestr(
                    "META-INF/versions/21/app/Main.class", self._class_bytes(65),
                )
            detected = step2.detect_jdk_from_artifact(war)
            self.assertEqual(detected["version"], "17")
            self.assertEqual(detected["class_count"], 1)

            report = root / "report"
            context = report / "evidence" / "context"
            deps = report / "evidence" / "dependencies"
            context.mkdir(parents=True)
            deps.mkdir(parents=True)
            output = context / "context.json"
            provenance = deps / "build_provenance.json"
            provenance.write_text(
                json.dumps({"sides": [
                    None,
                    {"side": "other", "artifact_path": str(war)},
                    {"side": "base", "artifact_path": ""},
                    {
                        "side": "current", "artifact_path": str(war),
                        "jdk_home": None, "build_tool": None,
                        "revision": None,
                    },
                ]}),
                encoding="utf-8",
            )
            evidence = step2.detect_artifact_jdk_evidence(output)
            self.assertEqual(evidence["current"]["version"], "17")
            self.assertEqual(evidence["current"]["build_tool"], "")
            provenance.write_text("bad-json", encoding="utf-8")
            self.assertEqual(step2.detect_artifact_jdk_evidence(output), {})
            for malformed in ([], {"sides": None}, {"sides": {}}, {"sides": ["bad"]}):
                provenance.write_text(json.dumps(malformed), encoding="utf-8")
                self.assertEqual(step2.detect_artifact_jdk_evidence(output), {})

        selected = step2.select_jdk_evidence(
            {"base": "8", "current": None},
            {"base": {"version": "11"}, "current": {}},
            {"base": "17", "current": None},
        )
        self.assertEqual(selected["base"]["source"], "user_confirmed")
        self.assertTrue(selected["base"]["evidence_conflict"])
        self.assertEqual(selected["current"]["source"], "not_found")

        self.assertIsNone(step2.parse_maven_help_evaluate_jdk(""))
        self.assertIsNone(step2.parse_maven_help_evaluate_jdk("no version"))
        self.assertEqual(
            step2.parse_maven_help_evaluate_jdk("noise\n11\n17%"), "17",
        )

    def test_git_commit_and_repository_helper_boundary_matrix(self):
        commit40 = "a" * 40
        commit64 = "b" * 64
        self.assertFalse(step2._git_path_is_absent(None))
        self.assertFalse(step2._git_path_is_absent("unrelated failure"))
        for message in step2._GIT_PATH_ABSENT_PATTERNS:
            self.assertTrue(step2._git_path_is_absent(message.upper()))

        for revision, side in ((None, ""), ("", "base"), ("g" * 40, "current")):
            with self.assertRaisesRegex(RuntimeError, "COMMIT_NOT_PINNED"):
                step2.require_pinned_git_commit(revision, side=side)

        with patch.object(step2, "run_cmd", return_value=(commit40.upper(), "", 0)):
            self.assertEqual(
                step2.require_pinned_git_commit(commit40.upper(), side="base"),
                commit40,
            )
        with patch.object(step2, "run_cmd", return_value=(commit64, "", 0)):
            self.assertEqual(step2.require_pinned_git_commit(commit64), commit64)
        for result in (
            ("", "missing object", 1),
            (commit40, "", 1),
            ("c" * 40, "", 0),
            ("", "", 2),
        ):
            with patch.object(step2, "run_cmd", return_value=result):
                with self.assertRaisesRegex(RuntimeError, "COMMIT_UNAVAILABLE"):
                    step2.require_pinned_git_commit(commit40, side="current")

        repo_cases = (
            (("true", "", 0), True),
            (("TRUE\n", "", 0), True),
            (("false", "", 0), False),
            (("", "fatal", 1), False),
        )
        for result, expected in repo_cases:
            with patch.object(step2, "run_cmd", return_value=result):
                self.assertIs(step2.is_git_repo("/repo"), expected)
        for result in (("false", "", 0), ("", "", 3)):
            with patch.object(step2, "run_cmd", return_value=result):
                with self.assertRaisesRegex(RuntimeError, "REPOSITORY_PROBE"):
                    step2.is_git_repo("/repo", strict_git=True)

        for result, expected in (
            (("/repo\n", "", 0), "/repo"),
            (("", "", 0), ""),
            (("ignored", "fatal", 2), ""),
        ):
            with patch.object(step2, "run_cmd", return_value=result):
                self.assertEqual(step2.get_git_root("/work"), expected)
        for result in (("", "stdout detail", 0), ("", "", 1)):
            with patch.object(step2, "run_cmd", return_value=result):
                with self.assertRaisesRegex(RuntimeError, "ROOT_DISCOVERY"):
                    step2.get_git_root("/work", strict_git=True)

        with patch.object(step2, "get_git_root", return_value=""):
            self.assertEqual(step2.get_repo_relative_prefix("/work"), "")
        with patch.object(step2, "get_git_root", return_value="/repo"), patch.object(
            step2.os.path, "relpath", return_value=".",
        ):
            self.assertEqual(step2.get_repo_relative_prefix("/repo"), "")
        with patch.object(step2, "get_git_root", return_value="/repo"), patch.object(
            step2.os.path, "relpath", side_effect=ValueError("different drive"),
        ):
            self.assertEqual(step2.get_repo_relative_prefix("D:/work"), "")
            with self.assertRaisesRegex(RuntimeError, "OUTSIDE_ROOT"):
                step2.get_repo_relative_prefix("D:/work", strict_git=True)

        with patch.object(
            step2, "run_cmd", return_value=("", "path not in the working tree", 1),
        ):
            self.assertEqual(
                step2.git_show_file(commit40, "missing", strict_git=True), "",
            )
        for result in (("stdout detail", "", 1), ("", "", 1)):
            with patch.object(step2, "run_cmd", return_value=result):
                with self.assertRaisesRegex(RuntimeError, "GIT_SHOW_FAILED"):
                    step2.git_show_file(commit40, "pom.xml", strict_git=True)

    def test_build_tool_and_jvm_diff_boundary_matrix(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build.gradle").write_text("", encoding="utf-8")
            self.assertEqual(step2.detect_build_tool("branch", root), "gradle")

        with patch.object(step2, "is_git_repo", return_value=False):
            self.assertEqual(step2.detect_build_tool(commit, "/repo"), "unknown")

        show_rows = iter([
            ("", "does not exist in revision", 1),
            ("<project/>", "", 0),
        ])
        with patch.object(step2, "is_git_repo", return_value=True), patch.object(
            step2, "build_manifest_candidates", return_value=["module/pom.xml", "pom.xml"],
        ), patch.object(
            step2, "run_cmd", side_effect=lambda *_args, **_kwargs: next(show_rows),
        ):
            self.assertEqual(step2.detect_build_tool(commit, "/repo", strict_git=True), "maven")

        for tree_result, strict, expected in (
            (("other\nbuild.gradle.kts\n", "", 0), False, "gradle"),
            (("other\n", "", 0), False, "unknown"),
            (("", "tree failed", 2), False, "unknown"),
        ):
            rows = iter([("", "does not exist in revision", 1), tree_result])
            with patch.object(step2, "is_git_repo", return_value=True), patch.object(
                step2,
                "build_manifest_candidates",
                side_effect=[["pom.xml"], ["build.gradle", "build.gradle.kts"]],
            ), patch.object(
                step2, "run_cmd", side_effect=lambda *_args, **_kwargs: next(rows),
            ):
                self.assertEqual(
                    step2.detect_build_tool(commit, "/repo", strict_git=strict),
                    expected,
                )
        for tree_result in (("tree output", "", 2), ("", "", 2)):
            rows = iter([("", "does not exist in revision", 1), tree_result])
            with patch.object(step2, "is_git_repo", return_value=True), patch.object(
                step2, "build_manifest_candidates", side_effect=[["pom.xml"], ["build.gradle"]],
            ), patch.object(
                step2, "run_cmd", side_effect=lambda *_args, **_kwargs: next(rows),
            ):
                with self.assertRaisesRegex(RuntimeError, "GIT_LS_TREE_FAILED"):
                    step2.detect_build_tool(commit, "/repo", strict_git=True)

        for result in (("", "diff failed", 2), ("diff output", "", 2)):
            with patch.object(step2, "is_git_repo", return_value=True), patch.object(
                step2, "run_cmd", return_value=result,
            ):
                self.assertEqual(step2.detect_jvm_param_changes("a", "b", "."), [])
                with self.assertRaisesRegex(RuntimeError, "GIT_DIFF_FAILED"):
                    step2.detect_jvm_param_changes("a", "b", ".", strict_git=True)
        with patch.object(step2, "is_git_repo", return_value=True), patch.object(
            step2, "run_cmd", return_value=("", "", 0),
        ):
            self.assertEqual(step2.detect_jvm_param_changes("a", "b", "."), [])
        harmless = "+++ file\n--- file\n context\n+java -Xmx1g\n"
        with patch.object(step2, "is_git_repo", return_value=True), patch.object(
            step2, "run_cmd", return_value=(harmless, "", 0),
        ):
            self.assertEqual(step2.detect_jvm_param_changes("a", "b", "."), [])

    def test_dependency_technology_and_source_walk_boundary_matrix(self):
        all_technologies = {
            "org.projectlombok:lombok": {},
            "org.glassfish.jaxb:jaxb-runtime": {},
            "net.bytebuddy:byte-buddy": {},
            "org.javassist:javassist": {},
            "org.aspectj:aspectjrt": {},
            "com.alibaba:dubbo": {},
            "io.netty:netty-common": {},
            "io.grpc:grpc-stub": {},
            "org.springframework.cloud:spring-cloud-starter": {},
            "com.alibaba.fastjson2:fastjson2": {},
            "org.mapstruct:mapstruct": {},
            "com.baomidou:mybatis-plus": {},
            "com.alibaba.cloud:spring-cloud-starter-alibaba-nacos-discovery": {},
            "com.alibaba.cloud:spring-cloud-starter-alibaba-sentinel": {},
            "org.apache.rocketmq:rocketmq-spring-boot-starter": {},
            "org.springframework.kafka:spring-kafka": {},
            "co.elastic.clients:elasticsearch-java": {},
            "redis.clients:jedis": {},
        }
        self.assertTrue(all(step2.detect_tech_flags(all_technologies).values()))
        self.assertFalse(any(step2.detect_tech_flags({}).values()))
        self.assertEqual(
            step2.detect_spring_cloud({
                "unrelated:artifact": {},
                "org.springframework.cloud:spring-cloud-commons-addon": {
                    "new_version": "", "old_version": "",
                },
            }),
            (True, ""),
        )
        self.assertEqual(
            step2.detect_spring_cloud({
                "org.springframework.cloud:spring-cloud-starter": {
                    "new_version": "2025.0", "old_version": "2024.0",
                },
            }),
            (True, "2025.0"),
        )

        graph = step2.build_dep_graph({
            "not-a-coordinate": {
                "change_type": "升级", "old_version": "1", "new_version": "2",
            },
            "g:a": {
                "change_type": "升级", "old_version": "1", "new_version": "2",
            },
        })
        self.assertEqual(graph["analysis_order"], ["g:a"])
        mixed = step2.topological_sort(
            ["root", "cycle-a", "cycle-b"],
            [("cycle-a", "cycle-b"), ("cycle-b", "cycle-a")],
        )
        self.assertEqual(mixed[0], "root")
        self.assertEqual(set(mixed[1:]), {"cycle-a", "cycle-b"})
        changed = step2.collect_changed_dependencies({
            "g:a:b": {
                "change_type": "升级", "old_version": "1", "new_version": "2",
            },
        })
        self.assertEqual(changed[0]["artifact_id"], "a")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "main" / "java"
            source.mkdir(parents=True)
            (source / "A.java").write_text("class A {}", encoding="utf-8")
            outer = iter([(str(root), [], []), (str(root), [], [])])
            first_inner = iter([(str(source), [], ["A.java"])])
            second_inner = iter([(str(source), [], ["A.java"])])
            with patch.object(
                step2.os,
                "walk",
                side_effect=[outer, first_inner, second_inner],
            ):
                self.assertEqual(
                    step2.auto_detect_source_dirs(str(root), "maven"),
                    [str(source)],
                )
            outer = iter([(str(root), [], [])])
            with patch.object(step2.os, "walk", side_effect=[outer, OSError("denied")]), patch.object(
                step2.os.path, "isdir", side_effect=[True, False, False],
            ):
                self.assertEqual(step2.auto_detect_source_dirs(str(root), "maven"), [])
            with patch.object(step2.os.path, "isabs", return_value=False), patch.object(
                step2.os.path, "abspath", return_value=str(root),
            ), patch.object(step2.os, "walk", return_value=iter(())):
                self.assertEqual(step2.auto_detect_source_dirs("relative", "gradle"), [])

    def test_maven_xml_and_gradle_expression_boundary_matrix(self):
        self.assertEqual(step2._xml_local_name(None), "")
        self.assertEqual(step2._xml_local_name("{urn:test}name"), "name")
        root = step2.ET.fromstring("<root><first/><second/></root>")
        self.assertIsNone(step2._direct_xml_child(None, "first"))
        self.assertIsNone(step2._direct_xml_child(root, "missing"))
        self.assertEqual(step2._direct_xml_child(root, "second").tag, "second")

        self.assertEqual(step2._resolve_maven_property("17", {}), "17")
        self.assertIsNone(step2._resolve_maven_property("${   }", {}))
        self.assertIsNone(step2._resolve_maven_property("${missing}", {}))
        self.assertIsNone(step2._resolve_maven_property("${a}", {"a": "${a}"}))
        self.assertIsNone(step2._resolve_maven_property("${a}", {"a": None}))
        chain = {f"k{i}": f"${{k{i + 1}}}" for i in range(12)}
        chain["k12"] = "17"
        self.assertIsNone(step2._resolve_maven_property("${k0}", chain))

        self.assertIsNone(step2.detect_jdk_from_pom("<project/>"))
        self.assertIsNone(step2.detect_jdk_from_pom(
            "<project><properties><empty/></properties><build><plugins>"
            "<plugin><configuration><release>17</release></configuration></plugin>"
            "<plugin><artifactId>irrelevant</artifactId></plugin>"
            "</plugins></build></project>"
        ))
        self.assertEqual(
            step2.detect_jdk_from_pom(
                "<project><properties><jdk.version>11</jdk.version></properties></project>"
            ),
            "11",
        )
        self.assertEqual(
            step2.detect_jdk_from_pom(
                "<project><properties><javaVersion>17</javaVersion></properties></project>"
            ),
            "17",
        )
        self.assertEqual(
            step2.detect_jdk_from_pom(
                "<project><build><plugins><plugin>"
                "<artifactId>kotlin-maven-plugin</artifactId>"
                "<configuration><jvmTarget>21</jvmTarget><jvmTarget>17</jvmTarget></configuration>"
                "</plugin></plugins></build></project>"
            ),
            "21",
        )
        self.assertIsNone(step2.detect_jdk_from_pom("<broken>without-version"))

        gradle_cases = (
            ("// targetCompatibility = 17", None),
            ("options.release = 17", "17"),
            ("targetCompatibility 11", "11"),
            ("val target = 21\ncompilerOptions.jvmTarget.set(target)", "21"),
            ("val target = 17\nval target = 17\ntargetCompatibility = target", "17"),
            ("val target = missing\ncompilerOptions.jvmTarget.set(target)", None),
            ("targetCompatibility = notAVersion()", None),
            ("java { toolchain { languageVersion.set(JavaLanguageVersion.of('17')) } }", "17"),
            ("kotlin { jvmToolchain(JavaVersion.VERSION_11) }", "11"),
            ("println('nothing relevant')", None),
        )
        for content, expected in gradle_cases:
            self.assertEqual(step2.detect_jdk_from_gradle(content), expected)
        self.assertEqual(
            step2.detect_jdk_from_gradle(
                "a = b\nb = c\nc = d\nd = 17\ntargetCompatibility = a"
            ),
            "17",
        )

    def test_artifact_archive_and_provenance_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ordinary = root / "ordinary.jar"
            with zipfile.ZipFile(ordinary, "w") as archive:
                archive.writestr("empty/", b"")
                archive.writestr("readme.txt", b"text")
                archive.writestr("META-INF/Version.class", self._class_bytes(65))
                archive.writestr("BOOT-INF/lib/Dep.class", self._class_bytes(65))
                archive.writestr("WEB-INF/lib/Dep.class", self._class_bytes(65))
                archive.writestr("bad/Old.class", self._class_bytes(44))
                archive.writestr("app/Main.class", self._class_bytes(61))
                archive.writestr("app/Main2.class", self._class_bytes(61))
            detected = step2.detect_jdk_from_artifact(ordinary)
            self.assertEqual(detected["version"], "17")
            self.assertEqual(detected["class_count"], 2)
            with patch.object(zipfile.ZipFile, "open", side_effect=RuntimeError("entry failed")):
                self.assertEqual(
                    step2.detect_jdk_from_artifact(ordinary)["status"],
                    "no_application_classes",
                )
            self.assertEqual(
                step2.detect_jdk_from_artifact(None)["status"], "artifact_missing",
            )

            report = root / "report"
            dependencies = report / "evidence" / "dependencies"
            context = report / "evidence" / "context"
            dependencies.mkdir(parents=True)
            context.mkdir(parents=True)
            relative_artifact = dependencies / "relative.jar"
            relative_artifact.write_bytes(ordinary.read_bytes())
            provenance = dependencies / "build_provenance.json"
            provenance.write_text(json.dumps({"sides": [{
                "side": "base", "artifact_path": "relative.jar",
                "jdk_home": "/jdk", "build_tool": "maven", "revision": "base",
            }]}), encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                candidates = list(step2._build_provenance_candidates(context / "context.json"))
                self.assertEqual(candidates[0], provenance.resolve())
                evidence = step2.detect_artifact_jdk_evidence(context / "context.json")
            self.assertEqual(evidence["base"]["version"], "17")
            self.assertEqual(evidence["base"]["revision"], "base")

            with patch.dict(
                os.environ,
                {"UPGRADE_REPORT_DIR": str(report.resolve())},
                clear=True,
            ):
                deduped = list(step2._build_provenance_candidates(context / "context.json"))
            self.assertEqual(deduped.count(provenance.resolve()), 1)
            self.assertEqual(list(step2._build_provenance_candidates("")), [])
            self.assertEqual(
                list(step2._build_provenance_candidates(root / "out.json")),
                [root.resolve() / "build_provenance.json"],
            )
            nested_context = root / "context" / "out.json"
            self.assertEqual(
                list(step2._build_provenance_candidates(nested_context)),
                [nested_context.resolve().parent / "build_provenance.json"],
            )

        selected = step2.select_jdk_evidence(
            {"base": "8", "current": "17"},
            {"base": {"version": "11"}},
            {},
        )
        self.assertEqual(selected["base"]["source"], "final_artifact_bytecode")
        self.assertTrue(selected["base"]["evidence_conflict"])
        self.assertEqual(selected["current"]["source"], "build_model")
        self.assertFalse(selected["current"]["evidence_conflict"])
        none_selected = step2.select_jdk_evidence(None, None, None)
        self.assertIsNone(none_selected["base"]["version"])

    def test_effective_model_and_manifest_resolution_boundary_matrix(self):
        with patch.object(step2, "get_git_root", return_value="/repo"), patch.object(
            step2, "create_detached_worktree", side_effect=RuntimeError("busy"),
        ):
            for pom_relpath in (None, "", "   "):
                self.assertIsNone(
                    step2.resolve_maven_jdk_from_effective_model(
                        "branch", "/repo", pom_relpath,
                    )
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = root / "worktree"
            (worktree / "module").mkdir(parents=True)
            (worktree / "module" / "pom.xml").write_text("<project/>", encoding="utf-8")
            rows = iter([
                ("", "failed", 1),
                ("not a version", "", 0),
                ("17%", "", 0),
            ])
            with patch.object(step2, "get_git_root", return_value=""), patch.object(
                step2, "create_detached_worktree", return_value=worktree,
            ), patch.object(step2, "mvn_cmd", return_value=["mvn"]), patch.object(
                step2, "run_cmd", side_effect=lambda *_args, **_kwargs: next(rows),
            ), patch.object(step2, "remove_detached_worktree") as remove:
                self.assertEqual(
                    step2.resolve_maven_jdk_from_effective_model(
                        "branch", str(root), " module/pom.xml "
                    ),
                    "17",
                )
                remove.assert_called_once()

            rows = iter([("noise", "", 0)] * 6)
            with patch.object(step2, "get_git_root", return_value=str(root)), patch.object(
                step2, "create_detached_worktree", return_value=worktree,
            ), patch.object(step2, "mvn_cmd", return_value=["mvn"]), patch.object(
                step2, "run_cmd", side_effect=lambda *_args, **_kwargs: next(rows),
            ), patch.object(step2, "remove_detached_worktree") as remove:
                self.assertIsNone(
                    step2.resolve_maven_jdk_from_effective_model(
                        "branch", str(root), "missing.xml"
                    )
                )
                remove.assert_called_once()

        pom8 = "<project><properties><java.version>8</java.version></properties></project>"
        pom17 = "<project><properties><java.version>17</java.version></properties></project>"
        with patch.object(step2, "is_git_repo", return_value=True), patch.object(
            step2, "build_manifest_candidates", return_value=["one.xml", "two.xml"],
        ), patch.object(
            step2, "git_show_file", side_effect=["", "", pom8, pom17],
        ):
            self.assertEqual(
                step2.detect_jdk_versions_from_manifests("base", "cur", ".", "maven"),
                ("8", "17", "two.xml"),
            )
        with patch.object(step2, "is_git_repo", return_value=True), patch.object(
            step2, "build_manifest_candidates", return_value=["pom.xml"],
        ), patch.object(step2, "git_show_file", side_effect=["", pom17]):
            self.assertEqual(
                step2.detect_jdk_versions_from_manifests("base", "cur", ".", "maven"),
                (None, "17", "pom.xml"),
            )
        with patch.object(step2, "is_git_repo", return_value=True), patch.object(
            step2, "build_manifest_candidates", return_value=[],
        ):
            self.assertEqual(
                step2.detect_jdk_versions_from_manifests("base", "cur", ".", "maven"),
                (None, None, "pom.xml"),
            )
        with patch.object(step2, "is_git_repo", return_value=True), patch.object(
            step2,
            "build_manifest_candidates",
            return_value=["one.gradle", "two.gradle", "three.gradle"],
        ), patch.object(
            step2,
            "git_show_file",
            side_effect=["targetCompatibility = 8", "", "targetCompatibility = 17"],
        ) as show:
            result = step2.detect_jdk_versions_from_manifests(
                "base", "cur", ".", "gradle"
            )
            self.assertEqual(result[:2], ("8", "17"))
            self.assertEqual(show.call_count, 3)

        for manifest_result, resolved, expected_calls in (
            ((None, None, "pom.xml"), ["8", "17"], 2),
            (("8", None, "pom.xml"), ["17"], 1),
            ((None, "17", "pom.xml"), ["8"], 1),
            (("8", "17", "pom.xml"), [], 0),
        ):
            with patch.object(
                step2, "detect_jdk_versions_from_manifests", return_value=manifest_result,
            ), patch.object(step2, "is_git_repo", return_value=True), patch.object(
                step2, "resolve_maven_jdk_from_effective_model", side_effect=resolved,
            ) as resolve:
                result = step2.detect_jdk_versions("base", "cur", ".", "maven")
                self.assertEqual(result, ("8", "17"))
                self.assertEqual(resolve.call_count, expected_calls)
        with patch.object(
            step2, "detect_jdk_versions_from_manifests", return_value=(None, None, "build.gradle"),
        ), patch.object(step2, "is_git_repo") as repo:
            self.assertEqual(
                step2.detect_jdk_versions("base", "cur", ".", "gradle"),
                (None, None),
            )
            repo.assert_not_called()

    def test_pinned_workspace_missing_and_empty_root_boundaries(self):
        commit = "d" * 40
        with step2.materialize_pinned_step2_source_workspace({}, commit, ".") as value:
            self.assertIsNone(value)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            worktree = root / "worktree"
            repository.mkdir()
            worktree.mkdir()
            base = {
                "current_ref_binding": {"repo_dir": str(repository)},
                "pinned_source_snapshot": {
                    "schema": step2.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                    "commit": commit,
                    "project_path": ".",
                    "source_roots": [],
                },
            }
            with patch.object(step2, "get_git_root", return_value=str(repository)), patch.object(
                step2, "create_detached_worktree", return_value=worktree,
            ), patch.object(step2, "remove_detached_worktree") as remove:
                with step2.materialize_pinned_step2_source_workspace(
                    base, commit, repository,
                ) as materialized:
                    self.assertEqual(materialized["mapped_source_dirs"], [])
                    self.assertEqual(materialized["stable_source_dirs"], [])
                remove.assert_called_once()

            missing_project = json.loads(json.dumps(base))
            missing_project["pinned_source_snapshot"]["project_path"] = "missing"
            with patch.object(step2, "get_git_root", return_value=str(repository)), patch.object(
                step2, "create_detached_worktree", return_value=worktree,
            ), patch.object(step2, "remove_detached_worktree") as remove:
                with self.assertRaisesRegex(RuntimeError, "PINNED_PROJECT_MISSING"):
                    with step2.materialize_pinned_step2_source_workspace(
                        missing_project, commit, repository,
                    ):
                        pass
                remove.assert_called_once()

            missing_source = json.loads(json.dumps(base))
            missing_source["pinned_source_snapshot"]["source_roots"] = ["missing"]
            with patch.object(step2, "get_git_root", return_value=str(repository)), patch.object(
                step2, "create_detached_worktree", return_value=worktree,
            ), patch.object(step2, "remove_detached_worktree") as remove:
                with self.assertRaisesRegex(RuntimeError, "PINNED_SOURCE_DIR_MISSING"):
                    with step2.materialize_pinned_step2_source_workspace(
                        missing_source, commit, repository,
                    ):
                        pass
                remove.assert_called_once()

            root_source = json.loads(json.dumps(base))
            root_source["pinned_source_snapshot"]["source_roots"] = ["."]
            with patch.object(step2, "get_git_root", return_value=str(repository)), patch.object(
                step2, "create_detached_worktree", return_value=worktree,
            ), patch.object(step2, "remove_detached_worktree"):
                with step2.materialize_pinned_step2_source_workspace(
                    root_source, commit, repository,
                ) as materialized:
                    self.assertEqual(materialized["mapped_source_dirs"], [str(worktree.resolve())])
                    self.assertEqual(
                        materialized["stable_source_dirs"],
                        [str(repository.resolve())],
                    )

            with patch.object(step2, "get_git_root", return_value=str(repository)), patch.object(
                step2, "create_detached_worktree", side_effect=RuntimeError("create failed"),
            ), patch.object(step2, "remove_detached_worktree") as remove:
                with self.assertRaisesRegex(RuntimeError, "create failed"):
                    with step2.materialize_pinned_step2_source_workspace(
                        base, commit, repository,
                    ):
                        pass
                remove.assert_not_called()

    def test_main_orchestration_boundary_matrix(self):
        commit_a = "a" * 40
        commit_b = "b" * 40

        def selected_pair(
            base_version,
            current_version,
            *,
            base_source="build_model",
            current_source="build_model",
            conflict_side="",
        ):
            return {
                "base": {
                    "version": base_version,
                    "source": base_source,
                    "evidence_conflict": conflict_side == "base",
                    "build_model_version": "8",
                    "artifact_bytecode_version": "11",
                },
                "current": {
                    "version": current_version,
                    "source": current_source,
                    "evidence_conflict": conflict_side == "current",
                    "build_model_version": "17",
                    "artifact_bytecode_version": "21",
                },
            }

        def invoke(
            *,
            orchestrated=None,
            cli_base="base",
            cli_current="current",
            base_revision=None,
            current_revision=None,
            source_args=None,
            pinned=None,
            auto_mode="empty",
            deps=None,
            spring=("2.7", "3.2", "step1_scope"),
            cloud=(False, None),
            selected=None,
            technologies=None,
            changed=None,
            output_graph=False,
        ):
            orchestrated = dict(orchestrated or {})
            deps = dict(deps or {
                "g:stable": {
                    "change_type": "未变",
                    "old_version": "1",
                    "new_version": "1",
                },
            })
            selected = selected or selected_pair("8", "17")
            technologies = dict(technologies or {})
            changed = list(changed or [])
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output = root / "context.json"
                dep_changes = root / "deps.csv"
                dep_changes.write_text("unused", encoding="utf-8")
                argv = [
                    "s2_context_from_deps.py",
                    "--dep-changes", str(dep_changes),
                    "--work-dir", str(root),
                    "--output", str(output),
                ]
                if cli_base is not None:
                    argv.extend(["--base", cli_base])
                if cli_current is not None:
                    argv.extend(["--current", cli_current])
                if base_revision is not None:
                    argv.extend(["--base-revision", base_revision])
                if current_revision is not None:
                    argv.extend(["--current-revision", current_revision])
                if source_args is not None:
                    argv.append("--source-dirs")
                    argv.extend(source_args)
                if output_graph:
                    argv.extend(["--output-dep-graph", str(root / "graph.json")])

                context_manager = MagicMock()
                if pinned is None:
                    pinned_workspace = None
                else:
                    project_root = root / "pinned"
                    project_root.mkdir()
                    detected = project_root / "src" / "main" / "java"
                    detected.mkdir(parents=True)
                    snapshot = {
                        "schema": step2.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                        "commit": current_revision or commit_b,
                        "project_path": ".",
                        "source_roots": [],
                    }
                    if "declared_tool" in pinned:
                        snapshot["build_tool"] = pinned["declared_tool"]
                    pinned_workspace = {
                        "snapshot": snapshot,
                        "project_root": project_root.resolve(),
                        "stable_source_dirs": list(pinned.get("stable", [])),
                    }
                context_manager.__enter__.return_value = pinned_workspace
                context_manager.__exit__.return_value = False

                if auto_mode == "detected":
                    auto_dirs = [
                        str(
                            (pinned_workspace or {}).get(
                                "project_root", root,
                            ) / "src" / "main" / "java"
                        )
                    ]
                elif auto_mode == "external":
                    auto_dirs = [str(root / "auto" / "src" / "main" / "java")]
                else:
                    auto_dirs = []

                with patch.object(sys, "argv", argv), patch.object(
                    step2, "load_orchestrated_step2_input", return_value=orchestrated,
                ), patch.object(
                    step2,
                    "require_pinned_git_commit",
                    side_effect=lambda revision, *_args, **_kwargs: revision,
                ), patch.object(
                    step2,
                    "materialize_pinned_step2_source_workspace",
                    return_value=context_manager,
                ), patch.object(step2, "load_dep_changes", return_value=deps), patch.object(
                    step2, "detect_build_tool", return_value="maven",
                ), patch.object(
                    step2, "auto_detect_source_dirs", return_value=auto_dirs,
                ), patch.object(
                    step2, "detect_spring_boot_version", return_value=spring,
                ), patch.object(
                    step2, "detect_spring_cloud", return_value=cloud,
                ), patch.object(
                    step2, "detect_artifact_jdk_evidence", return_value={},
                ), patch.object(
                    step2,
                    "detect_jdk_versions_from_manifests",
                    return_value=("8", "17", "pom.xml"),
                ), patch.object(
                    step2, "detect_jdk_versions", return_value=("8", "17"),
                ), patch.object(
                    step2, "select_jdk_evidence", return_value=selected,
                ), patch.object(
                    step2, "detect_tech_flags", return_value=technologies,
                ), patch.object(
                    step2, "collect_changed_dependencies", return_value=changed,
                ), patch.object(
                    step2, "detect_jvm_param_changes", return_value=[],
                ), patch.object(
                    step2,
                    "build_dep_graph",
                    return_value={"dependencies": [], "edges": []},
                ):
                    step2.main()
                return json.loads(output.read_text(encoding="utf-8"))

        # Both missing and one-sided missing branch arguments are distinct
        # parser decisions and must both remain blocking.
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out.json"
            dep_changes = Path(tmp) / "deps.csv"
            dep_changes.write_text("unused", encoding="utf-8")
            for branch_args in ([], ["--base", "base"]):
                argv = [
                    "s2_context_from_deps.py",
                    "--dep-changes", str(dep_changes),
                    "--output", str(output),
                    *branch_args,
                ]
                with patch.object(sys, "argv", argv), patch.object(
                    step2, "load_orchestrated_step2_input", return_value={},
                ):
                    with self.assertRaises(SystemExit):
                        step2.main()

        first = invoke(
            base_revision=commit_a,
            auto_mode="external",
            spring=(None, None, "not_found"),
            cloud=(True, None),
            selected=selected_pair(
                None,
                "17",
                base_source="not_found",
                current_source="build_model",
                conflict_side="current",
            ),
            technologies={"active": True, "inactive": False},
        )
        self.assertEqual(first["revision_source"], "branch_name")
        self.assertTrue(first["spring_cloud"])
        self.assertEqual(first["jdk_source"], "mixed")
        self.assertTrue(first["source_dirs"])
        self.assertTrue(first["no_changed_dependencies"])

        changed_row = {
            "coord": "g:a",
            "group_id": "g",
            "artifact_id": "a",
            "old_version": "1",
            "new_version": "2",
            "change_type": "升级",
            "scope": "compile",
        }
        second = invoke(
            source_args=["", "/explicit/src"],
            deps={"g:a": {"change_type": "升级", "old_version": "1", "new_version": "2"}},
            cloud=(True, "2025.0"),
            selected=selected_pair("8", None, current_source="not_found"),
            changed=[changed_row],
            output_graph=True,
        )
        self.assertEqual(second["source_dirs"], ["/explicit/src"])
        self.assertEqual(second["spring_cloud_version"], "2025.0")
        self.assertFalse(second["no_changed_dependencies"])

        explicit_orchestrated = {
            "base_branch": "state-base",
            "current_branch": "state-current",
            "base_resolved_commit": "c" * 40,
            "current_resolved_commit": "d" * 40,
            "source_dirs": ["/state/source"],
        }
        pinned_detected = invoke(
            orchestrated=explicit_orchestrated,
            cli_base="cli-base",
            cli_current="cli-current",
            base_revision=commit_a,
            current_revision=commit_b,
            source_args=["/cli/source"],
            pinned={"declared_tool": "maven", "stable": []},
            auto_mode="detected",
            selected=selected_pair("17", "17"),
        )
        self.assertEqual(pinned_detected["base_branch"], "cli-base")
        self.assertEqual(pinned_detected["revision_source"], "resolved_commit")
        self.assertEqual(pinned_detected["build_tool"], "maven")
        self.assertEqual(len(pinned_detected["source_dirs"]), 1)

        pinned_stable = invoke(
            orchestrated=explicit_orchestrated,
            cli_base=None,
            cli_current=None,
            pinned={"stable": ["/stable/src"]},
            selected=selected_pair("8", "17"),
        )
        self.assertEqual(pinned_stable["source_dirs"], ["/stable/src"])

        pinned_empty = invoke(
            orchestrated=explicit_orchestrated,
            cli_base=None,
            cli_current=None,
            pinned={"stable": []},
            auto_mode="empty",
            selected=selected_pair("8", "17"),
        )
        self.assertEqual(pinned_empty["source_dirs"], [])

        empty_orchestrated_sources = dict(explicit_orchestrated)
        empty_orchestrated_sources["source_dirs"] = []
        empty_sources = invoke(
            orchestrated=empty_orchestrated_sources,
            cli_base=None,
            cli_current=None,
            selected=selected_pair("8", "17"),
        )
        self.assertEqual(empty_sources["source_dirs"], [])

        with self.assertRaisesRegex(RuntimeError, "PINNED_BUILD_TOOL_MISMATCH"):
            invoke(
                orchestrated=explicit_orchestrated,
                cli_base=None,
                cli_current=None,
                pinned={"declared_tool": "gradle", "stable": ["/stable/src"]},
            )

    def test_residual_step2_helper_branch_matrix(self):
        commit = "a" * 40
        valid_snapshot = {
            "schema": step2.PINNED_SOURCE_SNAPSHOT_SCHEMA,
            "commit": commit,
            "project_path": ".",
            "source_roots": [],
        }
        self.assertEqual(
            step2._valid_pinned_source_snapshot(
                {"pinned_source_snapshot": valid_snapshot}, None,
            ),
            {},
        )
        for value in ("a/b", "../a", "a/../b"):
            expected = "a/b" if value == "a/b" else ""
            self.assertEqual(step2._normalize_pinned_relative_path(value), expected)

        rows = [
            None,
            {},
            {"coord": "", "resolution_status": ""},
            {"coord": "# comment", "resolution_status": ""},
            {
                "coord": "g:a", "resolution_status": "",
                "old_version": None, "new_version": "2",
            },
        ]
        context = MagicMock()
        context.__enter__.return_value = object()
        context.__exit__.return_value = False
        with patch.object(step2.os.path, "exists", return_value=True), patch.object(
            step2, "open_csv_read", return_value=context,
        ), patch.object(step2.csv, "DictReader", return_value=rows):
            loaded = step2.load_dep_changes("rows.csv")
        self.assertEqual(set(loaded), {"g:a"})
        self.assertEqual(loaded["g:a"]["old_version"], "")

        partial_dash = {
            "g:added": {
                "change_type": "新增", "old_version": "-", "new_version": "2",
            },
            "g:removed": {
                "change_type": "移除", "old_version": "1", "new_version": "-",
            },
        }
        self.assertEqual(step2.build_dep_graph(partial_dash)["total_dependencies"], 2)
        self.assertEqual(len(step2.collect_changed_dependencies(partial_dash)), 2)
        self.assertEqual(
            step2.compute_version_flags("-", "3", "8", "8"),
            (False, False, False),
        )
        self.assertEqual(
            step2.compute_version_flags("unknown", "3", "8", "8"),
            (True, False, False),
        )
        self.assertEqual(
            step2.topological_sort(
                ["a", "b", "c"], [("a", "c"), ("b", "c")],
            ),
            ["a", "b", "c"],
        )

        with patch.object(step2, "run_cmd", return_value=(None, "", 1)):
            self.assertFalse(step2.is_git_repo("."))
            with self.assertRaisesRegex(RuntimeError, "COMMIT_UNAVAILABLE"):
                step2.require_pinned_git_commit(commit)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "directory"
            directory.mkdir()
            self.assertEqual(step2.read_local_file(root, "directory"), "")
            with patch.object(step2, "is_git_repo", return_value=False):
                self.assertEqual(step2.detect_build_tool(None, root), "unknown")

            source = root / "src" / "main" / "java"
            source.mkdir(parents=True)
            (source / "README.txt").write_text("not source", encoding="utf-8")
            self.assertEqual(step2.auto_detect_source_dirs(root, "maven"), [])

            provenance = root / "build_provenance.json"
            provenance.write_text(json.dumps({"sides": [{}]}), encoding="utf-8")
            with patch.object(
                step2, "_build_provenance_candidates", return_value=iter([provenance]),
            ):
                self.assertEqual(step2.detect_artifact_jdk_evidence(), {})

        with patch.object(step2, "is_git_repo", return_value=True), patch.object(
            step2, "build_manifest_candidates", return_value=["pom.xml"],
        ), patch.object(step2, "run_cmd", return_value=("stdout detail", "", 1)):
            with self.assertRaisesRegex(RuntimeError, "stdout detail"):
                step2.detect_build_tool(commit, "/repo", strict_git=True)


if __name__ == "__main__":
    unittest.main()
