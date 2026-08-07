import csv
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
import unittest
from unittest.mock import patch


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
                step2, "detect_jdk_versions", return_value=("8", "17")
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
        self.assertEqual(payload["jdk_current"], "21")
        self.assertEqual(payload["jdk_source"], "user_confirmed")
        self.assertEqual(payload["springboot_base"], "2.6.15")
        self.assertEqual(payload["springboot_current"], "3.3.2")
        self.assertEqual(payload["springboot_version_source"], "user_confirmed")

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


if __name__ == "__main__":
    unittest.main()
