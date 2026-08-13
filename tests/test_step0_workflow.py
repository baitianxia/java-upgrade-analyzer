import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import run_step  # noqa: E402
import s1_dep_diff  # noqa: E402


class Step0WorkflowTest(unittest.TestCase):
    @staticmethod
    def complete_source_context(jdk_home: Path) -> dict:
        return {
            "analysis_mode": "checkout_build",
            "application_source": "/repos/application",
            "base_branch": "base",
            "current_branch": "current",
            "base_resolved_commit": "a" * 40,
            "current_resolved_commit": "b" * 40,
            "target_module": ".",
            "base_tool": "maven",
            "current_tool": "maven",
            "base_jdk_home": str(jdk_home),
            "current_jdk_home": str(jdk_home),
            "jdk_base": "8",
            "jdk_current": "8",
        }

    def test_java_home_detection_uses_jvm_reported_home_for_launcher_wrappers(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "jdk-21"
            home.mkdir()
            with mock.patch.object(
                run_step,
                "run_cmd",
                return_value=("", f"    java.home = {home}\n", 0),
            ):
                detected = run_step._java_home_from_executable("/tools/java")

        self.assertEqual(detected, home)

    def test_java8_reported_jre_home_is_normalized_to_the_full_jdk(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "jdk8"
            embedded_jre = home / "jre"
            embedded_jre.mkdir(parents=True)
            (home / "bin").mkdir()
            (home / "bin" / "javac").write_text("launcher", encoding="utf-8")
            (home / "release").write_text(
                'JAVA_VERSION="1.8.0_402"\n', encoding="utf-8"
            )
            with mock.patch.object(
                run_step,
                "run_cmd",
                return_value=("", f"    java.home = {embedded_jre}\n", 0),
            ):
                detected = run_step._java_home_from_executable("/tools/java")

        self.assertEqual(detected, home)

    def test_jdk_discovery_includes_home_reported_by_java_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "jdk-21"
            java = home / "bin" / "java"
            java.parent.mkdir(parents=True)
            java.write_text("launcher", encoding="utf-8")
            (home / "release").write_text(
                'JAVA_VERSION="21.0.8"\n', encoding="utf-8"
            )
            with mock.patch.object(
                run_step.shutil, "which", return_value="/tools/java"
            ), mock.patch.object(
                run_step, "_java_home_from_executable", return_value=home
            ), mock.patch.dict(run_step.os.environ, {"JAVA_HOME": ""}):
                homes = run_step.discover_jdk_homes()

        self.assertEqual(homes["21"], str(home.resolve()))

    def test_step0_accepts_a_complete_jdk8_platform_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "jdk8"
            (home / "bin").mkdir(parents=True)
            for executable in ("java", "javac", "javap"):
                (home / "bin" / executable).write_text(
                    "launcher", encoding="utf-8"
                )
            (home / "jre" / "lib").mkdir(parents=True)
            (home / "jre" / "lib" / "rt.jar").write_bytes(b"runtime")
            (home / "release").write_text(
                'JAVA_VERSION="1.8.0_402"\n', encoding="utf-8"
            )

            run_step.validate_step0_context(self.complete_source_context(home))

    def test_step0_rejects_a_jdk8_home_without_its_platform_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "jdk8"
            (home / "bin").mkdir(parents=True)
            for executable in ("java", "javac", "javap"):
                (home / "bin" / executable).write_text(
                    "launcher", encoding="utf-8"
                )
            (home / "release").write_text(
                'JAVA_VERSION="1.8.0_402"\n', encoding="utf-8"
            )

            with self.assertRaises(run_step.StepError) as raised:
                run_step.validate_step0_context(
                    self.complete_source_context(home)
                )

        self.assertIn("STEP0_FULL_JDK_REQUIRED", raised.exception.reason_codes)

    def test_step0_preflight_checks_both_sides_and_deduplicates_same_jdk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "jdk"
            home.mkdir()
            base = root / "base.jar"
            current = root / "current.jar"
            for artifact in (base, current):
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr("demo/App.class", b"class")
            asm = root / "asm.jar"
            asm.write_bytes(b"asm")
            context = self.complete_source_context(home)
            context.update({
                "analysis_mode": "artifact_inputs",
                "base_artifact_path": str(base),
                "current_artifact_path": str(current),
            })
            jdk_result = {
                "schema": "java-upgrade-analyzer.jdk-preflight.v1",
                "jdk_preflight_identity": "jdk-identity",
                "status": "passed",
            }
            with mock.patch.object(
                run_step, "preflight_jdk_home", return_value=jdk_result,
            ) as jdk_probe, mock.patch.object(
                run_step,
                "_preflight_pinned_build_tool",
                side_effect=lambda _context, _project, side: {
                    "side": side, "status": "passed",
                },
            ) as build_probe, mock.patch.object(
                run_step, "resolve_asm_jar", return_value=asm,
            ):
                result = run_step.run_step0_preflight(
                    context, root, root / ".upgrade-report",
                )

            persisted = json.loads(
                run_step.step0_preflight_path(root / ".upgrade-report")
                .read_text(encoding="utf-8")
            )

        self.assertEqual(jdk_probe.call_count, 1)
        self.assertEqual(build_probe.call_count, 2)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(
            result["git_worktree_list_contract"],
            "git worktree list --porcelain",
        )
        self.assertEqual(
            persisted["step0_preflight_identity"],
            result["step0_preflight_identity"],
        )
        self.assertEqual(set(result["artifacts"]), {"base", "current"})

    def test_step1_validates_newly_discovered_runtime_jars_immediately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "runtime.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("demo/App.class", b"class")
            sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            config = {
                side: {"artifacts": [{
                    "path": str(artifact),
                    "content_sha256": sha256,
                }]}
                for side in ("base", "current")
            }
            with mock.patch.object(
                run_step,
                "materialize_binary_pipeline_config",
                return_value=config,
            ):
                result = run_step.validate_step1_runtime_inputs({}, root)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["artifact_count"], 2)

    def test_step1_rejects_invalid_runtime_jar_before_later_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "runtime.jar"
            artifact.write_bytes(b"not-a-jar")
            sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            config = {
                side: {"artifacts": [{
                    "path": str(artifact),
                    "content_sha256": sha256,
                }]}
                for side in ("base", "current")
            }
            with mock.patch.object(
                run_step,
                "materialize_binary_pipeline_config",
                return_value=config,
            ), self.assertRaises(run_step.StepError) as raised:
                run_step.validate_step1_runtime_inputs({}, root)

        self.assertIn(
            "STEP1_RUNTIME_ARTIFACT_INVALID", raised.exception.reason_codes
        )

    def test_legacy_main_state_is_replaced_by_real_step0_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = run_step.ensure_main_state_structure(
                {
                    "schema": "java-upgrade-analyzer.main-state.v2",
                    "state": {"current_step": "step4"},
                    "step1": {"input": {"base_branch": "old"}},
                },
                tmp,
            )

        self.assertEqual(state["schema"], run_step.MAIN_STATE_SCHEMA)
        self.assertEqual(state["state"]["current_step"], "step0")
        self.assertEqual(state["step1"]["input"], {})

    def test_artifact_card_uses_original_filenames_and_shared_row_layout(self):
        context = {
            "analysis_mode": "artifact_inputs",
            "base_artifact_path": "/internal/cache/order-service-1.0.jar",
            "current_artifact_path": "/internal/cache/order-service-2.0.jar",
            "base_branch": "release/1.0",
            "current_branch": "release/2.0",
            "target_module": "order-service",
            "base_tool": "maven",
            "current_tool": "gradle",
            "base_jdk_home": "/jdks/8",
            "current_jdk_home": "/jdks/17",
            "application_source": "https://git.example.com/team/order-service.git",
            "application_source_display": "https://git.example.com/team/order-service.git",
            "dependency_source_git_urls": [
                "https://git.example.com/payment-sdk.git"
            ],
            "dependency_source_dirs": ["/data/sources/common-utils"],
            "input_origins": {},
        }

        interaction = run_step.build_step0_confirmation_interaction(context)
        rows = interaction["confirmation_table"]["rows"]

        self.assertEqual(
            [row["label"] for row in rows],
            [
                "最终制品",
                "版本分支",
                "目标模块",
                "构建工具",
                "JDK 目录",
                "应用源码",
                "依赖包源码",
            ],
        )
        self.assertIn("order-service-1.0.jar", rows[0]["base"])
        self.assertIn("order-service-2.0.jar", rows[0]["current"])
        self.assertNotIn("制品内版本", [row["label"] for row in rows])
        self.assertIn("order-service.git", rows[-2]["base"])
        self.assertIn("common-utils", rows[-1]["base"])
        self.assertIn(
            "https://git.example.com/payment-sdk.git 或 /data/sources/common-utils",
            rows[-1]["base"],
        )

    def test_artifact_application_version_comes_from_outer_application_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "payment-service.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/maven/com.example/payment-service/pom.properties",
                    "groupId=com.example\nartifactId=payment-service\nversion=2.4.0\n",
                )
                archive.writestr(
                    "BOOT-INF/lib/common-utils-9.9.0.jar",
                    b"nested dependency bytes",
                )

            result = run_step.detect_artifact_application_version(artifact)

        self.assertEqual(result["status"], "detected")
        self.assertEqual(result["version"], "2.4.0")
        self.assertEqual(result["identities"][0]["artifact_id"], "payment-service")

    def test_artifact_version_resolves_application_refs_before_step0_card(self):
        context = {
            "analysis_mode": "artifact_inputs",
            "application_source": "/repos/application",
            "base_artifact_path": "/artifacts/base.jar",
            "current_artifact_path": "/artifacts/current.jar",
            "input_origins": {},
        }

        def detect(path):
            version = "1.0.0" if str(path).endswith("base.jar") else "2.0.0"
            return {"status": "detected", "version": version, "identities": []}

        def match(_repo, version):
            return {
                "status": "resolved",
                "candidates": [{
                    "ref": f"origin/v{version}",
                    "commit": ("a" if version == "1.0.0" else "b") * 40,
                    "aliases": [f"refs/tags/v{version}"],
                }],
            }

        def resolve(updated, _project_dir, **_kwargs):
            resolved = dict(updated)
            resolved["base_resolved_commit"] = "a" * 40
            resolved["current_resolved_commit"] = "b" * 40
            return resolved, None

        with mock.patch.object(
            run_step, "detect_artifact_application_version", side_effect=detect
        ), mock.patch.object(
            run_step, "_step1_ref_repository", return_value=Path("/repos/application")
        ), mock.patch.object(
            run_step, "match_remote_refs_by_version", side_effect=match
        ), mock.patch.object(
            run_step, "resolve_step1_refs_for_execution", side_effect=resolve
        ), mock.patch.object(
            run_step, "_detect_build_tool_for_revision", return_value=""
        ), mock.patch.object(
            run_step, "_detect_step0_jdk_versions", return_value={}
        ), mock.patch.object(
            run_step, "discover_jdk_homes", return_value={}
        ), mock.patch.object(
            run_step, "rebuild_current_pinned_source_context", side_effect=lambda value, _project: value
        ):
            prepared, interaction = run_step.prepare_step0_context(
                context, "/workspace"
            )

        self.assertIsNone(interaction)
        self.assertEqual(prepared["base_branch"], "origin/v1.0.0")
        self.assertEqual(prepared["current_branch"], "origin/v2.0.0")
        self.assertEqual(prepared["input_origins"]["base_branch"], "detected")
        self.assertEqual(prepared["input_origins"]["current_branch"], "detected")

    def test_artifact_version_ref_ambiguity_is_merged_into_step0(self):
        context = {
            "analysis_mode": "artifact_inputs",
            "application_source": "/repos/application",
            "base_artifact_path": "/artifacts/base.jar",
            "current_artifact_path": "/artifacts/current.jar",
            "current_branch": "release/current",
            "input_origins": {},
        }
        match = {
            "status": "ambiguous",
            "candidates": [
                {"ref": "origin/v1.0.0", "commit": "a" * 40},
                {"ref": "upstream/v1.0.0", "commit": "b" * 40},
            ],
        }
        with mock.patch.object(
            run_step,
            "detect_artifact_application_version",
            side_effect=[
                {"status": "detected", "version": "1.0.0", "identities": []},
                {"status": "detected", "version": "2.0.0", "identities": []},
            ],
        ), mock.patch.object(
            run_step, "_step1_ref_repository", return_value=Path("/repos/application")
        ), mock.patch.object(
            run_step, "match_remote_refs_by_version", return_value=match
        ), mock.patch.object(
            run_step,
            "resolve_step1_refs_for_execution",
            side_effect=lambda updated, _project, **_kwargs: (updated, None),
        ), mock.patch.object(
            run_step, "_detect_build_tool_for_revision", return_value=""
        ), mock.patch.object(
            run_step, "_detect_step0_jdk_versions", return_value={}
        ), mock.patch.object(
            run_step, "discover_jdk_homes", return_value={}
        ):
            _prepared, interaction = run_step.prepare_step0_context(
                context, "/workspace"
            )

        self.assertEqual(interaction["step_id"], "step0")
        self.assertEqual(
            interaction["ref_resolution_requests"][0]["field"], "base_branch"
        )
        self.assertEqual(
            {
                candidate["commit"]
                for candidate in interaction["ref_resolution_requests"][0][
                    "candidates"
                ]
            },
            {"a" * 40, "b" * 40},
        )

    def test_source_card_keeps_same_layout(self):
        context = {
            "analysis_mode": "checkout_build",
            "base_branch": "main",
            "current_branch": "feature/jdk17",
            "target_module": "app",
            "base_tool": "maven",
            "current_tool": "maven",
            "base_jdk_home": "/jdks/8",
            "current_jdk_home": "/jdks/17",
            "application_source": "https://git.example.com/team/order-service.git",
            "application_source_display": "https://git.example.com/team/order-service.git",
            "input_origins": {},
        }

        rows = run_step.build_step0_confirmation_interaction(context)[
            "confirmation_table"
        ]["rows"]

        self.assertEqual(rows[0]["label"], "最终制品")
        self.assertIn("Step1", rows[0]["base"])
        self.assertEqual(rows[-2]["label"], "应用源码")
        self.assertEqual(rows[-1]["label"], "依赖包源码")

    def test_dependency_source_ambiguities_are_combined_into_binding_choices(self):
        versions = {"com.example:common-utils": {"base": "1.0", "current": "2.0"}}
        plan = {"unmatched_relevant_coords": []}
        candidates = {
            "com.example:common-utils": {
                "/repos/a": {
                    "repo_path": "/repos/a",
                    "source_dirs": ["/repos/a/src/main/java"],
                    "module_roots": ["/repos/a"],
                },
                "/repos/b": {
                    "repo_path": "/repos/b",
                    "source_dirs": ["/repos/b/src/main/java"],
                    "module_roots": ["/repos/b"],
                },
            }
        }

        def match(repo_path, version):
            commit = ("a" if repo_path.endswith("a") else "b") * 40
            return {
                "status": "resolved",
                "candidates": [{
                    "ref": f"origin/v{version}",
                    "commit": commit,
                    "remote": "origin",
                    "canonical_ref": f"refs/tags/v{version}",
                }],
            }

        context = {"dependency_source_dirs": ["/repos/a", "/repos/b"]}
        with mock.patch.object(
            run_step, "_dependency_change_versions", return_value=versions
        ), mock.patch.object(
            run_step,
            "_dependency_repo_mapping_candidates",
            return_value=(plan, candidates),
        ), mock.patch.object(
            run_step, "_version_candidate_groups", side_effect=match
        ):
            interaction = run_step.build_step1_dependency_source_interaction(
                context, "/tmp/report"
            )

        ambiguities = interaction["dependency_source_ambiguities"]
        self.assertEqual(len(ambiguities), 1)
        self.assertEqual(ambiguities[0]["kind"], "binding")
        self.assertEqual(len(ambiguities[0]["candidates"]), 2)
        for candidate in ambiguities[0]["candidates"]:
            self.assertTrue(candidate["repo_path"])
            self.assertTrue(candidate["base_commit"])
            self.assertTrue(candidate["current_commit"])
            self.assertTrue(candidate["selection_key"].startswith("depsrc:"))

    def test_selected_dependency_binding_merges_with_automatic_binding(self):
        existing = {
            "dependency_source_ref_bindings": [
                {"coord": "com.example:auto", "repo_path": "/repos/auto"}
            ],
            "dependency_repo_mappings": ["com.example:auto=/repos/auto"],
            "dependency_source_mappings": [
                "com.example:auto=/repos/auto/src/main/java"
            ],
        }
        response = {
            "dependency_source_ref_bindings": [
                {
                    "coord": "com.example:selected",
                    "repo_path": "/repos/selected",
                    "source_dirs": ["/repos/selected/src/main/java"],
                }
            ]
        }

        merged = run_step.merge_user_response_into_run_context(
            existing, response, Path("/")
        )

        self.assertEqual(
            {item["coord"] for item in merged["dependency_source_ref_bindings"]},
            {"com.example:auto", "com.example:selected"},
        )
        self.assertIn(
            "com.example:selected=/repos/selected",
            merged["dependency_repo_mappings"],
        )

    def test_step4_dependency_source_mapping_uses_selected_commit_not_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "dependency"
            report = root / "report"
            source = repo / "src" / "main" / "java"
            source.mkdir(parents=True)
            subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Test"],
                check=True,
            )
            tracked = source / "Version.java"
            tracked.write_text("class Version { int value = 1; }\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-m", "v1"],
                check=True,
                capture_output=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tracked.write_text("class Version { int value = 2; }\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-m", "v2"],
                check=True,
                capture_output=True,
            )
            context = {
                "dependency_source_ref_bindings": [{
                    "coord": "com.example:dependency",
                    "repo_path": str(repo),
                    "source_dirs": [str(source)],
                    "module_roots": [str(repo)],
                    "current_version": "1.0",
                    "current_ref": "v1.0",
                    "current_commit": commit,
                    "current_status": "resolved",
                }],
            }
            materialized_result = {
                "status": "remote_source_resolved",
                "resolved_commit": commit,
            }
            with mock.patch.object(
                run_step,
                "materialize_remote_source_candidate",
                return_value=materialized_result,
            ):
                with run_step.materialize_pinned_dependency_source_workspaces(
                    context, report
                ) as pinned:
                    mapping = pinned["dependency_source_mappings"][0]
                    _coord, pinned_source = mapping.split("=", 1)
                    pinned_file = Path(pinned_source) / "Version.java"
                    self.assertIn("value = 1", pinned_file.read_text(encoding="utf-8"))
                    self.assertNotEqual(Path(pinned_source), source)
                    worktree_source = Path(pinned_source)
                self.assertFalse(worktree_source.exists())

    def test_step1_identity_card_aggregates_both_sides(self):
        interaction = s1_dep_diff.build_step1_coordinate_ambiguity_interaction(
            [
                {
                    "side": "base",
                    "lib_entry": "BOOT-INF/lib/a-1.0.jar",
                    "artifact_id": "a",
                    "version": "1.0",
                    "reason_code": "PACKAGED_VERSION_UNCONFIRMED",
                },
                {
                    "side": "current",
                    "lib_entry": "BOOT-INF/lib/b-2.0.jar",
                    "artifact_id": "b",
                    "version": "2.0",
                    "reason_code": "DEPENDENCY_COORDINATES_UNRESOLVED",
                },
            ]
        )

        self.assertEqual(interaction["step_id"], "step1")
        self.assertEqual(len(interaction["unresolved_items"]), 2)
        self.assertTrue(any(line.startswith("Base") for line in interaction["checklist_lines"]))
        self.assertTrue(any(line.startswith("Current") for line in interaction["checklist_lines"]))

    def test_step1_scans_both_artifacts_before_requesting_identity_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_artifact = root / "base.jar"
            current_artifact = root / "current.jar"
            base_artifact.write_bytes(b"base")
            current_artifact.write_bytes(b"current")
            output = root / "report" / "dep_changes.csv"
            captured = {}

            def collect(artifact_path, **kwargs):
                side = kwargs["side"]
                return {}, {
                    "mode": "final_artifact",
                    "dep_entries": [],
                    "unresolved_items": [{
                        "side": side,
                        "lib_entry": f"BOOT-INF/lib/{side}.jar",
                        "artifact_id": side,
                        "version": "1.0",
                        "reason_code": "DEPENDENCY_COORDINATES_UNRESOLVED",
                    }],
                }

            argv = [
                "s1_dep_diff.py",
                "--base-artifact-path", str(base_artifact),
                "--current-artifact-path", str(current_artifact),
                "--base-tool", "maven",
                "--current-tool", "maven",
                "--output", str(output),
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                s1_dep_diff,
                "collect_packaged_deps_from_artifact_path",
                side_effect=collect,
            ) as collector, mock.patch.object(
                s1_dep_diff,
                "emit_step_interaction",
                side_effect=lambda interaction: captured.setdefault(
                    "interaction", interaction
                ),
            ), self.assertRaises(SystemExit) as raised:
                s1_dep_diff.main()

        self.assertEqual(raised.exception.code, s1_dep_diff.EXIT_AWAITING_USER)
        self.assertEqual(collector.call_count, 2)
        self.assertEqual(
            {item["side"] for item in captured["interaction"]["unresolved_items"]},
            {"base", "current"},
        )


if __name__ == "__main__":
    unittest.main()
