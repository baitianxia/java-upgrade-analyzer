from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s1_dep_diff
import s2_context_from_deps
import s3_scan


class Step1FailureAndInteractionContractTest(unittest.TestCase):
    def test_coordinate_errors_preserve_structured_evidence(self):
        artifact_error = s1_dep_diff.ArtifactCoordinateInputRequiredError(
            "/artifacts/app.jar", [{"artifact_id": "a"}],
        )
        self.assertEqual(artifact_error.artifact_path, "/artifacts/app.jar")
        self.assertEqual(artifact_error.unresolved_items, [{"artifact_id": "a"}])

        unresolved = s1_dep_diff.UnresolvedPackagedCoordinatesError([
            {"artifact_id": "client", "version": "1", "lib_entry": "lib/client.jar"},
        ], resolved_deps={"g:ok": {}})
        self.assertEqual(unresolved.resolved_deps, {"g:ok": {}})
        self.assertEqual(len(unresolved.unresolved_items), 1)
        self.assertIn("client", str(unresolved))

    def test_maven_failure_classification_is_specific_and_has_safe_fallback(self):
        causes = s1_dep_diff._infer_maven_failure_causes(
            "invalid target release; unsupported class file major version; "
            "JAVA_HOME is not defined correctly; could not resolve dependencies; "
            "could not find the selected project in the reactor"
        )
        self.assertEqual(len(causes), 5)
        self.assertTrue(any("JDK" in item for item in causes))
        self.assertTrue(any("依赖仓库" in item for item in causes))
        self.assertEqual(
            len(s1_dep_diff._infer_maven_failure_causes("unclassified failure")),
            1,
        )
        self.assertEqual(
            s1_dep_diff._infer_step1_blocked_causes(
                "mvn_package", "invalid target release",
            ),
            ["JDK 版本与目标分支的 Maven/Compiler 配置不兼容。"],
        )

    def test_cleanup_failure_is_attached_without_losing_primary_failure(self):
        blocked = s1_dep_diff.Step1CommandExecutionBlockedError(
            stage="mvn_package", command="mvn package", stderr_excerpt="build failed",
            suspected_causes=["cause"],
        )
        result = s1_dep_diff.append_cleanup_failure_to_blocked_error(
            blocked, OSError("busy"),
        )
        self.assertIs(result, blocked)
        self.assertIn("build failed", result.stderr_excerpt)
        self.assertIn("清理失败", result.stderr_excerpt)
        self.assertEqual(len(result.suspected_causes), 2)
        s1_dep_diff.append_cleanup_failure_to_blocked_error(blocked, OSError("again"))
        self.assertEqual(len(result.suspected_causes), 2)

        generic = s1_dep_diff.append_cleanup_failure_to_blocked_error(
            ValueError("primary"), OSError("cleanup"),
        )
        self.assertIsInstance(generic, RuntimeError)
        self.assertIn("primary", str(generic))
        self.assertIn("cleanup", str(generic))

    def test_missing_input_interaction_names_required_and_fallback_fields(self):
        interaction = s1_dep_diff.build_step1_missing_input_interaction([
            {
                "side": "base", "side_cn": "基准侧", "artifact_path": "/a/base.jar",
                "branch_field": "base_branch", "source_field": "base_source_project_dir",
            },
        ], unresolved_items=[{"artifact_id": "client", "version": "1"}])
        self.assertEqual(interaction["status"], "awaiting_user_input")
        self.assertEqual(interaction["required_fields"], ["base_branch"])
        self.assertEqual(interaction["fallback_inputs"][0]["field"], "base_source_project_dir")
        self.assertTrue(interaction["must_wait_for_user_reply"])
        self.assertIn("base_branch", interaction["question"])

        stdout = io.StringIO()
        with patch.object(s1_dep_diff, "normalize_diagnostic_payload", side_effect=lambda value, **_: value), patch.object(
            s1_dep_diff.sys, "stdout", stdout,
        ):
            s1_dep_diff.emit_step_interaction(interaction)
        emitted = stdout.getvalue()
        self.assertTrue(emitted.startswith(s1_dep_diff.STEP_INTERACTION_PREFIX))
        self.assertIn('"step_id": "step1"', emitted)


class Step1ModuleResolutionContractTest(unittest.TestCase):
    @staticmethod
    def _write_packaged_artifact(path, *, version="1.0.0", with_coordinates=True):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as nested:
            if with_coordinates:
                nested.writestr(
                    "META-INF/maven/org.example/demo/pom.properties",
                    "groupId=org.example\nartifactId=demo\n"
                    f"version={version}\n",
                )
            nested.writestr("org/example/Demo.class", b"class-bytes")
        with zipfile.ZipFile(path, "w") as outer:
            outer.writestr(
                f"BOOT-INF/lib/demo-{version}.jar",
                payload.getvalue(),
            )

    def test_module_id_resolution_supports_root_paths_coordinates_and_pom_xml(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "services" / "billing"
            module.mkdir(parents=True)
            pom = module / "pom.xml"
            pom.write_text(
                '<project xmlns="urn:maven"><groupId>com.acme</groupId>'
                '<artifactId>billing-api</artifactId></project>',
                encoding="utf-8",
            )
            self.assertEqual(
                s1_dep_diff.resolve_primary_module_id(str(pom), root),
                "billing-api",
            )
            self.assertEqual(
                s1_dep_diff.resolve_module_ids(
                    [".", str(pom), "com.acme:orders", None, ""], root,
                ),
                ["__root__", "billing-api", "orders"],
            )
            self.assertEqual(s1_dep_diff.resolve_module_ids(42, root), [])
            self.assertEqual(
                s1_dep_diff._resolve_module_dir_for_packaging("com.acme:billing-api", root),
                module.resolve(),
            )
            self.assertEqual(
                s1_dep_diff._resolve_module_dir_for_packaging(".", root), root.resolve(),
            )
            self.assertIsNone(
                s1_dep_diff._resolve_module_dir_for_packaging("missing", root),
            )

            with patch.object(
                s1_dep_diff, "resolve_primary_module_id", return_value=None,
            ):
                self.assertEqual(
                    s1_dep_diff.resolve_module_ids(
                        ["services/billing", ":root:api"], root,
                    ),
                    ["billing", "api"],
                )
                self.assertEqual(
                    s1_dep_diff._resolve_single_module_selector(
                        None, ["services/billing"], root,
                    ),
                    "services/billing",
                )

    def test_packaged_archive_read_failure_keeps_entry_identity_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/lib/demo-1.0.jar", b"not-read")
            with patch.object(
                s1_dep_diff, "_stream_nested_jar_to_spool",
                side_effect=OSError("injected read failure"),
            ):
                scanned = s1_dep_diff._scan_packaged_archive(artifact)

        self.assertFalse(scanned.complete)
        self.assertEqual(scanned.rows[0]["lib_name"], "demo-1.0.jar")
        self.assertEqual(scanned.rows[0]["match_source"], "outer-read-error")
        self.assertIn("injected read failure", scanned.rows[0]["read_error"])
        self.assertEqual(scanned.failures[0]["stage"], "nested_entry_read")
        self.assertTrue(s1_dep_diff._is_ignorable_packaging_support_dep({
            "lib_name": "spring-boot-jarmode-layertools-3.5.0.jar",
        }))

    def test_branch_collectors_preserve_primary_and_cleanup_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = root / "worktree"
            worktree.mkdir()
            common = (
                patch.object(s1_dep_diff, "build_java_env", return_value={}),
                patch.object(
                    s1_dep_diff, "create_branch_worktree", return_value=worktree,
                ),
                patch.object(
                    s1_dep_diff, "remove_branch_worktree",
                    side_effect=OSError("cleanup locked"),
                ),
            )
            with common[0], common[1], common[2], patch.object(
                s1_dep_diff, "collect_maven_deps_for_workspace",
                side_effect=RuntimeError("package failed"),
            ):
                with self.assertRaises(
                    s1_dep_diff.Step1CommandExecutionBlockedError,
                ) as packaged:
                    s1_dep_diff.get_packaged_deps_by_switching_branch(
                        "base", root, side="base",
                    )
            self.assertEqual(packaged.exception.stage, "mvn_package")
            self.assertIn("package failed", packaged.exception.stderr_excerpt)
            self.assertIn("cleanup locked", packaged.exception.stderr_excerpt)

            with patch.object(
                s1_dep_diff, "build_java_env", return_value={},
            ), patch.object(
                s1_dep_diff, "create_branch_worktree", return_value=worktree,
            ), patch.object(
                s1_dep_diff, "collect_runtime_deps_for_workspace",
                side_effect=RuntimeError("inventory failed"),
            ), patch.object(
                s1_dep_diff, "remove_branch_worktree",
                side_effect=OSError("cleanup locked"),
            ):
                with self.assertRaises(
                    s1_dep_diff.Step1CommandExecutionBlockedError,
                ) as runtime:
                    s1_dep_diff.get_runtime_deps_by_switching_branch(
                        "current", root, side="current",
                    )
            self.assertEqual(runtime.exception.stage, "mvn_dependency_list")
            self.assertIn("inventory failed", runtime.exception.stderr_excerpt)
            self.assertIn("cleanup locked", runtime.exception.stderr_excerpt)

    def test_runtime_branch_worktree_failure_is_mapped_without_running_build(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            s1_dep_diff, "build_java_env", return_value={},
        ), patch.object(
            s1_dep_diff, "create_branch_worktree",
            side_effect=PermissionError("permission denied"),
        ), patch.object(
            s1_dep_diff, "collect_runtime_deps_for_workspace",
        ) as collect:
            with self.assertRaises(
                s1_dep_diff.Step1CommandExecutionBlockedError,
            ) as raised:
                s1_dep_diff.get_runtime_deps_by_switching_branch(
                    "base", temporary, side="base",
                )

        collect.assert_not_called()
        self.assertEqual(raised.exception.stage, "prepare_branch_worktree")
        self.assertIn("权限不足", " ".join(raised.exception.suspected_causes))

    def test_packaged_branch_retains_artifact_before_worktree_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = root / "worktree"
            worktree.mkdir()
            artifact = worktree / "app.jar"
            artifact.write_bytes(b"artifact")
            meta = {"artifact_path": str(artifact)}
            with patch.object(
                s1_dep_diff, "build_java_env", return_value={},
            ), patch.object(
                s1_dep_diff, "create_branch_worktree", return_value=worktree,
            ), patch.object(
                s1_dep_diff, "collect_maven_deps_for_workspace",
                return_value=({"g:a": {"version": "1"}}, meta),
            ), patch.object(
                s1_dep_diff, "run_cmd", return_value=("a" * 40, "", 0),
            ), patch.object(
                s1_dep_diff, "retain_artifact_for_analysis",
            ) as retain, patch.object(
                s1_dep_diff, "remove_branch_worktree",
            ):
                deps, observed = (
                    s1_dep_diff.get_packaged_deps_by_switching_branch(
                        "base", root, side="base",
                        artifact_cache_dir=root / "retained",
                    )
                )

        self.assertEqual(deps, {"g:a": {"version": "1"}})
        self.assertEqual(observed["revision"], "a" * 40)
        retain.assert_called_once_with(meta, root / "retained", "base")

    def test_manual_instructions_use_one_resolved_module_selector(self):
        stderr = io.StringIO()
        with patch.object(s1_dep_diff.sys, "stderr", stderr), patch.object(
            s1_dep_diff, "IS_WINDOWS", False,
        ):
            s1_dep_diff.print_manual_instructions(
                "base", "current", primary_module="app", work_dir=".",
            )
        rendered = stderr.getvalue()
        self.assertIn("git checkout base", rendered)
        self.assertIn("git checkout current", rendered)
        self.assertIn("-pl :app -am", rendered)
        self.assertIn("--base-tool maven", rendered)
        self.assertIn("--current-tool maven", rendered)

    def test_step1_output_ranking_enumerates_every_declared_category(self):
        risk_cases = {
            "❓需人工确认": 0,
            "高": 1,
            "高（兼容性）": 1,
            "中": 2,
            "中（间接）": 2,
            "低": 3,
            "": 3,
            None: 3,
        }
        for value, expected in risk_cases.items():
            with self.subTest(risk=value):
                self.assertEqual(s1_dep_diff._step1_risk_rank(value), expected)

        change_cases = {
            "降级⚠️": 0,
            "大版本升级": 1,
            "移除": 2,
            "小版本升级": 3,
            "补丁升级": 4,
            "新增": 5,
            "版本格式不规则": 6,
            "已变更": 7,
            "未变": 8,
            "未知": 9,
            "": 9,
            None: 9,
        }
        for value, expected in change_cases.items():
            with self.subTest(change=value):
                self.assertEqual(s1_dep_diff._step1_change_rank(value), expected)

    def test_direct_artifact_main_writes_results_from_real_archive_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_artifact = root / "base.jar"
            current_artifact = root / "current.jar"
            for artifact, version in (
                (base_artifact, "1.0.0"),
                (current_artifact, "2.0.0"),
            ):
                self._write_packaged_artifact(artifact, version=version)
            base_sha256 = hashlib.sha256(base_artifact.read_bytes()).hexdigest()
            current_sha256 = hashlib.sha256(current_artifact.read_bytes()).hexdigest()
            output = root / "report" / "dep_changes.csv"
            stderr = io.StringIO()
            argv = [
                "s1_dep_diff.py",
                "--base-tool", "maven",
                "--current-tool", "maven",
                "--base-artifact-path", str(base_artifact),
                "--current-artifact-path", str(current_artifact),
                "--output", str(output),
            ]
            with patch.object(s1_dep_diff.sys, "argv", argv), patch.object(
                s1_dep_diff.sys, "stderr", stderr,
            ), patch.object(
                s1_dep_diff,
                "load_orchestrated_step1_input",
                return_value={},
            ), patch.dict(
                s1_dep_diff.os.environ,
                {"JUA_CONFIRM_MODE": "emit"},
                clear=False,
            ):
                self.assertIsNone(s1_dep_diff.main())

            with output.open("r", encoding="utf-8-sig", newline="") as stream:
                changes = list(csv.DictReader(stream))
            with (output.parent / "deps_current_resolved.csv").open(
                "r", encoding="utf-8-sig", newline="",
            ) as stream:
                current_inventory = list(csv.DictReader(stream))
            provenance = json.loads(
                (output.parent / "build_provenance.json").read_text(encoding="utf-8")
            )
            summary = (output.parent / "dep_summary.txt").read_text(encoding="utf-8")

            self.assertEqual(len(changes), 1)
            self.assertEqual(changes[0]["coord"], "org.example:demo")
            self.assertEqual(changes[0]["old_version"], "1.0.0")
            self.assertEqual(changes[0]["new_version"], "2.0.0")
            self.assertEqual(changes[0]["change_type"], "大版本升级")
            self.assertEqual(current_inventory[0]["version"], "2.0.0")
            self.assertTrue(provenance["both_artifacts_available"])
            self.assertFalse(provenance["both_build_executions_succeeded"])
            self.assertEqual(
                [item["artifact_sha256"] for item in provenance["sides"]],
                [base_sha256, current_sha256],
            )
            self.assertEqual(
                [item["build_execution_status"] for item in provenance["sides"]],
                ["not_executed", "not_executed"],
            )
            retained = output.parent / s1_dep_diff.STEP1_ARTIFACTS_DIRNAME
            self.assertTrue((retained / "base.jar").is_file())
            self.assertTrue((retained / "current.jar").is_file())
            self.assertIn("输入模式：用户提供 base/current 编译产物", summary)
            self.assertIn("大版本升级: 1", summary)
            self.assertIn("已配置为输出模式（emit）", stderr.getvalue())

    def test_direct_artifact_main_aggregates_real_unresolved_entries_before_interaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_artifact = root / "base.jar"
            current_artifact = root / "current.jar"
            self._write_packaged_artifact(base_artifact, with_coordinates=False)
            self._write_packaged_artifact(current_artifact, with_coordinates=False)
            stdout = io.StringIO()
            stderr = io.StringIO()
            argv = [
                "s1_dep_diff.py",
                "--base-tool", "maven",
                "--current-tool", "maven",
                "--base-artifact-path", str(base_artifact),
                "--current-artifact-path", str(current_artifact),
                "--debug-only",
            ]
            with patch.object(s1_dep_diff.sys, "argv", argv), patch.object(
                s1_dep_diff.sys, "stdout", stdout,
            ), patch.object(
                s1_dep_diff.sys, "stderr", stderr,
            ), patch.object(
                s1_dep_diff,
                "load_orchestrated_step1_input",
                return_value={},
            ), self.assertRaises(SystemExit) as raised:
                s1_dep_diff.main()

        self.assertEqual(raised.exception.code, s1_dep_diff.EXIT_AWAITING_USER)
        emitted = stdout.getvalue()
        self.assertTrue(emitted.startswith(s1_dep_diff.STEP_INTERACTION_PREFIX))
        interaction = json.loads(emitted.split(":", 1)[1])
        self.assertEqual(
            interaction["reason_code"],
            s1_dep_diff.DEPENDENCY_COORDINATES_UNRESOLVED,
        )
        self.assertEqual(
            {item["side"] for item in interaction["unresolved_items"]},
            {"base", "current"},
        )
        self.assertIn("已完成 Base/Current 最终制品扫描", stderr.getvalue())

    def test_direct_artifact_main_maps_real_ref_resolution_failure_to_interaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_artifact = root / "base.jar"
            current_artifact = root / "current.jar"
            self._write_packaged_artifact(base_artifact, with_coordinates=False)
            self._write_packaged_artifact(current_artifact, with_coordinates=False)
            stdout = io.StringIO()
            argv = [
                "s1_dep_diff.py",
                "--base", "release",
                "--base-tool", "maven",
                "--current-tool", "maven",
                "--base-artifact-path", str(base_artifact),
                "--current-artifact-path", str(current_artifact),
                "--debug-only",
            ]
            resolution = {
                "status": "ambiguous",
                "source_status": "remote_candidates_ambiguous",
                "requested_ref": "release",
                "candidates": [
                    {"ref": "origin/release", "commit": "a" * 40},
                    {"ref": "upstream/release", "commit": "b" * 40},
                ],
            }
            with patch.object(s1_dep_diff.sys, "argv", argv), patch.object(
                s1_dep_diff.sys, "stdout", stdout,
            ), patch.object(
                s1_dep_diff.sys, "stderr", io.StringIO(),
            ), patch.object(
                s1_dep_diff,
                "load_orchestrated_step1_input",
                return_value={},
            ), patch.object(
                s1_dep_diff,
                "resolve_step1_ref",
                return_value=resolution,
            ), self.assertRaises(SystemExit) as raised:
                s1_dep_diff.main()

        self.assertEqual(raised.exception.code, s1_dep_diff.EXIT_AWAITING_USER)
        interaction = json.loads(stdout.getvalue().split(":", 1)[1])
        self.assertEqual(interaction["reason_code"], "AMBIGUOUS_STEP1_SOURCE_REF")
        request = interaction["ref_resolution_requests"][0]
        self.assertEqual(request["field"], "base_branch")
        self.assertEqual(len(request["candidates"]), 2)

    def test_branch_main_maps_real_environment_failure_to_blocked_interaction(self):
        stdout = io.StringIO()
        argv = [
            "s1_dep_diff.py",
            "--base", "base-ref",
            "--current", "current-ref",
            "--base-tool", "maven",
            "--current-tool", "maven",
            "--debug-only",
        ]
        with patch.object(s1_dep_diff.sys, "argv", argv), patch.object(
            s1_dep_diff.sys, "stdout", stdout,
        ), patch.object(
            s1_dep_diff.sys, "stderr", io.StringIO(),
        ), patch.object(
            s1_dep_diff,
            "load_orchestrated_step1_input",
            return_value={},
        ), patch.object(
            s1_dep_diff,
            "build_java_env",
            side_effect=OSError("configured JDK is unavailable"),
        ), self.assertRaises(SystemExit) as raised:
            s1_dep_diff.main()

        self.assertEqual(raised.exception.code, s1_dep_diff.EXIT_AWAITING_USER)
        interaction = json.loads(stdout.getvalue().split(":", 1)[1])
        self.assertEqual(interaction["reason_code"], "STEP1_MAVEN_COMMAND_BLOCKED")
        self.assertEqual(interaction["blocked_stage"], "prepare_java_env")
        self.assertEqual(interaction["blocked_branch"], "base-ref")
        self.assertIn("configured JDK is unavailable", interaction["stderr_excerpt"])

    def test_direct_artifact_main_invokes_both_lazy_runtime_loaders(self):
        entry = {
            "coord": "g:a", "version": "1", "scope": "compile",
            "artifact_id": "a", "group_id": "g", "lib_entry": "lib/a.jar",
        }
        collector_sides = []

        def collect(_path, **kwargs):
            loader = kwargs["runtime_deps_loader"]
            self.assertEqual(loader(), {"g:a": entry})
            collector_sides.append(kwargs["side"])
            return {"g:a": entry}, {
                "mode": "final_artifact", "dep_entries": [entry], "deps": [entry],
                "archives": [], "matched_count": 1, "unresolved_items": [],
            }

        argv = [
            "s1_dep_diff.py", "--base-tool", "maven", "--current-tool", "maven",
            "--base-artifact-path", "base.jar", "--current-artifact-path", "current.jar",
            "--debug-only",
        ]
        orchestrated = {
            "base_resolved_commit": "a" * 40,
            "current_resolved_commit": "b" * 40,
            "base_ref_source_status": "remote_source_resolved",
            "current_ref_source_status": "user_confirmed_local_source",
        }
        runtime_meta = {
            "list_command": "dependency:list", "source_mode": "pinned",
            "resolved_commit": "a" * 40,
        }
        with patch.object(s1_dep_diff.sys, "argv", argv), patch.object(
            s1_dep_diff.sys, "stderr", io.StringIO(),
        ), patch.object(s1_dep_diff, "load_orchestrated_step1_input", return_value=orchestrated), patch.object(
            s1_dep_diff, "_collect_runtime_deps_for_artifact_input",
            return_value=({"g:a": entry}, runtime_meta),
        ) as runtime_collect, patch.object(
            s1_dep_diff, "collect_packaged_deps_from_artifact_path", side_effect=collect,
        ):
            self.assertIsNone(s1_dep_diff.main())
        self.assertEqual(collector_sides, ["base", "current"])
        self.assertEqual(runtime_collect.call_count, 2)

    def test_branch_build_failure_prints_each_sides_actual_build_tool_command(self):
        stderr = io.StringIO()
        argv = [
            "s1_dep_diff.py",
            "--base", "base-ref",
            "--current", "current-ref",
            "--base-tool", "maven",
            "--current-tool", "gradle",
            "--primary-module", "app",
        ]
        with patch.object(s1_dep_diff.sys, "argv", argv), patch.object(
            s1_dep_diff.sys, "stderr", stderr,
        ), patch.object(
            s1_dep_diff,
            "get_packaged_deps_by_switching_branch",
            side_effect=RuntimeError("build failed"),
        ), patch.object(
            s1_dep_diff,
            "_gradle_target_model",
            return_value={"gradle_path": ":app"},
        ), patch.object(
            s1_dep_diff,
            "gradle_cmd",
            return_value=["gradle"],
        ), self.assertRaises(SystemExit) as raised:
            s1_dep_diff.main()

        self.assertEqual(raised.exception.code, 1)
        rendered = stderr.getvalue()
        _prefix, base_and_current = rendered.split("git checkout base-ref", 1)
        base_section, current_section = base_and_current.split("git checkout current-ref", 1)
        self.assertIn("mvn -pl :app -am", base_section)
        self.assertNotIn("gradle", base_section)
        self.assertIn("gradle :app:build -x test", current_section)
        self.assertNotIn("mvn", current_section)


class Step2InferenceContractTest(unittest.TestCase):
    def test_pinned_source_snapshot_is_commit_bound_normalized_and_deduplicated(self):
        commit = "a" * 40
        snapshot = s2_context_from_deps._valid_pinned_source_snapshot(
            {
                "pinned_source_snapshot": {
                    "schema": s2_context_from_deps.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                    "commit": commit.upper(),
                    "project_path": "modules\\app",
                    "source_roots": [
                        "src\\main\\java",
                        "src/main/java",
                        "src/main/resources",
                    ],
                }
            },
            commit,
        )

        self.assertEqual(snapshot["commit"], commit)
        self.assertEqual(snapshot["project_path"], "modules/app")
        self.assertEqual(
            snapshot["source_roots"],
            ["src/main/java", "src/main/resources"],
        )

    def test_pinned_workspace_maps_stable_paths_and_always_removes_worktree(self):
        commit = "b" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "checkout"
            git_root = root / "repository"
            worktree = root / "detached"
            repository.mkdir()
            git_root.mkdir()
            (worktree / "modules" / "app" / "src" / "main" / "java").mkdir(
                parents=True,
            )
            orchestrated = {
                "current_ref_binding": {"repo_dir": str(repository)},
                "pinned_source_snapshot": {
                    "schema": s2_context_from_deps.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                    "commit": commit,
                    "project_path": "modules/app",
                    "source_roots": ["src/main/java"],
                },
            }

            with patch.object(
                s2_context_from_deps, "get_git_root", return_value=str(git_root),
            ), patch.object(
                s2_context_from_deps,
                "create_detached_worktree",
                return_value=worktree,
            ) as create, patch.object(
                s2_context_from_deps, "remove_detached_worktree",
            ) as remove, patch.object(
                s2_context_from_deps, "git_cmd", return_value=["git"],
            ):
                with s2_context_from_deps.materialize_pinned_step2_source_workspace(
                    orchestrated, commit, repository,
                ) as materialized:
                    self.assertEqual(
                        materialized["project_root"],
                        (worktree / "modules" / "app").resolve(),
                    )
                    self.assertEqual(
                        materialized["mapped_source_dirs"],
                        [str((worktree / "modules/app/src/main/java").resolve())],
                    )
                    self.assertEqual(
                        materialized["stable_source_dirs"],
                        [str((repository / "src/main/java").resolve())],
                    )

            create.assert_called_once_with(
                commit,
                git_root.resolve(),
                label="s2-src",
                runner=s2_context_from_deps.run_cmd,
                git_command=["git"],
            )
            remove.assert_called_once_with(
                worktree,
                git_root.resolve(),
                runner=s2_context_from_deps.run_cmd,
                git_command=["git"],
            )

    def test_pinned_relative_paths_reject_absolute_and_parent_escape(self):
        normalize = s2_context_from_deps._normalize_pinned_relative_path
        self.assertEqual(normalize("src\\main\\java"), "src/main/java")
        self.assertEqual(normalize("."), ".")
        self.assertEqual(normalize(".", allow_root=False), "")
        for invalid in ("../src", "/src", "C:/src"):
            self.assertEqual(normalize(invalid), "")

    def test_deprecated_m2_hook_never_uses_mutable_local_repository(self):
        self.assertEqual(
            s2_context_from_deps.get_pom_deps_from_m2("g", "a", "1"), [],
        )

    def test_spring_and_technology_detection_uses_resolved_dependency_scope(self):
        deps = {
            "org.springframework.cloud:spring-cloud-context": {"new_version": "4.1"},
            "org.projectlombok:lombok": {"new_version": "1.18"},
            "org.mybatis:mybatis": {"new_version": "3.5"},
            "unrelated:library": {"new_version": "1"},
        }
        self.assertEqual(s2_context_from_deps.detect_spring_cloud(deps), (True, "4.1"))
        flags = s2_context_from_deps.detect_tech_flags(deps)
        self.assertTrue(flags["spring_cloud"])
        self.assertTrue(flags["lombok"])
        self.assertTrue(flags["mybatis"])
        self.assertFalse(flags["kafka"])
        self.assertEqual(s2_context_from_deps.detect_spring_cloud({}), (False, None))

    def test_local_file_reader_follows_candidates_and_tolerates_read_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "second.txt").write_text("content", encoding="utf-8")
            self.assertEqual(
                s2_context_from_deps.read_local_file(root, "first.txt", "second.txt"),
                "content",
            )
            self.assertEqual(s2_context_from_deps.read_local_file(root, "missing"), "")

    def test_build_tool_detection_covers_checkout_fixed_commit_and_strict_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pom.xml").write_text("<project/>", encoding="utf-8")
            self.assertEqual(
                s2_context_from_deps.detect_build_tool("branch", root), "maven",
            )

        commit = "a" * 40
        with patch.object(s2_context_from_deps, "is_git_repo", return_value=True), patch.object(
            s2_context_from_deps, "build_manifest_candidates",
            side_effect=[["pom.xml"], ["build.gradle", "build.gradle.kts"]],
        ), patch.object(
            s2_context_from_deps, "run_cmd",
            side_effect=[("", "absent", 1), ("build.gradle\n", "", 0)],
        ):
            self.assertEqual(
                s2_context_from_deps.detect_build_tool(commit, "."), "gradle",
            )

        with patch.object(s2_context_from_deps, "is_git_repo", return_value=True), patch.object(
            s2_context_from_deps, "build_manifest_candidates", return_value=["pom.xml"],
        ), patch.object(
            s2_context_from_deps, "run_cmd", return_value=("", "permission denied", 1),
        ), patch.object(s2_context_from_deps, "_git_path_is_absent", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "STEP2_GIT_SHOW_FAILED"):
                s2_context_from_deps.detect_build_tool(commit, ".", strict_git=True)

    def test_jvm_parameter_diff_includes_only_added_or_removed_xx_flags(self):
        diff = (
            "--- a/start.sh\n+++ b/start.sh\n"
            "--XX:+UseOld\n+-XX:+UseG1GC -Xmx1g\n"
            "+echo unchanged\n"
        )
        with patch.object(s2_context_from_deps, "is_git_repo", return_value=True), patch.object(
            s2_context_from_deps, "run_cmd", return_value=(diff, "", 0),
        ):
            self.assertEqual(
                s2_context_from_deps.detect_jvm_param_changes("base", "current", "."),
                ["-XX:+UseG1GC", "-XX:+UseOld"],
            )
        with patch.object(s2_context_from_deps, "is_git_repo", return_value=False):
            self.assertEqual(
                s2_context_from_deps.detect_jvm_param_changes("base", "current", "."), [],
            )
        with patch.object(s2_context_from_deps, "is_git_repo", return_value=True), patch.object(
            s2_context_from_deps, "run_cmd", return_value=("", "failed", 1),
        ):
            with self.assertRaisesRegex(RuntimeError, "STEP2_GIT_DIFF_FAILED"):
                s2_context_from_deps.detect_jvm_param_changes(
                    "base", "current", ".", strict_git=True,
                )


class Step3ScannerContractTest(unittest.TestCase):
    def test_dependency_ledgers_record_unreadable_inputs_and_current_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broken = root / "broken.csv"
            broken.write_text("coord,new_version\n", encoding="utf-8")

            s3_scan.reset_scan_diagnostics()
            with patch.object(
                s3_scan, "open_csv_read", side_effect=OSError("denied"),
            ):
                self.assertEqual(s3_scan.load_dep_changes(str(broken)), [])
            self.assertEqual(
                s3_scan.get_scan_diagnostics()[0]["stage"],
                "dependency_changes_load",
            )

            s3_scan.reset_scan_diagnostics()
            with patch.object(
                s3_scan, "open_csv_read", side_effect=UnicodeError("bad encoding"),
            ):
                self.assertEqual(s3_scan.load_current_deps(str(broken)), [])
            self.assertEqual(
                s3_scan.get_scan_diagnostics()[0]["stage"],
                "current_dependencies_load",
            )

            current = root / "current.csv"
            current.write_text(
                "coord,new_version,scope\n"
                "g:kept,2.0,runtime\n"
                "g:removed,-,runtime\n",
                encoding="utf-8",
            )
            self.assertEqual(
                s3_scan.load_current_deps(str(current)),
                [{
                    "coord": "g:kept",
                    "new_version": "2.0",
                    "scope": "runtime",
                    "version": "2.0",
                }],
            )

    def test_final_artifact_provenance_parse_failure_is_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dep_list = root / "deps_current_resolved.csv"
            dep_list.write_text("coord,version\n", encoding="utf-8")
            (root / "build_provenance.json").write_text(
                "{invalid-json", encoding="utf-8",
            )
            s3_scan.reset_scan_diagnostics()

            artifact, reason = s3_scan.resolve_current_final_artifact_path(
                str(dep_list),
            )

        self.assertEqual(artifact, "")
        self.assertEqual(reason, "current_final_artifact_provenance_unreadable")
        diagnostics = s3_scan.get_scan_diagnostics()
        self.assertEqual(diagnostics[0]["stage"], "current_final_artifact_provenance_load")
        self.assertEqual(diagnostics[0]["error_type"], "JSONDecodeError")

    def test_outer_artifact_entry_read_failure_is_yielded_and_diagnosed(self):
        dependency = {
            "coord": "g:a",
            "version": "1",
            "scope": "runtime",
            "lib_entry": "BOOT-INF/lib/a.jar",
        }

        class BrokenOuter:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def namelist(self):
                return [dependency["lib_entry"]]

            def read(self, _entry):
                raise zipfile.BadZipFile("bad crc")

        s3_scan.reset_scan_diagnostics()
        with patch.object(s3_scan, "load_current_deps", return_value=[dependency]), patch.object(
            s3_scan,
            "resolve_current_final_artifact_path",
            return_value=("/retained/current.jar", ""),
        ), patch.object(s3_scan.zipfile, "ZipFile", return_value=BrokenOuter()):
            rows = list(s3_scan.iter_current_final_artifact_dependencies("deps.csv"))

        self.assertEqual(rows[0]["error_code"], "current_final_artifact_entry_unreadable")
        diagnostics = s3_scan.get_scan_diagnostics()
        self.assertEqual(diagnostics[0]["stage"], "current_final_artifact_dependency_read")
        self.assertIn("BOOT-INF/lib/a.jar", diagnostics[0]["path"])

    @staticmethod
    def _dependency_scan_input(jar_bytes=b"not-a-jar"):
        return {
            "dependency": {
                "coord": "g:a",
                "version": "1",
                "scope": "runtime",
                "lib_entry": "BOOT-INF/lib/a.jar",
            },
            "jar_bytes": jar_bytes,
            "error_code": "",
        }

    def test_dependency_compat_nested_jar_failure_is_not_a_clean_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "compat.csv"
            s3_scan.reset_scan_diagnostics()
            with patch.object(
                s3_scan,
                "iter_current_final_artifact_dependencies",
                return_value=[self._dependency_scan_input()],
            ):
                count = s3_scan.scan_dependency_compat([], output, "deps.csv")

            with output.open(encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))

        self.assertEqual(count, 1)
        self.assertEqual(row["风险类型"], "nested_jar_unreadable")
        self.assertEqual(
            s3_scan.get_scan_diagnostics()[0]["stage"],
            "dependency_compat_nested_jar_open",
        )

    def test_dependency_compat_class_read_failure_is_diagnosed(self):
        class BrokenNested:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def namelist(self):
                return ["demo/Api.class"]

            def open(self, _entry):
                raise zipfile.BadZipFile("bad class entry")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "compat.csv"
            s3_scan.reset_scan_diagnostics()
            with patch.object(
                s3_scan,
                "iter_current_final_artifact_dependencies",
                return_value=[self._dependency_scan_input(b"placeholder")],
            ), patch.object(s3_scan.zipfile, "ZipFile", return_value=BrokenNested()):
                count = s3_scan.scan_dependency_compat([], output, "deps.csv")

        self.assertEqual(count, 0)
        self.assertEqual(
            s3_scan.get_scan_diagnostics()[0]["stage"],
            "dependency_compat_class_read",
        )

    def test_dependency_classfile_entry_failure_is_reported_as_incomplete(self):
        class BrokenNested:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def namelist(self):
                return ["demo/Api.class"]

            def read(self, _entry, pwd=None):
                raise zipfile.BadZipFile("bad class entry")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "classfile.csv"
            s3_scan.reset_scan_diagnostics()
            with patch.object(
                s3_scan,
                "iter_current_final_artifact_dependencies",
                return_value=[self._dependency_scan_input(b"placeholder")],
            ), patch.object(s3_scan.zipfile, "ZipFile", return_value=BrokenNested()):
                risk_count = s3_scan.scan_dependency_classfile_versions(
                    [], output, "deps.csv",
                )
            with output.open(encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))

        self.assertEqual(risk_count, 1)
        self.assertIn("1 个 Class 条目无法读取", row["扫描结论"])
        self.assertEqual(
            s3_scan.get_scan_diagnostics()[0]["stage"],
            "dependency_classfile_entry_read",
        )

    def test_step3_coverage_reads_each_discovered_source_and_records_metrics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "src"
            source.mkdir()
            (source / "Demo.java").write_text("class Demo {}", encoding="utf-8")
            output = root / "coverage.json"
            s3_scan.reset_scan_diagnostics()

            payload = s3_scan.write_step3_coverage(
                root,
                [str(source)],
                ["javax"],
                ["javax"],
                str(output),
            )

        self.assertEqual(payload["status"], "complete")
        self.assertEqual(payload["metrics"]["files_scanned"], 1)
        self.assertEqual(payload["metrics"]["extension_counts"], {".java": 1})

    def test_dependency_version_selection_never_resurrects_removed_current_version(self):
        self.assertEqual(
            s3_scan.resolve_dep_version({"old_version": "1", "new_version": "2"}), "2",
        )
        self.assertEqual(
            s3_scan.resolve_dep_version({"old_version": "1", "new_version": "-"}), "1",
        )
        self.assertIsNone(s3_scan.resolve_dep_version({"old_version": "-", "new_version": "-"}))
        self.assertEqual(
            s3_scan.resolve_current_dep_version({"old_version": "1", "new_version": "2"}), "2",
        )
        self.assertIsNone(
            s3_scan.resolve_current_dep_version({"old_version": "1", "new_version": "-"}),
        )

    def test_safe_line_reader_limits_content_and_records_read_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.txt"
            path.write_text("\nfirst\nsecond\nthird\n", encoding="utf-8")
            self.assertEqual(s3_scan._safe_read_lines(path, limit=2), [(2, "first"), (3, "second")])
            with patch.object(s3_scan, "record_scan_diagnostic") as diagnostic:
                self.assertEqual(s3_scan._safe_read_lines(path.with_name("missing")), [])
            diagnostic.assert_called_once()

    def test_source_scanners_find_code_but_ignore_runtime_flag_comments(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "src" / "main"
            java = root / "java" / "Sample.java"
            java.parent.mkdir(parents=True)
            java.write_text(
                "import sun.misc.Unsafe;\n"
                "public class Sample implements java.io.Serializable {\n"
                "  void x() throws Exception { Class.forName(\"a.B\"); }\n"
                "}\n",
                encoding="utf-8",
            )
            dockerfile = root / "resources" / "Dockerfile.prod"
            dockerfile.parent.mkdir(parents=True)
            dockerfile.write_text(
                "# -XX:+UseConcMarkSweepGC ignored\n"
                "ENTRYPOINT java -XX:+UseConcMarkSweepGC -jar app.jar\n",
                encoding="utf-8",
            )
            output = Path(temporary) / "out"
            self.assertGreaterEqual(
                s3_scan.scan_jdk_internal(str(root), output / "internal.csv"), 1,
            )
            self.assertGreaterEqual(
                s3_scan.scan_reflection(str(root), output / "reflection.csv"), 1,
            )
            self.assertEqual(
                s3_scan.scan_serialization(str(root), output / "serialization.txt"), 1,
            )
            self.assertEqual(
                s3_scan.scan_jdk_runtime_flags(str(root), output / "flags.csv"), 1,
            )
            flags = (output / "flags.csv").read_text(encoding="utf-8-sig")
        self.assertIn("UseConcMarkSweepGC", flags)
        self.assertNotIn("ignored", flags)


if __name__ == "__main__":
    unittest.main()
