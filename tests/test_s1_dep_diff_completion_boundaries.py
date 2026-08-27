from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s1_dep_diff


class Step1DependencyDiffCompletionBoundaryTest(unittest.TestCase):
    @staticmethod
    def _step1_args(**overrides):
        values = {
            "base_branch": None,
            "current_branch": None,
            "base_tool": None,
            "current_tool": None,
            "base_artifact_path": None,
            "current_artifact_path": None,
            "base_source_project_dir": None,
            "current_source_project_dir": None,
            "base_jdk_home": None,
            "current_jdk_home": None,
            "primary_module": None,
            "modules": None,
            "active_maven_profile": [],
            "manual_coord_override": [],
            "manual_artifact_identity": [],
            "confirmed_unresolved_item": [],
            "allow_unresolved": False,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    @staticmethod
    def _main_entry(side="base", version="1.0.0", **overrides):
        entry = {
            "entry_id": f"{side}-entry",
            "lib_entry": f"BOOT-INF/lib/demo-{version}.jar",
            "lib_name": f"demo-{version}.jar",
            "coord": "org.example:demo",
            "group_id": "org.example",
            "artifact_id": "demo",
            "classifier": "",
            "version": version,
            "scope": "packaged",
            "remark": "fixture",
            "packaged_present": "true",
            "packaged_match_source": "embedded-pom",
            "read_error": "",
            "resolution_status": "resolved",
        }
        entry.update(overrides)
        return entry

    @classmethod
    def _main_meta(cls, side="base", version="1.0.0", **overrides):
        entry = cls._main_entry(side, version)
        meta = {
            "mode": "final_artifact",
            "archives": [],
            "deps": [entry],
            "dep_entries": [entry],
            "matched_count": 1,
            "runtime_only_count": 0,
            "runtime_only_coords": [],
            "unresolved_items": [],
        }
        meta.update(overrides)
        return meta

    def test_orchestrated_argument_merge_precedence_and_empty_matrix(self):
        marker = self._step1_args(base_branch="cli")
        self.assertIs(
            s1_dep_diff._merge_orchestrated_step1_args(marker, {}),
            marker,
        )
        self.assertEqual(s1_dep_diff._first_nonempty(), "")
        self.assertEqual(s1_dep_diff._first_nonempty("", None, "value"), "value")
        self.assertEqual(s1_dep_diff._first_nonempty("first", "second"), "first")

        explicit = self._step1_args(
            base_branch="cli-base",
            current_branch="cli-current",
            base_tool="maven",
            current_tool="gradle",
            base_artifact_path="cli-base.jar",
            current_artifact_path="cli-current.jar",
            base_source_project_dir="cli-base-src",
            current_source_project_dir="cli-current-src",
            base_jdk_home="cli-base-jdk",
            current_jdk_home="cli-current-jdk",
            primary_module="cli-module",
            modules=["cli-module"],
            active_maven_profile=["cli-profile"],
            manual_coord_override=["cli-override"],
            manual_artifact_identity=["cli-identity"],
            confirmed_unresolved_item=["cli-unresolved"],
            allow_unresolved=True,
        )
        persisted = {
            "base_resolved_commit": "persisted-base-commit",
            "current_resolved_commit": "persisted-current-commit",
            "base_tool": "gradle",
            "current_tool": "maven",
            "base_artifact_path": "persisted-base.jar",
            "current_artifact_path": "persisted-current.jar",
            "base_source_project_dir": "persisted-base-src",
            "current_source_project_dir": "persisted-current-src",
            "base_jdk_home": "persisted-base-jdk",
            "current_jdk_home": "persisted-current-jdk",
            "primary_module": "persisted-module",
            "modules": ["persisted-module"],
            "active_maven_profiles": ["persisted-profile"],
            "manual_coord_overrides": ["persisted-override"],
            "manual_artifact_identities": [{"side": "base"}],
            "confirmed_unresolved_items": [{"side": "current"}],
            "allow_unresolved": False,
        }
        s1_dep_diff._merge_orchestrated_step1_args(explicit, persisted)
        self.assertEqual(explicit.base_branch, "cli-base")
        self.assertEqual(explicit.current_branch, "cli-current")
        self.assertEqual(explicit.base_tool, "maven")
        self.assertEqual(explicit.current_tool, "gradle")
        self.assertEqual(explicit.base_artifact_path, "cli-base.jar")
        self.assertEqual(explicit.current_artifact_path, "cli-current.jar")
        self.assertEqual(explicit.base_source_project_dir, "cli-base-src")
        self.assertEqual(explicit.current_source_project_dir, "cli-current-src")
        self.assertEqual(explicit.base_jdk_home, "cli-base-jdk")
        self.assertEqual(explicit.current_jdk_home, "cli-current-jdk")
        self.assertEqual(explicit.primary_module, "cli-module")
        self.assertEqual(explicit.modules, ["cli-module"])
        self.assertEqual(explicit.active_maven_profile, ["cli-profile"])
        self.assertEqual(explicit.manual_coord_override, ["cli-override"])
        self.assertEqual(explicit.manual_artifact_identity, ["cli-identity"])
        self.assertEqual(explicit.confirmed_unresolved_item, ["cli-unresolved"])
        self.assertTrue(explicit.allow_unresolved)

        supplied = self._step1_args()
        s1_dep_diff._merge_orchestrated_step1_args(supplied, persisted)
        self.assertEqual(supplied.base_branch, "persisted-base-commit")
        self.assertEqual(supplied.current_branch, "persisted-current-commit")
        self.assertEqual(supplied.base_tool, "gradle")
        self.assertEqual(supplied.current_tool, "maven")
        self.assertEqual(supplied.modules, ["persisted-module"])
        self.assertEqual(supplied.active_maven_profile, ["persisted-profile"])
        self.assertEqual(supplied.manual_coord_override, ["persisted-override"])
        self.assertEqual(
            json.loads(supplied.manual_artifact_identity[0]),
            {"side": "base"},
        )
        self.assertEqual(
            json.loads(supplied.confirmed_unresolved_item[0]),
            {"side": "current"},
        )
        self.assertFalse(supplied.allow_unresolved)

        fallback = self._step1_args()
        s1_dep_diff._merge_orchestrated_step1_args(fallback, {
            "base_resolved_ref": "base-resolved-ref",
            "current_branch": "current-branch",
            "allow_unresolved": True,
        })
        self.assertEqual(fallback.base_branch, "base-resolved-ref")
        self.assertEqual(fallback.current_branch, "current-branch")
        self.assertEqual(fallback.active_maven_profile, [])
        self.assertEqual(fallback.manual_coord_override, [])
        self.assertEqual(fallback.manual_artifact_identity, [])
        self.assertEqual(fallback.confirmed_unresolved_item, [])
        self.assertTrue(fallback.allow_unresolved)

    def test_confirmed_source_resolution_and_runtime_provenance_matrix(self):
        self.assertEqual(
            s1_dep_diff._confirmed_source_resolution({}, "base"),
            {},
        )
        self.assertEqual(
            s1_dep_diff._confirmed_source_resolution({
                "base_resolved_commit": "abc",
                "base_ref_source_status": "untrusted",
            }, "base"),
            {},
        )
        for source_status in (
            "remote_source_resolved",
            "user_confirmed_local_source",
        ):
            with self.subTest(source_status=source_status):
                resolution = s1_dep_diff._confirmed_source_resolution({
                    "base_resolved_commit": " abc ",
                    "base_ref_source_status": f" {source_status} ",
                    "base_requested_ref": "release",
                    "base_resolved_ref": "origin/release",
                    "base_ref_resolution_mode": "live_remote",
                    "base_ref_resolution_fingerprint": "fingerprint",
                    "base_ref_remote": "origin",
                    "base_ref_remote_ref": "refs/heads/release",
                }, "base")
                self.assertEqual(resolution["resolved_commit"], "abc")
                self.assertEqual(resolution["source_status"], source_status)
                self.assertEqual(resolution["requested_ref"], "release")
                self.assertEqual(resolution["resolved_ref"], "origin/release")
                self.assertEqual(resolution["resolution_mode"], "live_remote")
                self.assertEqual(resolution["fingerprint"], "fingerprint")
                self.assertEqual(resolution["remote"], "origin")
                self.assertEqual(resolution["remote_ref"], "refs/heads/release")
        minimal_resolution = s1_dep_diff._confirmed_source_resolution({
            "current_resolved_commit": "commit",
            "current_ref_source_status": "remote_source_resolved",
        }, "current")
        self.assertEqual(minimal_resolution["requested_ref"], "")
        self.assertEqual(minimal_resolution["resolved_ref"], "")
        self.assertEqual(minimal_resolution["resolution_mode"], "")
        self.assertEqual(minimal_resolution["fingerprint"], "")
        self.assertEqual(minimal_resolution["remote"], "")
        self.assertEqual(minimal_resolution["remote_ref"], "")

        unchanged = {"existing": "value"}
        self.assertIs(
            s1_dep_diff._apply_runtime_provenance(unchanged, {}),
            unchanged,
        )
        runtime_meta = {
            "list_command": "mvn dependency:list",
            "source_mode": "checkout",
            "requested_ref": "requested",
            "resolved_ref": "resolved",
            "resolved_commit": "commit",
            "ref_resolution_mode": "exact",
            "ref_source_status": "remote_source_resolved",
            "ref_remote": "origin",
            "ref_remote_ref": "refs/heads/main",
        }
        target = {}
        self.assertIs(
            s1_dep_diff._apply_runtime_provenance(target, runtime_meta),
            target,
        )
        self.assertEqual(target["runtime_source_mode"], "checkout")
        self.assertEqual(target["revision"], "commit")
        self.assertEqual(target["ref_remote_ref"], "refs/heads/main")
        missing_optional = {"list_command": "gradle dependencies"}
        self.assertEqual(
            s1_dep_diff._apply_runtime_provenance({}, missing_optional)["revision"],
            "",
        )

    def test_provenance_side_artifact_build_and_precedence_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "app.jar"
            artifact.write_bytes(b"artifact")
            rich_meta = {
                "artifact_path": str(artifact),
                "resolved_ref": "meta-ref",
                "requested_ref": "meta-requested",
                "ref_resolution_mode": "meta-mode",
                "ref_source_status": "meta-status",
                "ref_remote": "meta-remote",
                "ref_remote_ref": "meta-remote-ref",
                "revision": "meta-revision",
                "jdk_home": "meta-jdk",
                "build_command": "mvn package",
                "build_tool": "maven",
                "original_artifact_path": "original.jar",
                "artifact_relative_path": "target/app.jar",
                "project_scope_hash": "scope",
                "source_state_hash": "source",
                "maven_model_hash": "maven-model",
                "gradle_model_hash": "gradle-model",
                "build_model_hash": "build-model",
                "active_maven_profiles": [" z ", "a", "", "a"],
            }
            orchestrated = {
                "base_resolved_ref": "persisted-ref",
                "base_requested_ref": "persisted-requested",
                "base_resolved_commit": "persisted-revision",
            }
            with patch.object(
                s1_dep_diff,
                "resolve_effective_jdk_home",
                return_value="configured-jdk",
            ):
                provided = s1_dep_diff._build_step1_provenance_side(
                    "base", rich_meta, "branch", "configured", "gradle",
                    "app", orchestrated, True,
                )
            self.assertEqual(provided["source_mode"], "provided_artifact")
            self.assertEqual(provided["build_execution_status"], "not_executed")
            self.assertFalse(provided["build_executed_by_system"])
            self.assertTrue(provided["artifact_available"])
            self.assertEqual(provided["ref"], "meta-ref")
            self.assertEqual(provided["revision"], "meta-revision")
            self.assertEqual(provided["jdk_home"], "meta-jdk")
            self.assertEqual(provided["build_tool"], "maven")
            self.assertEqual(provided["active_maven_profiles"], ["a", "z"])
            self.assertEqual(provided["build_model_hash"], "build-model")
            self.assertEqual(
                provided["artifact_sha256"],
                s1_dep_diff.sha256_file(artifact),
            )

            with patch.object(
                s1_dep_diff,
                "resolve_effective_jdk_home",
                return_value="configured-jdk",
            ):
                checkout_missing = s1_dep_diff._build_step1_provenance_side(
                    "base",
                    {"artifact_path": str(root / "missing.jar")},
                    "branch",
                    "configured",
                    "gradle",
                    None,
                    orchestrated,
                    False,
                )
                checkout_existing = s1_dep_diff._build_step1_provenance_side(
                    "current",
                    {
                        "artifact_path": str(artifact),
                        "artifact_sha256": "declared-hash",
                        "maven_model_hash": "maven-fallback",
                    },
                    "current-branch",
                    "configured",
                    "gradle",
                    None,
                    {},
                    False,
                )
                no_meta = s1_dep_diff._build_step1_provenance_side(
                    "current", None, "fallback-branch", None, "gradle", None,
                    {}, False,
                )
            self.assertEqual(checkout_missing["source_mode"], "checkout_build")
            self.assertEqual(checkout_missing["build_execution_status"], "failed")
            self.assertEqual(checkout_missing["ref"], "persisted-ref")
            self.assertEqual(checkout_missing["requested_ref"], "persisted-requested")
            self.assertEqual(checkout_missing["revision"], "persisted-revision")
            self.assertEqual(checkout_missing["jdk_home"], "configured-jdk")
            self.assertEqual(checkout_missing["build_tool"], "gradle")
            self.assertEqual(checkout_existing["build_execution_status"], "succeeded")
            self.assertEqual(checkout_existing["artifact_sha256"], "declared-hash")
            self.assertEqual(checkout_existing["build_model_hash"], "maven-fallback")
            self.assertEqual(no_meta["ref"], "fallback-branch")
            self.assertEqual(no_meta["requested_ref"], "fallback-branch")
            self.assertFalse(no_meta["artifact_available"])

    def test_alert_row_selection_reason_and_default_matrix(self):
        rows = [
            {
                "coord": "g:clean",
                "old_version": "1",
                "new_version": "2",
                "change_type": "大版本升级",
                "risk": "低",
                "resolution_status": "resolved",
            },
            {
                "coord": "g:downgrade",
                "old_version": "2",
                "new_version": "1",
                "change_type": "降级⚠️",
                "risk": "高",
                "resolution_status": "resolved",
            },
            {
                "coord": "g:unknown",
                "old_version": "1",
                "new_version": "2",
                "change_type": "版本格式不规则",
                "risk": "❓需人工确认",
                "resolution_status": "unresolved",
            },
            {
                "change_type": "降级⚠️",
                "risk": "❓需人工确认",
                "resolution_status": "",
            },
            {
                "change_type": "",
                "risk": "❓需人工确认",
                "resolution_status": None,
            },
            {
                "change_type": "降级⚠️",
                "risk": "",
                "resolution_status": "pending",
            },
        ]
        alerts, alert_rows = s1_dep_diff._build_step1_alert_rows(rows)
        self.assertEqual(alerts, rows[1:])
        self.assertEqual(len(alert_rows), 5)
        self.assertEqual(
            alert_rows[0]["review_reason"],
            "依赖版本发生降级",
        )
        self.assertEqual(
            alert_rows[1]["review_reason"],
            "风险状态不明确；依赖坐标解析状态：unresolved",
        )
        self.assertEqual(
            alert_rows[2]["review_reason"],
            "依赖版本发生降级；风险状态不明确",
        )
        self.assertEqual(
            alert_rows[2]["change_summary"],
            "-: - -> -，降级⚠️",
        )
        self.assertEqual(
            tuple(alert_rows[0]),
            s1_dep_diff.STEP1_ALERT_FIELDS,
        )
        self.assertEqual(alert_rows[3]["review_reason"], "风险状态不明确")
        self.assertEqual(
            alert_rows[4]["review_reason"],
            "依赖版本发生降级；依赖坐标解析状态：pending",
        )
        self.assertEqual(
            s1_dep_diff._build_step1_alert_rows([]),
            ([], []),
        )

    def test_summary_lines_direct_branch_empty_and_capped_matrix(self):
        resolved_entry = {
            "resolution_status": "resolved",
            "read_error": "",
        }
        with patch.object(
            s1_dep_diff, "resolve_primary_module_id", return_value="",
        ):
            direct_lines, direct_want = s1_dep_diff._build_step1_summary_lines(
                rows=[],
                alerts=[],
                curr_entries=[resolved_entry],
                unresolved_records=[],
                base_artifact_path="base.jar",
                current_artifact_path="current.jar",
                base_branch=None,
                current_branch=None,
                primary_module=None,
                work_dir=".",
                base_fmt="final_artifact",
                packaged_summary={"mode": "", "archives": None},
                base_meta={},
                curr_meta={},
                counts={},
            )
        direct_text = "\n".join(direct_lines)
        self.assertEqual(direct_want, "")
        self.assertIn("未生成需要优先复核", direct_text)
        self.assertIn("用户提供 base/current 编译产物", direct_text)
        self.assertIn("目标模块：未指定", direct_text)
        self.assertIn("current 打包模式：未知", direct_text)
        self.assertIn("当前打包依赖坐标未解析：0", direct_text)
        self.assertIn("当前打包依赖读取失败：0", direct_text)
        self.assertNotIn("current 打包产物样例", direct_text)

        alerts = [{
            "coord": f"g:a-{index}",
            "old_version": "2",
            "new_version": "1",
            "change_type": "降级⚠️",
            "risk": "高",
            "scope": "packaged",
            "remark": "review",
        } for index in range(51)]
        unresolved = [{"label": f"unknown-{index}"} for index in range(51)]
        curr_entries = [
            {"resolution_status": None, "read_error": None},
            {"resolution_status": "unresolved", "read_error": "broken"},
            {"resolution_status": "resolved", "read_error": ""},
        ]
        with patch.object(
            s1_dep_diff, "resolve_primary_module_id", return_value="app",
        ):
            branch_lines, branch_want = s1_dep_diff._build_step1_summary_lines(
                rows=[{}, {}],
                alerts=alerts,
                curr_entries=curr_entries,
                unresolved_records=unresolved,
                base_artifact_path=None,
                current_artifact_path=None,
                base_branch="base-ref",
                current_branch="current-ref",
                primary_module="app",
                work_dir="/repo",
                base_fmt="maven",
                packaged_summary={
                    "mode": "final_artifact",
                    "archives": [f"artifact-{index}.jar" for index in range(6)],
                },
                base_meta={"module_dir": "/repo/base/app"},
                curr_meta={"module_dir": "/repo/current/app"},
                counts={"新增": 1, "降级⚠️": 2, "移除": 1},
            )
        branch_text = "\n".join(branch_lines)
        self.assertEqual(branch_want, "app")
        self.assertIn("先看 dep_alerts.csv", branch_text)
        self.assertIn("自动切换 base/current 分支构建", branch_text)
        self.assertIn("当前打包依赖坐标未解析：2", branch_text)
        self.assertIn("当前打包依赖读取失败：1", branch_text)
        self.assertIn("current 打包产物样例", branch_text)
        self.assertIn("artifact-4.jar", branch_text)
        self.assertNotIn("artifact-5.jar", branch_text)
        self.assertIn("base 模块目录：/repo/base/app", branch_text)
        self.assertIn("current 模块目录：/repo/current/app", branch_text)
        self.assertLess(branch_text.index("- 降级⚠️: 2"), branch_text.index("- 新增: 1"))
        self.assertIn("6、坐标未解析依赖（前 50 项）", branch_text)
        self.assertIn("7、优先复核依赖（前 50 项）", branch_text)
        self.assertIn("unknown-49", branch_text)
        self.assertNotIn("unknown-50", branch_text)
        self.assertIn("g:a-49", branch_text)
        self.assertNotIn("g:a-50", branch_text)

        with patch.object(
            s1_dep_diff, "resolve_primary_module_id", return_value="module",
        ):
            empty_inventory_lines, _ = s1_dep_diff._build_step1_summary_lines(
                rows=[],
                alerts=[],
                curr_entries=[],
                unresolved_records=[{"label": "unknown"}],
                base_artifact_path="",
                current_artifact_path="",
                base_branch="base",
                current_branch="current",
                primary_module="module",
                work_dir=".",
                base_fmt="",
                packaged_summary={},
                base_meta={},
                curr_meta={},
                counts={},
            )
        empty_inventory_text = "\n".join(empty_inventory_lines)
        self.assertNotIn("当前打包依赖数", empty_inventory_text)
        self.assertIn("坐标未解析依赖", empty_inventory_text)

        with patch.object(
            s1_dep_diff, "resolve_primary_module_id", return_value="",
        ):
            partial_artifact_lines, _ = s1_dep_diff._build_step1_summary_lines(
                rows=[], alerts=[], curr_entries=[],
                unresolved_records=[{"label": "unknown"}],
                base_artifact_path="base.jar", current_artifact_path="",
                base_branch="base", current_branch="current",
                primary_module=None, work_dir=".", base_fmt="",
                packaged_summary={}, base_meta={}, curr_meta={}, counts={},
            )
        self.assertIn(
            "自动切换 base/current 分支构建",
            "\n".join(partial_artifact_lines),
        )

    def test_main_rejects_invalid_cli_and_incomplete_input_matrix(self):
        cases = (
            ([], 2, "required"),
            (["--base-tool", "maven", "--current-tool", "maven"], 1, "必须同时提供"),
            ([
                "--base-tool", "maven", "--current-tool", "maven",
                "--manual-coord-override", "invalid",
            ], 1, "人工坐标格式不合法"),
            ([
                "--base-tool", "maven", "--current-tool", "maven",
                "--manual-artifact-identity", "not-json",
            ], 1, "人工制品身份格式不合法"),
            ([
                "--base-tool", "maven", "--current-tool", "maven",
                "--confirmed-unresolved-item", "[]",
            ], 1, "confirmed_unresolved_items 格式不合法"),
            ([
                "--base-tool", "maven", "--current-tool", "maven",
                "--base-artifact-path", "base.jar",
            ], 1, "必须同时提供"),
            ([
                "--base-tool", "maven", "--current-tool", "maven",
                "--current-artifact-path", "current.jar",
            ], 1, "必须同时提供"),
            ([
                "--base-tool", "maven", "--current-tool", "maven",
                "--base", "base-only",
            ], 1, "必须同时提供"),
        )
        for arguments, exit_code, message in cases:
            with self.subTest(arguments=arguments), patch.object(
                s1_dep_diff, "load_orchestrated_step1_input", return_value={},
            ), patch.object(
                sys, "argv", ["s1_dep_diff.py", *arguments],
            ), patch("sys.stderr", new_callable=io.StringIO) as stderr, self.assertRaises(
                SystemExit,
            ) as caught:
                s1_dep_diff.main()
            self.assertEqual(caught.exception.code, exit_code)
            self.assertIn(message, stderr.getvalue())

    def test_main_direct_artifact_debug_loader_and_orchestration_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "dep_changes.csv"
            base_path = root / "base.jar"
            current_path = root / "current.jar"
            base_path.write_bytes(b"base")
            current_path.write_bytes(b"current")
            orchestrated = {
                "base_tool": "maven",
                "current_tool": "gradle",
                "base_artifact_path": str(base_path),
                "current_artifact_path": str(current_path),
                "base_source_project_dir": str(root / "base-source"),
                "current_source_project_dir": str(root / "current-source"),
                "base_resolved_commit": "b" * 40,
                "current_resolved_commit": "c" * 40,
                "base_requested_ref": "release-base",
                "current_requested_ref": "release-current",
                "base_resolved_ref": "origin/release-base",
                "current_resolved_ref": "origin/release-current",
                "base_ref_source_status": "remote_source_resolved",
                "current_ref_source_status": "user_confirmed_local_source",
                "base_ref_resolution_mode": "live_remote",
                "current_ref_resolution_mode": "local_confirmed",
                "base_ref_candidate_count": 2,
                "current_ref_candidate_count": 0,
                "base_ref_binding": {
                    "remote": "origin",
                    "canonical_ref": "refs/heads/release-base",
                },
                "current_ref_binding": "invalid-shape",
                "base_expected_commit": "b" * 40,
                "current_expected_commit": "",
                "base_allow_local_source": True,
                "current_allow_dirty_local_source": True,
                "primary_module": "app",
                "modules": ["app"],
                "active_maven_profiles": ["production"],
            }
            base_meta = self._main_meta("base")
            current_meta = self._main_meta("current")
            loader_results = [
                ({"org.example:demo": {"version": "1.0.0"}}, {
                    "list_command": "mvn dependency:list",
                    "source_mode": "remote_checkout",
                    "requested_ref": "release-base",
                    "resolved_ref": "origin/release-base",
                    "resolved_commit": "b" * 40,
                    "ref_resolution_mode": "live_remote",
                    "ref_source_status": "remote_source_resolved",
                    "ref_remote": "origin",
                    "ref_remote_ref": "refs/heads/release-base",
                }),
                ({"org.example:demo": {"version": "1.0.0"}}, {
                    "list_command": "gradle runtimeClasspath",
                    "source_mode": "local_source",
                }),
            ]
            loader_call_count = {"value": 0}

            def collect_artifact(_path, *, runtime_deps_loader, side, **_kwargs):
                first = runtime_deps_loader()
                second = runtime_deps_loader()
                self.assertIs(first, second)
                return (
                    {"org.example:demo": {
                        "version": "1.0.0",
                        "scope": "packaged",
                        "remark": "fixture",
                    }},
                    base_meta if side == "base" else current_meta,
                )

            def collect_runtime(*_args, **_kwargs):
                result = loader_results[loader_call_count["value"]]
                loader_call_count["value"] += 1
                return result

            with patch.object(
                s1_dep_diff, "load_orchestrated_step1_input", return_value=orchestrated,
            ), patch.object(
                s1_dep_diff,
                "collect_packaged_deps_from_artifact_path",
                side_effect=collect_artifact,
            ), patch.object(
                s1_dep_diff,
                "_collect_runtime_deps_for_artifact_input",
                side_effect=collect_runtime,
            ) as runtime_mock, patch.object(
                sys,
                "argv",
                [
                    "s1_dep_diff.py",
                    "--output", str(output),
                    "--debug-only",
                ],
            ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
                s1_dep_diff.main()

            self.assertEqual(loader_call_count["value"], 2)
            self.assertEqual(runtime_mock.call_count, 2)
            base_kwargs = runtime_mock.call_args_list[0].kwargs
            current_kwargs = runtime_mock.call_args_list[1].kwargs
            self.assertEqual(
                base_kwargs["source_resolution"]["source_status"],
                "remote_source_resolved",
            )
            self.assertEqual(base_kwargs["expected_remote"], "origin")
            self.assertEqual(
                base_kwargs["expected_remote_ref"],
                "refs/heads/release-base",
            )
            self.assertEqual(
                current_kwargs["source_resolution"]["source_status"],
                "user_confirmed_local_source",
            )
            self.assertEqual(current_kwargs["expected_remote"], "")
            self.assertEqual(current_kwargs["expected_remote_ref"], "")
            self.assertIn("调试模式完成", stderr.getvalue())
            self.assertEqual(base_meta["revision"], "b" * 40)
            self.assertEqual(current_meta["list_command"], "gradle runtimeClasspath")

            alternate_input = {
                "base_resolved_commit": "d" * 40,
                "base_ref_source_status": "remote_source_resolved",
                "base_ref_binding": "invalid-shape",
                "current_ref_binding": {
                    "remote": "upstream",
                    "canonical_ref": "refs/tags/current",
                },
                "current_expected_commit": "e" * 40,
            }
            alternate_meta = {
                "base": self._main_meta("base"),
                "current": self._main_meta("current"),
            }

            def alternate_collect(_path, *, runtime_deps_loader, side, **_kwargs):
                self.assertIs(runtime_deps_loader(), runtime_deps_loader())
                return (
                    {"org.example:demo": {
                        "version": "1.0.0",
                        "scope": "packaged",
                        "remark": "fixture",
                    }},
                    alternate_meta[side],
                )

            with patch.object(
                s1_dep_diff,
                "load_orchestrated_step1_input",
                return_value=alternate_input,
            ), patch.object(
                s1_dep_diff,
                "collect_packaged_deps_from_artifact_path",
                side_effect=alternate_collect,
            ), patch.object(
                s1_dep_diff,
                "_collect_runtime_deps_for_artifact_input",
                side_effect=[
                    ({}, {"list_command": "base-list"}),
                    ({}, {"list_command": "current-list"}),
                ],
            ) as alternate_runtime, patch.object(
                sys,
                "argv",
                [
                    "s1_dep_diff.py",
                    "--base-tool", "maven",
                    "--current-tool", "gradle",
                    "--base-artifact-path", str(base_path),
                    "--current-artifact-path", str(current_path),
                    "--output", str(root / "alternate.csv"),
                    "--debug-only",
                ],
            ), patch("sys.stderr", new_callable=io.StringIO):
                s1_dep_diff.main()

            alternate_base_kwargs = alternate_runtime.call_args_list[0].kwargs
            alternate_current_kwargs = alternate_runtime.call_args_list[1].kwargs
            self.assertEqual(alternate_base_kwargs["expected_commit"], "")
            self.assertEqual(alternate_base_kwargs["expected_remote"], "")
            self.assertEqual(alternate_base_kwargs["expected_remote_ref"], "")
            self.assertEqual(
                alternate_base_kwargs["source_resolution"]["resolved_commit"],
                "d" * 40,
            )
            self.assertEqual(
                alternate_current_kwargs["expected_commit"],
                "e" * 40,
            )
            self.assertEqual(alternate_current_kwargs["expected_remote"], "upstream")
            self.assertEqual(
                alternate_current_kwargs["expected_remote_ref"],
                "refs/tags/current",
            )
            self.assertEqual(alternate_current_kwargs["source_resolution"], {})

    def test_main_direct_artifact_failure_classification_matrix(self):
        base_arguments = [
            "s1_dep_diff.py",
            "--base-tool", "maven",
            "--current-tool", "maven",
            "--base-artifact-path", "base.jar",
            "--current-artifact-path", "current.jar",
        ]
        ref_errors = (
            s1_dep_diff.Step1RefResolutionRequiredError(
                "base", "/source", "base.jar", {"status": "ambiguous"},
            ),
            s1_dep_diff.SourceRevisionConfirmationRequiredError(
                "current", "/source", "current.jar", {},
            ),
        )
        for error, checklist in zip(ref_errors, (["select ref"], [])):
            with self.subTest(error=type(error).__name__), patch.object(
                s1_dep_diff, "load_orchestrated_step1_input", return_value={},
            ), patch.object(
                s1_dep_diff,
                "collect_packaged_deps_from_artifact_path",
                side_effect=error,
            ), patch.object(
                s1_dep_diff,
                "build_step1_ref_resolution_interaction",
                return_value={"summary": "ref blocked", "checklist_lines": checklist},
            ), patch.object(
                s1_dep_diff, "emit_step_interaction",
            ) as emit, patch.object(
                sys, "argv", base_arguments,
            ), patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(
                SystemExit,
            ) as caught:
                s1_dep_diff.main()
            self.assertEqual(caught.exception.code, s1_dep_diff.EXIT_AWAITING_USER)
            emit.assert_called_once()

        blocked_cases = (
            s1_dep_diff.Step1CommandExecutionBlockedError(
                stage="build", command="mvn package", stderr_excerpt="failed",
                branch="release", suspected_causes=["jdk", "network"],
            ),
            s1_dep_diff.Step1CommandExecutionBlockedError(
                stage="build", command="", stderr_excerpt="",
            ),
        )
        for error in blocked_cases:
            with self.subTest(blocked=bool(error.command)), patch.object(
                s1_dep_diff, "load_orchestrated_step1_input", return_value={},
            ), patch.object(
                s1_dep_diff,
                "collect_packaged_deps_from_artifact_path",
                side_effect=error,
            ), patch.object(
                s1_dep_diff,
                "build_step1_command_blocked_interaction",
                return_value={"summary": "command blocked"},
            ), patch.object(
                s1_dep_diff, "emit_step_interaction",
            ) as emit, patch.object(
                sys, "argv", base_arguments,
            ), patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(
                SystemExit,
            ) as caught:
                s1_dep_diff.main()
            self.assertEqual(caught.exception.code, s1_dep_diff.EXIT_AWAITING_USER)
            emit.assert_called_once()

        with patch.object(
            s1_dep_diff, "load_orchestrated_step1_input", return_value={},
        ), patch.object(
            s1_dep_diff,
            "collect_packaged_deps_from_artifact_path",
            side_effect=RuntimeError("unexpected"),
        ), patch.object(
            sys, "argv", base_arguments,
        ), patch("sys.stderr", new_callable=io.StringIO) as stderr, self.assertRaises(
            SystemExit,
        ) as caught:
            s1_dep_diff.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("直接产物模式执行失败", stderr.getvalue())

    def test_main_branch_mode_failure_empty_debug_and_output_matrix(self):
        base_arguments = [
            "s1_dep_diff.py",
            "--base", "base-ref",
            "--current", "current-ref",
            "--base-tool", "maven",
            "--current-tool", "gradle",
        ]
        deps = {
            "org.example:demo": {
                "version": "1.0.0",
                "scope": "packaged",
                "remark": "fixture",
            }
        }
        base_meta = self._main_meta("base", mode="maven")
        current_meta = self._main_meta("current", mode="gradle")
        with patch.object(
            s1_dep_diff, "load_orchestrated_step1_input", return_value={},
        ), patch.object(
            s1_dep_diff,
            "get_packaged_deps_by_switching_branch",
            side_effect=[(deps, base_meta), (deps, current_meta)],
        ) as collect, patch.object(
            sys, "argv", [*base_arguments, "--debug-only"],
        ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
            s1_dep_diff.main()
        self.assertIn("调试模式完成", stderr.getvalue())
        self.assertIsNone(collect.call_args_list[0].kwargs["artifact_cache_dir"])
        self.assertIsNone(collect.call_args_list[1].kwargs["artifact_cache_dir"])

        empty_cases = (
            (
                {"dep_entries": [], "deps": [], "unresolved_items": []},
                self._main_meta("current"),
                "基准分支解析结果为空",
            ),
            (
                self._main_meta("base"),
                {"dep_entries": [], "deps": [], "unresolved_items": []},
                "当前分支解析结果为空",
            ),
        )
        for raw_base_meta, raw_current_meta, expected in empty_cases:
            normalized_base_meta = {"mode": "final_artifact", **raw_base_meta}
            normalized_current_meta = {"mode": "final_artifact", **raw_current_meta}
            with self.subTest(expected=expected), patch.object(
                s1_dep_diff, "load_orchestrated_step1_input", return_value={},
            ), patch.object(
                s1_dep_diff,
                "get_packaged_deps_by_switching_branch",
                side_effect=[
                    (deps if normalized_base_meta.get("dep_entries") else {}, normalized_base_meta),
                    (deps if normalized_current_meta.get("dep_entries") else {}, normalized_current_meta),
                ],
            ), patch.object(
                sys, "argv", [*base_arguments, "--debug-only"],
            ), patch("sys.stderr", new_callable=io.StringIO) as stderr, self.assertRaises(
                SystemExit,
            ) as caught:
                s1_dep_diff.main()
            self.assertEqual(caught.exception.code, 1)
            self.assertIn(expected, stderr.getvalue())

        accepted_unresolved = {
            "mode": "final_artifact",
            "dep_entries": [],
            "deps": [],
            "unresolved_items": [{
                "label": "BOOT-INF/lib/unknown.jar",
                "lib_entry": "BOOT-INF/lib/unknown.jar",
                "reason_code": "missing_identity",
            }],
        }
        with patch.object(
            s1_dep_diff, "load_orchestrated_step1_input", return_value={},
        ), patch.object(
            s1_dep_diff,
            "get_packaged_deps_by_switching_branch",
            side_effect=[({}, accepted_unresolved), ({}, {
                "mode": "final_artifact",
                "dep_entries": [],
                "deps": [],
                "unresolved_items": [],
            })],
        ), patch.object(
            sys,
            "argv",
            [*base_arguments, "--allow-unresolved", "--debug-only"],
        ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
            s1_dep_diff.main()
        self.assertIn("调试模式完成", stderr.getvalue())

        unresolved_meta = self._main_meta(
            "base",
            unresolved_items=[{
                "label": "BOOT-INF/lib/unknown.jar",
                "lib_entry": "BOOT-INF/lib/unknown.jar",
                "reason_code": "missing_identity",
            }],
        )
        with patch.object(
            s1_dep_diff, "load_orchestrated_step1_input", return_value={},
        ), patch.object(
            s1_dep_diff,
            "get_packaged_deps_by_switching_branch",
            side_effect=[(deps, unresolved_meta), (deps, self._main_meta("current"))],
        ), patch.object(
            s1_dep_diff,
            "build_step1_coordinate_ambiguity_interaction",
            return_value={"summary": "coordinate ambiguous"},
        ), patch.object(
            s1_dep_diff, "emit_step_interaction",
        ) as emit, patch.object(
            sys, "argv", base_arguments,
        ), patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(
            SystemExit,
        ) as caught:
            s1_dep_diff.main()
        self.assertEqual(caught.exception.code, s1_dep_diff.EXIT_AWAITING_USER)
        emit.assert_called_once_with({"summary": "coordinate ambiguous"})

        with patch.object(
            s1_dep_diff, "load_orchestrated_step1_input", return_value={},
        ), patch.object(
            s1_dep_diff,
            "get_packaged_deps_by_switching_branch",
            side_effect=[(deps, self._main_meta("base")), (deps, self._main_meta("current"))],
        ), patch.object(
            sys, "argv", base_arguments,
        ), patch("sys.stderr", new_callable=io.StringIO) as stderr, self.assertRaises(
            SystemExit,
        ) as caught:
            s1_dep_diff.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("请指定 --output", stderr.getvalue())

        blocked_cases = (
            s1_dep_diff.Step1CommandExecutionBlockedError(
                stage="build", command="mvn package", stderr_excerpt="failed",
                branch="base-ref", suspected_causes=["jdk"],
            ),
            s1_dep_diff.Step1CommandExecutionBlockedError(
                stage="build", command="", stderr_excerpt="",
            ),
        )
        for error in blocked_cases:
            with self.subTest(blocked=bool(error.command)), patch.object(
                s1_dep_diff, "load_orchestrated_step1_input", return_value={},
            ), patch.object(
                s1_dep_diff,
                "get_packaged_deps_by_switching_branch",
                side_effect=error,
            ), patch.object(
                s1_dep_diff,
                "build_step1_command_blocked_interaction",
                return_value={"summary": "command blocked"},
            ), patch.object(
                s1_dep_diff, "emit_step_interaction",
            ) as emit, patch.object(
                sys, "argv", base_arguments,
            ), patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(
                SystemExit,
            ) as caught:
                s1_dep_diff.main()
            self.assertEqual(caught.exception.code, s1_dep_diff.EXIT_AWAITING_USER)
            emit.assert_called_once()

        with patch.object(
            s1_dep_diff, "load_orchestrated_step1_input", return_value={},
        ), patch.object(
            s1_dep_diff,
            "get_packaged_deps_by_switching_branch",
            side_effect=RuntimeError("unexpected"),
        ), patch.object(
            s1_dep_diff, "print_manual_instructions",
        ) as instructions, patch.object(
            sys, "argv", base_arguments,
        ), patch("sys.stderr", new_callable=io.StringIO) as stderr, self.assertRaises(
            SystemExit,
        ) as caught:
            s1_dep_diff.main()
        self.assertEqual(caught.exception.code, 1)
        instructions.assert_called_once()
        self.assertIn("自动执行失败", stderr.getvalue())

    def test_main_branch_output_missing_artifact_provenance_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "report" / "dep_changes.csv"
            base_entry = self._main_entry("base")
            current_entry = self._main_entry("current")
            base_meta = self._main_meta(
                "base", dep_entries=[base_entry], deps=[base_entry],
                artifact_path="",
            )
            current_meta = self._main_meta(
                "current", dep_entries=[current_entry], deps=[current_entry],
                artifact_path=str(root / "missing-current.jar"),
            )
            deps = {
                "org.example:demo": {
                    "version": "1.0.0",
                    "scope": "packaged",
                    "remark": "fixture",
                }
            }
            with patch.object(
                s1_dep_diff, "load_orchestrated_step1_input", return_value={},
            ), patch.object(
                s1_dep_diff,
                "get_packaged_deps_by_switching_branch",
                side_effect=[(deps, base_meta), (deps, current_meta)],
            ) as collect, patch.object(
                s1_dep_diff, "materialize_changed_dependency_jars",
            ) as materialize, patch.object(
                s1_dep_diff, "retain_artifact_for_analysis",
            ) as retain, patch.object(
                s1_dep_diff, "require_human_confirm", return_value=True,
            ), patch.dict(
                "os.environ", {"JUA_ORCHESTRATED": "1"}, clear=False,
            ), patch.object(
                sys,
                "argv",
                [
                    "s1_dep_diff.py",
                    "--base", "base-ref",
                    "--current", "current-ref",
                    "--base-tool", "maven",
                    "--current-tool", "gradle",
                    "--primary-module", "app",
                    "--output", str(output),
                ],
            ), patch("sys.stderr", new_callable=io.StringIO):
                s1_dep_diff.main()

            self.assertEqual(collect.call_count, 2)
            self.assertEqual(
                collect.call_args_list[0].kwargs["artifact_cache_dir"],
                output.parent / s1_dep_diff.STEP1_ARTIFACTS_DIRNAME,
            )
            materialize.assert_called_once()
            retain.assert_not_called()
            provenance = json.loads(
                (output.parent / "build_provenance.json").read_text(encoding="utf-8")
            )
            self.assertFalse(provenance["both_artifacts_available"])
            self.assertFalse(provenance["both_build_executions_succeeded"])
            self.assertFalse(provenance["both_builds_succeeded"])
            self.assertTrue(all(
                side["build_executed_by_system"] for side in provenance["sides"]
            ))

    def test_main_direct_output_clean_unresolved_and_confirmation_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_artifact = root / "base.jar"
            current_artifact = root / "current.jar"
            base_artifact.write_bytes(b"base-artifact")
            current_artifact.write_bytes(b"current-artifact")

            def execute(case_name, *, unresolved, confirmation):
                case_dir = root / case_name
                output = case_dir / "dep_changes.csv"
                base_entry = self._main_entry("base")
                current_entry = self._main_entry("current")
                unresolved_items = []
                if unresolved:
                    current_entry["resolution_status"] = "unresolved"
                    current_entry["read_error"] = "embedded metadata missing"
                    unresolved_items = [{
                        "label": current_entry["lib_entry"],
                        "lib_entry": current_entry["lib_entry"],
                        "reason_code": "embedded_metadata_missing",
                    }]
                base_meta = self._main_meta(
                    "base",
                    artifact_path=str(base_artifact),
                    original_artifact_path=str(base_artifact),
                    dep_entries=[base_entry],
                    deps=[base_entry],
                )
                current_meta = self._main_meta(
                    "current",
                    artifact_path=str(current_artifact),
                    original_artifact_path=str(current_artifact),
                    dep_entries=[current_entry],
                    deps=[current_entry],
                    unresolved_items=unresolved_items,
                )
                deps = {
                    "org.example:demo": {
                        "version": "1.0.0",
                        "scope": "packaged",
                        "remark": "fixture",
                    }
                }
                arguments = [
                    "s1_dep_diff.py",
                    "--base-tool", "maven",
                    "--current-tool", "maven",
                    "--base-artifact-path", str(base_artifact),
                    "--current-artifact-path", str(current_artifact),
                    "--output", str(output),
                ]
                if unresolved:
                    arguments.append("--allow-unresolved")
                with patch.object(
                    s1_dep_diff, "load_orchestrated_step1_input", return_value={},
                ), patch.object(
                    s1_dep_diff,
                    "collect_packaged_deps_from_artifact_path",
                    side_effect=[(deps, base_meta), (deps, current_meta)],
                ), patch.object(
                    s1_dep_diff, "retain_artifact_for_analysis",
                ) as retain, patch.object(
                    s1_dep_diff, "materialize_changed_dependency_jars",
                ) as materialize, patch.object(
                    s1_dep_diff, "require_human_confirm", return_value=confirmation,
                ), patch.dict(
                    "os.environ", {"JUA_ORCHESTRATED": "1"}, clear=False,
                ), patch.object(
                    sys, "argv", arguments,
                ), patch("sys.stderr", new_callable=io.StringIO):
                    if confirmation:
                        s1_dep_diff.main()
                    else:
                        with self.assertRaises(SystemExit) as caught:
                            s1_dep_diff.main()
                        self.assertEqual(caught.exception.code, 3)
                self.assertEqual(retain.call_count, 2)
                materialize.assert_called_once()
                return case_dir

            clean_dir = execute("clean", unresolved=False, confirmation=True)
            clean_summary = (clean_dir / "dep_summary.txt").read_text(encoding="utf-8")
            self.assertIn("未发现需要优先复核", clean_summary)
            self.assertIn("用户提供 base/current 编译产物", clean_summary)
            clean_provenance = json.loads(
                (clean_dir / "build_provenance.json").read_text(encoding="utf-8")
            )
            self.assertTrue(clean_provenance["both_artifacts_available"])
            self.assertFalse(clean_provenance["both_build_executions_succeeded"])
            self.assertTrue(clean_provenance["both_builds_succeeded"])

            unresolved_dir = execute(
                "unresolved", unresolved=True, confirmation=False,
            )
            unresolved_summary = (
                unresolved_dir / "dep_summary.txt"
            ).read_text(encoding="utf-8")
            self.assertIn("坐标未解析依赖", unresolved_summary)
            self.assertIn("embedded metadata missing", (
                unresolved_dir / "deps_current_resolved.csv"
            ).read_text(encoding="utf-8-sig"))

    def test_change_classifier_covers_every_version_relation(self):
        cases = (
            ("-", "1", ("新增", "待分析")),
            ("1", "-", ("移除", "待分析")),
            ("1", "1", ("未变", "待验证")),
            ("invalid", "1", ("版本格式不规则", "❓需人工确认")),
            ("1", "invalid", ("版本格式不规则", "❓需人工确认")),
            ("1", "2", ("大版本升级", "高")),
            ("2", "1", ("降级⚠️", "高")),
            ("1", "1.1", ("小版本升级", "中")),
            ("1.1", "1", ("降级⚠️", "高")),
            ("1.1", "1.1.1", ("补丁升级", "低")),
            ("1.1.1", "1.1", ("降级⚠️", "中")),
            ("1-RC1", "1-RC2", ("补丁升级", "低")),
            ("1-RC2", "1-RC1", ("降级⚠️", "中")),
            (
                "1.0-20240101.0900-123",
                "1.0.1-SNAPSHOT",
                ("补丁升级", "低"),
            ),
            (
                "1.0-20240102.0900-1",
                "1.0-20240101.0900-123",
                ("降级⚠️", "中"),
            ),
            ("1-GA", "1", ("已变更", "❓需人工确认")),
        )
        for old, new, expected in cases:
            with self.subTest(old=old, new=new):
                self.assertEqual(s1_dep_diff.classify_change(old, new), expected)

    def test_maven_selector_and_dependency_line_contract_matrix(self):
        self.assertIsNone(s1_dep_diff._normalize_maven_pl_with_workdir(None, None))
        self.assertIsNone(s1_dep_diff._normalize_maven_pl_with_workdir(" ", None))
        self.assertIsNone(s1_dep_diff._normalize_maven_pl_with_workdir(".", None))
        self.assertIsNone(s1_dep_diff._normalize_maven_pl_with_workdir("./", None))
        self.assertEqual(
            s1_dep_diff._normalize_maven_pl_with_workdir("artifact", None),
            ":artifact",
        )
        self.assertEqual(
            s1_dep_diff._normalize_maven_pl_with_workdir("g:a", None),
            "g:a",
        )
        self.assertEqual(
            s1_dep_diff._normalize_maven_pl_with_workdir("nested/path", None),
            "nested/path",
        )
        self.assertEqual(
            s1_dep_diff._normalize_maven_pl_with_workdir(r"nested\path", None),
            r"nested\path",
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "module"
            module.mkdir()
            pom = module / "pom.xml"
            pom.write_text("<project/>", encoding="utf-8")
            self.assertEqual(
                s1_dep_diff._normalize_maven_pl_with_workdir("module", root),
                "module",
            )
            self.assertEqual(
                s1_dep_diff._normalize_maven_pl_with_workdir("module/pom.xml", root),
                "module",
            )
            self.assertEqual(
                s1_dep_diff._normalize_maven_pl_with_workdir(str(pom), root),
                "module",
            )
            self.assertIsNone(
                s1_dep_diff._normalize_maven_pl_with_workdir("pom.xml", None),
            )
            self.assertEqual(
                s1_dep_diff._normalize_maven_pl_with_workdir("missing", root),
                ":missing",
            )
            self.assertEqual(
                s1_dep_diff._normalize_maven_pl_with_workdir("g:a", root),
                "g:a",
            )
            self.assertEqual(
                s1_dep_diff._normalize_maven_pl_with_workdir("nested/path", root),
                "nested/path",
            )
            self.assertEqual(
                s1_dep_diff._normalize_maven_pl_with_workdir(r"nested\path", root),
                r"nested\path",
            )

        invalid_lines = (
            None,
            "",
            "The following files have been resolved:",
            "The following dependencies have been resolved:",
            "ordinary build prose",
            " -- module app",
            "g:a:jar",
            "g:a:pom:1:runtime",
            ":a:jar:1:runtime",
            "g::jar:1:runtime",
            "g:a:jar::runtime",
            "g:a:jar:1:",
            "[g]:a:jar:1:runtime",
        )
        for line in invalid_lines:
            with self.subTest(line=line):
                self.assertIsNone(s1_dep_diff._parse_maven_dependency_list_line(line))

        default_jar = s1_dep_diff._parse_maven_dependency_list_line(
            "[INFO] g:a:1:custom-scope",
        )
        self.assertEqual(default_jar["key"], "g:a")
        self.assertEqual(default_jar["scope"], "custom-scope")
        self.assertEqual(default_jar["classifier"], "")
        classified = s1_dep_diff._parse_maven_dependency_list_line(
            "g:a:jar:tests:1:runtime:/tmp/a-1-tests.jar -- module app",
        )
        self.assertEqual(classified["key"], "g:a:tests")
        self.assertEqual(classified["artifact_file_name"], "a-1-tests.jar")
        self.assertEqual(classified["artifact_file_path"], "/tmp/a-1-tests.jar")
        empty_type = s1_dep_diff._parse_maven_dependency_list_line(
            "g:a::1:runtime",
        )
        self.assertEqual(empty_type["key"], "g:a")
        sparse_classifier = s1_dep_diff._parse_maven_dependency_list_line(
            "g:a:jar::tests:1:runtime",
        )
        self.assertEqual(sparse_classifier["classifier"], "tests")

    def test_manual_artifact_identity_invalid_valid_and_deduplication_matrix(self):
        self.assertEqual(s1_dep_diff.parse_manual_artifact_identities(None), ([], []))
        valid = {
            "side": "base",
            "lib_entry": "BOOT-INF/lib/a-1.jar",
            "group_id": "g",
            "artifact_id": "a",
            "version": "1",
        }
        valid_entry_id = {
            "side": "current",
            "entry_id": "entry-b",
            "group_id": "g",
            "artifact_id": "b",
            "version": "2",
            "classifier": "tests",
        }
        invalid = [
            "not-json",
            json.dumps([]),
            {**valid, "side": "other"},
            {**valid, "side": ""},
            {key: value for key, value in valid.items() if key != "lib_entry"},
            {**valid, "group_id": ""},
            {**valid, "artifact_id": ""},
            {**valid, "version": ""},
        ]
        identities, invalid_entries = s1_dep_diff.parse_manual_artifact_identities([
            *invalid,
            valid,
            dict(valid),
            json.dumps(valid_entry_id),
        ])
        self.assertEqual(len(invalid_entries), len(invalid))
        self.assertEqual(len(identities), 2)
        self.assertEqual(identities[0]["entry_id"], valid["lib_entry"])
        self.assertEqual(identities[1]["lib_entry"], "entry-b")
        self.assertEqual(identities[1]["coord"], "g:b:tests")

    def test_gradle_inventory_rejects_malformed_shapes_and_uses_project_truth(self):
        prefix = s1_dep_diff.GRADLE_ARTIFACT_INVENTORY_PREFIX
        modules = [
            None,
            {"gradle_path": ""},
            {
                "gradle_path": ":internal",
                "group_id": "project.g",
                "artifact_id": "internal",
                "version": "2",
            },
        ]
        rows = [
            "noise",
            prefix + "{",
            prefix + "[]",
            prefix + json.dumps({}),
            prefix + json.dumps({"artifact_id": "a", "version": "1", "file_name": "a-1.jar"}),
            prefix + json.dumps({"group_id": "g", "version": "1", "file_name": "a-1.jar"}),
            prefix + json.dumps({"group_id": "g", "artifact_id": "a", "file_name": "a-1.jar"}),
            prefix + json.dumps({"group_id": "g", "artifact_id": "a", "version": "unspecified", "file_name": "a.jar"}),
            prefix + json.dumps({"group_id": "g", "artifact_id": "a", "version": "1", "file_name": ""}),
            prefix + json.dumps({
                "group_id": "g", "artifact_id": "a", "version": "1",
                "file_name": r"C:\cache\a-1-tests.jar",
                "file_path": r"C:\cache\a-1-tests.jar",
            }),
            prefix + json.dumps({
                "project_path": ":internal",
                "file_name": "internal-2.jar",
                "file_path": "/cache/internal-2.jar",
            }),
            prefix + json.dumps({
                "group_id": "g", "artifact_id": "b", "version": "1",
                "file_name": "b-1.jar",
            }),
        ]
        self.assertEqual(s1_dep_diff.parse_gradle_artifact_inventory(None, None), {})
        deps = s1_dep_diff.parse_gradle_artifact_inventory("\n".join(rows), modules)
        self.assertEqual(set(deps), {"g:a:tests", "g:b", "project.g:internal"})
        self.assertEqual(deps["g:a:tests"]["artifact_file_name"], "a-1-tests.jar")
        self.assertEqual(
            deps["project.g:internal"]["artifact_file_path"],
            "/cache/internal-2.jar",
        )

    def test_gradle_dependency_report_external_and_project_rejection_matrix(self):
        modules = [
            None,
            {"gradle_path": ""},
            {"gradle_path": ":no-group", "artifact_id": "a", "version": "1"},
            {"gradle_path": ":no-artifact", "group_id": "g", "version": "1"},
            {"gradle_path": ":no-version", "group_id": "g", "artifact_id": "a"},
            {"gradle_path": ":unspecified", "group_id": "g", "artifact_id": "a", "version": "unspecified"},
            {"gradle_path": ":ok", "group_id": "project.g", "artifact_id": "ok", "version": "2"},
        ]
        report = """
            No dependencies
            A web-based report is available
            +--- broken FAILED
            ordinary output
            +--- project :missing
            +--- project :no-group
            +--- project :no-artifact
            +--- project :no-version
            +--- project :unspecified
            +--- project :ok
            +--- g:failed:FAILED
            +--- g:braced:{strictly-1}
            +--- g:direct:1 -> 2
            \\--- old.g:old-a:1 -> new.g:new-a:3
        """
        self.assertEqual(s1_dep_diff.parse_gradle_dependency_report(None, None), {})
        deps = s1_dep_diff.parse_gradle_dependency_report(report, modules)
        self.assertEqual(set(deps), {"project.g:ok", "g:direct", "new.g:new-a"})
        self.assertEqual(deps["g:direct"]["version"], "2")
        self.assertEqual(deps["new.g:new-a"]["version"], "3")
        self.assertEqual(deps["project.g:ok"]["gradle_project_path"], ":ok")

    def test_module_selector_resolution_and_profile_ownership_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "app"
            app.mkdir()
            pom = app / "pom.xml"
            pom.write_text(
                '<project xmlns="urn:test"><name>x</name><artifactId>app-id</artifactId></project>',
                encoding="utf-8",
            )
            empty = root / "empty" / "pom.xml"
            empty.parent.mkdir()
            empty.write_text("<project><artifactId></artifactId></project>", encoding="utf-8")
            broken = root / "broken" / "pom.xml"
            broken.parent.mkdir()
            broken.write_text("<project", encoding="utf-8")

            self.assertIsNone(s1_dep_diff.resolve_primary_module_id(None, root))
            self.assertIsNone(s1_dep_diff.resolve_primary_module_id(" ", root))
            self.assertEqual(s1_dep_diff.resolve_primary_module_id("g:plain", root), "plain")
            self.assertEqual(s1_dep_diff.resolve_primary_module_id("app/pom.xml", root), "app-id")
            self.assertEqual(s1_dep_diff.resolve_primary_module_id(str(pom), root), "app-id")
            self.assertEqual(s1_dep_diff.resolve_primary_module_id(str(pom), None), "app-id")
            self.assertEqual(s1_dep_diff.resolve_primary_module_id("empty/pom.xml", root), "empty")
            self.assertEqual(s1_dep_diff.resolve_primary_module_id("broken/pom.xml", root), "broken")
            self.assertEqual(s1_dep_diff.resolve_primary_module_id("missing/pom.xml", root), "missing")
            self.assertIsNone(s1_dep_diff.resolve_primary_module_id("pom.xml", None))
            directory_pom = root / "directory" / "pom.xml"
            directory_pom.mkdir(parents=True)
            self.assertEqual(
                s1_dep_diff.resolve_primary_module_id("directory/pom.xml", root),
                "directory",
            )

            self.assertEqual(s1_dep_diff._resolve_single_module_selector(None, None, root), ".")
            self.assertEqual(s1_dep_diff._resolve_single_module_selector(None, "app", root), "app")
            self.assertEqual(
                s1_dep_diff._resolve_single_module_selector(None, [None, "", "app", "app"], root),
                "app",
            )
            self.assertEqual(s1_dep_diff._resolve_single_module_selector("app", ["app"], root), "app")
            self.assertEqual(s1_dep_diff._resolve_single_module_selector("app", None, root), "app")
            self.assertEqual(s1_dep_diff._resolve_single_module_selector(None, ["a:"], root), "a:")
            self.assertEqual(s1_dep_diff._resolve_single_module_selector("a:", None, root), "a:")
            with self.assertRaises(RuntimeError):
                s1_dep_diff._resolve_single_module_selector(None, 7, root)
            with self.assertRaises(RuntimeError):
                s1_dep_diff._resolve_single_module_selector(None, ["app", "other"], root)
            with self.assertRaises(RuntimeError):
                s1_dep_diff._resolve_single_module_selector("app", ["other"], root)

            reactor = root / "pom.xml"
            self.assertEqual(s1_dep_diff._maven_profile_args_for_module(root, "app", ["p1", "", "p1"]), ["-Pp1"])
            self.assertEqual(s1_dep_diff._maven_profile_args_for_module(root, None), [])
            self.assertEqual(s1_dep_diff._maven_profile_args_for_module(root, "."), [])
            self.assertEqual(s1_dep_diff._maven_profile_args_for_module(root, "app"), [])
            reactor.write_text("<broken", encoding="utf-8")
            self.assertEqual(s1_dep_diff._maven_profile_args_for_module(root, "app"), [])
            reactor.write_text(
                "<project><modules><module>direct</module></modules>"
                "<profiles><ignored/><profile/><profile><name>x</name><id></id></profile>"
                "<profile><id>p1</id><modules><module>profile-app</module></modules></profile>"
                "</profiles></project>",
                encoding="utf-8",
            )
            self.assertEqual(s1_dep_diff._maven_profile_args_for_module(root, "direct"), [])
            self.assertEqual(s1_dep_diff._maven_profile_args_for_module(root, "profile-app"), ["-Pp1"])
            self.assertEqual(s1_dep_diff._maven_profile_args_for_module(root, "absent"), [])
            reactor.write_text(
                "<project><profiles>"
                "<profile><id>p1</id><modules><module>app</module></modules></profile>"
                "<profile><id>p2</id><modules><module>app</module></modules></profile>"
                "</profiles></project>",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                s1_dep_diff._maven_profile_args_for_module(root, "app")

    def test_gradle_failure_guidance_and_blocked_interaction_matrix(self):
        all_causes = s1_dep_diff._infer_gradle_failure_causes(
            "Timeout waiting to lock cache; invalid source release; JAVA_HOME; "
            "could not resolve all dependencies; task with path missing",
        )
        self.assertEqual(len(all_causes), 5)
        self.assertEqual(len(s1_dep_diff._infer_gradle_failure_causes("")), 1)
        for detail in (
            "could not target platform",
            "java installation missing",
            "could not find artifact",
            "configuration with name 'runtimeclasspath' not found",
        ):
            self.assertGreaterEqual(len(s1_dep_diff._infer_gradle_failure_causes(detail)), 1)

        plain = s1_dep_diff.build_step1_command_blocked_interaction(ValueError("plain"))
        self.assertEqual(plain["reason_code"], "step1_maven_command_blocked")
        self.assertEqual(plain["files_to_review"], [])
        empty = s1_dep_diff.build_step1_command_blocked_interaction(None)
        self.assertEqual(empty["stderr_excerpt"], "")
        gradle = s1_dep_diff.Step1CommandExecutionBlockedError(
            stage="gradle_build",
            command="gradle :app:build",
            stderr_excerpt="failed",
            side="current",
            branch="feature",
            jdk_field="current_jdk_home",
            jdk_home="/jdk",
            source_mode="branch",
            artifact_path="/app.jar",
            suspected_causes=["cause"],
        )
        gradle_payload = s1_dep_diff.build_step1_command_blocked_interaction(gradle)
        self.assertEqual(gradle_payload["reason_code"], "step1_gradle_command_blocked")
        self.assertEqual(gradle_payload["files_to_review"], ["/app.jar"])
        self.assertEqual(gradle_payload["missing_inputs"][0]["field"], "current_jdk_home")
        git_payload = s1_dep_diff.build_step1_command_blocked_interaction(
            s1_dep_diff.Step1CommandExecutionBlockedError(
                stage="prepare_branch_worktree",
                command="git worktree add",
                stderr_excerpt="busy",
                jdk_field="base_jdk_home",
            ),
        )
        self.assertEqual(git_payload["reason_code"], "step1_git_worktree_command_blocked")
        self.assertEqual(git_payload["missing_inputs"], [])
        blank_jdk = s1_dep_diff.build_step1_command_blocked_interaction(
            s1_dep_diff.Step1CommandExecutionBlockedError(
                stage="mvn_package", command="mvn package", stderr_excerpt="",
                jdk_field="base_jdk_home", jdk_home="",
            ),
        )
        self.assertEqual(blank_jdk["missing_inputs"][0]["field"], "base_jdk_home")

    def test_display_change_rows_and_project_catalog_merge_matrix(self):
        self.assertEqual(s1_dep_diff._display_coord(None), "")
        self.assertEqual(s1_dep_diff._display_coord({"coord": "g:a", "classifier": "tests"}), "g:a:tests")
        self.assertEqual(s1_dep_diff._display_coord({"artifact_id": "a"}), "a")
        self.assertEqual(s1_dep_diff._display_coord({"version": "1"}), "1")
        self.assertEqual(s1_dep_diff._display_coord({"lib_name": "a.jar"}), "a.jar")
        self.assertEqual(s1_dep_diff._display_coord({"lib_entry": "lib/a.jar"}), "lib/a.jar")
        self.assertEqual(s1_dep_diff._display_coord({}), "")

        base = {
            "coord": "g:a", "artifact_id": "a", "version": "2",
            "scope": "provided", "resolution_status": "resolved",
            "content_sha256": "a" * 64, "lib_entry": "base/a.jar",
            "read_error": "base-error",
        }
        current = {
            "coord": "g:a", "artifact_id": "a", "version": "1",
            "scope": "provided", "resolution_status": "resolved",
            "content_sha256": "b" * 64, "lib_entry": "current/a.jar",
            "read_error": "current-error",
        }
        downgraded = s1_dep_diff._make_step1_change_row(base, current, "g:a", "exact")
        self.assertEqual(downgraded["risk"], "低(非compile)")
        self.assertEqual(downgraded["base_read_error"], "base-error")
        self.assertEqual(downgraded["current_read_error"], "current-error")
        same_version = s1_dep_diff._make_step1_change_row(
            {**base, "version": "1"}, current, "g:a", "exact",
        )
        self.assertEqual(same_version["change_type"], "已变更")
        unresolved = s1_dep_diff._make_step1_change_row(
            base, None, "a", "unpaired", "ambiguous",
        )
        self.assertEqual(unresolved["resolution_status"], "unresolved")
        self.assertIn("pairing:ambiguous", unresolved["remark"])
        blank_values = s1_dep_diff._make_step1_change_row(
            {
                "coord": "g:blank", "version": " ", "scope": " ",
                "resolution_status": "failed", "remark": "base-remark",
                "packaged_match_source": "base-source",
            },
            {
                "coord": "g:blank", "version": " ",
                "scope": " ", "resolution_status": "resolved",
                "packaged_match_source": "current-source",
            },
            "g:blank", "exact",
        )
        self.assertEqual(blank_values["old_version"], "-")
        self.assertEqual(blank_values["new_version"], "-")
        self.assertEqual(blank_values["scope"], "packaged")
        self.assertEqual(blank_values["remark"], "base-remark")
        self.assertEqual(blank_values["base_packaged_match_source"], "base-source")
        self.assertEqual(blank_values["current_packaged_match_source"], "current-source")
        current_failed = s1_dep_diff._make_step1_change_row(
            {**base, "scope": "compile"},
            {**current, "scope": "compile", "resolution_status": "failed"},
            "g:a", "exact",
        )
        self.assertEqual(current_failed["resolution_status"], "unresolved")
        compile_downgrade = s1_dep_diff._make_step1_change_row(
            {**base, "scope": "compile"}, {**current, "scope": "compile"},
            "g:a", "exact",
        )
        self.assertEqual(compile_downgrade["risk"], "高")
        both_absent = s1_dep_diff._make_step1_change_row(None, None, "", "empty")
        self.assertEqual(both_absent["scope"], "packaged")

        exact_rows = s1_dep_diff._build_step1_change_rows([base], [current])
        self.assertEqual(exact_rows[0]["pairing_status"], "exact_coord")
        migrated_rows = s1_dep_diff._build_step1_change_rows(
            [{**base, "coord": "old:a"}],
            [{**current, "coord": "new:a"}],
        )
        self.assertEqual(migrated_rows[0]["pairing_status"], "unique_artifact_migration")
        one_sided = s1_dep_diff._build_step1_change_rows([base], [])
        self.assertEqual(one_sided[0]["pairing_status"], "base_only")
        current_only = s1_dep_diff._build_step1_change_rows([], [current])
        self.assertEqual(current_only[0]["pairing_status"], "current_only")
        ambiguous = s1_dep_diff._build_step1_change_rows(
            [{**base, "coord": "one:a"}, {**base, "coord": "two:a"}],
            [{**current, "coord": "three:a"}],
        )
        self.assertTrue(all(row["pairing_status"] == "unpaired_ambiguous" for row in ambiguous))
        identity_missing = s1_dep_diff._build_step1_change_rows(
            [{"artifact_id": "x", "version": "1"}],
            [{"artifact_id": "x", "version": "2"}],
        )
        self.assertEqual(identity_missing[0]["pairing_status"], "unique_artifact_migration")

        runtime = {
            "g:same": {"version": "1", "artifact_file_name": ""},
            "g:different": {"version": "9", "artifact_file_name": "keep.jar"},
            "g:complete": {"version": "1", "artifact_file_name": "present.jar"},
            "g:no-art": None,
        }
        catalog = {
            "g:new": {
                "key": "g:new", "coord": "g:new", "group_id": "g",
                "artifact_id": "new", "version": "1", "project_module": "new",
            },
            "g:same": {
                "version": "1", "project_module": "same",
                "artifact_file_name": "same.jar", "artifact_file_path": "/same.jar",
            },
            "g:different": {"version": "1", "project_module": "different"},
            "g:complete": {
                "version": "1", "project_module": "complete",
                "artifact_file_name": "replacement.jar",
            },
            "g:no-art": {"version": "", "project_module": "no-art"},
        }
        with patch.object(s1_dep_diff, "build_project_module_runtime_catalog", return_value=catalog):
            augmented = s1_dep_diff.augment_runtime_deps_with_project_modules(
                runtime, "/repo", "app",
            )
        self.assertIn("g:new", augmented)
        self.assertEqual(augmented["g:same"]["artifact_file_name"], "same.jar")
        self.assertNotIn("project_module", augmented["g:different"])
        self.assertEqual(augmented["g:complete"]["artifact_file_name"], "present.jar")
        self.assertEqual(augmented["g:no-art"]["project_module"], "no-art")
        with patch.object(s1_dep_diff, "build_project_module_runtime_catalog", return_value={}):
            self.assertEqual(
                s1_dep_diff.augment_runtime_deps_with_project_modules(None, "/repo", "app"),
                {},
            )

    def test_orchestrated_input_and_artifact_retention_matrix(self):
        with patch.dict(s1_dep_diff.os.environ, {}, clear=True):
            self.assertEqual(s1_dep_diff.load_orchestrated_step1_input(), {})
        with patch.dict(s1_dep_diff.os.environ, {"JUA_ORCHESTRATED": "1"}, clear=True):
            self.assertEqual(s1_dep_diff.load_orchestrated_step1_input(), {})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            runtime = report / ".runtime" / "state"
            runtime.mkdir(parents=True)
            state = runtime / s1_dep_diff.MAIN_STATE_FILE_NAME
            env = {"JUA_ORCHESTRATED": "1", "UPGRADE_REPORT_DIR": str(report)}
            with patch.dict(s1_dep_diff.os.environ, env, clear=True):
                self.assertEqual(s1_dep_diff.load_orchestrated_step1_input(), {})
                state.write_text("not-json", encoding="utf-8")
                self.assertEqual(s1_dep_diff.load_orchestrated_step1_input(), {})
                state.write_text(json.dumps(None), encoding="utf-8")
                self.assertEqual(s1_dep_diff.load_orchestrated_step1_input(), {})
                state.write_text(json.dumps({"step1": {"input": {"mode": "artifact"}}}), encoding="utf-8")
                self.assertEqual(
                    s1_dep_diff.load_orchestrated_step1_input(),
                    {"mode": "artifact"},
                )

            self.assertIsNone(s1_dep_diff.retain_artifact_for_analysis(None, None, "base"))
            self.assertEqual(
                s1_dep_diff.retain_artifact_for_analysis({"artifact_path": ""}, root, "base"),
                {"artifact_path": ""},
            )
            source_dir = root / "worktree" / "target"
            source_dir.mkdir(parents=True)
            source = source_dir / "app.tar.jar"
            source.write_bytes(b"artifact-bytes")
            cache = root / "cache"
            self.assertEqual(
                s1_dep_diff.retain_artifact_for_analysis(
                    {"artifact_path": str(source)}, None, "base",
                )["artifact_path"],
                str(source),
            )
            self.assertEqual(
                s1_dep_diff.retain_artifact_for_analysis(
                    {"artifact_path": str(root / "missing.jar")}, root / "cache-missing", "base",
                )["artifact_path"],
                str(root / "missing.jar"),
            )
            no_worktree = s1_dep_diff.retain_artifact_for_analysis(
                {"artifact_path": str(source)}, root / "cache-no-worktree", "current",
            )
            self.assertTrue(no_worktree["artifact_retained"])
            existing_relative = s1_dep_diff.retain_artifact_for_analysis(
                {
                    "artifact_path": str(source), "worktree_dir": str(root),
                    "artifact_relative_path": "already.jar",
                },
                root / "cache-existing-relative",
                "current",
            )
            self.assertEqual(existing_relative["artifact_relative_path"], "already.jar")
            meta = {
                "artifact_path": str(source),
                "worktree_dir": str(root / "worktree"),
                "artifact_relative_path": "",
            }
            retained = s1_dep_diff.retain_artifact_for_analysis(meta, cache, "base")
            self.assertEqual(retained["artifact_relative_path"], "target/app.tar.jar")
            self.assertTrue(Path(retained["artifact_path"]).is_file())
            self.assertEqual(Path(retained["artifact_path"]).read_bytes(), b"artifact-bytes")
            self.assertTrue(retained["artifact_retained"])
            repeated = s1_dep_diff.retain_artifact_for_analysis(retained, cache, "base")
            self.assertEqual(repeated["artifact_path"], retained["artifact_path"])

            suffixless = root / "plain"
            suffixless.write_bytes(b"plain")
            outside = s1_dep_diff.retain_artifact_for_analysis(
                {
                    "artifact_path": str(suffixless),
                    "worktree_dir": str(root / "other-worktree"),
                    "artifact_relative_path": "",
                },
                root / "other-cache",
                "",
            )
            self.assertEqual(outside["artifact_relative_path"], "")
            self.assertEqual(Path(outside["artifact_path"]).name, "artifact.jar")

    def test_missing_input_interaction_empty_branch_source_and_unresolved_matrix(self):
        empty = s1_dep_diff.build_step1_missing_input_interaction([], [])
        self.assertEqual(empty["files_to_review"], [])
        self.assertEqual(empty["required_fields"], [])
        self.assertEqual(empty["missing_inputs"], [])
        self.assertEqual(empty["fallback_inputs"], [])
        blank_label = s1_dep_diff.build_step1_missing_input_interaction([], [""])
        self.assertEqual(blank_label["required_fields"], [])

        blank = s1_dep_diff.build_step1_missing_input_interaction([{}], [{"label": ""}])
        self.assertIn("该侧产物", "\n".join(blank["checklist_lines"]))
        self.assertEqual(blank["required_fields"], [])

        payload = s1_dep_diff.build_step1_missing_input_interaction(
            [
                {
                    "side_cn": "基准侧",
                    "artifact_path": "/base.jar",
                    "branch_field": "base_branch",
                    "source_field": "base_source_project_dir",
                },
                {
                    "side_cn": "当前侧",
                    "side": "current",
                    "artifact_path": "/current.jar",
                    "branch_field": "current_branch",
                    "source_field": "current_source_project_dir",
                },
                {"side_cn": "仅分支", "branch_field": "other_branch"},
                {"side_cn": "仅源码", "source_field": "other_source_project_dir"},
            ],
            [{"artifact_id": "a", "version": "1", "label": "a:1"}],
        )
        self.assertEqual(payload["files_to_review"], ["/base.jar", "/current.jar"])
        self.assertEqual(
            payload["required_fields"],
            ["base_branch", "current_branch", "other_branch"],
        )
        self.assertEqual(len(payload["fallback_inputs"]), 3)
        self.assertEqual(payload["missing_inputs"][0]["side"], "base")
        self.assertEqual(payload["missing_inputs"][1]["side"], "current")
        self.assertTrue(any("a:1" in line for line in payload["checklist_lines"]))
        self.assertEqual(
            payload["input_normalization"]["required_fields"],
            payload["required_fields"],
        )

    def test_coordinate_followup_interaction_decision_matrix(self):
        empty = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="current", side_cn="当前侧", artifact_path="",
        )
        self.assertEqual(empty["kind"], "review")
        self.assertEqual(empty["required_fields"], [])
        self.assertEqual(empty["files_to_review"], [])
        blank_label = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="current", side_cn="当前侧", artifact_path="",
            unresolved_items=[""], primary_module="app",
        )
        self.assertEqual(blank_label["kind"], "review")

        version_only = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="base",
            side_cn="基准侧",
            artifact_path="/base.jar",
            unresolved_items=[{
                "artifact_id": "a",
                "version": "1",
                "label": "a:1",
                "reason_code": "PACKAGED_VERSION_UNCONFIRMED",
            }],
            branch_value="main",
            source_value="/repo",
            primary_module="app",
        )
        self.assertEqual(version_only["kind"], "input_request")
        self.assertEqual(version_only["required_fields"], ["manual_artifact_identities"])
        self.assertIn("manual_artifact_identities", version_only["question"])
        self.assertEqual(version_only["files_to_review"], ["/base.jar"])
        self.assertTrue(any("main" in line for line in version_only["checklist_lines"]))
        self.assertTrue(any("/repo" in line for line in version_only["checklist_lines"]))

        coordinate = [{
            "artifact_id": "b",
            "version": "2",
            "label": "b:2",
            "reason_code": "PACKAGED_COORDINATE_UNRESOLVED",
        }]
        primary_required = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="current",
            side_cn="当前侧",
            artifact_path="/current.jar",
            unresolved_items=coordinate,
            source_field="current_source_project_dir",
            source_value="",
            primary_module="",
        )
        self.assertEqual(primary_required["required_fields"], ["primary_module"])
        self.assertEqual(
            primary_required["fallback_inputs"][0]["field"],
            "current_source_project_dir",
        )
        self.assertIn("primary_module", primary_required["question"])

        source_required = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="current",
            side_cn="当前侧",
            artifact_path="/current.jar",
            unresolved_items=coordinate,
            source_field="current_source_project_dir",
            source_value="",
            primary_module="app",
        )
        self.assertEqual(
            source_required["required_fields"],
            ["current_source_project_dir"],
        )
        self.assertIn("current_source_project_dir", source_required["question"])

        already_tried = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="current",
            side_cn="当前侧",
            artifact_path="/current.jar",
            unresolved_items=coordinate,
            source_field="current_source_project_dir",
            source_value="/repo",
            primary_module="app",
        )
        self.assertEqual(already_tried["kind"], "review")
        self.assertEqual(already_tried["required_fields"], [])
        self.assertIn("人工确认", already_tried["question"])
        no_source_field = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="current", side_cn="当前侧", artifact_path="",
            unresolved_items=coordinate, source_field="", primary_module="app",
        )
        self.assertEqual(no_source_field["kind"], "review")
        unknown_reason = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="current", side_cn="当前侧", artifact_path="",
            unresolved_items=[{}], primary_module="app",
        )
        self.assertEqual(unknown_reason["kind"], "review")

        mixed = s1_dep_diff.build_step1_coordinate_followup_interaction(
            side="base",
            side_cn="基准侧",
            artifact_path="/base.jar",
            unresolved_items=[*coordinate, {
                "artifact_id": "c", "version": "3", "label": "c:3",
                "reason_code": "PACKAGED_VERSION_UNCONFIRMED",
            }],
            source_field="base_source_project_dir",
            source_value="",
            primary_module="app",
        )
        self.assertEqual(mixed["required_fields"], ["manual_artifact_identities"])
        self.assertEqual(mixed["fallback_inputs"][0]["field"], "base_source_project_dir")

    def test_ref_resolution_interaction_status_source_and_candidate_matrix(self):
        cases = (
            ("fetch_failed", "step1_remote_fetch_failed"),
            ("ref_moved", "step1_remote_ref_moved"),
            ("ambiguous", "ambiguous_step1_source_ref"),
            ("not_found", "step1_source_ref_not_found"),
        )
        for status, reason_code in cases:
            error = s1_dep_diff.Step1RefResolutionRequiredError(
                "base" if status == "ref_moved" else "current",
                "/repo" if status != "not_found" else "",
                "/app.jar" if status != "not_found" else "",
                {
                    "status": status,
                    "requested_ref": "feature" if status != "not_found" else "",
                    "candidates": [
                        {"ref": "refs/heads/feature", "commit": "a" * 40},
                        {"ref": "", "display_ref": "tag/v1", "commit": ""},
                    ] if status == "ambiguous" else [],
                    "failures": [{"reason": "offline"}] if status == "fetch_failed" else [],
                    "expected_commit": "e" * 40 if status == "ref_moved" else "",
                    "local_candidate_commit": "l" * 40 if status == "ref_moved" else "",
                    "configured_remotes": ["origin", "upstream"] if status == "ambiguous" else [],
                    "query_mode": "all_remotes" if status == "ambiguous" else "",
                },
            )
            payload = s1_dep_diff.build_step1_ref_resolution_interaction(error)
            self.assertEqual(payload["reason_code"], reason_code)
            if status == "fetch_failed":
                self.assertEqual(payload["required_fields"], [])
                self.assertFalse(payload["missing_inputs"][0]["required"])
            else:
                self.assertEqual(len(payload["required_fields"]), 1)
            if status == "ambiguous":
                candidates = payload["ref_resolution_requests"][0]["candidates"]
                self.assertTrue(all(item["selection_key"].startswith("s1ref:") for item in candidates))
                self.assertTrue(any("origin" in line for line in payload["checklist_lines"]))

        for source_status, reason_code in (
            ("repository_not_git", "step1_source_directory_not_git"),
            ("remote_configuration_missing", "step1_remote_configuration_missing"),
        ):
            payload = s1_dep_diff.build_step1_ref_resolution_interaction(
                s1_dep_diff.Step1RefResolutionRequiredError(
                    "current", "/repo", "/app.jar",
                    {"status": "not_found", "source_status": source_status},
                ),
            )
            self.assertEqual(payload["reason_code"], reason_code)

        default_side = s1_dep_diff.build_step1_ref_resolution_interaction(
            s1_dep_diff.Step1RefResolutionRequiredError("", "", "", {}),
        )
        self.assertEqual(default_side["ref_resolution_requests"][0]["side"], "current")
        self.assertEqual(default_side["files_to_review"], [])
        source_without_commit = s1_dep_diff.build_step1_ref_resolution_interaction(
            s1_dep_diff.SourceRevisionConfirmationRequiredError(
                "current", "/source", "", {},
            ),
        )
        self.assertNotIn(
            "detected_commit",
            source_without_commit["ref_resolution_requests"][0],
        )

        source_only = s1_dep_diff.build_step1_ref_resolution_interaction(
            s1_dep_diff.SourceRevisionConfirmationRequiredError(
                "base",
                "/source",
                "/base.jar",
                {
                    "resolved_commit": "c" * 40,
                    "resolved_ref": "main",
                    "fingerprint": "fp",
                    "source_status": "local_source_detected",
                    "expected_commit": "e" * 40,
                    "failures": [{"reason": "offline"}],
                    "repository_path": "/source",
                    "configured_remotes": ["origin"],
                    "query_mode": "explicit_remote",
                    "dirty": True,
                },
            ),
        )
        self.assertEqual(
            source_only["reason_code"],
            "step1_source_revision_confirmation_required",
        )
        request = source_only["ref_resolution_requests"][0]
        self.assertEqual(request["detected_ref"], "main")
        self.assertEqual(request["detected_commit"], "c" * 40)
        self.assertEqual(source_only["files_to_review"], ["/source"])
        self.assertEqual(
            source_only["action_requirements"]["confirm_local_source"]["required_fields"],
            ["base_allow_local_source", "base_allow_dirty_local_source"],
        )
        detected = request["candidates"][0]
        self.assertTrue(detected["selection_key"].startswith("s1ref:"))

        local_candidate = s1_dep_diff.build_step1_ref_resolution_interaction(
            s1_dep_diff.SourceRevisionConfirmationRequiredError(
                "current", "/source", "",
                {"local_candidate_commit": "d" * 40},
            ),
        )
        self.assertEqual(
            local_candidate["ref_resolution_requests"][0]["detected_ref"],
            "HEAD",
        )

    def test_module_directory_resolution_path_pom_coordinate_and_discovery_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(s1_dep_diff._resolve_module_dir_for_packaging(None, root), root.resolve())
            for selector in (".", "./", "__root__", "root"):
                self.assertEqual(s1_dep_diff._resolve_module_dir_for_packaging(selector, root), root.resolve())

            direct = root / "direct"
            direct.mkdir()
            direct_pom = direct / "pom.xml"
            direct_pom.write_text("<project><artifactId>direct-id</artifactId></project>", encoding="utf-8")
            self.assertEqual(s1_dep_diff._resolve_module_dir_for_packaging("direct", root), direct.resolve())
            self.assertEqual(s1_dep_diff._resolve_module_dir_for_packaging("direct/pom.xml", root), direct.resolve())
            self.assertEqual(s1_dep_diff._resolve_module_dir_for_packaging(str(direct_pom), root), direct.resolve())

            ordinary_file = root / "ordinary.txt"
            ordinary_file.write_text("x", encoding="utf-8")
            self.assertIsNone(s1_dep_diff._resolve_module_dir_for_packaging("ordinary.txt", root))
            nested = root / "nested" / "module"
            nested.mkdir(parents=True)
            self.assertEqual(
                s1_dep_diff._resolve_module_dir_for_packaging(r"nested\module", root),
                nested.resolve(),
            )

            group_module = root / "group-module"
            group_module.mkdir()
            (group_module / "pom.xml").write_text(
                "<project><groupId>g</groupId><artifactId>a</artifactId></project>",
                encoding="utf-8",
            )
            name_module = root / "by-name"
            name_module.mkdir()
            (name_module / "pom.xml").write_text(
                "<project><groupId>other</groupId><artifactId>different</artifactId></project>",
                encoding="utf-8",
            )
            excluded = root / "target" / "ignored"
            excluded.mkdir(parents=True)
            (excluded / "pom.xml").write_text(
                "<project><groupId>g</groupId><artifactId>excluded</artifactId></project>",
                encoding="utf-8",
            )
            self.assertEqual(s1_dep_diff._resolve_module_dir_for_packaging("g:a", root), group_module.resolve())
            self.assertEqual(s1_dep_diff._resolve_module_dir_for_packaging("a", root), group_module.resolve())
            self.assertEqual(s1_dep_diff._resolve_module_dir_for_packaging("by-name", root), name_module.resolve())
            deep_name = root / "deep" / "by-leaf"
            deep_name.mkdir(parents=True)
            (deep_name / "pom.xml").write_text(
                "<project><groupId>other</groupId><artifactId>different</artifactId></project>",
                encoding="utf-8",
            )
            self.assertEqual(
                s1_dep_diff._resolve_module_dir_for_packaging("by-leaf", root),
                deep_name.resolve(),
            )
            self.assertIsNone(s1_dep_diff._resolve_module_dir_for_packaging("g:missing", root))
            self.assertIsNone(s1_dep_diff._resolve_module_dir_for_packaging("a:", root))

            discovered = [
                {
                    "module": None, "gradle_path": None,
                    "artifact_id": None, "coord": None, "module_dir": None,
                },
                {
                    "module": "logical",
                    "gradle_path": ":gradle-path",
                    "artifact_id": "artifact-alias",
                    "coord": "disc.g:disc-a",
                    "module_dir": str(nested),
                },
            ]
            with patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": discovered}):
                for selector in (
                    "logical", ":gradle-path", "artifact-alias",
                    "disc.g:disc-a", "module",
                ):
                    self.assertEqual(
                        s1_dep_diff._resolve_module_dir_for_packaging(selector, root),
                        nested.resolve(),
                    )
            with patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": None}):
                self.assertIsNone(s1_dep_diff._resolve_module_dir_for_packaging("absent", root))
        self.assertEqual(
            s1_dep_diff._resolve_module_dir_for_packaging(None, ""),
            Path(".").resolve(),
        )

    def test_project_module_catalog_scope_identity_and_archive_matrix(self):
        scope = {
            "included_modules": [None, "", "target", "main", "classifier", "fallback", "multiple", "no-dir"],
            "target_module": "target",
        }
        modules = [
            {"module": None},
            {"module": "outside", "group_id": "g", "artifact_id": "outside", "version": "1"},
            {"module": "target", "group_id": "g", "artifact_id": "target", "version": "1"},
            {"module": "main", "group_id": "", "artifact_id": "main", "version": "1"},
            {"module": "main", "group_id": "g", "artifact_id": "", "version": "1"},
            {"module": "main", "group_id": "g", "artifact_id": "main", "version": ""},
            {"module": "main", "group_id": "g", "artifact_id": "main", "version": "unspecified"},
            {"module": "main", "group_id": "${group}", "artifact_id": "main", "version": "1"},
            {"module": "main", "group_id": "g", "artifact_id": "${artifact}", "version": "1"},
            {"module": "main", "group_id": "g", "artifact_id": "main", "version": "${version}"},
            {"module": "main", "group_id": "g", "artifact_id": "main", "version": "1", "module_dir": "/modules/main"},
            {"module": "classifier", "group_id": "g", "artifact_id": "classifier", "version": "1", "module_dir": "/modules/classifier"},
            {"module": "fallback", "group_id": "g", "artifact_id": "fallback", "version": "1", "module_dir": "/modules/fallback"},
            {"module": "multiple", "group_id": "g", "artifact_id": "multiple", "version": "1", "module_dir": "/modules/multiple"},
            {"module": "no-dir", "group_id": "g", "artifact_id": "no-dir", "version": "1"},
        ]
        archives = {
            "main": [Path("/artifacts/main-1.jar"), Path("/artifacts/main-1-tests.jar")],
            "classifier": [Path("/artifacts/classifier-1-tests.jar")],
            "fallback": [Path("/artifacts/custom-name.jar")],
            "multiple": [Path("/artifacts/one.jar"), Path("/artifacts/two.jar")],
        }

        def discover_archives(module_dir):
            return archives.get(Path(module_dir).name, [])

        with patch.object(s1_dep_diff, "build_project_scope", return_value=scope) as scope_mock, patch.object(
            s1_dep_diff, "discover_project_modules", return_value={"modules": modules},
        ), patch.object(
            s1_dep_diff, "_discover_packaged_archives", side_effect=discover_archives,
        ):
            catalog = s1_dep_diff.build_project_module_runtime_catalog(
                "/repo", None, build_tool=None, active_maven_profiles=["p1"],
            )
        self.assertEqual(set(catalog), {"g:main", "g:classifier", "g:fallback", "g:multiple", "g:no-dir"})
        self.assertEqual(catalog["g:main"]["artifact_file_name"], "main-1.jar")
        self.assertEqual(catalog["g:classifier"]["artifact_file_name"], "classifier-1-tests.jar")
        self.assertEqual(catalog["g:fallback"]["artifact_file_name"], "custom-name.jar")
        self.assertNotIn("artifact_file_name", catalog["g:multiple"])
        self.assertEqual(scope_mock.call_args.kwargs["active_profiles"], {"p1"})
        self.assertEqual(scope_mock.call_args.args[1], ".")

        with patch.object(
            s1_dep_diff, "build_project_scope",
            side_effect=[{"included_modules": [], "target_module": ""}, {"included_modules": ["a"], "target_module": ""}],
        ):
            self.assertEqual(s1_dep_diff.build_project_module_runtime_catalog("/repo", "app"), {})
            self.assertEqual(s1_dep_diff.build_project_module_runtime_catalog("/repo", "app"), {})

        with patch.object(s1_dep_diff, "build_project_scope", return_value={
            "included_modules": ["target"], "target_module": "target",
        }), patch.object(s1_dep_diff, "discover_project_modules", return_value={"modules": None}) as discovery_mock:
            self.assertEqual(
                s1_dep_diff.build_project_module_runtime_catalog(
                    "/repo", "target", build_tool="gradle", active_maven_profiles=["ignored"],
                ),
                {},
            )
        self.assertIsNone(discovery_mock.call_args.kwargs["active_profiles"])

    def test_miscellaneous_output_dispatch_business_entries_and_blocked_error_matrix(self):
        class Info:
            def __init__(self, filename, directory=False):
                self.filename = filename
                self._directory = directory

            def is_dir(self):
                return self._directory

        class Archive:
            def __init__(self, infos):
                self._infos = infos

            def infolist(self):
                return self._infos

        plain_entries = s1_dep_diff._business_content_entries(Archive([
            Info("folder/", True),
            Info("META-INF/MAVEN/g/a/pom.properties"),
            Info("META-INF/SIGNATURE.SF"),
            Info("BOOT-INF/lib/a.jar"),
            Info("lib/b.jar"),
            Info("app/Main.class"),
        ]))
        self.assertEqual(plain_entries, [
            ("META-INF/SIGNATURE.SF", "META-INF/SIGNATURE.SF"),
            ("app/Main.class", "app/Main.class"),
        ])
        signed_entries = s1_dep_diff._business_content_entries(Archive([
            Info("META-INF/SIGNATURE.SF"),
            Info("META-INF/SIGNATURE.RSA"),
            Info("META-INF/ORPHAN.SF"),
            Info("app/Main.class"),
        ]))
        self.assertEqual(signed_entries, [
            ("META-INF/ORPHAN.SF", "META-INF/ORPHAN.SF"),
            ("app/Main.class", "app/Main.class"),
        ])
        application_entries = s1_dep_diff._business_content_entries(Archive([
            Info("BOOT-INF/classes/"),
            Info("BOOT-INF/classes/app/Main.class"),
            Info("META-INF/MANIFEST.MF"),
            Info("other.txt"),
        ]))
        self.assertEqual(
            application_entries,
            [
                ("BOOT-INF/classes/app/Main.class", "app/Main.class"),
                ("META-INF/MANIFEST.MF", "META-INF/MANIFEST.MF"),
            ],
        )
        with self.assertRaises(ValueError):
            s1_dep_diff._business_content_entries(Archive([
                Info("BOOT-INF/classes/app/Main.class"),
                Info("WEB-INF/classes/app/Main.class"),
            ]))
        self.assertEqual(s1_dep_diff._business_content_entries(Archive([])), [])

        with patch.object(s1_dep_diff, "resolve_effective_jdk_home", return_value=""):
            blank = s1_dep_diff.build_step1_command_blocked_error(
                stage="prepare", command="", exc=None,
            )
            self.assertEqual(blank.side, "")
            self.assertEqual(blank.stderr_excerpt, "")
            self.assertEqual(blank.jdk_field, "")
            base = s1_dep_diff.build_step1_command_blocked_error(
                stage="mvn_package", command="mvn", exc=RuntimeError("failed"),
                side="base", branch="main", source_project_dir="/repo",
                artifact_path="/app.jar", source_mode="source-project",
            )
            self.assertEqual(base.jdk_field, "base_jdk_home")
            self.assertEqual(base.branch, "main")
            self.assertEqual(base.source_project_dir, "/repo")
            self.assertEqual(base.artifact_path, "/app.jar")
            self.assertEqual(base.source_mode, "source-project")
            explicit = s1_dep_diff.build_step1_command_blocked_error(
                stage="gradle_build", command="gradle", exc=RuntimeError("bad"),
                side="other", jdk_field="custom_jdk",
            )
            self.assertEqual(explicit.jdk_field, "custom_jdk")

        stdout = io.StringIO()
        with patch.object(s1_dep_diff.sys, "stdout", stdout):
            s1_dep_diff.emit_step_interaction({})
            s1_dep_diff.emit_step_interaction({"reason_code": "custom_reason"})
        emitted = stdout.getvalue().splitlines()
        self.assertEqual(len(emitted), 2)
        self.assertNotIn("diagnostic_guidance", emitted[0])
        self.assertIn("diagnostic_guidance", emitted[1])

        stderr = io.StringIO()
        with patch.object(s1_dep_diff.sys, "stderr", stderr):
            s1_dep_diff.print_parse_report(
                "base", {"g:a": {"version": "1", "scope": "runtime"}},
                "fixture", errors=None,
            )
            s1_dep_diff.print_parse_report("current", {}, "fixture", errors=["bad"])
        self.assertIn("解析失败：1 行", stderr.getvalue())

        for windows in (False, True):
            stream = io.StringIO()
            with patch.object(s1_dep_diff, "IS_WINDOWS", windows), patch.object(
                s1_dep_diff, "_resolve_single_module_selector", return_value=".",
            ), patch.object(
                s1_dep_diff, "_manual_package_command", side_effect=["base-package", "current-package"],
            ), patch.object(s1_dep_diff.sys, "stderr", stream):
                s1_dep_diff.print_manual_instructions("base", "current", work_dir="/repo")
            self.assertIn("base-package", stream.getvalue())
            self.assertIn("scripts\\s1_dep_diff.py" if windows else "scripts/s1_dep_diff.py", stream.getvalue())

        stream = io.StringIO()
        with patch.object(
            s1_dep_diff, "_resolve_single_module_selector", return_value=".",
        ), patch.object(
            s1_dep_diff, "_manual_package_command", side_effect=["maven-package", "gradle-package"],
        ) as package_command, patch.object(s1_dep_diff.sys, "stderr", stream):
            s1_dep_diff.print_manual_instructions(
                "base", "current", work_dir="/repo",
                base_tool="maven", current_tool="gradle",
            )
        self.assertEqual(
            [call.args[0] for call in package_command.call_args_list],
            ["maven", "gradle"],
        )

        with patch.object(s1_dep_diff, "create_detached_worktree", return_value="/tmp/wt") as create, patch.object(
            s1_dep_diff, "git_cmd", return_value=["git"],
        ):
            for side, label in (("base", "s1-b"), ("current", "s1-c"), (None, "s1-x")):
                self.assertEqual(s1_dep_diff.create_branch_worktree("main", "/repo", side), "/tmp/wt")
                self.assertEqual(create.call_args.kwargs["label"], label)

        with patch.object(
            s1_dep_diff, "_collect_gradle_runtime_deps_for_workspace", return_value=({"g:a": {}}, "gradle"),
        ) as gradle, patch.object(
            s1_dep_diff, "_collect_maven_runtime_deps_for_workspace", return_value=({"g:b": {}}, "maven"),
        ) as maven:
            self.assertEqual(
                s1_dep_diff.collect_runtime_deps_for_workspace("/repo", build_tool="gradle")[1],
                "gradle",
            )
            self.assertEqual(
                s1_dep_diff.collect_runtime_deps_for_workspace("/repo", build_tool=None)[1],
                "maven",
            )
        gradle.assert_called_once()
        maven.assert_called_once()

    def test_packaged_inventory_cache_validation_and_atomic_cleanup_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache.json"
            row = s1_dep_diff._build_packaged_entry("BOOT-INF/lib/a-1.jar")
            row["content_sha256"] = "a" * 64
            rows = [row]
            rows_sha = s1_dep_diff.hashlib.sha256(
                s1_dep_diff._canonical_packaged_inventory_bytes(rows),
            ).hexdigest()

            def write_payload(**overrides):
                payload = {
                    "schema_version": s1_dep_diff.PACKAGED_INVENTORY_CACHE_SCHEMA_VERSION,
                    "artifact_sha256": "artifact-sha",
                    "archive_bytes": 10,
                    "nested_entries": 1,
                    "rows": rows,
                    "rows_sha256": rows_sha,
                }
                payload.update(overrides)
                cache.write_text(json.dumps(payload), encoding="utf-8")

            invalid_payloads = (
                {"schema_version": None},
                {"schema_version": 999},
                {"artifact_sha256": ""},
                {"artifact_sha256": "other"},
                {"rows": "invalid"},
                {"rows": [{**row, "read_error": "broken"}]},
                {"archive_bytes": -1},
                {"nested_entries": -1},
                {"rows_sha256": None},
                {"rows_sha256": "wrong"},
            )
            for overrides in invalid_payloads:
                with self.subTest(overrides=overrides):
                    write_payload(**overrides)
                    self.assertIsNone(
                        s1_dep_diff._load_packaged_inventory_cache(cache, "artifact-sha"),
                    )
            write_payload()
            loaded = s1_dep_diff._load_packaged_inventory_cache(cache, "artifact-sha")
            self.assertTrue(loaded.complete)
            self.assertEqual(loaded.rows, rows)
            cache.write_text("not-json", encoding="utf-8")
            self.assertIsNone(s1_dep_diff._load_packaged_inventory_cache(cache, "artifact-sha"))

            scan = s1_dep_diff._PackagedArchiveScanResult(
                rows=rows, complete=True, failures=[], archive_bytes=10, nested_entries=1,
            )
            target = root / "written.json"
            s1_dep_diff._write_packaged_inventory_cache(target, "artifact-sha", scan)
            self.assertTrue(target.is_file())
            with patch.object(s1_dep_diff, "named_temporary_file", side_effect=OSError("open")):
                s1_dep_diff._write_packaged_inventory_cache(root / "open-failed.json", "sha", scan)
            with patch.object(s1_dep_diff.os, "replace", side_effect=OSError("replace")):
                s1_dep_diff._write_packaged_inventory_cache(root / "replace-failed.json", "sha", scan)
            self.assertEqual(list(root.glob(".jua-cache-*.tmp")), [])

    def test_packaged_archive_inspection_cache_hit_miss_and_completeness_matrix(self):
        row = s1_dep_diff._build_packaged_entry("BOOT-INF/lib/a-1.jar")
        row["content_sha256"] = "a" * 64
        complete = s1_dep_diff._PackagedArchiveScanResult(
            rows=[row], complete=True, failures=[], archive_bytes=10, nested_entries=1,
        )
        partial = s1_dep_diff._PackagedArchiveScanResult(
            rows=[], complete=False, failures=[{"stage": "scan"}], archive_bytes=10, nested_entries=0,
        )
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "app.jar"
            artifact.write_bytes(b"artifact")
            cache_dir = Path(directory) / "cache"

            stats = {"misses": 2}
            with patch.object(s1_dep_diff, "sha256_file", return_value="sha"), patch.object(
                s1_dep_diff, "_scan_packaged_archive", return_value=complete,
            ):
                self.assertEqual(s1_dep_diff._inspect_packaged_archive(artifact, None, stats), [row])
            self.assertEqual(stats["misses"], 3)

            with patch.object(s1_dep_diff, "sha256_file", return_value="sha"), patch.object(
                s1_dep_diff, "_scan_packaged_archive", return_value=complete,
            ):
                self.assertEqual(s1_dep_diff._inspect_packaged_archive(artifact, None, None), [row])
                empty_stats = {}
                self.assertEqual(s1_dep_diff._inspect_packaged_archive(artifact, None, empty_stats), [row])
            self.assertEqual(empty_stats["misses"], 1)

            with patch.object(s1_dep_diff, "sha256_file", return_value="sha"), patch.object(
                s1_dep_diff, "_load_packaged_inventory_cache", return_value=complete,
            ):
                self.assertEqual(s1_dep_diff._inspect_packaged_archive(artifact, cache_dir, None), [row])
                hit_stats = {"hits": 2}
                self.assertEqual(s1_dep_diff._inspect_packaged_archive(artifact, cache_dir, hit_stats), [row])
            self.assertEqual(hit_stats["hits"], 3)

            with patch.object(s1_dep_diff, "sha256_file", return_value="sha"), patch.object(
                s1_dep_diff, "_load_packaged_inventory_cache", return_value=complete,
            ):
                empty_hit_stats = {}
                self.assertEqual(
                    s1_dep_diff._inspect_packaged_archive(artifact, cache_dir, empty_hit_stats),
                    [row],
                )
            self.assertEqual(empty_hit_stats["hits"], 1)

            miss_stats = {"misses": 2}
            with patch.object(s1_dep_diff, "sha256_file", return_value="sha"), patch.object(
                s1_dep_diff, "_load_packaged_inventory_cache", return_value=None,
            ), patch.object(
                s1_dep_diff, "_scan_packaged_archive", return_value=partial,
            ), patch.object(s1_dep_diff, "_write_packaged_inventory_cache") as write:
                self.assertEqual(
                    s1_dep_diff._inspect_packaged_archive(artifact, cache_dir, miss_stats),
                    [],
                )
            self.assertEqual(miss_stats["misses"], 3)
            write.assert_not_called()

            invalid_complete = s1_dep_diff._PackagedArchiveScanResult(
                rows=[{"invalid": True}], complete=True, failures=[], archive_bytes=1, nested_entries=1,
            )
            with patch.object(s1_dep_diff, "sha256_file", return_value="sha"), patch.object(
                s1_dep_diff, "_load_packaged_inventory_cache", return_value=None,
            ), patch.object(
                s1_dep_diff, "_scan_packaged_archive", return_value=invalid_complete,
            ), patch.object(s1_dep_diff, "_write_packaged_inventory_cache") as write:
                s1_dep_diff._inspect_packaged_archive(artifact, cache_dir, {})
            write.assert_not_called()

            with patch.object(s1_dep_diff, "sha256_file", return_value="sha"), patch.object(
                s1_dep_diff, "_load_packaged_inventory_cache", return_value=None,
            ), patch.object(
                s1_dep_diff, "_scan_packaged_archive", return_value=complete,
            ), patch.object(s1_dep_diff, "_write_packaged_inventory_cache") as write:
                s1_dep_diff._inspect_packaged_archive(artifact, cache_dir, {})
            write.assert_called_once()

            identity_changes = (
                (None, ["before", "after"], "during packaged archive scan"),
                (cache_dir, ["before", "after"], "during packaged archive cache load"),
            )
            for selected_cache, hashes, message in identity_changes:
                with self.subTest(cache=selected_cache, message=message), patch.object(
                    s1_dep_diff, "sha256_file", side_effect=hashes,
                ), patch.object(
                    s1_dep_diff, "_load_packaged_inventory_cache", return_value=complete,
                ), patch.object(
                    s1_dep_diff, "_scan_packaged_archive", return_value=complete,
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        s1_dep_diff._inspect_packaged_archive(
                            artifact, selected_cache, None,
                        )

            with patch.object(
                s1_dep_diff, "sha256_file", side_effect=["before", "after"],
            ), patch.object(
                s1_dep_diff, "_load_packaged_inventory_cache", return_value=None,
            ), patch.object(
                s1_dep_diff, "_scan_packaged_archive", return_value=complete,
            ):
                with self.assertRaisesRegex(RuntimeError, "during packaged archive scan"):
                    s1_dep_diff._inspect_packaged_archive(artifact, cache_dir, None)

        s1_dep_diff._require_complete_packaged_archive_scan(None, "app.jar")
        with self.assertRaisesRegex(RuntimeError, "unknown archive scan failure"):
            s1_dep_diff._require_complete_packaged_archive_scan(
                {"scan_complete": False, "failures": []}, "app.jar",
            )
        with self.assertRaisesRegex(RuntimeError, "stage:entry:error"):
            s1_dep_diff._require_complete_packaged_archive_scan(
                {
                    "scan_complete": False,
                    "failures": [
                        {"stage": "stage", "entry": "entry", "error": "error"},
                        {"stage": "", "entry": "", "error": ""},
                    ],
                },
                "app.jar",
            )

    def test_nested_jar_metadata_empty_partial_group_and_classifier_matrix(self):
        def nested(entries):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for name, content in entries:
                    archive.writestr(name, content)
            stream.seek(0)
            return stream

        empty = s1_dep_diff._extract_packaged_dep_from_nested_jar_source(
            nested([]), "BOOT-INF/lib/unknown.jar", None,
        )
        self.assertEqual(empty["match_source"], "filename")
        self.assertEqual(empty["content_sha256"], "")

        partial = s1_dep_diff._extract_packaged_dep_from_nested_jar_source(
            nested([
                ("README.txt", "ignored"),
                ("META-INF/maven/g/a/not-pom.txt", "ignored"),
                ("META-INF/maven/g/missing-artifact/pom.properties", "groupId=g\nversion=1\n"),
                ("META-INF/maven/g/missing-version/pom.properties", "groupId=g\nartifactId=a\n"),
            ]),
            "BOOT-INF/lib/a-1.jar",
            "sha",
        )
        self.assertEqual(partial["content_sha256"], "sha")
        self.assertEqual(partial["match_source"], "filename")

        group_missing = s1_dep_diff._extract_packaged_dep_from_nested_jar_source(
            nested([(
                "META-INF/maven/unknown/a/pom.properties",
                "artifactId=a\nversion=1\n",
            )]),
            "BOOT-INF/lib/a-1.jar",
            "sha",
        )
        self.assertEqual(group_missing["coord"], "")
        self.assertEqual(group_missing["artifact_id"], "a")

        classified = s1_dep_diff._extract_packaged_dep_from_nested_jar_source(
            nested([(
                "META-INF/maven/g/a/pom.properties",
                "groupId=g\nartifactId=a\nversion=1\n",
            )]),
            "BOOT-INF/lib/a-1-tests.jar",
            "sha",
        )
        self.assertEqual(classified["coord"], "g:a:tests")
        self.assertEqual(classified["classifier"], "tests")

        unclassified = s1_dep_diff._extract_packaged_dep_from_nested_jar_source(
            nested([(
                "META-INF/maven/g/a/pom.properties",
                "groupId=g\nartifactId=a\nversion=1\n",
            )]),
            "BOOT-INF/lib/a-1.jar",
            "sha",
        )
        self.assertEqual(unclassified["coord"], "g:a")
        self.assertEqual(unclassified["classifier"], "")

        conflict_source = nested([
            (
                "META-INF/maven/shared/pom.properties",
                "groupId=g\nartifactId=a\nversion=1\n",
            ),
            (
                "META-INF/maven/shared/pom.properties",
                "groupId=g\nartifactId=b\nversion=2\n",
            ),
        ])
        conflict = s1_dep_diff._extract_packaged_dep_from_nested_jar_source(
            conflict_source, "BOOT-INF/lib/a-1.jar", "sha",
        )
        self.assertEqual(conflict["coord"], "g:a")
        self.assertEqual(conflict["match_source"], "embedded-pom-filename-match")
        self.assertEqual(len(conflict["metadata_anomalies"]), 1)
        self.assertIn("g:a:1:|g:b:2:", conflict["metadata_anomalies"][0])

        aggregate = s1_dep_diff._extract_packaged_dep_from_nested_jar_source(
            nested([
                (
                    "META-INF/maven/g/a/pom.properties",
                    "groupId=g\nartifactId=a\nversion=1\n",
                ),
                (
                    "META-INF/maven/g/b/pom.properties",
                    "groupId=g\nartifactId=b\nversion=2\n",
                ),
            ]),
            "BOOT-INF/lib/aggregate.jar",
            "sha",
        )
        self.assertEqual(aggregate["coord"], "")
        self.assertEqual(aggregate["match_source"], "filename")

        bad_zip = s1_dep_diff._extract_packaged_dep_from_nested_jar_source(
            io.BytesIO(b"not-a-zip"), "BOOT-INF/lib/broken.jar", "sha",
        )
        self.assertEqual(bad_zip["resolution_status"], "unresolved")
        self.assertIn("bad_nested_zip", bad_zip["read_error"])

        class MetadataReadFailure:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def infolist(self):
                return [type("Info", (), {"filename": "META-INF/maven/g/a/pom.properties"})()]

            def read(self, _info):
                raise OSError("metadata unavailable")

        with patch.object(s1_dep_diff.zipfile, "ZipFile", return_value=MetadataReadFailure()):
            metadata_failure = s1_dep_diff._extract_packaged_dep_from_nested_jar_source(
                io.BytesIO(), "BOOT-INF/lib/a-1.jar", "sha",
            )
        self.assertEqual(metadata_failure["resolution_status"], "unresolved")
        self.assertIn("metadata_read_error", metadata_failure["read_error"])

    def test_runtime_filename_identity_matching_precedence_and_ambiguity_matrix(self):
        self.assertEqual(
            s1_dep_diff._runtime_dependency_for_packaged_filename(None, None),
            (None, []),
        )

        invalid_runtime = {
            "none": None,
            "missing-group": {"artifact_id": "a", "version": "1"},
            "missing-artifact": {"group_id": "g", "version": "1"},
            "missing-version": {"group_id": "g", "artifact_id": "a"},
        }
        self.assertEqual(
            s1_dep_diff._runtime_dependency_for_packaged_filename(
                {"lib_entry": r"BOOT-INF\lib\a-1.jar", "version": ""},
                invalid_runtime,
            ),
            (None, []),
        )

        ambiguous_physical = {
            "g:a": {
                "group_id": "g",
                "artifact_id": "a",
                "version": "1",
                "artifact_file_names": ["", None, "/cache/mystery.jar", "/cache/other.jar"],
            },
        }
        self.assertEqual(
            s1_dep_diff._runtime_dependency_for_packaged_filename(
                {"lib_name": "mystery.jar"}, ambiguous_physical,
            ),
            (None, []),
        )

        inferred_classifier = {
            "g:a": {
                "coord": "g:a",
                "group_id": "g",
                "artifact_id": "a",
                "version": "1",
                "artifact_file_names": ["a-1-tests.jar", "a-1-sources.jar"],
            },
        }
        selected, candidates = s1_dep_diff._runtime_dependency_for_packaged_filename(
            {"lib_name": "a-1-tests.jar", "version": "1"},
            inferred_classifier,
        )
        self.assertEqual(selected["coord"], "g:a:tests")
        self.assertEqual(selected["classifier_source"], "runtime-version-filename-inference")
        self.assertEqual(candidates, [selected])

        declared_classifier = {
            "g:a:tests": {
                "coord": "g:a:tests",
                "group_id": "g",
                "artifact_id": "a",
                "version": "1",
                "classifier": "tests",
            },
        }
        selected, _ = s1_dep_diff._runtime_dependency_for_packaged_filename(
            {"lib_name": "a-1-tests.jar"}, declared_classifier,
        )
        self.assertEqual(selected["classifier_source"], "runtime-coordinate")
        self.assertEqual(selected["packaged_match_source"], "runtime-filename-classifier")

        mismatch = {
            "g:a:sources": {
                "group_id": "g",
                "artifact_id": "a",
                "version": "1",
                "classifier": "sources",
            },
        }
        self.assertEqual(
            s1_dep_diff._runtime_dependency_for_packaged_filename(
                {"lib_name": "a-1-tests.jar"}, mismatch,
            ),
            (None, []),
        )

        valid_but_unmatched = {
            "g:b": {"group_id": "g", "artifact_id": "b", "version": "2"},
        }
        self.assertEqual(
            s1_dep_diff._runtime_dependency_for_packaged_filename(
                {"lib_name": "a-1.jar"}, valid_but_unmatched,
            ),
            (None, []),
        )

        exact_declared_classifier = {
            "g:a:tests": {
                "coord": "g:a:tests",
                "group_id": "g",
                "artifact_id": "a",
                "version": "1",
                "classifier": "tests",
                "artifact_file_name": "renamed-tests.jar",
            },
        }
        selected, _ = s1_dep_diff._runtime_dependency_for_packaged_filename(
            {"lib_name": "renamed-tests.jar"}, exact_declared_classifier,
        )
        self.assertEqual(selected["coord"], "g:a:tests")
        self.assertEqual(selected["filename_layout"], "artifact-inventory")

        exact_and_conventional = {
            "g:a": {
                "group_id": "g",
                "artifact_id": "a",
                "version": "1",
                "artifact_file_names": ["a-1.jar", "other.jar"],
            },
        }
        selected, _ = s1_dep_diff._runtime_dependency_for_packaged_filename(
            {"lib_name": "a-1.jar"}, exact_and_conventional,
        )
        self.assertEqual(selected["coord"], "g:a")
        self.assertTrue(selected["physical_filename_version_match"])

        version_variants = {
            "g:a": {
                "group_id": "g",
                "artifact_id": "a",
                "observed_versions": ["0", "1", "2"],
                "artifact_file_name": "renamed.jar",
            },
        }
        selected, _ = s1_dep_diff._runtime_dependency_for_packaged_filename(
            {"lib_name": "renamed.jar", "version": "1"},
            version_variants,
        )
        self.assertEqual(selected["matched_runtime_version"], "1")
        selected_without_version, _ = s1_dep_diff._runtime_dependency_for_packaged_filename(
            {"lib_name": "renamed.jar"}, version_variants,
        )
        self.assertEqual(selected_without_version["matched_runtime_version"], "0")

        same_selected_version = {
            "first": {
                "coord": "g:a",
                "group_id": "g",
                "artifact_id": "a",
                "version": "1",
                "artifact_file_name": "renamed.jar",
            },
            "second": {
                "coord": "g:a",
                "group_id": "g",
                "artifact_id": "a",
                "version": "1",
                "artifact_file_name": "renamed.jar",
            },
        }
        selected, _ = s1_dep_diff._runtime_dependency_for_packaged_filename(
            {"lib_name": "renamed.jar", "version": "1"},
            same_selected_version,
        )
        self.assertEqual(selected["matched_runtime_version"], "1")

        ambiguous_coordinate = {
            "g:a": {"group_id": "g", "artifact_id": "a", "version": "1"},
            "h:a": {"group_id": "h", "artifact_id": "a", "version": "1"},
        }
        selected, candidates = s1_dep_diff._runtime_dependency_for_packaged_filename(
            {"lib_name": "a-1.jar"}, ambiguous_coordinate,
        )
        self.assertIsNone(selected)
        self.assertEqual([item["coord"] for item in candidates], ["g:a", "h:a"])

    def test_runtime_build_tool_collection_success_fallback_and_failure_matrix(self):
        maven_common = (
            patch.object(s1_dep_diff, "_resolve_single_module_selector", return_value=None),
            patch.object(s1_dep_diff, "_normalize_maven_pl_with_workdir", return_value=None),
            patch.object(s1_dep_diff, "_maven_profile_args_for_module", return_value=[]),
            patch.object(s1_dep_diff, "_maven_reactor_has_modules", return_value=False),
            patch.object(s1_dep_diff, "mvn_cmd", return_value=["mvn"]),
        )
        for stdout, stderr, expected_excerpt in (
            ("stdout failure", "", "stdout failure"),
            ("stdout failure", "stderr failure", "stderr failure"),
        ):
            with self.subTest(tool="maven", stderr=bool(stderr)), maven_common[0], maven_common[1], maven_common[2], maven_common[3], maven_common[4], patch.object(
                s1_dep_diff, "run_cmd", return_value=(stdout, stderr, 7),
            ):
                with self.assertRaisesRegex(RuntimeError, expected_excerpt):
                    s1_dep_diff._collect_maven_runtime_deps_for_workspace(".")

        def collect_gradle(results, *, inventory=None, fallback=None, modules=None):
            with patch.object(
                s1_dep_diff, "_resolve_single_module_selector", return_value=None,
            ), patch.object(
                s1_dep_diff, "_gradle_target_model", return_value={"gradle_path": ":app"},
            ), patch.object(
                s1_dep_diff, "discover_project_modules", return_value={"modules": modules},
            ), patch.object(
                s1_dep_diff, "gradle_cmd", return_value=["gradle"],
            ), patch.object(
                s1_dep_diff, "_run_gradle_command_with_lock_retry", side_effect=results,
            ), patch.object(
                s1_dep_diff, "parse_gradle_artifact_inventory", return_value=inventory or {},
            ) as inventory_parser, patch.object(
                s1_dep_diff, "parse_gradle_dependency_report", return_value=fallback or {},
            ) as fallback_parser, patch.object(
                s1_dep_diff, "augment_runtime_deps_with_project_modules",
                side_effect=lambda deps, *_args, **_kwargs: deps,
            ):
                result = s1_dep_diff._collect_gradle_runtime_deps_for_workspace(".")
            return result, inventory_parser, fallback_parser

        (deps, command), inventory_parser, fallback_parser = collect_gradle(
            [("inventory", "", 0, 1)],
            inventory={"g:a": {"version": "1"}},
            modules=None,
        )
        self.assertEqual(deps, {"g:a": {"version": "1"}})
        self.assertNotIn("fallback=", command)
        self.assertEqual(inventory_parser.call_args.kwargs["project_modules"], [])
        fallback_parser.assert_not_called()

        (deps, command), _, fallback_parser = collect_gradle(
            [("", "", 0, 1), ("fallback", "", 0, 1)],
            fallback={"g:b": {"version": "2"}},
            modules=None,
        )
        self.assertEqual(deps, {"g:b": {"version": "2"}})
        self.assertIn("fallback=", command)
        self.assertEqual(fallback_parser.call_args.kwargs["project_modules"], [])

        failure_cases = (
            (
                [("", "Task 'juaRuntimeArtifactInventory' not found", 1, 1), ("", "fallback failed", 2, 1)],
                "Task 'juaRuntimeArtifactInventory' not found",
            ),
            (
                [("Task 'juaRuntimeArtifactInventory' not found", "", 1, 1), ("", "fallback failed", 2, 1)],
                "Task 'juaRuntimeArtifactInventory' not found",
            ),
            (
                [("", "", 0, 1), ("", "fallback failed", 2, 1)],
                "artifact inventory returned no usable records",
            ),
        )
        for results, context in failure_cases:
            with self.subTest(tool="gradle", context=context):
                with self.assertRaises(s1_dep_diff.GradleCommandFailure) as raised:
                    collect_gradle(results)
            self.assertEqual(raised.exception.stage, "gradle_dependencies_fallback")
            self.assertIn(context, raised.exception.stderr)

        with self.assertRaises(s1_dep_diff.GradleCommandFailure) as raised:
            collect_gradle([("", "generic inventory failure", 3, 1)])
        self.assertEqual(raised.exception.stage, "gradle_artifact_inventory")
        self.assertIn("generic inventory failure", raised.exception.stderr)

    def test_direct_artifact_collection_path_loader_and_resolution_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "app.jar"
            artifact.write_bytes(b"artifact")
            folder = root / "folder"
            folder.mkdir()

            with self.assertRaisesRegex(RuntimeError, "不存在或不是文件"):
                s1_dep_diff.collect_packaged_deps_from_artifact_path(
                    root / "missing.jar",
                )
            with self.assertRaisesRegex(RuntimeError, "不存在或不是文件"):
                s1_dep_diff.collect_packaged_deps_from_artifact_path(folder)

            with patch.object(
                s1_dep_diff, "_detect_archive_packaging_type", return_value="thin_jar",
            ):
                with self.assertRaisesRegex(RuntimeError, "未发现可比较的嵌套依赖"):
                    s1_dep_diff.collect_packaged_deps_from_artifact_path(
                        "app.jar", work_dir=root,
                    )

            with patch.object(
                s1_dep_diff, "_detect_archive_packaging_type", return_value="boot_jar",
            ), patch.object(
                s1_dep_diff, "_inspect_packaged_archive", return_value=[],
            ), patch.object(s1_dep_diff, "_require_complete_packaged_archive_scan"):
                with self.assertRaisesRegex(RuntimeError, "未发现可比较的打包依赖"):
                    s1_dep_diff.collect_packaged_deps_from_artifact_path(artifact)

            raw = [{
                "entry_id": "a",
                "lib_entry": "BOOT-INF/lib/a-1.jar",
                "lib_name": "a-1.jar",
                "coord": "",
                "artifact_id": "a",
                "version": "1",
            }]
            resolved_entry = {**raw[0], "coord": "g:a", "resolution_status": "resolved"}
            unresolved_entry = {**raw[0], "resolution_status": "unresolved"}
            status_missing_entry = {**raw[0]}
            loader_calls = []

            def loader():
                loader_calls.append(True)
                return {"g:a": {"version": "1"}}

            common = (
                patch.object(s1_dep_diff, "_detect_archive_packaging_type", return_value="boot_jar"),
                patch.object(s1_dep_diff, "_inspect_packaged_archive", return_value=raw),
                patch.object(s1_dep_diff, "_require_complete_packaged_archive_scan"),
                patch.object(
                    s1_dep_diff, "_enrich_packaged_deps_with_runtime",
                    return_value=([resolved_entry, unresolved_entry], {"g:a": resolved_entry}, [unresolved_entry]),
                ),
            )
            with common[0], common[1], common[2], common[3]:
                with self.assertRaises(s1_dep_diff.ArtifactCoordinateInputRequiredError):
                    s1_dep_diff.collect_packaged_deps_from_artifact_path(
                        "app.jar", work_dir=root, runtime_deps_loader=loader,
                    )
            self.assertEqual(len(loader_calls), 1)

            with patch.object(
                s1_dep_diff, "_detect_archive_packaging_type", return_value="war",
            ), patch.object(
                s1_dep_diff, "_inspect_packaged_archive", return_value=raw,
            ), patch.object(
                s1_dep_diff, "_require_complete_packaged_archive_scan",
            ), patch.object(
                s1_dep_diff, "_enrich_packaged_deps_with_runtime",
                return_value=(
                    [resolved_entry, unresolved_entry, status_missing_entry],
                    {"g:a": resolved_entry},
                    [unresolved_entry],
                ),
            ):
                deps, meta = s1_dep_diff.collect_packaged_deps_from_artifact_path(
                    artifact,
                    runtime_deps={"g:a": {"version": "1"}},
                    runtime_deps_loader=lambda: self.fail("loader must not run"),
                    allow_unresolved=True,
                )
            self.assertEqual(set(deps), {"g:a"})
            self.assertEqual(meta["matched_count"], 1)
            self.assertEqual(meta["unresolved_items"], [unresolved_entry])

            relative_existing_file = Path(__file__).resolve().relative_to(Path.cwd())
            with patch.object(
                s1_dep_diff, "_detect_archive_packaging_type", return_value="packaged_jar",
            ), patch.object(
                s1_dep_diff, "_inspect_packaged_archive", return_value=raw,
            ), patch.object(
                s1_dep_diff, "_require_complete_packaged_archive_scan",
            ), patch.object(
                s1_dep_diff, "_enrich_packaged_deps_with_runtime",
                return_value=([resolved_entry], {"g:a": resolved_entry}, []),
            ):
                deps, meta = s1_dep_diff.collect_packaged_deps_from_artifact_path(
                    relative_existing_file,
                )
            self.assertEqual(set(deps), {"g:a"})
            self.assertEqual(meta["artifact_path"], str(Path(__file__).resolve()))

    def test_branch_collection_tool_dispatch_primary_failure_and_cleanup_matrix(self):
        blocked = s1_dep_diff.Step1CommandExecutionBlockedError(
            stage="custom", command="custom", stderr_excerpt="blocked",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worktree = root / "worktree"
            worktree.mkdir()

            missing_artifact = worktree / "missing.jar"
            with patch.object(
                s1_dep_diff, "build_java_env", return_value={},
            ), patch.object(
                s1_dep_diff, "create_branch_worktree", return_value=worktree,
            ), patch.object(
                s1_dep_diff, "collect_maven_deps_for_workspace",
                return_value=({}, {"artifact_path": str(missing_artifact)}),
            ) as maven, patch.object(
                s1_dep_diff, "run_cmd", return_value=("", "", 1),
            ), patch.object(s1_dep_diff, "remove_branch_worktree"):
                _deps, meta = s1_dep_diff.get_packaged_deps_by_switching_branch(
                    "release", root, build_tool=None,
                )
            maven.assert_called_once()
            self.assertEqual(meta["artifact_sha256"], "")
            self.assertEqual(meta["revision"], "")

            with patch.object(
                s1_dep_diff, "build_java_env", return_value={},
            ), patch.object(
                s1_dep_diff, "create_branch_worktree", return_value=worktree,
            ), patch.object(
                s1_dep_diff, "collect_maven_deps_for_workspace", side_effect=blocked,
            ), patch.object(s1_dep_diff, "remove_branch_worktree"):
                with self.assertRaises(s1_dep_diff.Step1CommandExecutionBlockedError) as raised:
                    s1_dep_diff.get_packaged_deps_by_switching_branch("release", root)
            self.assertIs(raised.exception, blocked)

            with patch.object(
                s1_dep_diff, "build_java_env", return_value={},
            ), patch.object(
                s1_dep_diff, "create_branch_worktree", return_value=worktree,
            ), patch.object(
                s1_dep_diff, "collect_gradle_deps_for_workspace", side_effect=RuntimeError("build failed"),
            ), patch.object(s1_dep_diff, "remove_branch_worktree"):
                with self.assertRaises(s1_dep_diff.Step1CommandExecutionBlockedError) as raised:
                    s1_dep_diff.get_packaged_deps_by_switching_branch(
                        "release", root, build_tool="gradle",
                    )
            self.assertEqual(raised.exception.stage, "gradle_build")
            self.assertIn("gradlew", raised.exception.command)

            with patch.object(
                s1_dep_diff, "build_java_env", return_value={},
            ), patch.object(
                s1_dep_diff, "create_branch_worktree", return_value=worktree,
            ), patch.object(
                s1_dep_diff, "collect_maven_deps_for_workspace", return_value=({}, {}),
            ), patch.object(
                s1_dep_diff, "run_cmd", return_value=("commit", "", 0),
            ), patch.object(
                s1_dep_diff, "remove_branch_worktree", side_effect=OSError("cleanup failed"),
            ):
                with self.assertRaises(s1_dep_diff.Step1CommandExecutionBlockedError) as raised:
                    s1_dep_diff.get_packaged_deps_by_switching_branch("release", root)
            self.assertEqual(raised.exception.stage, "cleanup_branch_worktree")

            with patch.object(
                s1_dep_diff, "build_java_env", side_effect=OSError("java unavailable"),
            ), patch.object(s1_dep_diff, "create_branch_worktree") as create:
                with self.assertRaises(s1_dep_diff.Step1CommandExecutionBlockedError) as raised:
                    s1_dep_diff.get_runtime_deps_by_switching_branch("release", root)
            create.assert_not_called()
            self.assertEqual(raised.exception.stage, "prepare_java_env")

            with patch.object(
                s1_dep_diff, "build_java_env", return_value={},
            ), patch.object(
                s1_dep_diff, "create_branch_worktree", return_value=worktree,
            ), patch.object(
                s1_dep_diff, "collect_runtime_deps_for_workspace", side_effect=blocked,
            ), patch.object(s1_dep_diff, "remove_branch_worktree"):
                with self.assertRaises(s1_dep_diff.Step1CommandExecutionBlockedError) as raised:
                    s1_dep_diff.get_runtime_deps_by_switching_branch("release", root)
            self.assertIs(raised.exception, blocked)

            with patch.object(
                s1_dep_diff, "build_java_env", return_value={},
            ), patch.object(
                s1_dep_diff, "create_branch_worktree", return_value=worktree,
            ), patch.object(
                s1_dep_diff, "collect_runtime_deps_for_workspace", side_effect=RuntimeError("inventory failed"),
            ), patch.object(s1_dep_diff, "remove_branch_worktree"):
                with self.assertRaises(s1_dep_diff.Step1CommandExecutionBlockedError) as raised:
                    s1_dep_diff.get_runtime_deps_by_switching_branch(
                        "release", root, build_tool="gradle",
                    )
            self.assertEqual(raised.exception.stage, "gradle_dependencies")
            self.assertIn("gradlew", raised.exception.command)

            with patch.object(
                s1_dep_diff, "build_java_env", return_value={},
            ), patch.object(
                s1_dep_diff, "create_branch_worktree", return_value=worktree,
            ), patch.object(
                s1_dep_diff, "collect_runtime_deps_for_workspace", return_value=({}, "command"),
            ), patch.object(
                s1_dep_diff, "remove_branch_worktree", side_effect=OSError("cleanup failed"),
            ):
                with self.assertRaises(s1_dep_diff.Step1CommandExecutionBlockedError) as raised:
                    s1_dep_diff.get_runtime_deps_by_switching_branch("release", root)
            self.assertEqual(raised.exception.stage, "cleanup_branch_worktree")

    def test_artifact_runtime_ref_trust_and_provenance_matrix(self):
        class Observer:
            def __init__(self):
                self.events = []

            def event(self, *args, **kwargs):
                self.events.append((args, kwargs))

        rich_resolution = {
            "status": "resolved",
            "source_status": "user_confirmed_local_source",
            "requested_ref": "requested-release",
            "resolved_ref": "refs/tags/release",
            "resolved_commit": "a" * 40,
            "resolution_mode": "user-confirmed",
            "candidates": [{"commit": "a" * 40}],
            "remote": "origin",
            "remote_ref": "refs/tags/release",
        }
        observer = Observer()
        with patch.object(s1_dep_diff, "resolve_step1_ref") as resolve, patch.object(
            s1_dep_diff, "get_runtime_deps_by_switching_branch",
            return_value=({"g:a": {"version": "1"}}, {"list_command": "command"}),
        ) as collect:
            deps, meta = s1_dep_diff._collect_runtime_deps_for_artifact_input(
                "", "release", ".", side="base", observer=observer,
                source_resolution=rich_resolution,
            )
        resolve.assert_not_called()
        self.assertEqual(collect.call_args.args[0], "a" * 40)
        self.assertEqual(set(deps), {"g:a"})
        self.assertEqual(meta["requested_ref"], "requested-release")
        self.assertEqual(meta["resolved_ref"], "refs/tags/release")
        self.assertEqual(meta["ref_resolution_mode"], "user-confirmed")
        self.assertEqual(meta["ref_remote"], "origin")
        self.assertEqual(meta["ref_remote_ref"], "refs/tags/release")
        self.assertEqual(observer.events[0][1]["details"]["candidate_count"], 1)
        self.assertIn("基准侧", observer.events[0][0][2])

        fallback_resolution = {
            "status": "resolved",
            "source_status": "remote_source_resolved",
            "resolved_commit": "b" * 40,
        }
        observer = Observer()
        with patch.object(
            s1_dep_diff, "resolve_step1_ref", return_value=fallback_resolution,
        ) as resolve, patch.object(
            s1_dep_diff, "get_runtime_deps_by_switching_branch",
            return_value=({}, {}),
        ):
            _deps, meta = s1_dep_diff._collect_runtime_deps_for_artifact_input(
                "/repo", "release", "/analysis", side="current", observer=observer,
                source_resolution={
                    "status": "resolved",
                    "source_status": "remote_source_resolved",
                    "resolved_commit": "",
                },
            )
        resolve.assert_called_once()

        with patch.object(
            s1_dep_diff, "resolve_step1_ref", return_value=fallback_resolution,
        ) as resolve, patch.object(
            s1_dep_diff, "get_runtime_deps_by_switching_branch", return_value=({}, {}),
        ):
            s1_dep_diff._collect_runtime_deps_for_artifact_input(
                "/repo", "release", "/analysis",
                source_resolution={"status": "not_found"},
                expected_commit="e" * 40,
                expected_remote="origin",
                expected_remote_ref="refs/heads/release",
            )
        self.assertEqual(resolve.call_args.kwargs["expected_commit"], "e" * 40)
        self.assertEqual(resolve.call_args.kwargs["expected_remote"], "origin")
        self.assertEqual(
            resolve.call_args.kwargs["expected_remote_ref"],
            "refs/heads/release",
        )
        self.assertEqual(meta["requested_ref"], "release")
        self.assertEqual(meta["resolved_ref"], "release")
        self.assertEqual(meta["ref_resolution_mode"], "exact")
        self.assertEqual(meta["ref_remote"], "")
        self.assertEqual(meta["ref_remote_ref"], "")
        self.assertEqual(observer.events[0][1]["details"]["candidate_count"], 0)
        self.assertIn("当前侧", observer.events[0][0][2])

        with patch.object(
            s1_dep_diff, "resolve_step1_ref", return_value=fallback_resolution,
        ) as resolve, patch.object(
            s1_dep_diff, "get_runtime_deps_by_switching_branch", return_value=({}, {}),
        ):
            s1_dep_diff._collect_runtime_deps_for_artifact_input(
                "/repo", "release", "/analysis",
                source_resolution={
                    "status": "resolved",
                    "source_status": "untrusted_local_source",
                    "resolved_commit": "c" * 40,
                },
            )
        resolve.assert_called_once()

        invalid_resolved_payloads = (
            {
                "status": "resolved",
                "source_status": "remote_source_resolved",
                "resolved_commit": "",
            },
            {
                "status": "resolved",
                "source_status": "untrusted_local_source",
                "resolved_commit": "d" * 40,
            },
            {
                "status": "resolved",
                "source_status": None,
                "resolved_commit": "d" * 40,
            },
            {
                "status": "not_found",
                "source_status": "remote_ref_not_found",
                "resolved_commit": "",
            },
        )
        for resolution in invalid_resolved_payloads:
            with self.subTest(resolution=resolution), patch.object(
                s1_dep_diff, "resolve_step1_ref", return_value=resolution,
            ), patch.object(
                s1_dep_diff, "get_runtime_deps_by_switching_branch",
            ) as collect:
                with self.assertRaises(s1_dep_diff.Step1RefResolutionRequiredError):
                    s1_dep_diff._collect_runtime_deps_for_artifact_input(
                        "/repo", "release", "/analysis",
                    )
            collect.assert_not_called()

        operational_failures = (
            (
                {
                    "status": "fetch_failed",
                    "source_status": "remote_expected_commit_unmaterializable",
                    "resolved_commit": "",
                },
                s1_dep_diff.PinnedCommitMaterializationError,
            ),
            (
                {
                    "status": "fetch_failed",
                    "source_status": "remote_query_failed",
                    "resolved_commit": "",
                    "failures": [],
                },
                s1_dep_diff.Step1RemoteOperationError,
            ),
        )
        for resolution, expected_error in operational_failures:
            with self.subTest(error=expected_error.__name__), patch.object(
                s1_dep_diff, "resolve_step1_ref", return_value=resolution,
            ):
                with self.assertRaises(expected_error):
                    s1_dep_diff._collect_runtime_deps_for_artifact_input(
                        "/repo", "release", "/analysis",
                    )

        source_resolution = {
            "status": "resolved",
            "source_status": "user_confirmed_local_source",
            "resolved_commit": "f" * 40,
        }
        with patch.object(
            s1_dep_diff, "resolve_step1_ref", return_value=source_resolution,
        ):
            with self.assertRaises(s1_dep_diff.SourceRevisionConfirmationRequiredError):
                s1_dep_diff._collect_runtime_deps_for_artifact_input(
                    "/repo", "", "/analysis",
                )
        self.assertEqual(
            s1_dep_diff._collect_runtime_deps_for_artifact_input(
                "", "", "/analysis",
            ),
            ({}, {
                "source_mode": "none",
                "source_project_dir": "",
                "list_command": "",
            }),
        )

    def test_maven_workspace_collection_build_discovery_and_resolution_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = [{
                "entry_id": "a",
                "lib_entry": "BOOT-INF/lib/a-1.jar",
                "lib_name": "a-1.jar",
                "coord": "",
                "artifact_id": "a",
                "version": "1",
            }]
            resolved = {**raw[0], "coord": "g:a", "resolution_status": "resolved"}
            unresolved = {**raw[0], "resolution_status": "unresolved"}
            status_missing = {**raw[0]}

            with patch.object(
                s1_dep_diff, "_resolve_single_module_selector", return_value=None,
            ), patch.object(
                s1_dep_diff, "_resolve_module_dir_for_packaging", return_value=None,
            ):
                with self.assertRaisesRegex(RuntimeError, "无法解析目标模块目录"):
                    s1_dep_diff.collect_maven_deps_for_workspace(root)

            for stdout, stderr, expected in (
                ("stdout build failure", "", "stdout build failure"),
                ("stdout build failure", "stderr build failure", "stderr build failure"),
            ):
                with self.subTest(stderr=bool(stderr)), patch.object(
                    s1_dep_diff, "_resolve_single_module_selector", return_value=None,
                ), patch.object(
                    s1_dep_diff, "_resolve_module_dir_for_packaging", return_value=str(root),
                ), patch.object(
                    s1_dep_diff, "_normalize_maven_pl_with_workdir", return_value=None,
                ), patch.object(
                    s1_dep_diff, "build_project_scope", return_value={},
                ), patch.object(
                    s1_dep_diff, "_maven_profile_args_for_module", return_value=[],
                ), patch.object(
                    s1_dep_diff, "mvn_cmd", return_value=["mvn"],
                ), patch.object(
                    s1_dep_diff, "run_cmd", return_value=(stdout, stderr, 5),
                ):
                    with self.assertRaisesRegex(RuntimeError, expected):
                        s1_dep_diff.collect_maven_deps_for_workspace(
                            root, active_maven_profiles=["profile"],
                        )

            with patch.object(
                s1_dep_diff, "_resolve_single_module_selector", return_value=None,
            ), patch.object(
                s1_dep_diff, "_resolve_module_dir_for_packaging", return_value=str(root),
            ), patch.object(
                s1_dep_diff, "_normalize_maven_pl_with_workdir", return_value=None,
            ), patch.object(
                s1_dep_diff, "build_project_scope", return_value={},
            ), patch.object(
                s1_dep_diff, "_maven_profile_args_for_module", return_value=[],
            ), patch.object(
                s1_dep_diff, "mvn_cmd", return_value=["mvn"],
            ), patch.object(
                s1_dep_diff, "run_cmd", return_value=("", "", 0),
            ), patch.object(
                s1_dep_diff, "_discover_packaged_archives", return_value=[],
            ):
                with self.assertRaisesRegex(RuntimeError, "未产出可解析的最终制品"):
                    s1_dep_diff.collect_maven_deps_for_workspace(root)

            archives = [
                root / "thin.jar", root / "empty.jar",
                root / "first.war", root / "app.war",
            ]
            manual_identity = [{
                "side": "base",
                "entry_id": "different-entry",
                "group_id": "manual",
                "artifact_id": "different",
                "version": "1",
            }]
            with patch.object(
                s1_dep_diff, "_resolve_single_module_selector", return_value=None,
            ), patch.object(
                s1_dep_diff, "_resolve_module_dir_for_packaging", return_value=str(root),
            ), patch.object(
                s1_dep_diff, "_normalize_maven_pl_with_workdir", return_value=None,
            ), patch.object(
                s1_dep_diff, "build_project_scope", return_value={},
            ) as scope, patch.object(
                s1_dep_diff, "_maven_profile_args_for_module", return_value=[],
            ), patch.object(
                s1_dep_diff, "mvn_cmd", return_value=["mvn"],
            ), patch.object(
                s1_dep_diff, "run_cmd", return_value=("", "", 0),
            ), patch.object(
                s1_dep_diff, "_discover_packaged_archives", return_value=archives,
            ), patch.object(
                s1_dep_diff, "_detect_archive_packaging_type",
                side_effect=["thin_jar", "boot_jar", "war", "war"],
            ), patch.object(
                s1_dep_diff, "_inspect_packaged_archive", side_effect=[[], raw, raw],
            ), patch.object(
                s1_dep_diff, "_require_complete_packaged_archive_scan",
            ), patch.object(
                s1_dep_diff, "collect_runtime_deps_for_workspace",
                return_value=({"g:a": {"version": "1"}}, None),
            ) as runtime, patch.object(
                s1_dep_diff, "_enrich_packaged_deps_with_runtime",
                side_effect=[
                    ([], {}, []),
                    (
                        [resolved, unresolved, status_missing],
                        {"g:a": resolved},
                        [unresolved],
                    ),
                ],
            ):
                deps, meta = s1_dep_diff.collect_maven_deps_for_workspace(
                    root,
                    manual_artifact_identities=manual_identity,
                    allow_unresolved=True,
                    side="base",
                    active_maven_profiles=["profile"],
                )
            self.assertEqual(set(deps), {"g:a"})
            self.assertEqual(meta["packaging_type"], "war")
            self.assertEqual(meta["list_command"], "")
            self.assertEqual(meta["matched_count"], 1)
            runtime.assert_called_once()
            self.assertEqual(scope.call_args.kwargs["active_profiles"], {"profile"})
            self.assertNotIn("-pl", meta["build_command"])

            def run_resolution_case(enriched, *, allow_unresolved):
                with patch.object(
                    s1_dep_diff, "_resolve_single_module_selector", return_value="app",
                ), patch.object(
                    s1_dep_diff, "_resolve_module_dir_for_packaging", return_value=str(root),
                ), patch.object(
                    s1_dep_diff, "_normalize_maven_pl_with_workdir", return_value=":app",
                ), patch.object(
                    s1_dep_diff, "build_project_scope", return_value={},
                ), patch.object(
                    s1_dep_diff, "_maven_profile_args_for_module", return_value=[],
                ), patch.object(
                    s1_dep_diff, "mvn_cmd", return_value=["mvn"],
                ), patch.object(
                    s1_dep_diff, "run_cmd", return_value=("", "", 0),
                ), patch.object(
                    s1_dep_diff, "_discover_packaged_archives", return_value=[root / "app.jar"],
                ), patch.object(
                    s1_dep_diff, "_detect_archive_packaging_type", return_value="boot_jar",
                ), patch.object(
                    s1_dep_diff, "_inspect_packaged_archive",
                    return_value=[{**raw[0], "coord": "g:a"}],
                ), patch.object(
                    s1_dep_diff, "_require_complete_packaged_archive_scan",
                ), patch.object(
                    s1_dep_diff, "_enrich_packaged_deps_with_runtime", return_value=enriched,
                ):
                    return s1_dep_diff.collect_maven_deps_for_workspace(
                        root, allow_unresolved=allow_unresolved,
                    )

            with self.assertRaises(s1_dep_diff.UnresolvedPackagedCoordinatesError):
                run_resolution_case(
                    ([unresolved], {}, [unresolved]), allow_unresolved=False,
                )
            with self.assertRaisesRegex(RuntimeError, "未发现可比较的打包依赖"):
                run_resolution_case(([], {}, []), allow_unresolved=True)

    def test_gradle_workspace_collection_discovery_observer_and_resolution_matrix(self):
        class Observer:
            cache_dir = None

            def __init__(self):
                self.counters = []

            def phase(self, *_args, **_kwargs):
                return s1_dep_diff.nullcontext()

            def increment_counter(self, name, value):
                self.counters.append((name, value))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = [{
                "entry_id": "a",
                "lib_entry": "BOOT-INF/lib/a-1.jar",
                "lib_name": "a-1.jar",
                "coord": "",
                "artifact_id": "a",
                "version": "1",
            }]
            resolved = {**raw[0], "coord": "g:a", "resolution_status": "resolved"}
            unresolved = {**raw[0], "resolution_status": "unresolved"}
            status_missing = {**raw[0]}

            def common_patches(archives):
                return (
                    patch.object(s1_dep_diff, "_resolve_single_module_selector", return_value=None),
                    patch.object(
                        s1_dep_diff, "_gradle_target_model",
                        return_value={"module_dir": str(root), "gradle_path": ":app"},
                    ),
                    patch.object(s1_dep_diff, "build_project_scope", return_value={}),
                    patch.object(s1_dep_diff, "gradle_cmd", return_value=["gradle"]),
                    patch.object(
                        s1_dep_diff, "_run_gradle_command_with_lock_retry",
                        return_value=("", "", 0, 1),
                    ),
                    patch.object(s1_dep_diff, "_discover_packaged_archives", return_value=archives),
                )

            patches = common_patches([])
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                with self.assertRaisesRegex(RuntimeError, "未产出可解析的最终制品"):
                    s1_dep_diff.collect_gradle_deps_for_workspace(root)

            archives = [
                root / "thin.jar", root / "empty.jar",
                root / "first.jar", root / "app.jar",
            ]
            patches = common_patches(archives)
            observer = Observer()
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patch.object(
                s1_dep_diff, "_detect_archive_packaging_type",
                side_effect=["thin_jar", "packaged_jar", "boot_jar", "boot_jar"],
            ), patch.object(
                s1_dep_diff, "_inspect_packaged_archive", side_effect=[[], raw, raw],
            ), patch.object(
                s1_dep_diff, "_require_complete_packaged_archive_scan",
            ), patch.object(
                s1_dep_diff, "collect_runtime_deps_for_workspace",
                return_value=({"g:a": {"version": "1"}}, "gradle dependencies"),
            ) as runtime, patch.object(
                s1_dep_diff, "_enrich_packaged_deps_with_runtime",
                side_effect=[
                    ([], {}, []),
                    (
                        [resolved, unresolved, status_missing],
                        {"g:a": resolved},
                        [unresolved],
                    ),
                ],
            ):
                deps, meta = s1_dep_diff.collect_gradle_deps_for_workspace(
                    root,
                    manual_artifact_identities=[{"entry_id": "different"}],
                    allow_unresolved=True,
                    observer=observer,
                )
            self.assertEqual(set(deps), {"g:a"})
            self.assertEqual(meta["matched_count"], 1)
            self.assertEqual(meta["packaging_type"], "boot_jar")
            runtime.assert_called_once()
            self.assertEqual(
                {name for name, _value in observer.counters},
                {"cache_hits", "cache_misses", "archive_bytes", "nested_entries"},
            )

            def run_resolution_case(enriched, *, allow_unresolved):
                patches = common_patches([root / "app.jar"])
                with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patch.object(
                    s1_dep_diff, "_detect_archive_packaging_type", return_value="boot_jar",
                ), patch.object(
                    s1_dep_diff, "_inspect_packaged_archive",
                    return_value=[{**raw[0], "coord": "g:a"}],
                ), patch.object(
                    s1_dep_diff, "_require_complete_packaged_archive_scan",
                ), patch.object(
                    s1_dep_diff, "_enrich_packaged_deps_with_runtime", return_value=enriched,
                ):
                    return s1_dep_diff.collect_gradle_deps_for_workspace(
                        root, allow_unresolved=allow_unresolved,
                    )

            with self.assertRaises(s1_dep_diff.UnresolvedPackagedCoordinatesError):
                run_resolution_case(
                    ([unresolved], {}, [unresolved]), allow_unresolved=False,
                )
            with self.assertRaisesRegex(RuntimeError, "未发现可比较的打包依赖"):
                run_resolution_case(([], {}, []), allow_unresolved=True)

    def test_packaged_dependency_enrichment_identity_and_confirmation_matrix(self):
        def packaged(**overrides):
            row = {
                "entry_id": "entry-a",
                "lib_entry": "BOOT-INF/lib/a-1.jar",
                "lib_name": "a-1.jar",
                "coord": "",
                "group_id": "",
                "artifact_id": "a",
                "version": "1",
                "classifier": "",
                "filename_stem": "a-1",
                "match_source": "filename",
                "metadata_anomalies": [],
            }
            row.update(overrides)
            return row

        self.assertEqual(
            s1_dep_diff._enrich_packaged_deps_with_runtime(
                [],
                {
                    "": None,
                    "single": {"version": "1"},
                    "g:a": {
                        "version": "1",
                        "artifact_file_name": "a-1.jar",
                    },
                    "g:b:tests": {
                        "coord": "g:b:tests",
                        "version": "2",
                        "classifier": "tests",
                    },
                },
            ),
            ([], {}, []),
        )

        manual_identities = [
            {
                "side": "base",
                "lib_entry": "BOOT-INF/lib/renamed.jar",
                "group_id": "g",
                "artifact_id": "manual",
                "version": "2",
                "classifier": "",
            },
        ]
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(
                entry_id="renamed", lib_entry="BOOT-INF/lib/renamed.jar",
                lib_name="renamed.jar", artifact_id="renamed", version="",
                filename_stem="renamed",
            )],
            {},
            manual_artifact_identities=manual_identities,
            confirmed_unresolved_items=[{
                "artifact_id": "renamed", "version": "",
                "entry_id": "renamed", "side": "base",
            }],
            side="base",
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:manual"})
        self.assertEqual(entries[0]["version"], "2")
        self.assertEqual(entries[0]["match_source"], "manual_artifact_identity")

        ambiguous_manual = [
            {
                "side": "current",
                "lib_entry": "BOOT-INF/lib/a-1.jar",
                "group_id": group,
                "artifact_id": "a",
                "version": "1",
            }
            for group in ("one", "two")
        ]
        ambiguous_items = [
            packaged(entry_id="ambiguous-empty"),
            packaged(entry_id="ambiguous-existing", metadata_anomalies=["prior"]),
        ]
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            ambiguous_items,
            {},
            manual_artifact_identities=ambiguous_manual,
            side="current",
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 2)
        self.assertTrue(all(any(
            str(value).startswith("manual_artifact_identity_ambiguous:")
            for value in entry["metadata_anomalies"]
        ) for entry in entries))
        self.assertIn("prior", entries[1]["metadata_anomalies"])

        generic_override = {
            ("a", "1"): {
                "group_id": "g", "artifact_id": "a", "coord": "g:a",
            },
        }
        classifier_override = {
            ("a", "1", "tests"): {
                "group_id": "g", "artifact_id": "a", "coord": "g:a",
            },
        }
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged()], {}, manual_coord_overrides=generic_override,
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:a"})
        self.assertEqual(entries[0]["version"], "1")

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(
                lib_entry="BOOT-INF/lib/a-1-tests.jar",
                lib_name="a-1-tests.jar", classifier="tests",
                filename_stem="a-1-tests",
            )],
            {},
            manual_coord_overrides=classifier_override,
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:a:tests"})

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(group_id="fallback.group")],
            {},
            manual_coord_overrides={("a", "1"): {"note": "fallback fields"}},
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(entries[0]["group_id"], "fallback.group")

        ambiguous_runtime = {
            "one:a": {"group_id": "one", "artifact_id": "a", "version": "1"},
            "two:a": {"group_id": "two", "artifact_id": "a", "version": "1"},
        }
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged()],
            ambiguous_runtime,
            manual_coord_overrides=generic_override,
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:a"})
        self.assertFalse(any(
            str(value).startswith("runtime_filename_coordinate_ambiguous:")
            for value in entries[0]["metadata_anomalies"]
        ))

        stem_runtime = {
            "g:custom": {
                "group_id": "g", "artifact_id": "custom", "version": "1",
            },
        }
        entries, _resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(
                lib_entry="BOOT-INF/lib/renamed.jar", lib_name="renamed.jar",
                artifact_id="", version="", filename_stem="custom-1",
            )],
            stem_runtime,
        )
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(entries[0]["coord"], "g:custom")

        multiple_stem_runtime = {
            f"{group}:custom": {
                "group_id": group, "artifact_id": "custom", "version": "1",
            }
            for group in ("one", "two")
        }
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(
                lib_entry="BOOT-INF/lib/renamed.jar", lib_name="renamed.jar",
                artifact_id="", version="", filename_stem="custom-1",
            )],
            multiple_stem_runtime,
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(match_source="archive")],
            {"g:a": {"group_id": "g", "artifact_id": "a", "version": "1"}},
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:a"})

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(match_source="archive")],
            {
                "one:a": {"group_id": "one", "artifact_id": "a", "version": "1"},
                "two:a": {"group_id": "two", "artifact_id": "a", "version": "1"},
            },
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(
                artifact_id="", version="", filename_stem=None,
                match_source="filename",
            )],
            stem_runtime,
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(
                artifact_id="a", version="", match_source="archive",
            )],
            {},
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(metadata_anomalies=["prior"])],
            ambiguous_runtime,
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertIn("prior", entries[0]["metadata_anomalies"])
        self.assertTrue(any(
            str(value).startswith("runtime_filename_coordinate_ambiguous:")
            for value in entries[0]["metadata_anomalies"]
        ))

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(metadata_anomalies=[])],
            ambiguous_runtime,
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertTrue(any(
            str(value).startswith("runtime_filename_coordinate_ambiguous:")
            for value in entries[0]["metadata_anomalies"]
        ))

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged()],
            {"g:a": {"group_id": "g", "artifact_id": "a", "version": "1"}},
            manual_coord_overrides={
                ("a", "1"): {
                    "group_id": "wrong", "artifact_id": "a", "coord": "wrong:a",
                },
            },
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:a"})

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(
                lib_name="", lib_entry="BOOT-INF/lib/renamed.jar",
                group_id="g", artifact_id="a", version="1",
            )],
            {},
            manual_coord_overrides=generic_override,
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)

        confirmed = [
            {"artifact_id": "wrong", "version": "1"},
            {"artifact_id": "a", "version": "wrong"},
            {"artifact_id": "a", "version": "1", "entry_id": "wrong-entry"},
            {"artifact_id": "a", "version": "1"},
        ]
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(
                coord="g:a", group_id="g", match_source="embedded-pom",
                entry_id="", lib_entry="",
            )],
            {},
            confirmed_unresolved_items=confirmed,
            side="base",
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(entries[0]["resolution_status"], "unresolved")

        inventory_runtime = {
            "g:a": {
                "group_id": "g", "artifact_id": "a", "version": "1",
                "artifact_file_name": "a-1.jar",
            },
        }
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged()],
            inventory_runtime,
            confirmed_unresolved_items=[{
                "artifact_id": "a", "version": "1", "source": "filename",
            }],
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:a"})

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged()],
            inventory_runtime,
            confirmed_unresolved_items=[{
                "artifact_id": "a", "version": "1", "source": "",
            }],
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)

        project_runtime = {
            "g:a": {
                "group_id": "g", "artifact_id": "a", "version": "1",
                "project_module": "app",
            },
        }
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged()],
            project_runtime,
            confirmed_unresolved_items=[{
                "artifact_id": "a", "version": "1", "source": "filename",
            }],
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:a"})

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged()],
            inventory_runtime,
            confirmed_unresolved_items=[{
                "artifact_id": "a", "version": "1", "source": "manual-review",
            }],
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)

        classifier_runtime = {
            "g:a:tests": {
                "group_id": "g", "artifact_id": "a", "version": "1",
                "classifier": "tests",
            },
        }
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged(
                lib_entry="BOOT-INF/lib/a-1-tests.jar",
                lib_name="a-1-tests.jar", classifier="tests",
                filename_stem="a-1-tests",
            )],
            classifier_runtime,
            confirmed_unresolved_items=[{
                "artifact_id": "a", "version": "1", "classifier": "tests",
                "source": "filename",
            }],
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)

        conventional_runtime = {
            "g:a": {"group_id": "g", "artifact_id": "a", "version": "1"},
        }
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged()],
            conventional_runtime,
            confirmed_unresolved_items=[{
                "artifact_id": "a", "version": "1", "source": "filename",
            }],
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)

        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            [packaged()],
            {},
            manual_coord_overrides=generic_override,
            confirmed_unresolved_items=[{
                "artifact_id": "a", "version": "1", "source": "review",
            }],
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:a"})

        unknown_items = [
            packaged(
                entry_id="unknown-one", lib_entry="", lib_name="",
                artifact_id="", version="", classifier="", coord="",
                match_source=None, metadata_anomalies=["prior"],
            ),
            packaged(
                entry_id="unknown-two", lib_entry="", lib_name="",
                artifact_id="", version="", classifier="tests", coord="",
                match_source="archive", metadata_anomalies=[],
            ),
        ]
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            unknown_items,
            {},
            confirmed_unresolved_items=[
                {
                    "artifact_id": "", "version": "", "entry_id": "unknown-one",
                    "source": "",
                },
                {
                    "artifact_id": "", "version": "", "entry_id": "unknown-two",
                    "source": "archive-review",
                },
            ],
        )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 2)
        by_id = {entry["entry_id"]: entry for entry in entries}
        self.assertIn("<unknown-artifact>", by_id["unknown-one"]["coord"])
        self.assertTrue(by_id["unknown-two"]["coord"].endswith(":tests"))
        self.assertIn("prior", by_id["unknown-one"]["metadata_anomalies"])

        with patch.object(
            s1_dep_diff, "_runtime_dependency_for_packaged_filename",
            return_value=({
                "group_id": "", "artifact_id": "", "classifier": "",
                "packaged_match_source": "",
            }, []),
        ):
            entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
                [packaged(
                    lib_name="", group_id="g", artifact_id="a",
                    coord="", match_source="filename",
                )],
                {},
            )
        self.assertEqual(unresolved, [])
        self.assertEqual(set(resolved), {"g:a"})

        with patch.object(
            s1_dep_diff, "_runtime_dependency_for_packaged_filename",
            return_value=({
                "group_id": "g", "artifact_id": "a", "classifier": "tests",
                "classifier_source": "runtime-version-filename-inference",
                "packaged_match_source": "runtime-filename-classifier",
            }, []),
        ):
            entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
                [packaged()], {},
            )
        self.assertEqual(resolved, {})
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(entries[0]["version_confirmation_status"], "unconfirmed")

        boundary_items = [
            packaged(
                entry_id="coord-missing", coord="", group_id="",
                artifact_id="a", version="1", match_source="embedded-pom",
            ),
            packaged(
                entry_id="version-unconfirmed", coord="g:a", group_id="g",
                artifact_id="a", version="1", match_source="filename",
            ),
            packaged(
                entry_id="unknown", lib_entry="", lib_name="", coord="",
                group_id="", artifact_id="", version="", classifier="",
                match_source="archive",
            ),
            packaged(
                entry_id="classifier-coordinate-missing", coord="", group_id="",
                artifact_id="a", version="1", classifier="tests",
                match_source="embedded-pom",
            ),
            packaged(
                entry_id="resolved", coord="g:a", group_id="g",
                artifact_id="a", version="1", match_source="embedded-pom",
            ),
            packaged(
                entry_id="resolved-anomaly", coord="g:b", group_id="g",
                artifact_id="b", version="2", match_source="embedded-pom",
                metadata_anomalies=["prior"],
            ),
        ]
        entries, resolved, unresolved = s1_dep_diff._enrich_packaged_deps_with_runtime(
            boundary_items, {}, side="current",
        )
        self.assertEqual(set(resolved), {"g:a", "g:b"})
        self.assertEqual(len(unresolved), 4)
        statuses = {entry["entry_id"]: entry for entry in entries}
        self.assertEqual(
            statuses["coord-missing"]["version_confirmation_status"],
            "confirmed",
        )
        self.assertEqual(
            statuses["version-unconfirmed"]["version_confirmation_status"],
            "unconfirmed",
        )
        self.assertIn("<unknown-artifact>", statuses["unknown"]["coord"])
        self.assertTrue(
            statuses["classifier-coordinate-missing"]["coord"].endswith(":tests"),
        )
        self.assertIn("prior", statuses["resolved-anomaly"]["metadata_anomalies"])

    def test_dependency_jar_materialization_rows_runtime_closure_and_launcher_matrix(self):
        def nested_bytes(marker):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("demo/Dependency.class", marker)
            return stream.getvalue()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_artifact = root / "base.war"
            current_artifact = root / "current.jar"
            base_libs = {
                "WEB-INF/lib/a-1.jar": nested_bytes(b"a-base"),
                "WEB-INF/lib/upgrade.jar": nested_bytes(b"upgrade"),
                "WEB-INF/lib/keep.jar": nested_bytes(b"keep"),
                "WEB-INF/lib/classifier-only.jar": nested_bytes(b"classifier-only"),
                "WEB-INF/lib/blank-coord.jar": nested_bytes(b"blank-coord"),
            }
            current_libs = {
                "lib/a-2.jar": nested_bytes(b"a-current"),
            }
            with zipfile.ZipFile(base_artifact, "w") as archive:
                for name, content in base_libs.items():
                    archive.writestr(name, content)
                archive.writestr("WEB-INF/classes/app/Main.class", b"base-main")
            with zipfile.ZipFile(current_artifact, "w") as archive:
                for name, content in current_libs.items():
                    archive.writestr(name, content)
                archive.writestr("app/Main.class", b"current-main")

            rows = [
                {
                    "resolution_status": "unresolved",
                    "change_type": "新增",
                    "old_version": "1",
                    "base_lib_entry": "ignored.jar",
                },
                {
                    "resolution_status": "resolved",
                    "change_type": "未变",
                    "old_version": "1",
                    "base_lib_entry": "ignored.jar",
                },
                {
                    "resolution_status": "resolved",
                    "change_type": "大版本升级",
                    "coord": "g:a",
                    "base_coord": "",
                    "current_coord": "g:a",
                    "old_version": "1",
                    "new_version": "2",
                    "scope": "runtime",
                    "base_lib_entry": r"WEB-INF\lib\a-1.jar",
                    "current_lib_entry": "lib/a-2.jar",
                    "base_packaged_match_source": "embedded-pom",
                    "current_packaged_match_source": "manual_override",
                },
                {
                    "resolution_status": "resolved",
                    "change_type": "新增",
                    "base_coord": "g:upgrade",
                    "old_version": "1",
                    "new_version": "-",
                    "base_lib_entry": "WEB-INF/lib/upgrade.jar",
                },
                {
                    "resolution_status": "resolved",
                    "change_type": "新增",
                    "base_coord": "g:keep:tests",
                    "old_version": "1",
                    "new_version": "",
                    "base_lib_entry": "WEB-INF/lib/keep.jar",
                },
                {
                    "resolution_status": "resolved",
                    "change_type": "新增",
                    "base_coord": "g:classifier-only",
                    "base_classifier": "tests",
                    "old_version": "1",
                    "new_version": "-",
                    "base_lib_entry": "WEB-INF/lib/classifier-only.jar",
                },
                {
                    "resolution_status": "resolved",
                    "change_type": "新增",
                    "coord": "",
                    "base_coord": "",
                    "base_classifier": "tests",
                    "old_version": "1",
                    "new_version": "-",
                    "base_lib_entry": "WEB-INF/lib/blank-coord.jar",
                },
                {
                    "resolution_status": "resolved",
                    "change_type": "新增",
                    "old_version": None,
                    "new_version": "-",
                },
                {
                    "resolution_status": "resolved",
                    "change_type": None,
                    "old_version": "-",
                    "new_version": "-",
                },
                {
                    "resolution_status": None,
                    "change_type": "新增",
                    "old_version": "1",
                    "base_lib_entry": "ignored.jar",
                },
            ]
            base_entries = [
                {
                    "coord": "g:a", "version": "1", "scope": "runtime",
                    "lib_entry": "WEB-INF/lib/a-1.jar",
                    "resolution_status": "resolved",
                    "packaged_match_source": "embedded-pom",
                },
                {
                    "coord": "g:upgrade:tests", "version": "1", "scope": "runtime",
                    "classifier": "tests",
                    "lib_entry": "WEB-INF/lib/upgrade.jar",
                    "resolution_status": "resolved",
                    "packaged_match_source": "runtime-filename-classifier",
                },
                {
                    "coord": "g:keep", "version": "1", "scope": None,
                    "classifier": "",
                    "lib_entry": "WEB-INF/lib/keep.jar",
                    "resolution_status": "resolved",
                },
                {
                    "coord": "g:test", "version": "1", "scope": "test",
                    "lib_entry": "ignored-test.jar", "resolution_status": "resolved",
                },
                {
                    "coord": "g:optional", "version": "1", "scope": "optional",
                    "lib_entry": "ignored-optional.jar", "resolution_status": "resolved",
                },
                {
                    "coord": "g:provided", "version": "1", "scope": "provided",
                    "lib_entry": "provided.jar", "resolution_status": "resolved",
                },
                {
                    "coord": "", "version": "1", "scope": "provided",
                    "lib_entry": "provided-fallback.jar", "resolution_status": "resolved",
                },
                {
                    "coord": "g:unresolved", "version": "1", "scope": "runtime",
                    "lib_entry": "unresolved.jar", "resolution_status": "unresolved",
                },
                {
                    "coord": "g:unresolved-fallback", "version": "1", "scope": "runtime",
                    "lib_entry": "", "resolution_status": "unresolved",
                },
                {
                    "coord": "", "version": "", "scope": "runtime",
                    "lib_entry": "not-retained.jar",
                },
                {
                    "coord": "", "version": "", "scope": "runtime",
                    "lib_entry": "",
                },
                {
                    "coord": "g:dash", "version": "-", "scope": "runtime",
                    "lib_entry": "dash.jar", "resolution_status": "resolved",
                },
            ]
            current_entries = [{
                "coord": "g:a", "version": "2", "scope": "runtime",
                "lib_entry": "lib/a-2.jar", "resolution_status": "resolved",
            }]
            output = root / "output"
            stale_dir = output / s1_dep_diff.STEP1_DEPENDENCY_JARS_DIRNAME
            stale_dir.mkdir(parents=True)
            (stale_dir / "stale.txt").write_text("stale", encoding="utf-8")
            manifest_path, items = s1_dep_diff.materialize_changed_dependency_jars(
                rows,
                {
                    "base": {
                        "artifact_path": str(base_artifact),
                        "artifact_sha256": "",
                    },
                    "current": {
                        "artifact_path": str(current_artifact),
                        "artifact_sha256": "f" * 64,
                    },
                },
                output,
                base_entries=base_entries,
                current_entries=current_entries,
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

            boot_artifact = root / "boot.jar"
            with zipfile.ZipFile(boot_artifact, "w") as archive:
                archive.writestr("BOOT-INF/lib/a.jar", nested_bytes(b"boot-a"))
                archive.writestr("BOOT-INF/classes/app/Main.class", b"boot-main")
                archive.writestr("BOOT-INF/classes/app/config.yml", b"enabled: true")
                archive.writestr(
                    "BOOT-INF/classpath.idx",
                    '- "BOOT-INF/lib/a.jar"\n',
                )
            boot_manifest_path, boot_items = s1_dep_diff.materialize_changed_dependency_jars(
                [],
                {"current": {"artifact_path": str(boot_artifact)}},
                root / "boot-output",
                current_entries=[{
                    "coord": "g:a", "version": "1", "scope": "runtime",
                    "lib_entry": "BOOT-INF/lib/a.jar",
                    "resolution_status": "resolved",
                }],
            )
            boot_manifest = json.loads(
                boot_manifest_path.read_text(encoding="utf-8"),
            )

        self.assertFalse((stale_dir / "stale.txt").exists())
        self.assertEqual(len(items), 6)
        by_entry = {item["lib_entry"]: item for item in items}
        self.assertEqual(by_entry["WEB-INF/lib/upgrade.jar"]["coord"], "g:upgrade:tests")
        self.assertEqual(by_entry["WEB-INF/lib/upgrade.jar"]["classifier"], "tests")
        self.assertEqual(by_entry["WEB-INF/lib/keep.jar"]["coord"], "g:keep:tests")
        self.assertEqual(
            by_entry["WEB-INF/lib/classifier-only.jar"]["coord"],
            "g:classifier-only:tests",
        )
        self.assertEqual(by_entry["WEB-INF/lib/blank-coord.jar"]["coord"], "")
        self.assertTrue(all(
            item["runtime_classpath_authority"] == "outer_archive_entry_order"
            for item in items
        ))
        business_by_side = {
            item["side"]: item for item in manifest["business_artifacts"]
        }
        self.assertEqual(
            business_by_side["base"]["container_and_launcher_kind"],
            "servlet-war",
        )
        self.assertEqual(
            business_by_side["current"]["container_and_launcher_kind"],
            "java-classpath",
        )
        base_closure = manifest["runtime_closure"]["base"]
        self.assertEqual(base_closure["coverage_status"], "partial")
        self.assertTrue(any(
            gap.startswith("external_provided_runtime_not_materialized:")
            for gap in base_closure["coverage_gaps"]
        ))
        self.assertTrue(any(
            gap.startswith("runtime_dependency_unresolved:")
            for gap in base_closure["coverage_gaps"]
        ))
        self.assertIn(
            "runtime_dependency_not_retained:not-retained.jar",
            base_closure["coverage_gaps"],
        )
        self.assertEqual(
            manifest["runtime_closure"]["current"]["coverage_status"],
            "complete",
        )
        self.assertEqual(
            boot_items[0]["runtime_classpath_authority"],
            "spring_boot_classpath_index",
        )
        self.assertEqual(boot_items[0]["runtime_classpath_index"], 0)
        self.assertEqual(
            boot_manifest["business_artifacts"][0]["container_and_launcher_kind"],
            "spring-boot-executable-jar",
        )
        self.assertEqual(boot_manifest["business_artifacts"][0]["class_count"], 1)

    def test_dependency_jar_materialization_request_conflict_matrix(self):
        def changed_row(**overrides):
            row = {
                "resolution_status": "resolved",
                "change_type": "新增",
                "old_version": "1",
                "new_version": "-",
                "base_coord": "g:a",
                "base_lib_entry": "lib/a.jar",
            }
            row.update(overrides)
            return row

        cases = (
            (
                [changed_row(base_lib_entry="", base_coord="g:a")], [],
                "依赖缺少最终制品条目: g:a",
            ),
            (
                [changed_row(base_lib_entry=None, base_coord="", coord="")], [],
                "依赖缺少最终制品条目: <unknown>",
            ),
            (
                [changed_row(base_coord="g:a:one", base_classifier="two")], [],
                "classifier 冲突",
            ),
            (
                [changed_row(base_coord="g:a")],
                [{
                    "coord": "h:a", "version": "1", "scope": "runtime",
                    "lib_entry": "lib/a.jar", "resolution_status": "resolved",
                }],
                "同一制品条目身份冲突",
            ),
            (
                [changed_row(base_coord="g:a")],
                [{
                    "coord": "g:a:", "version": "1", "scope": "runtime",
                    "lib_entry": "lib/a.jar", "resolution_status": "resolved",
                }],
                "同一制品条目身份冲突",
            ),
            (
                [changed_row(base_coord="g:a:one")],
                [{
                    "coord": "g:a:two", "version": "1", "scope": "runtime",
                    "lib_entry": "lib/a.jar", "resolution_status": "resolved",
                }],
                "同一制品条目身份冲突",
            ),
            (
                [changed_row(base_coord="g:a"), changed_row(base_coord="", coord="")],
                [],
                "最终制品不可用",
            ),
            (
                [changed_row(base_coord="g:a")],
                [{
                    "coord": "g:a", "version": "2", "scope": "runtime",
                    "lib_entry": "lib/a.jar", "resolution_status": "resolved",
                }],
                "同一制品条目身份冲突",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (rows, base_entries, message) in enumerate(cases):
                with self.subTest(index=index), self.assertRaisesRegex(ValueError, message):
                    s1_dep_diff.materialize_changed_dependency_jars(
                        rows,
                        {},
                        root / f"out-{index}",
                        base_entries=base_entries,
                    )

    def test_dependency_jar_materialization_archive_cardinality_safety_and_identity_matrix(self):
        def nested_bytes(marker):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("demo/Dependency.class", marker)
            return stream.getvalue()

        def materialize_one(artifact, output, *, coord="g:a", classifier=""):
            return s1_dep_diff.materialize_changed_dependency_jars(
                [],
                {"current": {"artifact_path": str(artifact)}},
                output,
                current_entries=[{
                    "coord": coord,
                    "classifier": classifier,
                    "version": "1",
                    "scope": "runtime",
                    "lib_entry": "lib/a.jar",
                    "resolution_status": "resolved",
                }],
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, items = s1_dep_diff.materialize_changed_dependency_jars(
                [], None, root / "no-side-metadata",
            )
            self.assertEqual(items, [])
            self.assertTrue(manifest.is_file())

            with self.assertRaisesRegex(ValueError, "最终制品不可用"):
                s1_dep_diff.materialize_changed_dependency_jars(
                    [{
                        "resolution_status": "resolved",
                        "change_type": "新增",
                        "old_version": "1",
                        "new_version": "-",
                        "base_coord": "g:a",
                        "base_lib_entry": "lib/a.jar",
                    }],
                    {"base": {"artifact_path": str(root / "does-not-exist.jar")}},
                    root / "missing-artifact-output",
                )

            missing = root / "missing-entry.jar"
            with zipfile.ZipFile(missing, "w") as archive:
                archive.writestr("app/Main.class", b"main")
            with self.assertRaisesRegex(ValueError, "条目数量异常.*（0）"):
                materialize_one(missing, root / "missing-output")

            duplicate = root / "duplicate-entry.jar"
            with zipfile.ZipFile(duplicate, "w") as archive:
                archive.writestr("lib/a.jar", nested_bytes(b"one"))
                archive.writestr("lib/a.jar", nested_bytes(b"two"))
            with self.assertRaisesRegex(ValueError, "条目数量异常.*（2）"):
                materialize_one(duplicate, root / "duplicate-output")

            directory_entry = root / "directory-entry.jar"
            with zipfile.ZipFile(directory_entry, "w") as archive:
                archive.writestr("lib/a.jar/", b"")
            with self.assertRaisesRegex(ValueError, "条目数量异常.*（0）"):
                s1_dep_diff.materialize_changed_dependency_jars(
                    [],
                    {"current": {"artifact_path": str(directory_entry)}},
                    root / "directory-entry-output",
                    current_entries=[{
                        "coord": "g:a", "version": "1", "scope": "runtime",
                        "lib_entry": "lib/a.jar/", "resolution_status": "resolved",
                    }],
                )

            safe = root / "safe.jar"
            with zipfile.ZipFile(safe, "w") as archive:
                archive.writestr("lib/a.jar", nested_bytes(b"safe"))
                archive.writestr("app/Main.class", b"main")

            with patch.object(
                s1_dep_diff, "require_safe_archive", side_effect=RuntimeError("unsafe"),
            ):
                with self.assertRaisesRegex(RuntimeError, "unsafe"):
                    materialize_one(safe, root / "unsafe-existing")

            def delete_then_fail(path, **_kwargs):
                Path(path).unlink()
                raise RuntimeError("unsafe after delete")

            with patch.object(
                s1_dep_diff, "require_safe_archive", side_effect=delete_then_fail,
            ):
                with self.assertRaisesRegex(RuntimeError, "unsafe after delete"):
                    materialize_one(safe, root / "unsafe-missing")

            with patch.object(
                s1_dep_diff, "require_safe_archive",
                side_effect=[None, RuntimeError("business unsafe")],
            ):
                with self.assertRaisesRegex(RuntimeError, "business unsafe"):
                    materialize_one(safe, root / "business-unsafe-existing")

            safety_calls = []

            def delete_business_then_fail(path, **_kwargs):
                safety_calls.append(Path(path))
                if len(safety_calls) == 2:
                    Path(path).unlink()
                    raise RuntimeError("business unsafe after delete")

            with patch.object(
                s1_dep_diff, "require_safe_archive",
                side_effect=delete_business_then_fail,
            ):
                with self.assertRaisesRegex(RuntimeError, "business unsafe after delete"):
                    materialize_one(safe, root / "business-unsafe-missing")

            for classifier in ("", "tests"):
                conflict = root / f"identity-conflict-{classifier or 'plain'}.jar"
                with zipfile.ZipFile(conflict, "w") as archive:
                    archive.writestr("lib/a.jar", nested_bytes(b"one"))
                    archive.writestr("lib/b.jar", nested_bytes(b"two"))
                entries = [
                    {
                        "coord": f"g:a{':' + classifier if classifier else ''}",
                        "classifier": classifier,
                        "version": "1",
                        "scope": "runtime",
                        "lib_entry": entry,
                        "resolution_status": "resolved",
                    }
                    for entry in ("lib/a.jar", "lib/b.jar")
                ]
                with self.subTest(classifier=classifier), self.assertRaisesRegex(
                    ValueError,
                    "同一 GAV 对应多个不同字节",
                ):
                    s1_dep_diff.materialize_changed_dependency_jars(
                        [],
                        {"current": {"artifact_path": str(conflict)}},
                        root / f"identity-output-{classifier or 'plain'}",
                        current_entries=entries,
                    )

    def test_packaged_archive_scan_duplicate_prefix_budget_and_extraction_matrix(self):
        def nested_bytes():
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w"):
                pass
            return stream.getvalue()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.jar"
            with zipfile.ZipFile(duplicate, "w") as archive:
                archive.writestr("BOOT-INF/lib/a.jar", nested_bytes())
                archive.writestr("BOOT-INF/lib/a.jar", nested_bytes())
                archive.writestr("config.yml", "one")
                archive.writestr("config.yml", "two")
            duplicate_result = s1_dep_diff._scan_packaged_archive(duplicate)
            self.assertFalse(duplicate_result.complete)
            errors = {item["error"] for item in duplicate_result.failures}
            self.assertEqual(
                errors,
                {"ARCHIVE_DUPLICATE_DEPENDENCY_ENTRY", "ARCHIVE_DUPLICATE_ENTRY"},
            )

            allowed_duplicate = root / "allowed-duplicate.jar"
            with zipfile.ZipFile(allowed_duplicate, "w") as archive:
                archive.writestr("META-INF/maven/g/a/pom.properties", "one")
                archive.writestr("META-INF/maven/g/a/pom.properties", "two")
            self.assertTrue(s1_dep_diff._scan_packaged_archive(allowed_duplicate).complete)

            unsafe = root / "unsafe.jar"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("../escape.txt", "bad")
                archive.writestr("/absolute.txt", "bad")
            unsafe_result = s1_dep_diff._scan_packaged_archive(unsafe)
            self.assertFalse(unsafe_result.complete)
            self.assertEqual(
                {item["entry"] for item in unsafe_result.failures},
                {"../escape.txt", "/absolute.txt"},
            )
            self.assertTrue(all(
                item["error"] == "ARCHIVE_ENTRY_PATH_UNSAFE"
                for item in unsafe_result.failures
            ))

            prefixes = root / "prefixes.jar"
            with zipfile.ZipFile(prefixes, "w") as archive:
                archive.writestr("BOOT-INF/lib/a.jar", nested_bytes())
                archive.writestr("WEB-INF/lib/b.jar", nested_bytes())
                archive.writestr("lib/c.jar", nested_bytes())
                archive.writestr("other/d.jar", nested_bytes())
                archive.writestr("not-a-jar.txt", "x")
            prefix_result = s1_dep_diff._scan_packaged_archive(prefixes)
            self.assertTrue(prefix_result.complete)
            self.assertEqual(prefix_result.nested_entries, 3)

            with patch.object(s1_dep_diff, "STEP1_MAX_TOTAL_DEPENDENCY_BYTES", -1):
                self.assertEqual(
                    s1_dep_diff._scan_packaged_archive(prefixes).failures[0]["error"],
                    "ARCHIVE_DEPENDENCY_BYTES_EXCEEDED",
                )
            with patch.object(
                s1_dep_diff, "_archive_entry_expansion_ratio", return_value=(0, "SIZE_ERROR"),
            ):
                size_error = s1_dep_diff._scan_packaged_archive(prefixes)
            self.assertEqual(len(size_error.failures), 3)
            with patch.object(s1_dep_diff, "STEP1_MAX_DEPENDENCY_JAR_BYTES", -1):
                oversized = s1_dep_diff._scan_packaged_archive(prefixes)
            self.assertTrue(all(item["error"] == "ARCHIVE_NESTED_SIZE_EXCEEDED" for item in oversized.failures))
            with patch.object(
                s1_dep_diff, "_extract_packaged_dep_from_nested_jar_source", return_value=None,
            ):
                none_result = s1_dep_diff._scan_packaged_archive(prefixes)
            self.assertEqual(none_result.rows, [])

            read_error_dep = s1_dep_diff._build_packaged_entry("BOOT-INF/lib/broken.jar")
            read_error_dep.update({
                "read_error": "metadata failed",
                "resolution_status": "unresolved",
            })
            support_dep = s1_dep_diff._build_packaged_entry(
                "BOOT-INF/lib/spring-boot-jarmode-layertools-1.jar",
            )
            support_dep["artifact_id"] = "spring-boot-jarmode-layertools"
            normal_dep = s1_dep_diff._build_packaged_entry("BOOT-INF/lib/normal-1.jar")
            with patch.object(
                s1_dep_diff, "_extract_packaged_dep_from_nested_jar_source",
                side_effect=[read_error_dep, support_dep, normal_dep],
            ):
                mixed_result = s1_dep_diff._scan_packaged_archive(prefixes)
            self.assertFalse(mixed_result.complete)
            self.assertEqual(mixed_result.rows, [read_error_dep, normal_dep])
            self.assertEqual(
                mixed_result.failures[0]["stage"], "embedded_metadata_read",
            )


if __name__ == "__main__":
    unittest.main()
