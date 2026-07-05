import io
import csv
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s1_dep_diff  # noqa: E402
from pipeline_constants import STEP1_ARTIFACTS_DIRNAME  # noqa: E402


class Step1PackagedDepsTest(unittest.TestCase):
    def _nested_jar_bytes(self, entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as nested:
            for name, content in entries:
                nested.writestr(name, content)
        return buffer.getvalue()

    def test_retain_artifact_for_analysis_preserves_exact_bytes_and_updates_meta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "build/app.jar"
            artifact.parent.mkdir()
            artifact.write_bytes(b"exact-artifact")
            meta = {"artifact_path": str(artifact), "archives": [str(artifact)]}

            s1_dep_diff.retain_artifact_for_analysis(meta, root / "report" / STEP1_ARTIFACTS_DIRNAME, "current")

            retained = Path(meta["artifact_path"])
            self.assertEqual(retained.read_bytes(), b"exact-artifact")
            self.assertEqual(meta["original_artifact_path"], str(artifact))
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
            base_meta = {
                "mode": "final_artifact",
                "archives": [str(work_dir / "base.jar")],
                "deps": [base_entry],
                "dep_entries": [base_entry],
                "matched_count": 1,
                "runtime_only_count": 0,
                "runtime_only_coords": [],
                "module_dir": str(work_dir / "base-module"),
            }
            curr_meta = {
                "mode": "final_artifact",
                "archives": [str(work_dir / "current.jar")],
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
                    "--work-dir",
                    str(work_dir),
                    "--output",
                    str(output_path),
                ],
            ):
                s1_dep_diff.main()

            alerts_path = work_dir / "s1_dep_alerts.csv"
            self.assertTrue(alerts_path.exists())
            with alerts_path.open("r", encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["coord"], "org.example:demo-lib")
        self.assertEqual(rows[0]["old_version"], "2.0.0")
        self.assertEqual(rows[0]["new_version"], "1.0.0")
        self.assertEqual(rows[0]["change_type"], "降级⚠️")
        self.assertEqual(
            set(rows[0].keys()),
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
            },
        )


if __name__ == "__main__":
    unittest.main()
