import io
import csv
import os
import subprocess
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
                "/same/project",
                primary_module="app",
                side="current",
                artifact_path="/tmp/current.jar",
            )

        self.assertEqual(deps, branch_deps)
        self.assertEqual(meta["source_mode"], "checkout_branch")
        self.assertEqual(meta["branch"], "a" * 40)
        self.assertEqual(meta["requested_ref"], "current-release")
        self.assertEqual(meta["resolved_ref"], "origin/current-release")
        ref_call.assert_called_once_with("/same/project", "current-release")
        branch_call.assert_called_once()
        self.assertEqual(branch_call.call_args.args[0], "a" * 40)
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
                    str(repo), base_commit, str(repo), side="base"
                )
                current_deps, current_meta = s1_dep_diff._collect_runtime_deps_for_artifact_input(
                    str(repo), current_commit, str(repo), side="current"
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

            alerts_path = work_dir / "dep_alerts.csv"
            summary_path = work_dir / "dep_summary.txt"
            self.assertTrue(alerts_path.exists())
            self.assertTrue(summary_path.exists())
            summary_text = summary_path.read_text(encoding="utf-8")
            with alerts_path.open("r", encoding="utf-8", newline="") as f:
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
